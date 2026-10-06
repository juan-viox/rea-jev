/**
 * Deterministic target sniffing for the route hook: path tokens, file magic,
 * directory heuristics, URLs, CDP / inspector endpoints, and the RE keyword
 * pre-filter. Read-only, bounded (≤16 tokens, ≤64 bytes per file plus one PE
 * header read), and silent on every error.
 *
 * @module sniff
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { redact } from './redact.mjs';

/** File extensions that make a bare token a path candidate. */
export const TARGET_EXTENSIONS = Object.freeze(['app', 'asar', 'apk', 'ipa', 'dmg', 'zip', 'exe', 'dll', 'dylib', 'so', 'hop', 'msix', 'appx', 'node']);

/**
 * Reverse-engineering keyword pre-filter. Matches whole words (prefix
 * alternatives such as `decompil` extend over the rest of the word) and the
 * dotted tokens `.so`, `.app`, `.net` wherever they appear.
 */
export const KEYWORD_RE = (() => {
  const words = [
    'reverse[- ]?engineer\\w*', 'decompil\\w*', 'disassembl\\w*', 'pseudocode', 'xrefs?', 'binary', 'binaries', 'mach-?o', 'elf', 'pe',
    'dll', 'dylib', 'asar', 'electron', 'apk', 'ipa', 'assembly', 'hopper', 'ghidra', 'jadx',
    'how does .{0,60}(?:work|do)', 'understand how', 'trace .{0,40}(?:feature|flow|call)', 'recreate', 'clone the feature',
    'port(?:ing)? .{0,40}feature', 'strings? (?:in|from) the', 'symbols?', 'obfuscat\\w*', 'minified', 'bundle', 'source ?map',
    'cdp', 'devtools', 'inspector',
  ];
  return new RegExp(`(?<!\\w)(?:${words.join('|')})(?!\\w)|\\.(?:so|app|net)(?!\\w)`, 'i');
})();

const MAX_TOKENS = 16;
const EXT_ALT = TARGET_EXTENSIONS.join('|');
const UNQUOTED_PATH_RE = /(?<![\w@:/.\-~])((?:~|\.{1,2})?\/[^\s"'`<>|;()[\]{}]+)/g;
const QUOTED_RE = /"([^"\n]{2,400})"|'([^'\n]{2,400})'|`([^`\n]{2,400})`/g;
const BARE_FILE_RE = new RegExp(`(?<![\\w/.\\-])([\\w][\\w.\\-]*\\.(?:${EXT_ALT}))(?![\\w\\-]|\\.\\w)`, 'gi');
const URL_RE = /\b(?:https?|wss?):\/\/[^\s"'<>`)\]]+/gi;
const HOST_PORT_RE = /(?<![\w.:/@-])((?:localhost|\[[0-9a-f:]+\]|\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9-]+(?:\.[a-z0-9-]+)+):(\d{2,5}))(?![\w.])/gi;
const REMOTE_DEBUG_RE = /--remote-debugging-port[= ](\d{2,5})/gi;
const INSPECT_FLAG_RE = /--inspect(?:-brk|-wait)?(?:[= ](?:([\w.[\]:-]+?):)?(\d{2,5}))?(?![\w-])/gi;
const TRAILING_PUNCT_RE = /[.,;:!?'"`)\]]+$/;
/** Paths under these never get a magic read (device nodes, kernel pseudo-files can block or lie). */
const NO_MAGIC_PREFIXES = ['/dev/', '/proc/', '/sys/'];

/**
 * @typedef {Object} PathToken
 * @property {string} raw            as written in the prompt
 * @property {string} abs            resolved absolute path (`~` expanded, relative to cwd)
 * @property {boolean} exists
 * @property {boolean} isDir
 * @property {string} ext            lower-case extension without the dot ('' when none)
 * @property {string|null} magic     file: pe|managed_pe|native_pe|elf|macho|fat_macho|zip|apk|ipa|msix|appx|asar; dir: app_bundle|javascript_application|android; else null
 * @property {string|null} targetKind route `target_kind` candidate derived from magic/ext, or null
 */

/**
 * @typedef {Object} Sniff
 * @property {PathToken[]} pathTokens
 * @property {string[]} urls           credentials and query strings stripped (see `safeUrl`)
 * @property {string[]} cdpEndpoints
 * @property {string[]} inspectorEndpoints
 * @property {boolean} keywordHit
 * @property {string[]} hints          human strings, e.g. "path /Applications/Notes.app is a macOS app bundle"
 * @property {string|null} declaredTarget first existing path token (abs) or first URL (credentials stripped)
 */

/**
 * Sniff a user prompt for concrete targets.
 *
 * @param {unknown} prompt
 * @param {string} [cwd]
 * @returns {Sniff}
 */
export function sniffPrompt(prompt, cwd = process.cwd()) {
  const text = prompt == null ? '' : String(prompt);
  const out = { pathTokens: [], urls: [], cdpEndpoints: [], inspectorEndpoints: [], keywordHit: false, hints: [], declaredTarget: null };
  if (!text) return out;

  out.keywordHit = KEYWORD_RE.test(text);
  const endpoints = extractEndpoints(text);
  out.urls = endpoints.urls;
  out.cdpEndpoints = endpoints.cdpEndpoints;
  out.inspectorEndpoints = endpoints.inspectorEndpoints;

  const base = typeof cwd === 'string' && cwd ? cwd : process.cwd();
  for (const raw of extractPathCandidates(text)) {
    if (out.pathTokens.length >= MAX_TOKENS) break;
    const token = describePath(raw, base);
    if (token) out.pathTokens.push(token);
  }

  for (const t of out.pathTokens) {
    const hint = hintFor(t);
    if (hint) out.hints.push(hint);
  }
  for (const u of out.urls) if (!out.cdpEndpoints.includes(u) && !out.inspectorEndpoints.includes(u)) out.hints.push(`url ${u}`);
  for (const e of out.cdpEndpoints) out.hints.push(`CDP endpoint ${e} (${isLoopback(e) ? 'loopback' : 'remote'})`);
  for (const e of out.inspectorEndpoints) out.hints.push(`inspector endpoint ${e} (${isLoopback(e) ? 'loopback' : 'remote'})`);

  const firstExisting = out.pathTokens.find((t) => t.exists);
  out.declaredTarget = firstExisting ? firstExisting.abs : out.urls[0] ?? null;
  return out;
}

/**
 * Resolve and inspect one path candidate (stat + magic / directory heuristic).
 *
 * @param {string} raw
 * @param {string} [cwd]
 * @returns {PathToken|null}
 */
export function describePath(raw, cwd = process.cwd()) {
  const cleaned = String(raw ?? '').trim();
  if (!cleaned) return null;
  const abs = resolvePath(cleaned, cwd);
  if (!abs) return null;
  const ext = path.extname(abs).replace(/^\./, '').toLowerCase();
  let exists = false;
  let isDir = false;
  let isRegular = false;
  try {
    const st = fs.statSync(abs, { throwIfNoEntry: false });
    if (st) {
      exists = true;
      isDir = st.isDirectory();
      // Only regular files get a magic read: opening a FIFO, socket or device
      // node blocks synchronously and no timer can interrupt that.
      isRegular = st.isFile();
    }
  } catch {
    exists = false;
  }
  let magic = null;
  if (exists) magic = isDir ? dirKind(abs) : isRegular && !NO_MAGIC_PREFIXES.some((p) => abs.startsWith(p)) ? magicOf(abs, ext) : null;
  return { raw: cleaned, abs, exists, isDir, ext, magic, targetKind: targetKindFor({ exists, isDir, ext, magic }) };
}

/**
 * Detect a file's format from its leading bytes. Read-only; null on any
 * error or unknown format. `MZ` files get the PE CLI-header check:
 * data directory 14 with a non-zero RVA → `managed_pe`, else `native_pe`
 * (`pe` when the header cannot be parsed).
 *
 * @param {string} filePath
 * @param {string} [ext] lower-case extension, used to refine zip containers
 * @returns {string|null}
 */
export function magicOf(filePath, ext = path.extname(String(filePath)).replace(/^\./, '').toLowerCase()) {
  let fd;
  try {
    fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(64);
    const n = fs.readSync(fd, buf, 0, 64, 0);
    const b = buf.subarray(0, n);
    if (n >= 2 && b[0] === 0x4d && b[1] === 0x5a) return peKind(fd, b, n);
    if (n >= 4 && b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return 'elf';
    if (n >= 4) {
      const hex = b.subarray(0, 4).toString('hex');
      if (hex === 'cffaedfe' || hex === 'cefaedfe' || hex === 'feedfacf' || hex === 'feedface') return 'macho';
      if (hex === 'cafebabe' || hex === 'bebafeca') return 'fat_macho';
      if (b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04) return zipKind(ext);
    }
    if (n >= 20 && b.readUInt32LE(0) === 4) {
      const idx = b.indexOf('{"files"');
      if (idx >= 4 && idx <= 24) return 'asar';
    }
    return null;
  } catch {
    return null;
  } finally {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
        /* ignore */
      }
    }
  }
}

/**
 * Directory heuristics: `Contents/MacOS` → app_bundle; `package.json`,
 * `main.js` or `app.asar` → javascript_application; `AndroidManifest.xml` → android.
 *
 * @param {string} dir
 * @returns {'app_bundle'|'javascript_application'|'android'|null}
 */
export function dirKind(dir) {
  try {
    if (existsAt(dir, 'Contents', 'MacOS')) return 'app_bundle';
    if (['package.json', 'main.js', 'app.asar', path.join('resources', 'app.asar'), path.join('Contents', 'Resources', 'app.asar')].some((f) => existsAt(dir, f))) {
      return 'javascript_application';
    }
    if (existsAt(dir, 'AndroidManifest.xml')) return 'android';
  } catch {
    /* ignore */
  }
  return null;
}

/**
 * Extract URLs and classify CDP / Node inspector endpoints in free text.
 * Also understands `host:9222`, `host:9229`, `--remote-debugging-port=N`
 * and `--inspect[-brk]=[host:]port`.
 *
 * @param {string} text
 * @returns {{urls: string[], cdpEndpoints: string[], inspectorEndpoints: string[]}}
 */
export function extractEndpoints(text) {
  const s = String(text ?? '');
  const urls = unique((s.match(URL_RE) ?? []).map(stripTrailingPunct).map(safeUrl).filter(Boolean));
  const cdp = [];
  const inspector = [];
  for (const u of urls) {
    const kind = endpointKind(u);
    if (kind === 'cdp') cdp.push(u);
    else if (kind === 'inspector') inspector.push(u);
  }
  for (const m of s.matchAll(HOST_PORT_RE)) {
    const hostPort = m[1];
    if (urls.some((u) => u.includes(hostPort))) continue;
    const port = m[2];
    if (port === '9222') cdp.push(hostPort);
    else if (port === '9229') inspector.push(hostPort);
  }
  for (const m of s.matchAll(REMOTE_DEBUG_RE)) cdp.push(`http://127.0.0.1:${m[1]}`);
  // REA's inspector tools take the literal-loopback HTTP endpoint (`http://127.0.0.1:9229`), not a ws:// URL.
  for (const m of s.matchAll(INSPECT_FLAG_RE)) inspector.push(`http://${m[1] ?? '127.0.0.1'}:${m[2] ?? '9229'}`);
  return { urls, cdpEndpoints: unique(cdp), inspectorEndpoints: unique(inspector) };
}

/**
 * A URL with its credentials (userinfo), query string and fragment removed,
 * so nothing secret rides along in hints, the ledger, or a Jev request. Falls
 * back to `redact()` when the string does not parse as a URL.
 *
 * @param {string} url
 * @returns {string}
 */
export function safeUrl(url) {
  const s = String(url ?? '');
  try {
    const u = new URL(s);
    u.username = '';
    u.password = '';
    u.search = '';
    u.hash = '';
    return u.toString().replace(/\/$/, s.endsWith('/') ? '/' : '');
  } catch {
    return redact(s);
  }
}

/**
 * True when the endpoint's host is loopback: localhost, *.localhost,
 * 127.0.0.0/8, ::1, the IPv4-mapped forms ::ffff:127.* and ::ffff:7f00:1
 * (how the WHATWG parser normalises them), or 0.0.0.0. Accepts URLs or
 * `host:port`.
 *
 * Deliberately more permissive than REA's own rule (REA accepts only a
 * literal `127.0.0.1` / `[::1]` host): the gate denies endpoints that would
 * observe another machine; REA itself rejects the rest with a clear error.
 *
 * @param {unknown} endpoint
 * @returns {boolean}
 */
export function isLoopback(endpoint) {
  if (typeof endpoint !== 'string' || !endpoint.trim()) return false;
  const s = endpoint.trim();
  let host;
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `tcp://${s}`);
    host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  } catch {
    return false;
  }
  if (!host) return false;
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  if (host === '::1' || host === '0:0:0:0:0:0:0:1') return true;
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) return true;
  if (host.startsWith('::ffff:127.')) return true;
  if (/^(?:0:0:0:0:0:ffff|::ffff):7f[0-9a-f]{2}:[0-9a-f]{1,4}$/.test(host)) return true;
  if (host === '0.0.0.0') return true;
  return false;
}

/**
 * Map a token's magic / extension to a route `target_kind`, or null.
 *
 * @param {{exists?: boolean, isDir?: boolean, ext?: string, magic?: string|null}} t
 * @returns {string|null}
 */
export function targetKindFor(t) {
  const magic = t.magic ?? null;
  switch (magic) {
    case 'app_bundle':
    case 'macho':
    case 'fat_macho':
    case 'elf':
    case 'native_pe':
    case 'pe':
      return 'native_binary';
    case 'managed_pe':
      return 'managed_assembly';
    case 'asar':
    case 'javascript_application':
      return 'javascript_application';
    case 'apk':
    case 'android':
      return 'android_apk';
    case 'zip':
    case 'ipa':
    case 'msix':
    case 'appx':
      return 'package_archive';
    default:
      break;
  }
  if (t.exists && t.isDir) return null;
  switch (t.ext) {
    case 'app':
    case 'hop':
    case 'exe':
    case 'dll':
    case 'dylib':
    case 'so':
    case 'node':
      return 'native_binary';
    case 'asar':
      return 'javascript_application';
    case 'apk':
      return 'android_apk';
    case 'zip':
    case 'ipa':
    case 'dmg':
    case 'msix':
    case 'appx':
      return 'package_archive';
    default:
      return null;
  }
}

const MAGIC_LABELS = {
  app_bundle: 'a macOS app bundle',
  javascript_application: 'a JavaScript application directory (package.json / main.js / app.asar)',
  android: 'an Android project or extracted package (AndroidManifest.xml)',
  macho: 'a Mach-O binary',
  fat_macho: 'a fat (universal) Mach-O binary',
  elf: 'an ELF binary',
  native_pe: 'a native PE binary',
  managed_pe: 'a .NET (managed CLI) PE assembly',
  pe: 'a PE binary (header not parsed)',
  zip: 'a zip archive',
  apk: 'an Android package (apk)',
  ipa: 'an iOS app archive (ipa)',
  msix: 'an MSIX package',
  appx: 'an APPX package',
  asar: 'an ASAR archive (Electron)',
};

function hintFor(t) {
  if (t.exists) {
    if (t.magic && MAGIC_LABELS[t.magic]) return `path ${t.abs} is ${MAGIC_LABELS[t.magic]}`;
    if (t.isDir) return `path ${t.abs} is a directory`;
    return `path ${t.abs} exists (format not recognized${t.ext ? `, .${t.ext}` : ''})`;
  }
  if (looksLikePath(t.raw)) return `path ${t.abs} was not found on disk`;
  return null;
}

function extractPathCandidates(text) {
  const found = [];
  const push = (raw) => {
    const cleaned = stripTrailingPunct(String(raw ?? '').trim());
    if (cleaned && cleaned.length <= 1024 && !found.includes(cleaned)) found.push(cleaned);
  };
  // Quoted paths first; their spans are blanked so the unquoted and bare
  // scans below cannot re-match fragments of them.
  let rest = text;
  for (const m of text.matchAll(QUOTED_RE)) {
    const inner = m[1] ?? m[2] ?? m[3];
    if (inner && looksLikePath(inner)) {
      push(inner);
      rest = rest.slice(0, m.index) + ' '.repeat(m[0].length) + rest.slice(m.index + m[0].length);
    }
  }
  const withoutUrls = rest.replace(URL_RE, ' ');
  for (const m of withoutUrls.matchAll(UNQUOTED_PATH_RE)) push(m[1]);
  for (const m of withoutUrls.matchAll(BARE_FILE_RE)) push(m[1]);
  return found;
}

function looksLikePath(s) {
  if (/^(?:~\/|~$|\.{1,2}\/|\/)/.test(s)) return true;
  return new RegExp(`\\.(?:${EXT_ALT})$`, 'i').test(s);
}

function resolvePath(raw, cwd) {
  let p = raw;
  if (p === '~') p = os.homedir();
  else if (p.startsWith('~/')) p = path.join(os.homedir(), p.slice(2));
  try {
    return path.isAbsolute(p) ? path.normalize(p) : path.resolve(cwd, p);
  } catch {
    return null;
  }
}

function peKind(fd, head, n) {
  try {
    if (n < 0x40) return 'pe';
    const lfanew = head.readUInt32LE(0x3c);
    if (lfanew < 0x40 || lfanew > 0x100000) return 'pe';
    const hdr = Buffer.alloc(24 + 112 + 16 * 8);
    const got = fs.readSync(fd, hdr, 0, hdr.length, lfanew);
    if (got < 26 || hdr.toString('latin1', 0, 4) !== 'PE\0\0') return 'pe';
    const optMagic = hdr.readUInt16LE(24);
    const dirBase = optMagic === 0x20b ? 24 + 112 : optMagic === 0x10b ? 24 + 96 : -1;
    if (dirBase < 0 || got < dirBase) return 'pe';
    const numberOfRva = hdr.readUInt32LE(dirBase - 4);
    const cliOffset = dirBase + 14 * 8;
    if (numberOfRva < 15 || got < cliOffset + 8) return 'native_pe';
    return hdr.readUInt32LE(cliOffset) !== 0 ? 'managed_pe' : 'native_pe';
  } catch {
    return 'pe';
  }
}

function zipKind(ext) {
  switch (ext) {
    case 'apk':
      return 'apk';
    case 'ipa':
      return 'ipa';
    case 'msix':
      return 'msix';
    case 'appx':
      return 'appx';
    default:
      return 'zip';
  }
}

function endpointKind(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  const p = u.pathname || '/';
  if (/\/devtools\//i.test(p) || /^\/json(?:\/(?:version|list|new|protocol|activate|close))?\/?$/i.test(p) || u.port === '9222') return 'cdp';
  if ((u.protocol === 'ws:' || u.protocol === 'wss:') && /\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(p)) return 'inspector';
  if (u.port === '9229') return 'inspector';
  return null;
}

function existsAt(...parts) {
  try {
    return fs.statSync(path.join(...parts), { throwIfNoEntry: false }) != null;
  } catch {
    return false;
  }
}

function stripTrailingPunct(s) {
  return String(s ?? '').replace(TRAILING_PUNCT_RE, '');
}

function unique(list) {
  return [...new Set(list)];
}
