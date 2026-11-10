/**
 * Deterministic target sniffing for the route hook: path tokens, file magic,
 * directory heuristics, URLs, CDP / inspector endpoints, and the RE keyword
 * pre-filter. Read-only, bounded (≤16 tokens, ≤64 bytes per file plus one PE
 * header read, and for a `.apk` one bounded read of the zip central directory
 * to tell a Flutter build from a plain package; for a directory one bounded
 * listing to tell a desktop application folder), and silent on every error.
 *
 * @module sniff
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { redact } from './redact.mjs';

/**
 * Extensions that name a firmware image on their own. `.bin` and `.img` are
 * not here: they name anything, so a file with one of them is firmware only
 * when its magic says so.
 */
export const FIRMWARE_EXTENSIONS = Object.freeze(['fw', 'rom', 'hex', 'ihex', 'srec', 'uf2', 'ubi', 'squashfs', 'trx', 'dfu']);

/** Recorded web traffic: extension → the `format` value `inspect_web_network_capture` takes. */
const WEB_RECORDING_BY_EXT = Object.freeze({ har: 'har', saz: 'saz', qlog: 'qlog', sqlog: 'qlog', mitm: 'mitmproxy' });
/** Recorded web traffic: magic → that same `format` value (mitmproxy's native flow files have no magic). */
const WEB_RECORDING_BY_MAGIC = Object.freeze({ har: 'har', saz: 'saz', qlog: 'qlog' });

/** File extensions that make a bare token a path candidate. */
export const TARGET_EXTENSIONS = Object.freeze([
  'app', 'asar', 'apk', 'ipa', 'dmg', 'zip', 'exe', 'dll', 'dylib', 'so', 'hop', 'msix', 'appx', 'node',
  // Artifact kinds rea-agents 6.5.0 reads with a format-aware tool.
  'wasm', 'sqlite', 'sqlite3', 'db', 'db3', 'pcap', 'pcapng', 'har', 'saz', 'qlog', 'sqlog', 'mitm',
  // Artifact kinds rea-agents 6.8.0 reads with a format-aware tool.
  'ips', 'ko', 'beam', 'pyc', 'gguf', 'safetensors', 'cubin', 'ptx', 'fatbin', 'pck',
  ...FIRMWARE_EXTENSIONS,
]);

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
    'firmware', 'pcap(?:ng)?', 'packet captures?', 'wasm', 'webassembly',
    'crash reports?', 'kernel modules?', 'bytecode', 'gguf', 'safetensors', 'il2cpp', 'cubin', 'fatbin', 'ptx',
  ];
  return new RegExp(`(?<!\\w)(?:${words.join('|')})(?!\\w)|\\.(?:so|app|net)(?!\\w)`, 'i');
})();

const MAX_TOKENS = 16;
const EXT_ALT = TARGET_EXTENSIONS.join('|');
/** `<` in the lookbehind keeps a closing XML tag (`</task-id>`) from reading as the path `/task-id`. */
const UNQUOTED_PATH_RE = /(?<![\w@:/.\-~<])((?:~|\.{1,2})?\/[^\s"'`<>|;()[\]{}]+)/g;
/** A leading slash command (`/name`, `/plugin:name`): one segment, no dot, nothing but whitespace after it. */
const SLASH_COMMAND_RE = /^\s*\/[A-Za-z][\w-]*(?::[A-Za-z][\w-]*)?(?=\s|$)/;
/** A prompt that is one or more XML elements and nothing else: the host's own envelopes, not the user's words. */
const ENVELOPE_RE = /^\s*<[a-z][\w-]*(?:\s[^<>]*)?>[\s\S]*<\/[a-z][\w-]*>\s*$/i;
const QUOTED_RE = /"([^"\n]{2,400})"|'([^'\n]{2,400})'|`([^`\n]{2,400})`/g;
const BARE_FILE_RE = new RegExp(`(?<![\\w/.\\-])([\\w][\\w.\\-]*\\.(?:${EXT_ALT}))(?![\\w\\-]|\\.\\w)`, 'gi');
const URL_RE = /\b(?:https?|wss?):\/\/[^\s"'<>`)\]]+/gi;
const HOST_PORT_RE = /(?<![\w.:/@-])((?:localhost|\[[0-9a-f:]+\]|\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9-]+(?:\.[a-z0-9-]+)+):(\d{2,5}))(?![\w.])/gi;
const REMOTE_DEBUG_RE = /--remote-debugging-port[= ](\d{2,5})/gi;
const INSPECT_FLAG_RE = /--inspect(?:-brk|-wait)?(?:[= ](?:([\w.[\]:-]+?):)?(\d{2,5}))?(?![\w-])/gi;
const TRAILING_PUNCT_RE = /[.,;:!?'"`)\]]+$/;
/** Paths under these never get a magic read (device nodes, kernel pseudo-files can block or lie). */
const NO_MAGIC_PREFIXES = ['/dev/', '/proc/', '/sys/'];
/** pcap file magics: µs and ns timestamps, both byte orders. */
const PCAP_MAGICS = new Set(['a1b2c3d4', 'd4c3b2a1', 'a1b23c4d', '4d3cb2a1']);
/** IL2CPP `global-metadata.dat` (`0xFAB11BAF` little-endian) and CUDA fat binary (`0xBA55ED50` little-endian) magics, as the first four bytes read as hex. */
const IL2CPP_METADATA_HEX = 'af1bb1fa';
const CUDA_FATBIN_HEX = '50ed55ba';
/** A safetensors header (little-endian u64 byte length, then the JSON header) longer than this is not sniffed as one. */
const SAFETENSORS_HEADER_MAX = 256 * 1024 * 1024;
/** Most entries of a directory read to tell a desktop application folder. */
const DIRECTORY_ENTRIES_MAX = 512;
/** Magics `firmwareMagic()` returns; each maps to `firmware_image`. */
const FIRMWARE_MAGICS = new Set(['uimage', 'squashfs', 'cramfs', 'jffs2', 'ubi', 'ubifs', 'trx', 'dtb', 'uf2', 'dfuse', 'android_boot', 'intel_hex', 'srec']);
/** Zip end-of-central-directory signature and the most it can sit from the end (22-byte record plus a 65535-byte comment). */
const ZIP_EOCD_SIG = 0x06054b50;
const ZIP_TAIL_MAX = 22 + 0xffff;
/** Bytes of an APK's central directory read to look for the Flutter engine library. */
const APK_DIRECTORY_MAX = 1 << 20;

/**
 * @typedef {Object} PathToken
 * @property {string} raw            as written in the prompt
 * @property {string} abs            resolved absolute path (`~` expanded, relative to cwd)
 * @property {boolean} exists
 * @property {boolean} isDir
 * @property {string} ext            lower-case extension without the dot ('' when none)
 * @property {string|null} magic     file: pe|managed_pe|native_pe|elf|elf_rel|macho|fat_macho|zip|apk|flutter_apk|ipa|msix|appx|saz|asar|wasm|sqlite|pcap|pcapng|har|qlog|ips|beam|pyc|gguf|safetensors|il2cpp_metadata|cuda_fatbin|pck|compressed|a firmware magic (uimage, squashfs, cramfs, jffs2, ubi, ubifs, trx, dtb, uf2, dfuse, android_boot, intel_hex, srec); dir: app_bundle|javascript_application|android|desktop_application; else null
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
 * True when the whole prompt is markup the host injected rather than text the
 * user typed: a task notification, a subagent hand-back, or similar markup
 * the host injects. Such a prompt starts with an XML element and
 * ends with a closing tag; a user prompt that merely quotes a tag does not.
 *
 * @param {unknown} prompt
 * @returns {boolean}
 */
export function isHarnessEnvelope(prompt) {
  return typeof prompt === 'string' && ENVELOPE_RE.test(prompt);
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
 * (`pe` when the header cannot be parsed). A `PK` container is refined by
 * extension, and a `.apk` by one bounded read of its central directory
 * (`flutter_apk` when it names `libflutter.so`). `\0asm` → `wasm`,
 * `SQLite format 3\0` → `sqlite`, the pcap and pcapng magics, the firmware
 * container and filesystem magics (`firmwareMagic`), a compressed stream
 * (`compressed`: gzip, xz, lzma, bzip2, zstd, lz4), and the text formats a
 * JSON head reveals (`har`, `qlog`, an Apple `ips` crash report) or a hex
 * record starts (`intel_hex`, `srec`). The formats rea-agents 6.8.0 added:
 * an ELF whose `e_type` is `ET_REL` → `elf_rel` (a `.ko` kernel module routes
 * on it), `FOR1…BEAM` → `beam`, a CPython `.pyc` header (16-bit magic, `\r\n`)
 * → `pyc`, `GGUF` → `gguf`, a safetensors header (little-endian u64 length
 * then `{`) → `safetensors`, `0xFAB11BAF` → `il2cpp_metadata`, `0xBA55ED50`
 * → `cuda_fatbin`, `GDPC` → `pck` (Godot).
 *
 * @param {string} filePath
 * @param {string} [ext] lower-case extension, used to refine zip containers and text formats
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
    if (n >= 4 && b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return elfKind(b, n);
    if (n >= 4) {
      const hex = b.subarray(0, 4).toString('hex');
      if (hex === IL2CPP_METADATA_HEX) return 'il2cpp_metadata';
      if (hex === CUDA_FATBIN_HEX) return 'cuda_fatbin';
      const ascii = b.subarray(0, 4).toString('latin1');
      if (ascii === 'GGUF') return 'gguf';
      if (ascii === 'GDPC') return 'pck';
      if (ascii === 'FOR1' && n >= 12 && b.subarray(8, 12).toString('latin1') === 'BEAM') return 'beam';
      if (ext === 'pyc' && n >= 16 && b[2] === 0x0d && b[3] === 0x0a) return 'pyc';
      if (n >= 9 && b[8] === 0x7b && b.readBigUInt64LE(0) <= BigInt(SAFETENSORS_HEADER_MAX) && b.readBigUInt64LE(0) > 0n) return 'safetensors';
      if (hex === 'cffaedfe' || hex === 'cefaedfe' || hex === 'feedfacf' || hex === 'feedface') return 'macho';
      if (hex === 'cafebabe' || hex === 'bebafeca') return 'fat_macho';
      if (b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04) return ext === 'apk' ? apkFlavor(fd) : zipKind(ext);
      if (hex === '0061736d') return 'wasm';
      if (PCAP_MAGICS.has(hex)) return 'pcap';
      if (hex === '0a0d0d0a' && n >= 12) {
        const order = b.subarray(8, 12).toString('hex');
        if (order === '1a2b3c4d' || order === '4d3c2b1a') return 'pcapng';
      }
      const fw = firmwareMagic(b, n, hex);
      if (fw) return fw;
      if (compressedMagic(b, n, hex)) return 'compressed';
    }
    if (n >= 16 && b.subarray(0, 16).toString('latin1') === 'SQLite format 3\0') return 'sqlite';
    if (n >= 20 && b.readUInt32LE(0) === 4) {
      const idx = b.indexOf('{"files"');
      if (idx >= 4 && idx <= 24) return 'asar';
    }
    return textKind(b, n, ext);
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
 * `elf_rel` when the ELF's `e_type` (offset 16, in the byte order `EI_DATA`
 * names) is `ET_REL`: a relocatable object, which on a `.ko` file is a Linux
 * kernel module. Every other ELF, and a header too short to read, is `elf`.
 *
 * @param {Buffer} b leading bytes
 * @param {number} n bytes read
 * @returns {'elf'|'elf_rel'}
 */
function elfKind(b, n) {
  if (n < 18) return 'elf';
  const type = b[5] === 2 ? b.readUInt16BE(16) : b.readUInt16LE(16);
  return type === 1 ? 'elf_rel' : 'elf';
}

/**
 * Directory heuristics: `Contents/MacOS` → app_bundle; `package.json`,
 * `main.js` or `app.asar` → javascript_application; `AndroidManifest.xml` →
 * android; otherwise, from one bounded listing (≤ DIRECTORY_ENTRIES_MAX
 * entries), a top-level `.exe`, `UnityPlayer.dll`, a `.pck` or a `*_Data`
 * directory → desktop_application (the installed-application folders
 * `inspect_desktop_application` triages).
 *
 * @param {string} dir
 * @returns {'app_bundle'|'javascript_application'|'android'|'desktop_application'|null}
 */
export function dirKind(dir) {
  try {
    if (existsAt(dir, 'Contents', 'MacOS')) return 'app_bundle';
    if (['package.json', 'main.js', 'app.asar', path.join('resources', 'app.asar'), path.join('Contents', 'Resources', 'app.asar')].some((f) => existsAt(dir, f))) {
      return 'javascript_application';
    }
    if (existsAt(dir, 'AndroidManifest.xml')) return 'android';
    if (isDesktopApplicationDir(dir)) return 'desktop_application';
  } catch {
    /* ignore */
  }
  return null;
}

function isDesktopApplicationDir(dir) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true }).slice(0, DIRECTORY_ENTRIES_MAX);
  } catch {
    return false;
  }
  return entries.some((e) => {
    const name = e.name.toLowerCase();
    if (e.isDirectory()) return name.endsWith('_data');
    return name.endsWith('.exe') || name === 'unityplayer.dll' || name.endsWith('.pck');
  });
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
  if (magic && FIRMWARE_MAGICS.has(magic)) return 'firmware_image';
  switch (magic) {
    case 'app_bundle':
    case 'macho':
    case 'fat_macho':
    case 'elf':
    case 'native_pe':
    case 'pe':
      return 'native_binary';
    case 'elf_rel':
      return t.ext === 'ko' ? 'kernel_module' : 'native_binary';
    case 'managed_pe':
      return 'managed_assembly';
    case 'asar':
    case 'javascript_application':
      return 'javascript_application';
    case 'apk':
    case 'android':
      return 'android_apk';
    case 'flutter_apk':
      return 'flutter_app';
    case 'zip':
    case 'ipa':
    case 'msix':
    case 'appx':
      return 'package_archive';
    case 'wasm':
      return 'wasm_module';
    case 'sqlite':
      return 'sqlite_database';
    case 'pcap':
    case 'pcapng':
    case 'har':
    case 'saz':
    case 'qlog':
      return 'packet_capture';
    case 'ips':
      return 'crash_report';
    case 'beam':
      return 'beam_module';
    case 'pyc':
      return 'python_bytecode';
    case 'gguf':
    case 'safetensors':
      return 'model_artifact';
    case 'il2cpp_metadata':
      return 'il2cpp_metadata';
    case 'cuda_fatbin':
      return 'gpu_code_object';
    case 'pck':
      return 'package_archive';
    case 'desktop_application':
      return 'desktop_application';
    default:
      // `compressed` and unknown magics fall through to the extension: a
      // compressed stream is firmware only when its extension says so.
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
    case 'wasm':
      return 'wasm_module';
    case 'sqlite':
    case 'sqlite3':
    case 'db':
    case 'db3':
      return 'sqlite_database';
    case 'pcap':
    case 'pcapng':
    case 'har':
    case 'saz':
    case 'qlog':
    case 'sqlog':
    case 'mitm':
      return 'packet_capture';
    case 'ips':
      return 'crash_report';
    case 'ko':
      return 'kernel_module';
    case 'beam':
      return 'beam_module';
    case 'pyc':
      return 'python_bytecode';
    case 'gguf':
    case 'safetensors':
      return 'model_artifact';
    case 'cubin':
    case 'ptx':
    case 'fatbin':
      return 'gpu_code_object';
    case 'pck':
      return 'package_archive';
    default:
      return FIRMWARE_EXTENSIONS.includes(t.ext) ? 'firmware_image' : null;
  }
}

/**
 * The `format` value `inspect_web_network_capture` takes for a recorded-web-
 * traffic token (`har`, `mitmproxy`, `saz`, `qlog`): from its magic when the
 * file was read, else from its extension. Null for a pcap/pcapng capture and
 * for anything else. mitmproxy's native flow files have no magic and no fixed
 * extension, so only `.mitm` names them; otherwise the user has to say.
 *
 * @param {{ext?: string, magic?: string|null}|null|undefined} t
 * @returns {'har'|'mitmproxy'|'saz'|'qlog'|null}
 */
export function webRecordingFormat(t) {
  if (!t) return null;
  if (t.magic) return WEB_RECORDING_BY_MAGIC[t.magic] ?? null;
  return WEB_RECORDING_BY_EXT[t.ext ?? ''] ?? null;
}

const MAGIC_LABELS = {
  app_bundle: 'a macOS app bundle',
  javascript_application: 'a JavaScript application directory (package.json / main.js / app.asar)',
  android: 'an Android project or extracted package (AndroidManifest.xml)',
  desktop_application: 'an installed desktop application directory (.exe, UnityPlayer.dll, .pck or *_Data present)',
  macho: 'a Mach-O binary',
  fat_macho: 'a fat (universal) Mach-O binary',
  elf: 'an ELF binary',
  elf_rel: 'a relocatable ELF object (ET_REL; a kernel module when named .ko)',
  native_pe: 'a native PE binary',
  managed_pe: 'a .NET (managed CLI) PE assembly',
  pe: 'a PE binary (header not parsed)',
  zip: 'a zip archive',
  apk: 'an Android package (apk)',
  ipa: 'an iOS app archive (ipa)',
  msix: 'an MSIX package',
  appx: 'an APPX package',
  asar: 'an ASAR archive (Electron)',
  saz: 'a Fiddler SAZ web-traffic archive',
  flutter_apk: 'an Android package built with Flutter (apk with libflutter.so)',
  wasm: 'a WebAssembly module',
  sqlite: 'a SQLite 3 database',
  pcap: 'a pcap packet capture',
  pcapng: 'a pcapng packet capture',
  har: 'a HAR web-traffic recording (JSON)',
  qlog: 'a qlog QUIC trace',
  ips: 'an Apple .ips crash report (JSON)',
  beam: 'an Erlang BEAM bytecode module',
  pyc: 'a CPython .pyc bytecode file',
  gguf: 'a GGUF model file',
  safetensors: 'a safetensors model file',
  il2cpp_metadata: 'a Unity IL2CPP global-metadata file',
  cuda_fatbin: 'a CUDA fat binary (GPU code objects)',
  pck: 'a Godot .pck resource pack',
  uimage: 'a U-Boot uImage firmware image',
  squashfs: 'a SquashFS filesystem image (firmware)',
  cramfs: 'a CramFS filesystem image (firmware)',
  jffs2: 'a JFFS2 flash filesystem image (firmware)',
  ubi: 'a UBI flash volume image (firmware)',
  ubifs: 'a UBIFS filesystem image (firmware)',
  trx: 'a Broadcom TRX firmware image',
  dtb: 'a flattened device tree or FIT firmware image',
  uf2: 'a UF2 firmware image',
  dfuse: 'a DfuSe firmware image',
  android_boot: 'an Android boot image (firmware)',
  intel_hex: 'an Intel HEX firmware image',
  srec: 'a Motorola S-record firmware image',
  compressed: 'a compressed stream (gzip, xz, lzma, bzip2, zstd or lz4)',
};

function hintFor(t) {
  if (t.exists) {
    if (t.magic === 'compressed' && FIRMWARE_EXTENSIONS.includes(t.ext)) return `path ${t.abs} is ${MAGIC_LABELS.compressed}, firmware by its .${t.ext} extension`;
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
  // A leading slash command is how the prompt was invoked, not a path.
  const base = text.replace(SLASH_COMMAND_RE, (m) => ' '.repeat(m.length));
  // Quoted paths first; their spans are blanked so the unquoted and bare
  // scans below cannot re-match fragments of them.
  let rest = base;
  for (const m of base.matchAll(QUOTED_RE)) {
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
    case 'saz':
      return 'saz';
    default:
      return 'zip';
  }
}

/**
 * `flutter_apk` when the package's central directory names `libflutter.so`
 * (the Flutter engine, shipped next to the `libapp.so` Dart AOT snapshot),
 * else `apk`. Reads the end-of-central-directory record from the file's tail
 * and at most APK_DIRECTORY_MAX bytes of the directory; a ZIP64 archive, a
 * directory that does not fit the cap without showing the name, or any read
 * error stays `apk`.
 *
 * @param {number} fd open file descriptor
 * @returns {'apk'|'flutter_apk'}
 */
function apkFlavor(fd) {
  try {
    const size = fs.fstatSync(fd).size;
    if (size < 22) return 'apk';
    const tailLen = Math.min(size, ZIP_TAIL_MAX);
    const tail = Buffer.alloc(tailLen);
    const got = fs.readSync(fd, tail, 0, tailLen, size - tailLen);
    let eocd = -1;
    for (let i = got - 22; i >= 0; i -= 1) {
      if (tail.readUInt32LE(i) === ZIP_EOCD_SIG) {
        eocd = i;
        break;
      }
    }
    if (eocd < 0) return 'apk';
    const dirSize = tail.readUInt32LE(eocd + 12);
    const dirOffset = tail.readUInt32LE(eocd + 16);
    if (dirSize === 0xffffffff || dirOffset === 0xffffffff || dirOffset >= size) return 'apk';
    const len = Math.min(dirSize, APK_DIRECTORY_MAX, size - dirOffset);
    const dir = Buffer.alloc(len);
    const read = fs.readSync(fd, dir, 0, len, dirOffset);
    return dir.subarray(0, read).includes('libflutter.so') ? 'flutter_apk' : 'apk';
  } catch {
    return 'apk';
  }
}

/**
 * Firmware container and filesystem magics, both byte orders where the
 * format allows both. Null when none matches.
 *
 * @param {Buffer} b leading bytes
 * @param {number} n bytes read
 * @param {string} hex the first four bytes as hex
 * @returns {string|null}
 */
function firmwareMagic(b, n, hex) {
  if (hex === '27051956') return 'uimage'; // U-Boot legacy image
  if (hex === '68737173' || hex === '73717368') return 'squashfs'; // hsqs / sqsh
  if (hex === '453dcd28' || hex === '28cd3d45') return 'cramfs';
  if (hex === '55424923') return 'ubi'; // UBI#
  if (hex === '31181006' || hex === '06101831') return 'ubifs';
  if (hex === '48445230') return 'trx'; // HDR0
  if (hex === 'd00dfeed') return 'dtb'; // flattened device tree, FIT image
  if (hex === '5546320a') return 'uf2'; // UF2\n
  if ((b[0] === 0x85 && b[1] === 0x19 && b[3] === 0xe0) || (b[0] === 0x19 && b[1] === 0x85 && b[2] === 0xe0)) return 'jffs2';
  if (n >= 8 && b.subarray(0, 8).toString('latin1') === 'ANDROID!') return 'android_boot';
  if (n >= 5 && b.subarray(0, 5).toString('latin1') === 'DfuSe') return 'dfuse';
  return null;
}

/**
 * True for the compressed-stream magics firmware blobs commonly wear: gzip,
 * xz, lzma (alone), bzip2, zstd, lz4 frame.
 *
 * @param {Buffer} b
 * @param {number} n
 * @param {string} hex
 * @returns {boolean}
 */
function compressedMagic(b, n, hex) {
  if (b[0] === 0x1f && b[1] === 0x8b) return true;
  if (n >= 6 && hex === 'fd377a58' && b[4] === 0x5a && b[5] === 0x00) return true;
  if (hex === '28b52ffd' || hex === '04224d18') return true;
  if (b[0] === 0x42 && b[1] === 0x5a && b[2] === 0x68) return true; // BZh
  if (b[0] === 0x5d && b[1] === 0x00 && b[2] === 0x00) return true; // lzma_alone, the usual properties byte
  return false;
}

/**
 * Text formats a 64-byte head reveals: a JSON object whose first keys show a
 * HAR (`"log"`, with `"version"` or a `.har` extension) or a qlog
 * (`"qlog_version"` / `"qlog_format"`, or a JSON-SEQ record separator on a
 * `.qlog`/`.sqlog` file), an Apple crash report (a JSON object on a `.ips`
 * file, or one whose head shows `"app_name"` or `"bug_type"`), an Intel HEX
 * record (`:` + 8 hex digits), or a Motorola S-record header (`S0` + 6 hex
 * digits). Null otherwise.
 *
 * @param {Buffer} b
 * @param {number} n
 * @param {string} ext
 * @returns {'har'|'qlog'|'ips'|'intel_hex'|'srec'|null}
 */
function textKind(b, n, ext) {
  let i = 0;
  if (n >= 3 && b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) i = 3;
  let jsonSeq = false;
  if (i < n && b[i] === 0x1e) {
    jsonSeq = true;
    i += 1;
  }
  while (i < n && (b[i] === 0x20 || b[i] === 0x09 || b[i] === 0x0a || b[i] === 0x0d)) i += 1;
  if (i >= n) return null;
  const head = b.subarray(i, n).toString('latin1');
  if (head[0] === '{') {
    if (/"qlog_(?:version|format)"/.test(head) || (jsonSeq && (ext === 'qlog' || ext === 'sqlog'))) return 'qlog';
    if (/"log"\s*:/.test(head) && (ext === 'har' || /"version"\s*:/.test(head))) return 'har';
    if (ext === 'ips' || /"(?:app_name|bug_type)"\s*:/.test(head)) return 'ips';
    return null;
  }
  if (jsonSeq) return ext === 'qlog' || ext === 'sqlog' ? 'qlog' : null;
  if (/^:[0-9A-Fa-f]{8}/.test(head)) return 'intel_hex';
  if (/^S0[0-9A-Fa-f]{6}/.test(head)) return 'srec';
  return null;
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
