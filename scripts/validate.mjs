#!/usr/bin/env node
/**
 * rea-jev repository self-check (DESIGN.md §9).
 *
 * Usage:
 *   node scripts/validate.mjs [--write-catalog] [--root <dir>]
 *
 * Checks, in order:
 *   1. `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `.mcp.json`
 *      and `hooks/hooks.json` parse and carry the fields the plugin needs.
 *   2. Every hook command references an existing script under `scripts/`.
 *   3. The PreToolUse/PostToolUse matcher matches both REA tool-name forms
 *      (`mcp__rea__x`, `mcp__plugin_rea-jev_rea__x`) and not `mcp__area__x`.
 *   4. `skills/reverse-engineer/SKILL.md` frontmatter has `name` and a
 *      `description` of at most 1024 characters.
 *   5. The `rea-agents@<pin>` in `.mcp.json` equals `data/rea-tool-catalog.json`'s version.
 *   6. Every backticked REA tool reference in `skills/**\/*.md` and `agents/*.md`
 *      names a tool in the catalog, except the documented Android allowlist.
 *   7. `skills/reverse-engineer/references/tool-catalog.md` equals what
 *      `--write-catalog` would generate (one table per catalog kind).
 *
 * Exit 0 and print `ok` when everything passes; otherwise print one `FAIL: ...`
 * line per problem and exit 1. `--write-catalog` regenerates the catalog
 * Markdown from `data/` before checking; nothing else is ever written.
 * `--root <dir>` validates another tree (used by the negative test).
 */

import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import process from 'node:process';

/** Repository root when run in place (scripts/..). */
export const DEFAULT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** The matcher DESIGN.md §4 prescribes for PreToolUse/PostToolUse. */
export const CANONICAL_MATCHER = 'mcp__(plugin_rea-jev_)?rea__';

/** Tool-name forms the matcher must accept, and one it must reject. */
export const MATCHER_MUST_MATCH = ['mcp__rea__open_binary', 'mcp__plugin_rea-jev_rea__open_binary'];
export const MATCHER_MUST_NOT_MATCH = ['mcp__area__x'];

/** Hook events DESIGN.md §4 requires in hooks/hooks.json. */
export const REQUIRED_HOOK_EVENTS = ['SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PostToolUse', 'Stop'];

/** Events that must carry a tool-name matcher so the hook only runs on REA tools. */
const MATCHED_EVENTS = ['PreToolUse', 'PostToolUse'];

const SKILL_DIR = 'skills/reverse-engineer';
const SKILL_FILE = `${SKILL_DIR}/SKILL.md`;
const CATALOG_MD = `${SKILL_DIR}/references/tool-catalog.md`;
const CATALOG_JSON = 'data/rea-tool-catalog.json';

/**
 * Android tools REA documents (docs/android-analysis.md) that the 4.0.1 MCP
 * catalog does not list. The skill may name them with a version caveat.
 */
export const ANDROID_TOOL_ALLOWLIST = new Set([
  'inspect_android_package',
  'search_android_classes',
  'inspect_android_class',
  'inspect_android_method',
  'trace_android_references',
]);

/**
 * snake_case identifiers from DESIGN.md §5–§6 and REA's MCP prompt names whose
 * first segment collides with an REA tool verb (compare_, trace_, capture_,
 * build_, open_ …) but which are not tools. Anything here is never flagged.
 */
export const SPEC_VOCABULARY = new Set([
  // §5.1 workflow choices
  'investigate_feature', 'compare_versions', 'trace_crash_or_bug', 'audit_unknowns',
  'capture_runtime_behavior', 'build_from_findings',
  // §5.4 local facts and §3 ledger fields
  'open_session_not_closed', 'evidence_ids_seen', 'evidence_ids_cited', 'limitations_flagged',
  'unknowns_recorded', 'tool_calls', 'declared_target', 'target_hint', 'prompt_excerpt',
  'input_hash', 'input_excerpt', 'evidence_ids', 'shadow_block',
  // REA MCP prompt names (docs/mcp-prompts.md)
  'trace_crash', 'audit_residual_unknowns', 'prepare_bounded_process_capture',
  // REA Evidence ID prefix used in prose
  'ev_',
]);

/* ------------------------------------------------------------------------ */
/* Effect classes and catalog Markdown                                       */
/* ------------------------------------------------------------------------ */

/**
 * Effect class of a catalog tool, mirroring DESIGN.md §3 `EFFECT_CLASS`.
 * Kept local so the validator stays runnable before scripts/lib exists.
 * @param {{name:string, effects?:{launchesProcess?:boolean}}} tool
 * @returns {'runtime'|'mutation'|'status'|'inspect'}
 */
export function effectClass(tool) {
  const n = String(tool?.name || '');
  if (tool?.effects?.launchesProcess && /^(capture_|observe_)/.test(n)) return 'runtime';
  if (
    /^(set_|annotate_|import_|export_)/.test(n) ||
    ['unset_bookmark', 'record_unknown', 'update_unknown', 'extract_artifact', 'open_binary', 'close_binary'].includes(n)
  ) return 'mutation';
  if (
    /^current_/.test(n) ||
    ['binary_session', 'list_unknowns', 'get_navigation_context', 'get_evidence_bundle', 'verify_unknown_resolution', 'list_documents'].includes(n)
  ) return 'status';
  return 'inspect';
}

/** One-line subtitle per catalog kind; sections follow the catalog's own kind order. */
const KIND_SUBTITLES = {
  'official-proxy': 'Official proxy — Hopper/Ghidra provider primitives.',
  enhanced: 'Enhanced — composed native analysis.',
  'native-provider': 'Native provider — Mach-O metadata and native UI.',
  'artifact-provider': 'Artifact provider — packages, archives, bundles.',
  'managed-provider': 'Managed provider — .NET PE/CLI.',
  application: 'Application workflows — managed and JavaScript graphs, reconstruction.',
  'browser-provider': 'Browser provider — Chrome DevTools Protocol.',
  'electron-provider': 'Electron provider.',
  'runtime-provider': 'Runtime provider — V8 Inspector.',
  session: 'Session — target lifecycle, Evidence, unknowns, comparisons.',
};

/**
 * First sentence of a description, capped at `max` characters, escaped for a
 * Markdown table cell.
 * @param {string} text
 * @param {number} [max]
 */
export function firstSentence(text, max = 140) {
  const t = String(text || '').replace(/\s+/g, ' ').trim();
  const m = /^(.*?[.!?])(?:\s|$)/.exec(t);
  let s = m ? m[1] : t;
  if (s.length > max) {
    // Cut on a word boundary (dropping a comma left dangling by the cut), then
    // never end on a conjunction, article, or preposition.
    s = s.slice(0, max - 1).replace(/[,;:]?\s+\S*$/, '');
    for (;;) {
      const w = /\s(\S+)$/.exec(s);
      if (!w || !TRAILING_STOPWORDS.has(w[1].toLowerCase())) break;
      s = s.slice(0, w.index);
    }
    s = `${s.trimEnd()}…`;
  }
  return s.replace(/\|/g, '\\|');
}

/** Words a truncated description cell must not end on. */
const TRAILING_STOPWORDS = new Set([
  'and', 'or', 'an', 'a', 'the', 'of', 'to', 'with', 'without', 'by', 'for', 'in', 'on',
  'as', 'at', 'from', 'into', 'than', 'then', 'that', 'which', 'its',
]);

/**
 * Render `references/tool-catalog.md` from the JSON catalog: one table per
 * catalog kind with columns tool, description, required inputs, effect class.
 * @param {{version:string, tool_count?:number, tools:Array<object>}} catalog
 * @returns {string}
 */
export function generateToolCatalogMarkdown(catalog) {
  const tools = Array.isArray(catalog?.tools) ? catalog.tools : [];
  const version = catalog?.version || 'unknown';
  const byKind = new Map(); // insertion order = the catalog's own kind order
  for (const t of tools) {
    const kind = t.kind || 'other';
    if (!byKind.has(kind)) byKind.set(kind, []);
    byKind.get(kind).push(t);
  }
  const counts = { runtime: 0, mutation: 0, status: 0, inspect: 0 };
  for (const t of tools) counts[effectClass(t)] += 1;

  const out = [];
  out.push(`# REA tool catalog (rea-agents ${version})`, '');
  out.push(
    `Generated from rea-agents ${version} (${tools.length} tools). Source: \`data/rea-tool-catalog.json\`. Do not edit by hand; regenerate with \`node scripts/validate.mjs --write-catalog\` after bumping the pin.`,
    '',
  );
  out.push(
    'Tool names are bare. In Claude Code they appear as `mcp__rea__<tool>` (REA registered globally by `rea setup`) or `mcp__plugin_rea-jev_rea__<tool>` (REA bundled by this plugin). Required inputs are the schema\'s `required` list; optional inputs are in the JSON catalog.',
    '',
  );
  out.push('**Effect class** is what the rea-jev gate (`scripts/lib/rea.mjs`) uses, derived from the name and the `launchesProcess` effect:', '');
  out.push('| Class | Rule | Gate behavior |', '|---|---|---|');
  out.push(`| \`runtime\` (${counts.runtime}) | launches a process and the name starts with \`capture_\` or \`observe_\` | local hard rules, then a Jev scope/risk check; may \`ask\` or \`deny\` |`);
  out.push(`| \`mutation\` (${counts.mutation}) | \`set_*\`, \`annotate_*\`, \`import_*\`, \`export_*\`, \`unset_bookmark\`, \`record_unknown\`, \`update_unknown\`, \`extract_artifact\`, \`open_binary\`, \`close_binary\` | never deduplicated; resets the redundancy window |`);
  out.push(`| \`status\` (${counts.status}) | \`binary_session\`, \`list_unknowns\`, \`get_navigation_context\`, \`current_*\`, \`get_evidence_bundle\`, \`verify_unknown_resolution\`, \`list_documents\` | never deduplicated, never sent to Jev |`);
  out.push(`| \`inspect\` (${counts.inspect}) | everything else | an identical repeated call (same tool + same input) is denied until a mutation happens; results are scored by the evidence hook |`, '');
  out.push(`Contents: ${[...byKind].map(([k, list]) => `[${k}](#${k}-${list.length}-tools)`).join(' · ')}`, '');

  for (const [kind, list] of byKind) {
    out.push(`## ${kind} (${list.length} tools)`, '');
    out.push(KIND_SUBTITLES[kind] || `${kind}.`, '');
    out.push('| Tool | Description | Required inputs | Effect |', '|---|---|---|---|');
    for (const t of list) {
      const req = Array.isArray(t.required) && t.required.length ? t.required.map((r) => `\`${r}\``).join(', ') : '—';
      out.push(`| \`${t.name}\` | ${firstSentence(t.description)} | ${req} | ${effectClass(t)} |`);
    }
    out.push('');
  }
  return `${out.join('\n').trimEnd()}\n`;
}

/* ------------------------------------------------------------------------ */
/* Small parsers                                                             */
/* ------------------------------------------------------------------------ */

/**
 * Minimal YAML frontmatter reader: top-level `key: value` pairs, folded/literal
 * block scalars (`>`/`|`) joined with spaces, nested mappings ignored.
 * Returns null when the text has no frontmatter.
 * @param {string} text
 * @returns {Record<string,string>|null}
 */
export function parseFrontmatter(text) {
  const m = /^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/.exec(String(text || ''));
  if (!m) return null;
  const out = {};
  let block = null;
  for (const line of m[1].split(/\r?\n/)) {
    const kv = /^([A-Za-z_][\w-]*):(?:\s+(.*))?$/.exec(line);
    if (kv) {
      const key = kv[1];
      const val = (kv[2] ?? '').trim();
      if (/^[>|][-+]?$/.test(val)) {
        block = { key, lines: [] };
        out[key] = '';
      } else {
        block = null;
        out[key] = val.replace(/^(['"])(.*)\1$/, '$2');
      }
    } else if (block && /^\s+\S/.test(line)) {
      block.lines.push(line.trim());
      out[block.key] = block.lines.join(' ');
    } else if (!/^\s/.test(line) || line.trim() === '') {
      block = null;
    }
  }
  return out;
}

/**
 * Backticked inline code spans outside fenced blocks.
 * @param {string} markdown
 * @returns {string[]}
 */
export function inlineCodeSpans(markdown) {
  const noFences = String(markdown || '').replace(/```[\s\S]*?```/g, '');
  const spans = [];
  for (const m of noFences.matchAll(/`([^`\n]+)`/g)) spans.push(m[1]);
  return spans;
}

/**
 * Normalize a code span to a snake_case identifier, stripping a trailing
 * call-argument list; null when the span is not an identifier.
 * @param {string} span
 * @returns {string|null}
 */
export function toolCandidate(span) {
  const s = String(span || '').trim().replace(/\(.*\)$/, '');
  return /^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/.test(s) ? s : null;
}

/* ------------------------------------------------------------------------ */
/* Validation                                                                */
/* ------------------------------------------------------------------------ */

function walkMarkdown(dir, acc = []) {
  if (!existsSync(dir)) return acc;
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walkMarkdown(p, acc);
    else if (name.endsWith('.md')) acc.push(p);
  }
  return acc;
}

/**
 * Run every check against `root`.
 * @param {{root?:string, writeCatalog?:boolean}} [opts]
 * @returns {{failures:string[], notes:string[], wrote:string|null}}
 */
export function runValidation(opts = {}) {
  const root = resolve(opts.root || DEFAULT_ROOT);
  const failures = [];
  const notes = [];
  let wrote = null;
  const fail = (msg) => failures.push(msg);

  const readJson = (rel) => {
    const p = join(root, rel);
    if (!existsSync(p)) { fail(`${rel}: missing`); return null; }
    try { return JSON.parse(readFileSync(p, 'utf8')); } catch (e) { fail(`${rel}: invalid JSON (${e.message})`); return null; }
  };

  /* 1. Manifests ---------------------------------------------------------- */
  const plugin = readJson('.claude-plugin/plugin.json');
  if (plugin) {
    if (plugin.name !== 'rea-jev') fail(`.claude-plugin/plugin.json: name must be "rea-jev" (got ${JSON.stringify(plugin.name)})`);
    if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(String(plugin.name))) fail('.claude-plugin/plugin.json: name must be kebab-case');
    if (!/^\d+\.\d+\.\d+/.test(String(plugin.version || ''))) fail('.claude-plugin/plugin.json: version must be semver');
    if (!plugin.description) fail('.claude-plugin/plugin.json: description is required');
    const uc = plugin.userConfig || {};
    if (!uc.typesafe_api_key?.sensitive) fail('.claude-plugin/plugin.json: userConfig.typesafe_api_key must be sensitive');
    if (uc.mode && uc.mode.default !== 'advise') fail('.claude-plugin/plugin.json: userConfig.mode.default must be "advise"');
  }

  const market = readJson('.claude-plugin/marketplace.json');
  if (market) {
    if (!market.name) fail('.claude-plugin/marketplace.json: name is required');
    const entry = Array.isArray(market.plugins) ? market.plugins.find((p) => p?.name === 'rea-jev') : null;
    if (!entry) fail('.claude-plugin/marketplace.json: plugins[] must contain "rea-jev"');
    else if (entry.source !== './') fail(`.claude-plugin/marketplace.json: plugin source must be "./" (got ${JSON.stringify(entry.source)})`);
  }

  const mcp = readJson('.mcp.json');
  let pin = null;
  if (mcp) {
    const rea = mcp.mcpServers?.rea;
    if (!rea) fail('.mcp.json: mcpServers.rea is required');
    else {
      const args = Array.isArray(rea.args) ? rea.args : [];
      const spec = args.find((a) => /^rea-agents@/.test(String(a)));
      if (!spec) fail('.mcp.json: mcpServers.rea.args must include "rea-agents@<version>"');
      else {
        pin = String(spec).slice('rea-agents@'.length);
        if (!/^\d+\.\d+\.\d+/.test(pin)) fail(`.mcp.json: rea-agents pin must be an exact version (got ${JSON.stringify(pin)})`);
      }
      if (!args.includes('mcp')) fail('.mcp.json: mcpServers.rea.args must end with "mcp"');
    }
  }

  /* 2–3. Hooks ------------------------------------------------------------ */
  const hooks = readJson('hooks/hooks.json');
  if (hooks) {
    const table = hooks.hooks;
    if (!table || typeof table !== 'object') fail('hooks/hooks.json: top-level "hooks" object is required');
    else {
      for (const ev of REQUIRED_HOOK_EVENTS) if (!Array.isArray(table[ev]) || !table[ev].length) fail(`hooks/hooks.json: event ${ev} is missing`);
      for (const [ev, entries] of Object.entries(table)) {
        if (!Array.isArray(entries)) { fail(`hooks/hooks.json: ${ev} must be an array`); continue; }
        entries.forEach((entry, i) => {
          const where = `hooks/hooks.json: ${ev}[${i}]`;
          if (MATCHED_EVENTS.includes(ev)) {
            if (typeof entry?.matcher !== 'string' || !entry.matcher) fail(`${where}: matcher is required so the hook only runs on REA tools`);
            else checkMatcher(entry.matcher, where, fail);
          }
          const list = Array.isArray(entry?.hooks) ? entry.hooks : null;
          if (!list || !list.length) { fail(`${where}: hooks[] is required`); return; }
          list.forEach((h, j) => {
            const w = `${where}.hooks[${j}]`;
            if (h?.type !== 'command') fail(`${w}: type must be "command"`);
            if (typeof h?.command !== 'string') { fail(`${w}: command is required`); return; }
            if (h.timeout !== undefined && !(Number.isFinite(h.timeout) && h.timeout > 0)) fail(`${w}: timeout must be a positive number of seconds`);
            const refs = [...h.command.matchAll(/\$\{CLAUDE_PLUGIN_ROOT\}\/([^"'\s]+)/g)].map((m) => m[1]);
            if (!refs.length) fail(`${w}: command must reference "\${CLAUDE_PLUGIN_ROOT}/scripts/<hook>.mjs"`);
            for (const ref of refs) {
              if (!ref.startsWith('scripts/')) fail(`${w}: ${ref} is not under scripts/`);
              if (!existsSync(join(root, ref))) fail(`${w}: ${ref} does not exist`);
            }
          });
        });
      }
    }
  }
  checkMatcher(CANONICAL_MATCHER, 'DESIGN.md §4 canonical matcher', fail);

  /* 4. Skill frontmatter -------------------------------------------------- */
  const skillPath = join(root, SKILL_FILE);
  if (!existsSync(skillPath)) fail(`${SKILL_FILE}: missing`);
  else {
    const fm = parseFrontmatter(readFileSync(skillPath, 'utf8'));
    if (!fm) fail(`${SKILL_FILE}: no YAML frontmatter`);
    else {
      if (!fm.name) fail(`${SKILL_FILE}: frontmatter name is required`);
      else if (fm.name !== 'reverse-engineer') fail(`${SKILL_FILE}: frontmatter name must be "reverse-engineer" (got ${JSON.stringify(fm.name)})`);
      if (!fm.description) fail(`${SKILL_FILE}: frontmatter description is required`);
      else if (fm.description.length > 1024) fail(`${SKILL_FILE}: description is ${fm.description.length} chars (max 1024)`);
    }
  }

  /* 5. Pin equals catalog version ---------------------------------------- */
  const catalog = readJson(CATALOG_JSON);
  if (catalog) {
    if (!Array.isArray(catalog.tools) || !catalog.tools.length) fail(`${CATALOG_JSON}: tools[] is empty`);
    if (typeof catalog.tool_count === 'number' && Array.isArray(catalog.tools) && catalog.tool_count !== catalog.tools.length) {
      fail(`${CATALOG_JSON}: tool_count ${catalog.tool_count} != tools.length ${catalog.tools.length}`);
    }
    if (pin && catalog.version !== pin) fail(`.mcp.json pins rea-agents@${pin} but ${CATALOG_JSON} is version ${catalog.version}`);
  }

  /* 6. Backticked tool references ---------------------------------------- */
  if (catalog && Array.isArray(catalog.tools)) {
    const names = new Set(catalog.tools.map((t) => t.name));
    const verbs = new Set(catalog.tools.map((t) => String(t.name).split('_')[0]));
    const props = new Set();
    for (const t of catalog.tools) for (const k of Object.keys(t.props || {})) props.add(k);
    const files = [...walkMarkdown(join(root, 'skills')), ...walkMarkdown(join(root, 'agents'))];
    for (const file of files) {
      const rel = relative(root, file);
      const seen = new Set();
      for (const span of inlineCodeSpans(readFileSync(file, 'utf8'))) {
        const id = toolCandidate(span);
        if (!id || seen.has(id)) continue;
        seen.add(id);
        if (names.has(id) || ANDROID_TOOL_ALLOWLIST.has(id)) continue;
        if (!id.includes('_')) continue; // single words are never tool references
        if (SPEC_VOCABULARY.has(id) || props.has(id)) continue;
        if (verbs.has(id.split('_')[0])) fail(`${rel}: \`${id}\` is not a tool in rea-agents@${catalog.version} (see ${CATALOG_JSON})`);
      }
    }
  }

  /* 7. Generated catalog Markdown ---------------------------------------- */
  if (catalog && Array.isArray(catalog.tools)) {
    const expected = generateToolCatalogMarkdown(catalog);
    const mdPath = join(root, CATALOG_MD);
    if (opts.writeCatalog) {
      mkdirSync(dirname(mdPath), { recursive: true });
      writeFileSync(mdPath, expected);
      wrote = mdPath;
    }
    if (!existsSync(mdPath)) fail(`${CATALOG_MD}: missing; run \`node scripts/validate.mjs --write-catalog\``);
    else if (readFileSync(mdPath, 'utf8') !== expected) {
      fail(`${CATALOG_MD}: stale; run \`node scripts/validate.mjs --write-catalog\``);
    }
  }

  return { failures, notes, wrote };
}

function checkMatcher(source, where, fail) {
  let re;
  try { re = new RegExp(source); } catch (e) { fail(`${where}: matcher is not a valid regex (${e.message})`); return; }
  for (const s of MATCHER_MUST_MATCH) if (!re.test(s)) fail(`${where}: matcher ${JSON.stringify(source)} does not match ${s}`);
  for (const s of MATCHER_MUST_NOT_MATCH) if (re.test(s)) fail(`${where}: matcher ${JSON.stringify(source)} must not match ${s}`);
}

/* ------------------------------------------------------------------------ */
/* CLI                                                                       */
/* ------------------------------------------------------------------------ */

function parseArgs(argv) {
  const opts = { writeCatalog: false, root: undefined };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--write-catalog') opts.writeCatalog = true;
    else if (a === '--root') { opts.root = argv[i + 1]; i += 1; }
    else if (a === '-h' || a === '--help') { opts.help = true; }
    else { opts.unknown = a; }
  }
  return opts;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help || opts.unknown) {
    const msg = 'usage: node scripts/validate.mjs [--write-catalog] [--root <dir>]';
    if (opts.unknown) { console.error(`unknown argument: ${opts.unknown}\n${msg}`); process.exit(1); }
    console.log(msg);
    return;
  }
  if (opts.root && !existsSync(opts.root)) { console.error(`--root ${opts.root} does not exist`); process.exit(1); }
  const { failures, notes, wrote } = runValidation(opts);
  if (wrote) console.log(`wrote ${relative(process.cwd(), wrote) || wrote}`);
  for (const n of notes) console.error(`note: ${n}`);
  if (failures.length) {
    for (const f of failures) console.log(`FAIL: ${f}`);
    console.log(`${failures.length} failure(s)`);
    process.exit(1);
  }
  console.log('ok');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
