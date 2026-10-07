/**
 * REA tool knowledge: name matching, effect classes, the first-tool table,
 * canonical input hashing, and result parsing (Evidence IDs, limitations).
 *
 * Data comes from `data/rea-tool-catalog.json`, generated from the pinned
 * `rea-agents` release. Everything degrades gracefully when the catalog is
 * missing: name-based heuristics take over.
 *
 * @module rea
 */

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { truncate } from './redact.mjs';

/**
 * Matches both ways REA can be registered: globally by `rea setup`
 * (`mcp__rea__<tool>`) and through this plugin's `.mcp.json`
 * (`mcp__plugin_rea-jev_rea__<tool>`). Does not match `mcp__area__x`.
 */
export const REA_TOOL_MATCHER = /mcp__(plugin_rea-jev_)?rea__/;
const REA_TOOL_FULL = /^mcp__(plugin_rea-jev_)?rea__(.+)$/;

/** Absolute path of the generated tool catalog. */
export const CATALOG_PATH = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../data/rea-tool-catalog.json');

/** Evidence IDs as REA emits them: `ev_` + 64 lowercase hex characters. */
export const EVIDENCE_ID_RE = /\bev_[0-9a-f]{64}\b/g;

/** The four effect classes, used by the gate, evidence and stop hooks. */
export const EFFECT_CLASSES = Object.freeze(['runtime', 'mutation', 'status', 'inspect']);

const MUTATION_EXACT = new Set(['unset_bookmark', 'record_unknown', 'update_unknown', 'extract_artifact', 'open_binary', 'close_binary']);
const MUTATION_PREFIX = ['set_', 'annotate_', 'import_', 'export_'];
const STATUS_EXACT = new Set(['binary_session', 'list_unknowns', 'get_navigation_context', 'get_evidence_bundle', 'verify_unknown_resolution', 'list_documents']);
const STATUS_PREFIX = ['current_'];
const RUNTIME_PREFIX = ['capture_', 'observe_'];
/** Catalog kinds whose network-attaching tools observe a live browser, Electron or Node process. */
const LIVE_PROVIDER_KINDS = new Set(['browser-provider', 'electron-provider', 'runtime-provider']);
/** Tools that compare or reconcile runtime captures; their results legitimately describe observed behavior. */
const RUNTIME_EVIDENCE_TOOLS = new Set(['compare_web_captures', 'compare_web_screenshots', 'reconcile_javascript_runtime']);
/** Name fallback for `isStaticTool` when the catalog is unavailable. */
const LIVE_TOOL_FALLBACK = new Set([
  'list_browser_targets', 'inspect_web_page', 'analyze_web_bundle', 'discover_webmcp_tools',
  'list_electron_targets', 'inspect_electron_page', 'list_javascript_runtime_targets',
]);
/** Evidence IDs kept per result; the rest is counted (`evidenceCount`) so a hostile artifact cannot bloat the ledger. */
export const EVIDENCE_IDS_MAX = 64;

/**
 * First tool per route `target_kind`, from REA's own skill. `then` lists the
 * typical follow-ups. `android_apk` names a tool that the pinned release may
 * not ship; `firstToolFor()` resolves the fallback against the catalog.
 */
export const FIRST_TOOL_BY_TARGET = Object.freeze({
  native_binary: { first: 'open_binary', arg: 'path', then: ['binary_overview', 'search_strings', 'trace_feature'] },
  javascript_application: { first: 'analyze_javascript_application', arg: 'input_path', then: ['trace_application_feature', 'trace_javascript_semantics'] },
  managed_assembly: { first: 'inspect_managed_artifact', arg: 'path', then: ['inspect_managed_members', 'inspect_managed_native_boundaries'] },
  android_apk: { first: 'inspect_android_package', arg: 'path', then: ['inspect_artifact'], fallback: { first: 'open_binary', arg: 'path', then: ['inspect_artifact', 'extract_artifact'] } },
  package_archive: { first: 'open_binary', arg: 'path', then: ['inspect_artifact', 'extract_artifact'] },
  website_in_browser: { first: 'list_browser_targets', arg: 'cdp_endpoint', then: ['inspect_web_page', 'analyze_web_bundle', 'observe_web_session'] },
  electron_or_node_runtime: { first: 'list_electron_targets', arg: 'cdp_endpoint', alt: 'list_javascript_runtime_targets', then: ['inspect_electron_page', 'observe_javascript_runtime'] },
  source_repository: { first: null, note: 'ordinary source code; REA is not needed' },
  unknown_or_missing: { first: null, note: 'ask the user which artifact to inspect before opening anything' },
});

let catalogCache = null;

/**
 * True for a Claude Code tool name that belongs to an REA MCP server.
 *
 * @param {unknown} toolName
 * @returns {boolean}
 */
export function isReaTool(toolName) {
  return typeof toolName === 'string' && REA_TOOL_FULL.test(toolName);
}

/**
 * Strip the MCP prefix: `mcp__plugin_rea-jev_rea__open_binary` → `open_binary`.
 * Names without an REA prefix are returned unchanged.
 *
 * @param {unknown} toolName
 * @returns {string}
 */
export function bareToolName(toolName) {
  const s = toolName == null ? '' : String(toolName);
  const m = REA_TOOL_FULL.exec(s);
  return m ? m[2] : s;
}

/**
 * Load (and cache) the tool catalog. Never throws; a missing or corrupt file
 * yields an empty catalog with `version: ''`.
 *
 * @returns {{version: string, source: string, toolCount: number, tools: object[], byName: Map<string, object>}}
 */
export function loadCatalog() {
  if (catalogCache) return catalogCache;
  try {
    const raw = JSON.parse(readFileSync(CATALOG_PATH, 'utf8'));
    const tools = Array.isArray(raw.tools) ? raw.tools.filter((t) => t && typeof t.name === 'string') : [];
    catalogCache = {
      version: String(raw.version ?? ''),
      source: String(raw.source ?? 'rea-agents'),
      toolCount: tools.length,
      tools,
      byName: new Map(tools.map((t) => [t.name, t])),
    };
  } catch {
    catalogCache = { version: '', source: 'rea-agents', toolCount: 0, tools: [], byName: new Map() };
  }
  return catalogCache;
}

/**
 * The pinned `rea-agents` version the catalog was generated from, or null.
 *
 * @returns {string|null}
 */
export function reaPin() {
  return loadCatalog().version || null;
}

/**
 * Catalog entry for a tool (full or bare name), or null when unknown.
 *
 * @param {string} toolName
 * @returns {object|null}
 */
export function catalogTool(toolName) {
  return loadCatalog().byName.get(bareToolName(toolName)) ?? null;
}

/**
 * Catalog `kind` of a tool (e.g. 'official-proxy', 'enhanced', 'session'), or null.
 *
 * @param {string} toolName
 * @returns {string|null}
 */
export function toolKind(toolName) {
  return catalogTool(toolName)?.kind ?? null;
}

/**
 * Effect class of a tool:
 * - `mutation`: `set_*`, `annotate_*`, `import_*`, `export_*`, `unset_bookmark`,
 *   `record_unknown`, `update_unknown`, `extract_artifact`, `open_binary`, `close_binary`
 * - `status`: `binary_session`, `list_unknowns`, `get_navigation_context`, `current_*`,
 *   `get_evidence_bundle`, `verify_unknown_resolution`, `list_documents`
 * - `runtime`: `capture_*` / `observe_*` whose catalog entry has `launchesProcess`
 *   (tools missing from the catalog are classified by name alone)
 * - `inspect`: everything else
 *
 * @param {string} toolName full or bare
 * @returns {'runtime'|'mutation'|'status'|'inspect'}
 */
export function effectClass(toolName) {
  const name = bareToolName(toolName);
  if (MUTATION_EXACT.has(name) || MUTATION_PREFIX.some((p) => name.startsWith(p))) return 'mutation';
  if (STATUS_EXACT.has(name) || STATUS_PREFIX.some((p) => name.startsWith(p))) return 'status';
  if (RUNTIME_PREFIX.some((p) => name.startsWith(p))) {
    const entry = catalogTool(name);
    const launches = entry ? entry.effects?.launchesProcess === true : true;
    if (launches) return 'runtime';
  }
  return 'inspect';
}

/**
 * True when the tool performs static analysis, i.e. its result cannot describe
 * anything as executed or observed. False for every `capture_*` / `observe_*`
 * tool (whether or not it launches a process), for the passive CDP / Inspector
 * tools that attach to a live browser, Electron or Node process (catalog kind
 * browser-/electron-/runtime-provider with `accessesNetwork`), and for the
 * tools that compare or reconcile runtime captures. `analyze_javascript_application`
 * stays static: it reads files. The gate's `effectClass` is unchanged by this.
 *
 * @param {string} toolName
 * @returns {boolean}
 */
export function isStaticTool(toolName) {
  const name = bareToolName(toolName);
  if (RUNTIME_PREFIX.some((p) => name.startsWith(p))) return false;
  if (RUNTIME_EVIDENCE_TOOLS.has(name)) return false;
  const entry = catalogTool(name);
  if (entry) return !(LIVE_PROVIDER_KINDS.has(entry.kind) && entry.effects?.accessesNetwork === true);
  return !LIVE_TOOL_FALLBACK.has(name);
}

/**
 * Resolve the first tool for a route target, applying the catalog fallback
 * (e.g. Android tools absent from the pinned release).
 *
 * @param {string} targetKind one of the `target_kind` options
 * @returns {{first: string|null, arg?: string, then: string[], alt?: string, note?: string, available: boolean}}
 */
export function firstToolFor(targetKind) {
  const entry = FIRST_TOOL_BY_TARGET[targetKind];
  if (!entry) return { first: null, then: [], note: 'unknown target kind', available: false };
  const { byName } = loadCatalog();
  const known = (name) => byName.size === 0 || byName.has(name);
  if (entry.first && !known(entry.first) && entry.fallback) {
    return { ...entry.fallback, then: [...entry.fallback.then], available: true, note: `${entry.first} is not in rea-agents ${reaPin() ?? ''}`.trim() };
  }
  return { first: entry.first, arg: entry.arg, alt: entry.alt, then: [...(entry.then ?? [])], note: entry.note, available: entry.first ? known(entry.first) : false };
}

/**
 * Human line for the route block, e.g.
 * `open_binary(path), then binary_overview / search_strings / trace_feature`.
 *
 * @param {string} targetKind
 * @returns {string}
 */
export function describeFirstTool(targetKind) {
  const t = firstToolFor(targetKind);
  if (!t.first) return t.note ?? 'no REA tool applies';
  const head = t.arg ? `${t.first}(${t.arg})` : t.first;
  const alt = t.alt ? ` or ${t.alt}` : '';
  const then = t.then.length ? `, then ${t.then.join(' / ')}` : '';
  return `${head}${alt}${then}`;
}

/**
 * Deterministic JSON with sorted object keys (for hashing tool inputs).
 * `undefined` values are dropped from objects and become null in arrays.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalJson(value) {
  return JSON.stringify(sortKeys(value, 0)) ?? 'null';
}

/**
 * `sha256:<hex>` of `bareTool + canonicalJson(toolInput)`; the redundancy key
 * shared by the gate (PreToolUse) and evidence (PostToolUse) hooks.
 *
 * @param {string} toolName full or bare
 * @param {unknown} toolInput
 * @returns {string}
 */
export function hashInput(toolName, toolInput) {
  const h = createHash('sha256');
  h.update(bareToolName(toolName) + canonicalJson(toolInput ?? {}));
  return `sha256:${h.digest('hex')}`;
}

/**
 * Claude Code replaces a tool result that is too large for the context with a
 * notice of the form "Error: result (N characters) exceeds maximum allowed
 * tokens. Output has been saved to <path>." (current builds write
 * "N characters across M lines") followed by instructions to the assistant on
 * how to read that file. Hooks receive the notice, not the result. The path
 * runs to the end of its line, so directories with spaces survive. Returns
 * the character count and the saved path, or null for anything else.
 */
const OVERSIZE_NOTICE_RE =
  /^Error: result \(([\d,]+) characters(?: across [\d,]+ lines?)?\) exceeds maximum allowed tokens\. Output has been saved to ([^\r\n]+?)\.?[ \t]*(?:\r?\n|$)/;

/**
 * Recognize Claude Code's size notice (see OVERSIZE_NOTICE_RE).
 *
 * @param {unknown} text
 * @returns {{chars: number, path: string}|null}
 */
export function harnessOversizeNotice(text) {
  if (typeof text !== 'string') return null;
  const m = OVERSIZE_NOTICE_RE.exec(text.trimStart());
  if (!m) return null;
  return { chars: Number(m[1].replace(/,/g, '')) || 0, path: m[2] };
}

/**
 * Parse an MCP tool result from REA.
 *
 * Accepts `{content:[{type:'text',text}], structuredContent?, isError?}`, a
 * bare content array `[{type:'text',text}]`, a plain string, or any object
 * (stringified). Evidence IDs are collected from the text (the first
 * `EVIDENCE_IDS_MAX` unique ones; `evidenceCount` is the full count).
 * Limitations come only from REA's envelope positions, never from arbitrary
 * nested artifact data (a plist or package.json echoed by REA may carry an
 * `unknowns` key of its own): the keys `limitations`, `limitation`,
 * `residual_unknowns`, `unknowns`, and `coverage.*unknown*` at the top level,
 * under `result`, and under `result.coverage` / `coverage` (≤ 40 items), plus
 * a `completeness` object whose status is not complete, rendered as one
 * sentence (`completeness incomplete; missing_sections: events`).
 * `unknowns` holds the subset that came from the two unknown keys. `empty` is
 * true when there was no response at all (null, '', `{}`, `[]`, or content
 * with no text), which the evidence hook records as a failed call so the
 * gate never treats it as a reusable result.
 *
 * @param {unknown} toolResponse
 * @returns {{text: string, json: unknown|null, evidenceIds: string[], evidenceCount: number, limitations: string[], unknowns: string[], truncated: boolean, error: string|null, bytes: number, empty: boolean}}
 */
export function parseReaResult(toolResponse) {
  const out = { text: '', json: null, evidenceIds: [], evidenceCount: 0, limitations: [], unknowns: [], truncated: false, error: null, bytes: 0, empty: false };
  if (toolResponse == null) {
    out.empty = true;
    return out;
  }
  // Some hosts hand the MCP content array over bare.
  if (Array.isArray(toolResponse) && toolResponse.every((c) => c && typeof c === 'object' && !Array.isArray(c) && ('type' in c || 'text' in c))) {
    toolResponse = { content: toolResponse };
  }

  let text = '';
  let structured = null;
  let isError = false;
  if (typeof toolResponse === 'string') {
    text = toolResponse;
  } else if (typeof toolResponse === 'object') {
    if (Array.isArray(toolResponse.content)) {
      text = toolResponse.content
        .filter((c) => c && typeof c.text === 'string')
        .map((c) => c.text)
        .join('\n');
    } else if (typeof toolResponse.text === 'string') {
      text = toolResponse.text;
    }
    if (toolResponse.structuredContent && typeof toolResponse.structuredContent === 'object') structured = toolResponse.structuredContent;
    isError = toolResponse.isError === true;
    if (!text && !structured) {
      const keys = Array.isArray(toolResponse) ? toolResponse.length : Object.keys(toolResponse).length;
      const contentOnly = Array.isArray(toolResponse.content) && keys === 1 + (isError ? 1 : 0);
      if (keys === 0 || contentOnly) out.empty = true;
      text = keys === 0 ? '' : safeStringify(toolResponse);
    }
  } else {
    text = String(toolResponse);
  }
  if (!text.trim() && !structured) out.empty = true;

  out.text = text;
  out.bytes = Buffer.byteLength(text, 'utf8');

  let json = structured;
  if (json == null) {
    const trimmed = text.trim();
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      try {
        json = JSON.parse(trimmed);
      } catch {
        json = null;
      }
    }
  }
  out.json = json ?? null;

  const idSource = structured ? `${text}\n${safeStringify(structured)}` : text;
  const allIds = unique(idSource.match(EVIDENCE_ID_RE) ?? []);
  out.evidenceCount = allIds.length;
  out.evidenceIds = allIds.slice(0, EVIDENCE_IDS_MAX);

  if (json && typeof json === 'object' && !Array.isArray(json)) {
    const ctx = { limitations: [], unknowns: [], seen: new Set(), count: 0, truncated: false };
    collectEnvelope(json, ctx);
    out.limitations = ctx.limitations;
    out.unknowns = ctx.unknowns;
    out.truncated = ctx.truncated;
  }
  if (!out.truncated && /\[truncated\]|…\[\d+ chars omitted\]…/.test(text)) out.truncated = true;

  if (isError) {
    out.error = truncate(text.trim(), 300) || 'tool reported an error';
  } else if (json && typeof json === 'object' && !Array.isArray(json) && json.error != null) {
    out.error = truncate(typeof json.error === 'string' ? json.error : safeStringify(json.error), 300);
  }
  return out;
}

const WALK_MAX_ITEMS = 40;

/**
 * Collect limitations from REA's envelope positions only, in document order:
 * the root object, `result`, and the `coverage` object at either of those.
 * Nothing deeper is read, so keys that belong to the analyzed artifact's own
 * data (a plist, a package.json) cannot pose as REA limitations.
 */
function collectEnvelope(root, ctx) {
  collectContainer(root, ctx, { isCoverage: false, isRoot: true });
}

function collectContainer(node, ctx, { isCoverage, isRoot }) {
  for (const [k, v] of Object.entries(node)) {
    const key = k.toLowerCase();
    if (key === 'truncated' && v === true) ctx.truncated = true;
    if (key === 'limitations' || key === 'limitation') collect(v, ctx.limitations, ctx);
    else if (key === 'residual_unknowns' || key === 'unknowns') collect(v, ctx.unknowns, ctx, ctx.limitations);
    else if (isCoverage && /unknown/i.test(key)) collect(v, ctx.limitations, ctx);
    else if (!isCoverage && key === 'completeness' && isObj(v)) collect(completenessGap(v), ctx.limitations, ctx);
    else if (!isCoverage && key === 'coverage' && isObj(v)) collectContainer(v, ctx, { isCoverage: true, isRoot: false });
    else if (isRoot && key === 'result' && isObj(v)) collectContainer(v, ctx, { isCoverage: false, isRoot: false });
  }
}

function isObj(v) {
  return v != null && typeof v === 'object' && !Array.isArray(v);
}

const COMPLETE_STATUSES = new Set(['complete', 'complete_within_window']);
/** Sections named under these keys are what the result could not include. */
const COMPLETENESS_GAP_KEYS = ['missing_sections', 'truncated_sections', 'unavailable_sections'];

/**
 * One sentence for a `completeness` object whose status is not complete
 * (`completeness incomplete; missing_sections: events`), or null. Sections
 * filtered by the caller's own policy (`policy_filtered_sections`,
 * `excluded`) are left out: they vary with the input, not with what the tool
 * could do, and would make every page look like a new gap.
 */
function completenessGap(c) {
  const status = typeof c.status === 'string' ? c.status.trim() : '';
  if (!status || COMPLETE_STATUSES.has(status)) return null;
  const parts = [`completeness ${status}`];
  for (const k of COMPLETENESS_GAP_KEYS) {
    const names = Array.isArray(c[k]) ? c[k].filter((s) => typeof s === 'string' && s).slice(0, 6) : [];
    if (names.length) parts.push(`${k}: ${names.join(', ')}`);
  }
  return parts.join('; ');
}

function collect(value, list, ctx, mirror) {
  const items = Array.isArray(value) ? value : value == null ? [] : [value];
  for (const item of items) {
    if (ctx.count >= WALK_MAX_ITEMS) return;
    const s = itemToString(item);
    if (!s || ctx.seen.has(s)) continue;
    ctx.seen.add(s);
    ctx.count += 1;
    list.push(s);
    if (mirror) mirror.push(s);
  }
}

const ITEM_FIELDS = ['message', 'text', 'question', 'summary', 'reason', 'description', 'detail', 'title', 'kind', 'code'];

function itemToString(item) {
  if (item == null) return '';
  if (typeof item === 'string') return item.trim().slice(0, 200);
  if (typeof item !== 'object') return String(item).slice(0, 200);
  for (const f of ITEM_FIELDS) if (typeof item[f] === 'string' && item[f].trim()) return item[f].trim().slice(0, 200);
  return safeStringify(item).slice(0, 200);
}

function sortKeys(value, depth) {
  if (value === undefined) return null;
  if (value === null || typeof value !== 'object') return value;
  if (depth > 50) return '[depth]';
  if (Array.isArray(value)) return value.map((v) => sortKeys(v, depth + 1));
  const out = {};
  for (const k of Object.keys(value).sort()) {
    if (value[k] === undefined) continue;
    out[k] = sortKeys(value[k], depth + 1);
  }
  return out;
}

function unique(list) {
  return [...new Set(list)];
}

function safeStringify(value) {
  try {
    return JSON.stringify(value) ?? '';
  } catch {
    return String(value);
  }
}
