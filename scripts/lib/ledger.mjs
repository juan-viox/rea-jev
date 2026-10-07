/**
 * Per-session JSONL ledger plus the optional decisions log.
 *
 * Layout under the data dir (`REA_JEV_HOME` || `CLAUDE_PLUGIN_DATA` || `~/.rea-jev`):
 *   sessions/<session_id>.jsonl   one event per line (route / pre / post / stop)
 *   decisions.jsonl               every decision, only when REA_JEV_LOG=1
 *
 * Directories are created 0o700, files 0o600. Callers store hashes, IDs and
 * ≤200-char redacted excerpts, never full tool inputs or outputs. Every
 * function here is synchronous and never throws.
 *
 * @module ledger
 */

import fs from 'node:fs';
import path from 'node:path';
import { resolveHome, debug } from './hookio.mjs';
import { effectClass, bareToolName } from './rea.mjs';

const DEFAULT_MAX_BYTES = 8 * 1024 * 1024;
/** Largest file whose dropped head is still scanned for the latest `route` event. */
const ROUTE_SCAN_MAX_BYTES = 256 * 1024 * 1024;
const HEAD_CHUNK = 1024 * 1024;
/** Default `is_re_task` cutoff (DESIGN.md §5.1 `T_ROUTE_RE`) used to tell RE routes from follow-up prompts. */
const ROUTE_RE_DEFAULT = 0.35;

/**
 * @typedef {Object} LedgerEvent
 * @property {number} t epoch ms (added by appendEvent when missing)
 * @property {'route'|'pre'|'post'|'stop'} kind
 * @property {string} [tool]            bare tool name (pre/post)
 * @property {string} [input_hash]      `sha256:...` (pre/post)
 * @property {string} [input_excerpt]   ≤200 chars, redacted
 * @property {string} [decision]        pre: allow|ask|deny|silent; stop: allow|block|shadow_block
 * @property {string} [source]          pre: local|jev
 * @property {boolean} [ok]             post
 * @property {string[]} [evidence_ids]  post
 * @property {string[]} [limitations]   post, each ≤120 chars
 * @property {number} [bytes]           post
 * @property {string[]} [notes]         post: low_relevance|unknown_candidate|agent_directed_text
 * @property {string} [effect]          post: effect class, when the hook recorded it
 * @property {boolean} [oversize_notice] post: the host replaced the result with its size notice
 * @property {boolean} [recovered]      post: the saved result was read back and judged in the notice's place
 * @property {string} [prompt_excerpt]  route, ≤200 chars (ledger excerpt)
 * @property {string} [prompt_for_jev]  route, ≤1200 chars: the redacted request the gate/evidence/stop hooks send to Jev
 * @property {string|null} [declared_target] route
 * @property {string} [target_hint]     route
 * @property {Record<string, unknown>} [answers]
 * @property {string} [reason]          stop
 */

/**
 * The data directory (see module doc).
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {string}
 */
export function ledgerDir(env = process.env) {
  return resolveHome(env);
}

/**
 * Directory holding per-session files.
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {string}
 */
export function sessionsDir(env = process.env) {
  return path.join(ledgerDir(env), 'sessions');
}

/**
 * Path of one session's JSONL file. The id is sanitised to `[A-Za-z0-9._-]`.
 * @param {string} sessionId
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {string}
 */
export function sessionPath(sessionId, env = process.env) {
  return path.join(sessionsDir(env), `${safeId(sessionId)}.jsonl`);
}

/**
 * Path of the decisions log.
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {string}
 */
export function decisionsPath(env = process.env) {
  return path.join(ledgerDir(env), 'decisions.jsonl');
}

/**
 * Make a session id safe for a filename.
 * @param {unknown} id
 * @returns {string}
 */
export function safeId(id) {
  const s = String(id ?? '')
    .replace(/[^A-Za-z0-9._-]/g, '_')
    .slice(0, 128);
  return s || 'unknown';
}

/**
 * Append one event to the session ledger. Adds `t` when missing. Events
 * without a `kind` are dropped. Returns true on success, false otherwise.
 *
 * @param {string} sessionId
 * @param {Partial<LedgerEvent> & {kind: string}} event
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {boolean}
 */
export function appendEvent(sessionId, event, env = process.env) {
  if (!event || typeof event !== 'object' || typeof event.kind !== 'string') return false;
  try {
    const record = { t: Date.now(), ...event };
    appendLine(sessionPath(sessionId, env), record);
    return true;
  } catch (err) {
    debug(`ledger append failed: ${err?.code ?? err?.name ?? 'error'}`);
    return false;
  }
}

/**
 * Read a session's events (oldest first). Malformed lines are skipped. Files
 * larger than `maxBytes` are read from the tail only, except that the latest
 * `route` event from the dropped head is kept (it anchors the declared target
 * and the user's request for every later hook). Returns [] on any error.
 *
 * @param {string} sessionId
 * @param {NodeJS.ProcessEnv} [env]
 * @param {{maxBytes?: number}} [opts]
 * @returns {LedgerEvent[]}
 */
export function readEvents(sessionId, env = process.env, opts = {}) {
  return readJsonl(sessionPath(sessionId, env), opts.maxBytes ?? DEFAULT_MAX_BYTES);
}

/**
 * Append a decision record to `decisions.jsonl` when `REA_JEV_LOG=1`.
 * Adds `t` when missing. Returns true only when a line was written.
 *
 * @param {Record<string, unknown>} record e.g. {hook:'pre', session_id, decision, source, latency_ms, usage, confidences, bands}
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {boolean}
 */
export function logDecision(record, env = process.env) {
  if (env.REA_JEV_LOG !== '1') return false;
  if (!record || typeof record !== 'object') return false;
  try {
    appendLine(decisionsPath(env), { t: Date.now(), ...record });
    return true;
  } catch (err) {
    debug(`decision log failed: ${err?.code ?? err?.name ?? 'error'}`);
    return false;
  }
}

/**
 * Read decision records, optionally only those from the last `days` days.
 *
 * @param {{days?: number, env?: NodeJS.ProcessEnv, maxBytes?: number}} [opts]
 * @returns {Array<Record<string, unknown>>}
 */
export function readDecisions(opts = {}) {
  const { days, env = process.env, maxBytes = DEFAULT_MAX_BYTES } = opts;
  const all = readJsonl(decisionsPath(env), maxBytes);
  if (!Number.isFinite(days) || days <= 0) return all;
  const since = Date.now() - days * 86_400_000;
  return all.filter((r) => Number(r.t) >= since);
}

/**
 * Derive the facts the hooks need from a session's events.
 *
 * `identicalCallSeen(tool, hash)` is true when a successful `post` with the
 * same bare tool and `input_hash` exists, it returned something (non-zero
 * bytes or an Evidence ID), and no `mutation`-class call has completed since.
 * `findIdenticalCall` returns that post event (for its Evidence IDs) or null.
 *
 * `lastRoute` is the most recent route event of any kind (it carries the
 * declared target forward through follow-up prompts). `lastReRoute` is the
 * most recent route event that was a reverse-engineering request: not
 * `decision: 'silent'` and not `is_re_task` below `T_ROUTE_RE`. `userRequest`
 * is that event's redacted prompt (`prompt_for_jev`, else `prompt_excerpt`),
 * so a "thanks, format that as a table" follow-up never becomes the question
 * the evidence, gate and stop hooks judge against.
 *
 * `limitationsNoted` is the subset of `limitationsFlagged` that came from
 * posts carrying an `unknown_candidate` note: the limitations the agent was
 * told about, as opposed to merely recorded.
 *
 * @param {LedgerEvent[]} events
 * @param {{routeRe?: number}} [opts] `routeRe` overrides the `is_re_task` cutoff (default 0.35)
 * @returns {{
 *   hasReaActivity: boolean,
 *   openBinaryWithoutClose: boolean,
 *   lastRoute: LedgerEvent|null,
 *   lastReRoute: LedgerEvent|null,
 *   userRequest: string,
 *   declaredTarget: string|null,
 *   toolCalls: number,
 *   toolCallsSinceMutation: number,
 *   identicalCallSeen: (tool: string, hash: string) => boolean,
 *   findIdenticalCall: (tool: string, hash: string) => LedgerEvent|null,
 *   evidenceIds: string[],
 *   limitationsFlagged: string[],
 *   limitationsNoted: string[],
 *   unknownsRecorded: number,
 *   stopBlocksThisSession: number,
 *   lastStopBlockAt: number|null,
 *   lastPost: LedgerEvent|null,
 *   events: LedgerEvent[],
 * }}
 */
export function summarize(events, opts = {}) {
  const list = Array.isArray(events) ? events.filter((e) => e && typeof e === 'object') : [];
  const routeRe = Number.isFinite(opts.routeRe) ? opts.routeRe : ROUTE_RE_DEFAULT;
  let hasReaActivity = false;
  let openBinaryWithoutClose = false;
  let lastRoute = null;
  let lastReRoute = null;
  let lastPost = null;
  let toolCalls = 0;
  let toolCallsSinceMutation = 0;
  let unknownsRecorded = 0;
  let stopBlocks = 0;
  let lastStopBlockAt = null;
  let lastMutationIdx = -1;
  const evidence = new Set();
  const limitations = new Set();
  const noted = new Set();
  const posts = [];

  list.forEach((e, idx) => {
    switch (e.kind) {
      case 'route':
        lastRoute = e;
        if (isReRoute(e, routeRe)) lastReRoute = e;
        break;
      case 'pre':
        hasReaActivity = true;
        break;
      case 'post': {
        hasReaActivity = true;
        toolCalls += 1;
        lastPost = e;
        const tool = bareToolName(e.tool ?? '');
        const ok = e.ok !== false;
        const effect = typeof e.effect === 'string' ? e.effect : effectClass(tool);
        if (effect === 'mutation') {
          lastMutationIdx = idx;
          toolCallsSinceMutation = 0;
        } else {
          toolCallsSinceMutation += 1;
        }
        if (ok && tool === 'open_binary') openBinaryWithoutClose = true;
        if (ok && tool === 'close_binary') openBinaryWithoutClose = false;
        if (ok && tool === 'record_unknown') unknownsRecorded += 1;
        if (Array.isArray(e.evidence_ids)) for (const id of e.evidence_ids) if (typeof id === 'string') evidence.add(id);
        if (Array.isArray(e.limitations)) {
          const notedPost = Array.isArray(e.notes) && e.notes.includes('unknown_candidate');
          for (const l of e.limitations) {
            if (typeof l !== 'string') continue;
            limitations.add(l);
            if (notedPost) noted.add(l);
          }
        }
        const hasBody = (Number(e.bytes) || 0) > 0 || (Array.isArray(e.evidence_ids) && e.evidence_ids.length > 0);
        posts.push({ tool, hash: typeof e.input_hash === 'string' ? e.input_hash : null, ok, reusable: ok && hasBody, idx, event: e });
        break;
      }
      case 'stop':
        if (e.decision === 'block') {
          stopBlocks += 1;
          if (Number.isFinite(Number(e.t))) lastStopBlockAt = Number(e.t);
        }
        break;
      default:
        break;
    }
  });

  const findIdenticalCall = (tool, hash) => {
    if (!hash) return null;
    const bare = bareToolName(tool);
    for (let i = posts.length - 1; i >= 0; i -= 1) {
      const p = posts[i];
      if (p.idx <= lastMutationIdx) break;
      if (p.reusable && p.hash === hash && p.tool === bare) return p.event;
    }
    return null;
  };

  const userRequest = typeof lastReRoute?.prompt_for_jev === 'string' ? lastReRoute.prompt_for_jev : typeof lastReRoute?.prompt_excerpt === 'string' ? lastReRoute.prompt_excerpt : '';

  return {
    hasReaActivity,
    openBinaryWithoutClose,
    lastRoute,
    lastReRoute,
    userRequest,
    declaredTarget: typeof lastRoute?.declared_target === 'string' ? lastRoute.declared_target : null,
    toolCalls,
    toolCallsSinceMutation,
    identicalCallSeen: (tool, hash) => findIdenticalCall(tool, hash) !== null,
    findIdenticalCall,
    evidenceIds: [...evidence],
    limitationsFlagged: [...limitations],
    limitationsNoted: [...noted],
    unknownsRecorded,
    stopBlocksThisSession: stopBlocks,
    lastStopBlockAt,
    lastPost,
    events: list,
  };
}

/**
 * Create a directory and its missing parents, one level at a time, mode 0o700.
 * Unlike `fs.mkdirSync(..., {recursive: true})` this is bounded by the path
 * depth, so a pathological location (e.g. under /proc) fails instead of
 * spinning. Throws on failure.
 *
 * @param {string} dir absolute path
 */
export function ensureDir(dir) {
  const target = path.resolve(dir);
  const missing = [];
  let cur = target;
  for (let guard = 0; guard < 256; guard += 1) {
    const st = fs.statSync(cur, { throwIfNoEntry: false });
    if (st) {
      if (!st.isDirectory()) throw Object.assign(new Error(`not a directory: ${cur}`), { code: 'ENOTDIR' });
      break;
    }
    missing.push(cur);
    const parent = path.dirname(cur);
    if (parent === cur) throw Object.assign(new Error(`no existing ancestor for ${target}`), { code: 'ENOENT' });
    cur = parent;
  }
  for (const d of missing.reverse()) fs.mkdirSync(d, { mode: 0o700 });
}

/** A route event counts as a reverse-engineering request unless it says otherwise. */
function isReRoute(e, routeRe) {
  if (e.decision === 'silent') return false;
  const p = e.answers?.is_re_task?.noul;
  if (typeof p === 'number' && Number.isFinite(p) && p < routeRe) return false;
  return true;
}

function appendLine(file, record) {
  ensureDir(path.dirname(file));
  fs.appendFileSync(file, JSON.stringify(record) + '\n', { encoding: 'utf8', mode: 0o600 });
}

function readJsonl(file, maxBytes) {
  try {
    const stat = fs.statSync(file, { throwIfNoEntry: false });
    if (!stat || !stat.isFile()) return [];
    if (stat.size <= maxBytes) return parseLines(fs.readFileSync(file, 'utf8'));

    const fd = fs.openSync(file, 'r');
    let text;
    let headRoute = null;
    try {
      const buf = Buffer.alloc(maxBytes);
      const n = fs.readSync(fd, buf, 0, maxBytes, stat.size - maxBytes);
      text = buf.subarray(0, n).toString('utf8');
      const nl = text.indexOf('\n');
      text = nl >= 0 ? text.slice(nl + 1) : '';
      if (stat.size <= ROUTE_SCAN_MAX_BYTES) headRoute = lastRouteIn(fd, stat.size - maxBytes + (nl >= 0 ? nl + 1 : 0));
    } finally {
      fs.closeSync(fd);
    }
    const out = parseLines(text);
    if (headRoute && !out.some((e) => e.kind === 'route')) out.unshift(headRoute);
    return out;
  } catch (err) {
    debug(`ledger read failed: ${err?.code ?? err?.name ?? 'error'}`);
    return [];
  }
}

function parseLines(text) {
  const out = [];
  for (const line of text.split('\n')) {
    const s = line.trim();
    if (!s) continue;
    try {
      const v = JSON.parse(s);
      if (v && typeof v === 'object' && !Array.isArray(v)) out.push(v);
    } catch {
      /* skip malformed line */
    }
  }
  return out;
}

/** The last `route` event in the first `end` bytes of `fd`, read in 1 MB chunks; null when none. */
function lastRouteIn(fd, end) {
  let last = null;
  let carry = '';
  const buf = Buffer.alloc(HEAD_CHUNK);
  for (let pos = 0; pos < end; ) {
    const n = fs.readSync(fd, buf, 0, Math.min(HEAD_CHUNK, end - pos), pos);
    if (n <= 0) break;
    pos += n;
    const chunk = carry + buf.subarray(0, n).toString('utf8');
    const lines = chunk.split('\n');
    carry = lines.pop() ?? '';
    for (const line of lines) {
      if (!line.includes('"kind":"route"')) continue;
      try {
        const v = JSON.parse(line);
        if (v && v.kind === 'route') last = v;
      } catch {
        /* skip */
      }
    }
  }
  return last;
}
