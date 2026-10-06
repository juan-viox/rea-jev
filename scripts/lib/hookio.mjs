/**
 * Hook I/O helpers shared by every hook script and the CLI.
 *
 * The contract every hook follows: read JSON from stdin, decide, write at most
 * one JSON object to stdout, exit 0. Anything unexpected means "do nothing"
 * (fail open). These helpers make that the path of least resistance.
 *
 * @module hookio
 */

import { homedir } from 'node:os';
import path from 'node:path';

/** The four System 1 modes, least to most assertive. */
export const MODES = Object.freeze(['off', 'shadow', 'advise', 'enforce']);

/** Mode used when nothing valid is configured. */
export const DEFAULT_MODE = 'advise';

/**
 * Read all of stdin and parse it as a JSON object.
 *
 * Resolves `null` (never rejects) when stdin is a TTY, empty, too large,
 * not valid JSON, not a plain object, or does not close within `timeoutMs`.
 * Callers treat `null` as "exit 0, emit nothing".
 *
 * @param {{maxBytes?: number, timeoutMs?: number, stream?: NodeJS.ReadableStream}} [opts]
 * @returns {Promise<Record<string, unknown>|null>}
 */
export function readStdinJson(opts = {}) {
  const { maxBytes = 8 * 1024 * 1024, timeoutMs = 3000, stream = process.stdin } = opts;
  return new Promise((resolve) => {
    if (!stream || stream.isTTY) return resolve(null);
    const chunks = [];
    let size = 0;
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try {
        stream.removeAllListeners('data');
        stream.pause();
      } catch {
        /* ignore */
      }
      resolve(value);
    };
    const timer = setTimeout(() => finish(null), timeoutMs);
    timer.unref?.();
    stream.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxBytes) return finish(null);
      chunks.push(chunk);
    });
    stream.on('end', () => {
      const text = Buffer.concat(chunks.map((c) => (Buffer.isBuffer(c) ? c : Buffer.from(String(c))))).toString('utf8').trim();
      if (!text) return finish(null);
      try {
        const parsed = JSON.parse(text);
        finish(parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null);
      } catch {
        finish(null);
      }
    });
    stream.on('error', () => finish(null));
    try {
      stream.resume();
    } catch {
      finish(null);
    }
  });
}

/**
 * Write one JSON object to stdout followed by a newline. No-op for null.
 *
 * @param {unknown} obj
 */
export function emit(obj) {
  if (obj == null) return;
  process.stdout.write(JSON.stringify(obj) + '\n');
}

/**
 * Exit after stdout has flushed (pipes are asynchronous on some platforms,
 * so a bare `process.exit` right after a write can lose the output).
 * Default exit code 0 = "hook ran, nothing to say".
 *
 * @param {number} [code=0]
 */
export function exitSilently(code = 0) {
  process.exitCode = code;
  process.stdout.write('', () => process.exit(code));
}

/**
 * Emit one object, then exit with `code` once it has flushed.
 *
 * @param {unknown} obj
 * @param {number} [code=0]
 */
export function emitAndExit(obj, code = 0) {
  process.exitCode = code;
  const text = obj == null ? '' : JSON.stringify(obj) + '\n';
  process.stdout.write(text, () => process.exit(code));
}

/**
 * Run `fn(signal)` with a hard time budget. Resolves to `fn`'s value, or to
 * `fallback` when `fn` throws or `ms` elapses first (the signal is aborted
 * then). Never rejects. The timer is unref'd so it cannot keep a hook alive.
 *
 * @template T
 * @param {number} ms
 * @param {(signal: AbortSignal) => Promise<T>|T} fn
 * @param {{fallback?: T}} [opts]
 * @returns {Promise<T|undefined>}
 */
export async function withBudget(ms, fn, opts = {}) {
  const { fallback } = opts;
  const ac = new AbortController();
  let timer;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => {
      ac.abort();
      resolve({ timedOut: true });
    }, Math.max(1, Number(ms) || 1));
    timer.unref?.();
  });
  try {
    const result = await Promise.race([
      Promise.resolve()
        .then(() => fn(ac.signal))
        .then((value) => ({ value })),
      timeout,
    ]);
    if (result && result.timedOut) {
      debug(`budget of ${ms} ms exceeded`);
      return fallback;
    }
    return result.value;
  } catch (err) {
    debug(`withBudget: ${err?.name ?? 'Error'}${err?.code ? ` ${err.code}` : ''}`);
    return fallback;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Read a plugin option. Claude Code hands `userConfig` values to hooks as
 * `CLAUDE_PLUGIN_OPTION_<NAME>`; that wins over the plain variable
 * (`plain`, default `<NAME>`). Empty strings count as unset.
 *
 * @param {string} name e.g. 'TYPESAFE_API_KEY' or 'MODE'
 * @param {{env?: NodeJS.ProcessEnv, plain?: string}} [opts]
 * @returns {string|undefined}
 */
export function pluginOption(name, opts = {}) {
  const { env = process.env, plain = name } = opts;
  const key = 'CLAUDE_PLUGIN_OPTION_' + String(name).toUpperCase().replace(/[^A-Z0-9]/g, '_');
  const fromPlugin = env[key];
  if (fromPlugin != null && String(fromPlugin).trim() !== '') return String(fromPlugin);
  const fromPlain = env[plain];
  if (fromPlain != null && String(fromPlain).trim() !== '') return String(fromPlain);
  return undefined;
}

/**
 * Resolve the System 1 mode: `CLAUDE_PLUGIN_OPTION_MODE`, then `REA_JEV_MODE`,
 * else 'advise'. Unknown values fall back to 'advise'.
 *
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {'off'|'shadow'|'advise'|'enforce'}
 */
export function mode(env = process.env) {
  const raw = pluginOption('MODE', { env, plain: 'REA_JEV_MODE' });
  const m = String(raw ?? '').trim().toLowerCase();
  return MODES.includes(m) ? /** @type {any} */ (m) : DEFAULT_MODE;
}

/**
 * True when `REA_JEV_DEBUG=1`.
 *
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {boolean}
 */
export function isDebug(env = process.env) {
  return env.REA_JEV_DEBUG === '1';
}

/**
 * Print a debug line to stderr when `REA_JEV_DEBUG=1`. Never throws.
 * Callers are responsible for not passing secrets.
 *
 * @param {...unknown} parts
 */
export function debug(...parts) {
  if (!isDebug()) return;
  try {
    process.stderr.write('[rea-jev] ' + parts.map(stringify).join(' ') + '\n');
  } catch {
    /* ignore */
  }
}

/**
 * Resolve the data directory: `REA_JEV_HOME`, else `CLAUDE_PLUGIN_DATA`,
 * else `~/.rea-jev`. A leading `~` is expanded.
 *
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {string}
 */
export function resolveHome(env = process.env) {
  const candidate = firstNonEmpty(env.REA_JEV_HOME, env.CLAUDE_PLUGIN_DATA);
  if (!candidate) return path.join(homedir(), '.rea-jev');
  return expandTilde(candidate);
}

/**
 * Read a tunable threshold `REA_JEV_T_<NAME>` as a finite number, else `fallback`.
 *
 * @param {string} name e.g. 'ROUTE_MIN'
 * @param {number} fallback
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {number}
 */
export function threshold(name, fallback, env = process.env) {
  const key = 'REA_JEV_T_' + String(name).toUpperCase().replace(/[^A-Z0-9]/g, '_');
  const n = Number.parseFloat(env[key] ?? '');
  return Number.isFinite(n) ? n : fallback;
}

/**
 * Expand a leading `~` or `~/` to the home directory.
 *
 * @param {string} p
 * @returns {string}
 */
export function expandTilde(p) {
  const s = String(p ?? '');
  if (s === '~') return homedir();
  if (s.startsWith('~/')) return path.join(homedir(), s.slice(2));
  return s;
}

function firstNonEmpty(...values) {
  for (const v of values) if (v != null && String(v).trim() !== '') return String(v).trim();
  return undefined;
}

function stringify(v) {
  if (typeof v === 'string') return v;
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}
