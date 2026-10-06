/**
 * Shared helpers for the hook tests: spawn a hook script with a stdin payload
 * against the fake Jev server, with a clean environment and a temp ledger dir.
 *
 * Not a test file itself (the runner only picks up `tests/*.test.mjs`).
 *
 * @module hook-harness
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { appendEvent, readEvents } from '../scripts/lib/ledger.mjs';

/** Repository root. */
export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
/** tests/fixtures. */
export const FIXTURES = path.join(ROOT, 'tests', 'fixtures');
/** The existing .app fixture directory (Contents/MacOS present). */
export const SAMPLE_APP = path.join(FIXTURES, 'Sample.app');

let counter = 0;

/**
 * Environment with every real key / override stripped, pointed at `fakeUrl`
 * and a temp ledger dir. `extra` wins.
 *
 * @param {{fakeUrl?: string, home: string, mode?: string, key?: boolean, extra?: Record<string, string>}} opts
 * @returns {Record<string, string>}
 */
export function hookEnv({ fakeUrl, home, mode = 'advise', key = true, extra = {} }) {
  const env = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (/^(TYPESAFE_API_KEY|OPENROUTER_API_KEY|JEV_BASE_URL|REA_JEV_|CLAUDE_PLUGIN_)/.test(k)) continue;
    env[k] = v;
  }
  env.REA_JEV_HOME = home;
  env.REA_JEV_LOG = '0';
  env.REA_JEV_TIMEOUT_MS = '5000';
  env.REA_JEV_MODE = mode;
  if (fakeUrl) env.JEV_BASE_URL = fakeUrl;
  if (key) env.TYPESAFE_API_KEY = 'test-key-not-real';
  return { ...env, ...extra };
}

/**
 * Load a stdin fixture and override fields.
 *
 * @param {string} name file under tests/fixtures/stdin
 * @param {Record<string, unknown>} [overrides]
 * @returns {Record<string, unknown>}
 */
export function payload(name, overrides = {}) {
  const base = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'stdin', name), 'utf8'));
  return { ...base, ...overrides };
}

/**
 * A fresh session id per test so ledgers never collide.
 *
 * @param {string} [prefix]
 * @returns {string}
 */
export function newSession(prefix = 'test') {
  counter += 1;
  return `${prefix}-${process.pid}-${Date.now()}-${counter}`;
}

/**
 * Spawn `scripts/<hook>.mjs`, pipe `input` (object → JSON, string as-is) on
 * stdin, and collect the result. `json` is the parsed stdout or null.
 *
 * @param {string} hook e.g. 'hook-gate'
 * @param {unknown} input
 * @param {Record<string, string>} env
 * @returns {Promise<{code: number|null, stdout: string, stderr: string, json: any, ms: number}>}
 */
export function runHook(hook, input, env) {
  const script = path.join(ROOT, 'scripts', `${hook}.mjs`);
  const started = Date.now();
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [script], { env, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('close', (code) => {
      let json = null;
      if (stdout.trim()) {
        try {
          json = JSON.parse(stdout);
        } catch {
          json = { __unparseable__: stdout };
        }
      }
      resolve({ code, stdout, stderr, json, ms: Date.now() - started });
    });
    child.stdin.on('error', () => {});
    child.stdin.end(typeof input === 'string' ? input : JSON.stringify(input));
  });
}

/**
 * Seed ledger events for a session in the given home dir.
 *
 * @param {string} home REA_JEV_HOME
 * @param {string} sessionId
 * @param {Array<Record<string, unknown>>} events
 */
export function seedLedger(home, sessionId, events) {
  const env = { ...process.env, REA_JEV_HOME: home };
  delete env.CLAUDE_PLUGIN_DATA;
  for (const e of events) {
    if (!appendEvent(sessionId, e, env)) throw new Error(`could not seed ledger event ${JSON.stringify(e).slice(0, 80)}`);
  }
}

/**
 * Read a session's ledger events from the given home dir.
 *
 * @param {string} home
 * @param {string} sessionId
 */
export function ledgerEvents(home, sessionId) {
  const env = { ...process.env, REA_JEV_HOME: home };
  delete env.CLAUDE_PLUGIN_DATA;
  return readEvents(sessionId, env);
}

/**
 * Create a temp dir for a test file's ledger.
 *
 * @param {string} label
 * @returns {string}
 */
export function makeTmp(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `rea-jev-${label}-`));
}
