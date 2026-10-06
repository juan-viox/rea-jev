/**
 * Local fake Jev server for tests and for trying the plugin without a key.
 *
 * Speaks the TypeSafe / OpenRouter request shape `{model, state, questions}`
 * and answers `{model, answers, usage}`. For every question it returns a
 * deterministic canned answer by type unless the `script` overrides that
 * question key (value or function). Failure scenarios are selected per
 * request via the `x-fake-jev` header, `state.__fake__`, or a question keyed
 * `__fake__` whose `instructions` names the scenario:
 *
 *   429-then-200 | 529-then-200   first request fails with that status, later ones succeed
 *   429 | 500 | 401 | 422 | 529   always that status
 *   slow[:ms]                     delay before a normal 200 (default 10000 ms)
 *   malformed-json                200 with a truncated JSON body
 *   not-object                    200 with `[]`
 *   drop                          destroy the socket (network error)
 *
 * Usage in tests:
 *   const fake = await startFakeJev({ script: { is_re_task: 0.9, target_kind: 'native_binary' } });
 *   process.env.JEV_BASE_URL = fake.url; ... await fake.close();
 *
 * Standalone:  node tests/fake-jev.mjs --port 4321 [--script answers.json]
 *
 * @module fake-jev
 */

import http from 'node:http';
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
import { choiceConfidence, scoreConfidence } from '../scripts/lib/jev.mjs';

/** Header that selects a failure scenario for one request. */
export const FAKE_HEADER = 'x-fake-jev';
/** Model string the fake reports. */
export const FAKE_MODEL = 'jev-1.13.0-fake';

const MAX_BODY = 16 * 1024 * 1024;

/**
 * @typedef {Object} FakeJev
 * @property {string} url           base URL (POST to it, any path)
 * @property {number} port
 * @property {Array<{method: string, url: string, headers: Record<string, string|string[]|undefined>, body: any, at: number}>} requests
 * @property {Record<string, unknown>} script  live-editable per-question overrides
 * @property {number} inflight      requests currently being handled
 * @property {number} maxInflight   highest `inflight` seen
 * @property {() => Promise<void>} close
 * @property {import('node:http').Server} server
 */

/**
 * Start the fake on an ephemeral port (or `port`).
 *
 * `script[key]` may be: a number (noul probability; choice option index;
 * score level), a string (choice option), a partial answer object
 * (`{noul}`, `{choice}`, `{probabilities}`), `{raw: <answer>}` to return an
 * answer verbatim (for malformed-answer tests), or a function
 * `(question, state, body, key) => any of the above`. A scripted Choice option
 * that is not one of the question's criteria is a test bug: the fake answers
 * 500 instead of silently picking the first option.
 *
 * `fake.inflight` / `fake.maxInflight` track concurrent requests.
 *
 * @param {{script?: Record<string, unknown>, port?: number, host?: string, scenario?: string|null, latencyMs?: number, model?: string}} [opts]
 * @returns {Promise<FakeJev>}
 */
export async function startFakeJev(opts = {}) {
  const { script = {}, port = 0, host = '127.0.0.1', scenario = null, latencyMs = 0, model = FAKE_MODEL } = opts;
  const requests = [];
  const counters = new Map();
  const fakeRef = { inflight: 0, maxInflight: 0 };
  const server = http.createServer((req, res) => {
    fakeRef.inflight += 1;
    fakeRef.maxInflight = Math.max(fakeRef.maxInflight, fakeRef.inflight);
    res.on('close', () => {
      fakeRef.inflight -= 1;
    });
    handle(req, res, { script, requests, counters, scenario, latencyMs, model }).catch((err) => {
      try {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: { message: `fake-jev crashed: ${err?.message ?? err}` } }));
      } catch {
        /* ignore */
      }
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => resolve());
  });
  const addr = server.address();
  const url = `http://${host}:${addr.port}`;
  return {
    url,
    port: addr.port,
    requests,
    script,
    server,
    get inflight() {
      return fakeRef.inflight;
    },
    get maxInflight() {
      return fakeRef.maxInflight;
    },
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}

async function handle(req, res, ctx) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) {
      res.writeHead(413).end();
      return;
    }
    chunks.push(chunk);
  }
  const bodyText = Buffer.concat(chunks).toString('utf8');
  let body = null;
  try {
    body = bodyText ? JSON.parse(bodyText) : null;
  } catch {
    body = null;
  }
  ctx.requests.push({ method: req.method, url: req.url, headers: req.headers, body, at: Date.now() });

  if (req.method !== 'POST') return send(res, 405, { error: { message: 'POST only' } });
  if (!body || typeof body !== 'object') return send(res, 422, { error: { message: 'body is not JSON' } });

  const scenario = pickScenario(req, body, ctx.scenario);
  if (scenario) {
    const handled = await applyScenario(scenario, req, res, ctx);
    if (handled) return undefined;
  }
  if (ctx.latencyMs > 0) await sleep(ctx.latencyMs);
  return send(res, 200, buildResponse(body, ctx.script, ctx.model, bodyText.length));
}

function pickScenario(req, body, fallback) {
  const fromHeader = req.headers[FAKE_HEADER];
  if (typeof fromHeader === 'string' && fromHeader.trim()) return fromHeader.trim();
  const state = body.state;
  if (state && typeof state === 'object' && !Array.isArray(state) && typeof state.__fake__ === 'string') return state.__fake__;
  const q = body.questions && body.questions.__fake__;
  if (q && typeof q.instructions === 'string') return q.instructions;
  return fallback || null;
}

async function applyScenario(scenario, req, res, ctx) {
  const thenOk = /^(\d{3})-then-200$/.exec(scenario);
  if (thenOk) {
    const n = (ctx.counters.get(scenario) ?? 0) + 1;
    ctx.counters.set(scenario, n);
    if (n <= 1) {
      send(res, Number(thenOk[1]), { error: { message: `fake ${thenOk[1]} (attempt ${n})` } });
      return true;
    }
    return false;
  }
  if (/^\d{3}$/.test(scenario)) {
    send(res, Number(scenario), { error: { message: `fake ${scenario}` } });
    return true;
  }
  const slow = /^slow(?::(\d+))?$/.exec(scenario);
  if (slow) {
    await sleep(slow[1] ? Number(slow[1]) : 10_000);
    return false;
  }
  if (scenario === 'malformed-json') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{"model":"fake","answers":{"x":');
    return true;
  }
  if (scenario === 'not-object') {
    send(res, 200, []);
    return true;
  }
  if (scenario === 'drop') {
    req.socket.destroy();
    return true;
  }
  return false;
}

/**
 * Build a full response for a request body using the script.
 *
 * @param {{model?: string, state?: unknown, questions?: Record<string, any>}} body
 * @param {Record<string, unknown>} script
 * @param {string} [model]
 * @param {number} [bodyChars]
 * @returns {{model: string, answers: Record<string, any>, usage: {input_tokens: number, output_tokens: number}}}
 */
export function buildResponse(body, script = {}, model = FAKE_MODEL, bodyChars = 0) {
  const questions = body?.questions && typeof body.questions === 'object' ? body.questions : {};
  const answers = {};
  let count = 0;
  for (const [key, q] of Object.entries(questions)) {
    if (key === '__fake__') continue;
    count += 1;
    let spec = script[key];
    if (typeof spec === 'function') spec = spec(q, body.state, body, key);
    answers[key] = buildAnswer(q, spec);
  }
  return {
    model,
    answers,
    usage: { input_tokens: Math.ceil((bodyChars || JSON.stringify(body ?? {}).length) / 4), output_tokens: 20 * count },
  };
}

/**
 * Build one answer for a question from a script value (see `startFakeJev`).
 *
 * @param {{type?: string, criteria?: any}} q
 * @param {unknown} spec
 * @returns {Record<string, any>}
 */
export function buildAnswer(q, spec) {
  const type = q?.type;
  if (spec && typeof spec === 'object' && 'raw' in spec) return spec.raw;
  if (type === 'noul') return { type: 'noul', noul: noulValue(spec) };
  if (type === 'choice') return choiceAnswer(Object.keys(q.criteria ?? {}), spec);
  if (type === 'score') return scoreAnswer(Array.isArray(q.criteria) ? q.criteria : [], spec);
  return { type: 'noul', noul: 0.5 };
}

function noulValue(spec) {
  if (typeof spec === 'number') return clamp01(spec);
  if (spec && typeof spec === 'object' && typeof spec.noul === 'number') return clamp01(spec.noul);
  return 0.5;
}

function choiceAnswer(options, spec) {
  if (options.length === 0) return { type: 'choice', choice: '', probabilities: {}, confidence: 0 };
  let probs;
  if (spec && typeof spec === 'object' && spec.probabilities && typeof spec.probabilities === 'object') {
    probs = {};
    for (const o of options) probs[o] = Number(spec.probabilities[o]) || 0;
    normalize(probs);
  } else {
    let pick;
    const named = typeof spec === 'string' ? spec : spec && typeof spec === 'object' && typeof spec.choice === 'string' ? spec.choice : null;
    if (named !== null && !options.includes(named)) throw new Error(`scripted option "${named}" is not one of the question's criteria (${options.join(', ')})`);
    if (named !== null) pick = named;
    else if (typeof spec === 'number') pick = options[Math.min(options.length - 1, Math.max(0, Math.round(spec)))];
    const top = pick ? 0.9 : 0.7;
    pick = pick ?? options[0];
    probs = spread(options, pick, options.length === 1 ? 1 : top);
  }
  const choice = Object.entries(probs).sort((a, b) => b[1] - a[1])[0][0];
  return { type: 'choice', choice, probabilities: probs, confidence: round(choiceConfidence(Object.values(probs))) };
}

function scoreAnswer(levels, spec) {
  const n = levels.length;
  if (n === 0) return { type: 'score', score: 0, probabilities: {}, legend: {}, confidence: 0 };
  let p = new Array(n).fill(0);
  if (spec && typeof spec === 'object' && spec.probabilities) {
    const src = spec.probabilities;
    for (let i = 0; i < n; i += 1) p[i] = Number(Array.isArray(src) ? src[i] : src[String(i)]) || 0;
    const sum = p.reduce((a, b) => a + b, 0);
    p = sum > 0 ? p.map((v) => v / sum) : peaked(n, Math.floor((n - 1) / 2), 0.8);
  } else if (typeof spec === 'number') {
    p = peaked(n, Math.min(n - 1, Math.max(0, Math.round(spec))), 0.9);
  } else if (spec && typeof spec === 'object' && typeof spec.score === 'number') {
    p = peaked(n, Math.min(n - 1, Math.max(0, Math.round(spec.score))), 0.9);
  } else {
    p = peaked(n, Math.floor((n - 1) / 2), 0.8);
  }
  const probabilities = {};
  const legend = {};
  let score = 0;
  for (let i = 0; i < n; i += 1) {
    probabilities[String(i)] = round(p[i]);
    legend[String(i)] = typeof levels[i] === 'string' ? levels[i] : JSON.stringify(levels[i]);
    score += i * p[i];
  }
  return { type: 'score', score: round(score), probabilities, legend, confidence: round(scoreConfidence(p)) };
}

function peaked(n, m, top) {
  const p = new Array(n).fill(0);
  if (n === 1) {
    p[0] = 1;
    return p;
  }
  p[m] = top;
  const neighbors = [m - 1, m + 1].filter((i) => i >= 0 && i < n);
  for (const i of neighbors) p[i] = (1 - top) / neighbors.length;
  return p;
}

function spread(options, pick, top) {
  const probs = {};
  const rest = options.length - 1;
  for (const o of options) probs[o] = o === pick ? top : rest > 0 ? (1 - top) / rest : 0;
  return probs;
}

function normalize(probs) {
  const sum = Object.values(probs).reduce((a, b) => a + b, 0);
  const keys = Object.keys(probs);
  for (const k of keys) probs[k] = sum > 0 ? round(probs[k] / sum) : round(1 / keys.length);
}

function send(res, status, payload) {
  const text = JSON.stringify(payload);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(text) });
  res.end(text);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function clamp01(x) {
  return Math.min(1, Math.max(0, Number(x) || 0));
}

function round(x) {
  return Math.round(x * 1e6) / 1e6;
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const args = process.argv.slice(2);
  const port = Number(args[args.indexOf('--port') + 1]) || 4321;
  const scriptIdx = args.indexOf('--script');
  let script = {};
  if (scriptIdx >= 0 && args[scriptIdx + 1]) {
    try {
      script = JSON.parse(fs.readFileSync(args[scriptIdx + 1], 'utf8'));
    } catch (err) {
      process.stderr.write(`fake-jev: cannot read script: ${err?.message ?? err}\n`);
      process.exit(1);
    }
  }
  startFakeJev({ port, script })
    .then((fake) => {
      process.stdout.write(`fake-jev listening on ${fake.url}  (JEV_BASE_URL=${fake.url} TYPESAFE_API_KEY=fake)\n`);
    })
    .catch((err) => {
      process.stderr.write(`fake-jev: ${err?.message ?? err}\n`);
      process.exit(1);
    });
}
