/**
 * Jev client: TypeSafe System One over HTTP, direct or through OpenRouter.
 *
 * `askJev` never throws on expected failures. It returns a Result object so a
 * hook can fail open with one `if (!r.ok)`. Confidence math follows the
 * formulas on https://docs.typesafe.ai/confidence exactly.
 *
 * @module jev
 */

import { pluginOption, debug } from './hookio.mjs';

/** Provider table. Both accept `{model, state, questions}` and return `{model, answers, usage}`. */
export const PROVIDERS = Object.freeze({
  typesafe: Object.freeze({
    url: 'https://api.typesafe.ai/v1/systemone',
    model: 'jev-latest',
    keyEnv: 'TYPESAFE_API_KEY',
  }),
  openrouter: Object.freeze({
    url: 'https://openrouter.ai/api/alpha/decisions',
    model: 'typesafe/jev-1.13',
    keyEnv: 'OPENROUTER_API_KEY',
  }),
});

/** Per-call budget (ms) including the one retry, when `REA_JEV_TIMEOUT_MS` is unset. */
export const DEFAULT_TIMEOUT_MS = 4000;
/** USD per 1M input tokens; output tokens are free. */
export const INPUT_PRICE_USD_PER_M = 0.042;
/** API limits. */
export const CHOICE_MAX_OPTIONS = 255;
export const SCORE_MIN_LEVELS = 2;
export const SCORE_MAX_LEVELS = 10;
export const CONTEXT_TOKENS = 32000;
/** Keep a single request under this many estimated tokens. */
export const REQUEST_TOKEN_BUDGET = 24000;
/** Default policy bands. */
export const DEFAULT_BANDS = Object.freeze({ act: 0.75, confirm: 0.45 });

const OPENROUTER_REFERER = 'https://github.com/juan-viox/rea-jev';
const OPENROUTER_TITLE = 'rea-jev';
const QUESTION_TYPES = new Set(['noul', 'choice', 'score']);

/**
 * @typedef {Object} Provider
 * @property {'typesafe'|'openrouter'} id
 * @property {string} url    endpoint to POST to (`JEV_BASE_URL` overrides)
 * @property {string} model  model id (`REA_JEV_MODEL` overrides)
 * @property {string} key    bearer token (never log it)
 */

/**
 * @typedef {Object} JevOk
 * @property {true} ok
 * @property {Record<string, JevAnswer>} answers
 * @property {{input_tokens: number, output_tokens: number, cost?: number}} usage
 * @property {string} model
 * @property {number} latencyMs
 * @property {'typesafe'|'openrouter'} provider
 * @property {number} attempts
 * @property {string[]} [dropped] question keys whose answers were malformed and removed
 */

/**
 * @typedef {Object} JevFail
 * @property {false} ok
 * @property {'no_key'|'timeout'|'http_4xx'|'http_5xx'|'bad_json'|'network'|'invalid'} reason
 * @property {number} [status]
 * @property {string} [detail]   short, secret-free explanation
 * @property {number} latencyMs
 * @property {'typesafe'|'openrouter'|null} provider
 * @property {number} attempts
 */

/** @typedef {JevOk|JevFail} JevResult */

/**
 * @typedef {{type:'noul', noul:number}
 *         | {type:'choice', choice:string, confidence?:number, probabilities:Record<string, number>}
 *         | {type:'score', score:number, confidence?:number, probabilities:Record<string, number>, legend?:Record<string, string>}} JevAnswer
 */

/**
 * Resolve the per-call budget: `REA_JEV_TIMEOUT_MS` or 4000.
 *
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {number}
 */
export function resolveTimeoutMs(env = process.env) {
  const n = Number.parseInt(env.REA_JEV_TIMEOUT_MS ?? '', 10);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_TIMEOUT_MS;
}

/**
 * Resolve provider, key, model and URL from the environment.
 *
 * Precedence: `CLAUDE_PLUGIN_OPTION_TYPESAFE_API_KEY` > `TYPESAFE_API_KEY`
 * (both → typesafe) > `OPENROUTER_API_KEY` (→ openrouter). `JEV_BASE_URL`
 * replaces the endpoint, `REA_JEV_MODEL` the model id. Returns `null` when
 * no key is present.
 *
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {Provider|null}
 */
export function resolveProvider(env = process.env) {
  let id = null;
  let key = null;
  const typesafeKey = pluginOption('TYPESAFE_API_KEY', { env });
  if (typesafeKey) {
    id = 'typesafe';
    key = typesafeKey;
  } else if (nonEmpty(env.OPENROUTER_API_KEY)) {
    id = 'openrouter';
    key = env.OPENROUTER_API_KEY.trim();
  }
  if (!id) return null;
  const base = PROVIDERS[id];
  return {
    id,
    url: nonEmpty(env.JEV_BASE_URL) ? env.JEV_BASE_URL.trim() : base.url,
    model: nonEmpty(env.REA_JEV_MODEL) ? env.REA_JEV_MODEL.trim() : base.model,
    key,
  };
}

/**
 * Ask Jev. Never throws on expected failures.
 *
 * - One retry on HTTP 429/529, inside the same `timeoutMs` budget.
 * - Headers: `Authorization: Bearer`, `Content-Type: application/json`;
 *   OpenRouter also gets `HTTP-Referer` and `X-Title`.
 * - Body (both providers): `{ model, state, questions }`.
 * - Local validation (`invalid`): no questions, unknown type, Choice with
 *   fewer than 2 or more than 255 options, Score outside 2–10 levels.
 * - Answers are validated against the questions (`sanitizeAnswers`): a Noul
 *   outside [0, 1], a Choice naming an option that was not offered, or a Score
 *   outside its levels is dropped; a response with no valid answer is `bad_json`.
 *
 * @param {{
 *   state: unknown,
 *   questions: Record<string, {type:string, instructions:unknown, criteria?:unknown}>,
 *   timeoutMs?: number,
 *   env?: NodeJS.ProcessEnv,
 *   fetchImpl?: typeof fetch,
 *   provider?: Provider,
 * }} params
 * @returns {Promise<JevResult>}
 */
export async function askJev(params) {
  const { state, questions, timeoutMs, env = process.env, fetchImpl, provider } = params ?? {};
  const started = Date.now();
  const prov = provider ?? resolveProvider(env);
  let attempts = 0;
  const fail = (reason, extra = {}) => ({
    ok: false,
    reason,
    latencyMs: Date.now() - started,
    provider: prov?.id ?? null,
    attempts,
    ...extra,
  });

  if (!prov) return fail('no_key');
  const invalid = validateQuestions(questions);
  if (invalid) return fail('invalid', { detail: invalid });

  const budget = Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : resolveTimeoutMs(env);
  const deadline = started + budget;
  const body = JSON.stringify({ model: prov.model, state, questions });
  const headers = {
    Authorization: `Bearer ${prov.key}`,
    'Content-Type': 'application/json',
    Accept: 'application/json',
  };
  if (prov.id === 'openrouter') {
    headers['HTTP-Referer'] = OPENROUTER_REFERER;
    headers['X-Title'] = OPENROUTER_TITLE;
  }
  const doFetch = fetchImpl ?? globalThis.fetch;
  if (typeof doFetch !== 'function') return fail('network', { detail: 'fetch unavailable' });

  for (;;) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) return fail('timeout');
    attempts += 1;
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), remaining);
    let status;
    let text;
    try {
      const res = await doFetch(prov.url, { method: 'POST', headers, body, signal: ac.signal });
      status = res.status;
      text = await res.text();
    } catch (err) {
      clearTimeout(timer);
      if (ac.signal.aborted || err?.name === 'AbortError' || err?.name === 'TimeoutError') return fail('timeout');
      return fail('network', { detail: errorLabel(err) });
    }
    clearTimeout(timer);

    if (status === 429 || status === 529) {
      const left = deadline - Date.now();
      const wait = Math.min(250, Math.max(0, Math.floor(left / 4)));
      if (attempts < 2 && left - wait > 50) {
        debug(`jev: ${status}, retrying in ${wait} ms`);
        await sleep(wait);
        continue;
      }
      return fail(status === 429 ? 'http_4xx' : 'http_5xx', { status, detail: shortBody(text) });
    }
    if (status >= 500) return fail('http_5xx', { status, detail: shortBody(text) });
    if (status >= 400) return fail('http_4xx', { status, detail: shortBody(text) });

    let json;
    try {
      json = JSON.parse(text);
    } catch {
      return fail('bad_json', { status, detail: 'response is not JSON' });
    }
    if (!json || typeof json !== 'object' || Array.isArray(json) || !isPlainObject(json.answers)) {
      return fail('bad_json', { status, detail: 'response has no answers object' });
    }
    const { answers, dropped } = sanitizeAnswers(json.answers, questions);
    if (dropped.length) debug(`jev: dropped malformed answers: ${dropped.join(', ')}`);
    if (Object.keys(answers).length === 0) return fail('bad_json', { status, detail: 'every answer is malformed or out of range' });
    return {
      ok: true,
      answers,
      ...(dropped.length && { dropped }),
      usage: normalizeUsage(json.usage),
      model: typeof json.model === 'string' ? json.model : prov.model,
      latencyMs: Date.now() - started,
      provider: prov.id,
      attempts,
    };
  }
}

/**
 * Validate a questions map against the documented limits.
 *
 * @param {unknown} questions
 * @returns {string|null} a short problem description, or null when valid
 */
export function validateQuestions(questions) {
  if (!isPlainObject(questions)) return 'questions must be an object';
  const keys = Object.keys(questions);
  if (keys.length === 0) return 'questions is empty';
  for (const key of keys) {
    const q = questions[key];
    if (!isPlainObject(q)) return `question ${key} is not an object`;
    if (!QUESTION_TYPES.has(q.type)) return `question ${key} has unknown type ${String(q.type)}`;
    if (q.instructions == null || q.instructions === '') return `question ${key} has no instructions`;
    if (q.type === 'choice') {
      if (!isPlainObject(q.criteria)) return `choice ${key} needs a criteria object`;
      const n = Object.keys(q.criteria).length;
      if (n < 2) return `choice ${key} needs at least 2 options`;
      if (n > CHOICE_MAX_OPTIONS) return `choice ${key} has ${n} options (max ${CHOICE_MAX_OPTIONS})`;
    }
    if (q.type === 'score') {
      if (!Array.isArray(q.criteria)) return `score ${key} needs a criteria array`;
      const n = q.criteria.length;
      if (n < SCORE_MIN_LEVELS || n > SCORE_MAX_LEVELS) return `score ${key} has ${n} levels (allowed ${SCORE_MIN_LEVELS}–${SCORE_MAX_LEVELS})`;
    }
  }
  return null;
}

/**
 * Validate answers against the questions that were asked. A hook must never
 * enforce on a malformed or out-of-range answer, so anything that fails the
 * shape check is dropped and the hook sees "no opinion" for that key:
 * - noul: `noul` is a finite number in [0, 1];
 * - choice: `choice` is one of the question's own criteria keys; `probabilities`
 *   is reduced to those keys with values in [0, 1]; a bad `confidence` is removed;
 * - score: `score` is a finite number in [0, levels − 1]; `probabilities` is
 *   reduced to the level indexes with values in [0, 1].
 * Keys that were not asked are dropped as well.
 *
 * @param {Record<string, unknown>} answers raw `answers` object from the provider
 * @param {Record<string, {type: string, criteria?: unknown}>} questions
 * @returns {{answers: Record<string, JevAnswer>, dropped: string[]}}
 */
export function sanitizeAnswers(answers, questions) {
  const out = {};
  const dropped = [];
  const qs = isPlainObject(questions) ? questions : {};
  for (const [key, q] of Object.entries(qs)) {
    const a = isPlainObject(answers) ? answers[key] : undefined;
    const clean = sanitizeAnswer(a, q);
    if (clean) out[key] = clean;
    else if (a !== undefined) dropped.push(key);
  }
  return { answers: out, dropped };
}

function sanitizeAnswer(a, q) {
  if (!isPlainObject(a) || !isPlainObject(q)) return null;
  if (q.type === 'noul') {
    if (!unit(a.noul)) return null;
    return { type: 'noul', noul: a.noul };
  }
  if (q.type === 'choice') {
    const criteria = isPlainObject(q.criteria) ? q.criteria : {};
    if (typeof a.choice !== 'string' || !Object.hasOwn(criteria, a.choice)) return null;
    const probabilities = {};
    if (isPlainObject(a.probabilities)) {
      for (const k of Object.keys(criteria)) if (unit(a.probabilities[k])) probabilities[k] = a.probabilities[k];
    }
    const clean = { type: 'choice', choice: a.choice, probabilities };
    if (unit(a.confidence)) clean.confidence = a.confidence;
    return clean;
  }
  if (q.type === 'score') {
    const levels = Array.isArray(q.criteria) ? q.criteria.length : 0;
    if (typeof a.score !== 'number' || !Number.isFinite(a.score) || a.score < 0 || a.score > Math.max(0, levels - 1)) return null;
    const probabilities = {};
    if (isPlainObject(a.probabilities)) {
      for (let i = 0; i < levels; i += 1) if (unit(a.probabilities[String(i)])) probabilities[String(i)] = a.probabilities[String(i)];
    }
    const clean = { type: 'score', score: a.score, probabilities };
    if (unit(a.confidence)) clean.confidence = a.confidence;
    if (isPlainObject(a.legend)) clean.legend = a.legend;
    return clean;
  }
  return null;
}

function unit(v) {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 1;
}

/**
 * True when an answer is confident enough to drive a hard action (deny, block):
 * its confidence is at or above the `confirm` band. Below that the hooks degrade
 * to a soft action (`ask`, `systemMessage`) or stay silent (DESIGN.md §0 principle 3).
 *
 * @param {JevAnswer|unknown} answer
 * @param {{act?: number, confirm?: number}} [bands]
 * @returns {boolean}
 */
export function isDecisive(answer, bands = {}) {
  return band(confidenceOf(answer), bands) !== 'escalate';
}

/**
 * Confidence 0..1 for any answer. Noul: |2p−1|. Choice/Score: the answer's own
 * `confidence` when present, else computed from `probabilities`.
 *
 * @param {JevAnswer|unknown} answer
 * @returns {number} 0 for missing or malformed answers
 */
export function confidenceOf(answer) {
  if (!isPlainObject(answer)) return 0;
  if (answer.type === 'noul' || (answer.type == null && typeof answer.noul === 'number')) {
    return typeof answer.noul === 'number' ? clamp01(Math.abs(2 * answer.noul - 1)) : 0;
  }
  if (typeof answer.confidence === 'number' && Number.isFinite(answer.confidence)) return clamp01(answer.confidence);
  if (answer.type === 'choice') return choiceConfidence(answer.probabilities);
  if (answer.type === 'score') return scoreConfidence(answer.probabilities);
  return 0;
}

/**
 * Choice confidence: (p_max − 1/n) / (1 − 1/n). Accepts an array of
 * probabilities or the `probabilities` map. Values are normalised to sum 1.
 *
 * @param {number[]|Record<string, number>} probabilities
 * @returns {number}
 */
export function choiceConfidence(probabilities) {
  const p = normalizedValues(probabilities);
  const n = p.length;
  if (n === 0) return 0;
  if (n === 1) return 1;
  const pmax = Math.max(...p);
  return clamp01((pmax - 1 / n) / (1 - 1 / n));
}

/**
 * Score confidence: max(0, 1 − Σ p_i·|i−m| / MAD_unif), with
 * MAD_unif = (1/n)·Σ |i − (n−1)/2| and m the most likely level. Accepts an
 * array ordered by level, or the `probabilities` map keyed "0".."n-1".
 *
 * @param {number[]|Record<string, number>} probabilitiesByLevelIndex
 * @returns {number}
 */
export function scoreConfidence(probabilitiesByLevelIndex) {
  const p = normalizedValues(probabilitiesByLevelIndex, true);
  const n = p.length;
  if (n < 2) return n === 1 ? 1 : 0;
  let m = 0;
  for (let i = 1; i < n; i += 1) if (p[i] > p[m]) m = i;
  let spread = 0;
  for (let i = 0; i < n; i += 1) spread += p[i] * Math.abs(i - m);
  let mad = 0;
  for (let i = 0; i < n; i += 1) mad += Math.abs(i - (n - 1) / 2);
  mad /= n;
  if (mad <= 0) return 1;
  return clamp01(1 - spread / mad);
}

/**
 * Policy band for a confidence value.
 *
 * @param {number} confidence
 * @param {{act?: number, confirm?: number}} [bands] defaults act=0.75, confirm=0.45
 * @returns {'act'|'confirm'|'escalate'}
 */
export function band(confidence, bands = {}) {
  const act = Number.isFinite(bands.act) ? bands.act : DEFAULT_BANDS.act;
  const confirm = Number.isFinite(bands.confirm) ? bands.confirm : DEFAULT_BANDS.confirm;
  const c = Number(confidence);
  if (!Number.isFinite(c)) return 'escalate';
  if (c >= act) return 'act';
  if (c >= confirm) return 'confirm';
  return 'escalate';
}

/**
 * Build a Noul question.
 * @param {unknown} instructions
 * @param {{true?: unknown, false?: unknown}} [criteria]
 */
export const noul = (instructions, criteria) => ({
  type: 'noul',
  instructions,
  ...(criteria && { criteria }),
});

/**
 * Build a Choice question.
 * @param {unknown} instructions
 * @param {Record<string, unknown>} criteria option → description (or null)
 */
export const choice = (instructions, criteria) => ({ type: 'choice', instructions, criteria });

/**
 * Build a Score question.
 * @param {unknown} instructions
 * @param {unknown[]} levels ordered level descriptions (2–10)
 */
export const score = (instructions, levels) => ({ type: 'score', instructions, criteria: levels });

/**
 * Estimated USD cost. Uses `usage.cost` when the provider reports one,
 * otherwise `input_tokens` × $0.042 / 1M (output is free).
 *
 * @param {{input_tokens?: number, cost?: number}|null|undefined} usage
 * @returns {number}
 */
export function estimateCost(usage) {
  if (!usage) return 0;
  if (typeof usage.cost === 'number' && Number.isFinite(usage.cost)) return usage.cost;
  const tokens = Number(usage.input_tokens) || 0;
  return (tokens / 1_000_000) * INPUT_PRICE_USD_PER_M;
}

/**
 * Rough token estimate: characters / 4 of the value (JSON-encoded unless a string).
 *
 * @param {unknown} value
 * @returns {number}
 */
export function estimateTokens(value) {
  if (value == null) return 0;
  const text = typeof value === 'string' ? value : safeJson(value);
  return Math.ceil(text.length / 4);
}

/**
 * Options of a Choice answer sorted by probability, highest first.
 *
 * @param {JevAnswer|unknown} answer
 * @param {number} [n=2]
 * @returns {Array<{option: string, p: number}>}
 */
export function topChoices(answer, n = 2) {
  if (!isPlainObject(answer) || !isPlainObject(answer.probabilities)) return [];
  return Object.entries(answer.probabilities)
    .map(([option, p]) => ({ option, p: Number(p) || 0 }))
    .sort((a, b) => b.p - a.p)
    .slice(0, Math.max(0, n));
}

function normalizeUsage(u) {
  const src = isPlainObject(u) ? u : {};
  const out = {
    input_tokens: toCount(src.input_tokens ?? src.prompt_tokens),
    output_tokens: toCount(src.output_tokens ?? src.completion_tokens),
  };
  if (typeof src.cost === 'number' && Number.isFinite(src.cost)) out.cost = src.cost;
  return out;
}

function normalizedValues(probabilities, byLevelIndex = false) {
  let values;
  if (Array.isArray(probabilities)) {
    values = probabilities.map((v) => Number(v) || 0);
  } else if (isPlainObject(probabilities)) {
    const entries = Object.entries(probabilities);
    if (byLevelIndex) entries.sort((a, b) => Number(a[0]) - Number(b[0]));
    values = entries.map(([, v]) => Number(v) || 0);
  } else {
    return [];
  }
  values = values.map((v) => (v < 0 ? 0 : v));
  const sum = values.reduce((a, b) => a + b, 0);
  if (sum > 0 && Math.abs(sum - 1) > 1e-6) return values.map((v) => v / sum);
  return values;
}

function toCount(v) {
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? Math.round(n) : 0;
}

function clamp01(x) {
  if (!Number.isFinite(x)) return 0;
  return Math.min(1, Math.max(0, x));
}

function isPlainObject(v) {
  return v != null && typeof v === 'object' && !Array.isArray(v);
}

function nonEmpty(v) {
  return v != null && String(v).trim() !== '';
}

/**
 * Wait `ms`. The timer is deliberately NOT unref'd: once the first fetch has
 * completed nothing else keeps the event loop alive, and an unref'd timer
 * would let Node exit during the retry wait (the hooks' own safety timers,
 * which are unref'd, remain the backstop; the enclosing deadline bounds `ms`).
 */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function errorLabel(err) {
  const name = err?.name ?? 'Error';
  const code = err?.code ?? err?.cause?.code;
  return code ? `${name} ${code}` : name;
}

function shortBody(text) {
  if (typeof text !== 'string' || !text) return undefined;
  return text.replace(/\s+/g, ' ').slice(0, 160);
}

function safeJson(value) {
  try {
    return JSON.stringify(value) ?? '';
  } catch {
    return String(value);
  }
}
