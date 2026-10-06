import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  PROVIDERS,
  resolveProvider,
  resolveTimeoutMs,
  askJev,
  confidenceOf,
  choiceConfidence,
  scoreConfidence,
  band,
  noul,
  choice,
  score,
  estimateCost,
  estimateTokens,
  topChoices,
  validateQuestions,
  sanitizeAnswers,
  isDecisive,
} from '../scripts/lib/jev.mjs';
import { startFakeJev, FAKE_HEADER } from './fake-jev.mjs';

const servers = [];
async function fake(opts) {
  const s = await startFakeJev(opts);
  servers.push(s);
  return s;
}
after(async () => {
  await Promise.all(servers.map((s) => s.close()));
});

const envFor = (s, extra = {}) => ({ TYPESAFE_API_KEY: 'test-key-not-real', JEV_BASE_URL: s.url, ...extra });

describe('resolveProvider', () => {
  test('returns null without any key', () => {
    assert.equal(resolveProvider({}), null);
    assert.equal(resolveProvider({ TYPESAFE_API_KEY: '   ' }), null);
  });
  test('TypeSafe wins over OpenRouter when both are set', () => {
    const p = resolveProvider({ TYPESAFE_API_KEY: 't', OPENROUTER_API_KEY: 'o' });
    assert.equal(p.id, 'typesafe');
    assert.equal(p.url, PROVIDERS.typesafe.url);
    assert.equal(p.model, 'jev-latest');
    assert.equal(p.key, 't');
  });
  test('OpenRouter is used when only its key is present', () => {
    const p = resolveProvider({ OPENROUTER_API_KEY: 'o' });
    assert.equal(p.id, 'openrouter');
    assert.equal(p.url, PROVIDERS.openrouter.url);
    assert.equal(p.model, 'typesafe/jev-1.13');
  });
  test('plugin option key wins over the plain variable', () => {
    const p = resolveProvider({ CLAUDE_PLUGIN_OPTION_TYPESAFE_API_KEY: 'plugin', TYPESAFE_API_KEY: 'plain', OPENROUTER_API_KEY: 'o' });
    assert.equal(p.id, 'typesafe');
    assert.equal(p.key, 'plugin');
  });
  test('JEV_BASE_URL and REA_JEV_MODEL override endpoint and model', () => {
    const p = resolveProvider({ OPENROUTER_API_KEY: 'o', JEV_BASE_URL: 'http://127.0.0.1:1/x', REA_JEV_MODEL: 'jev-1.13.0' });
    assert.equal(p.url, 'http://127.0.0.1:1/x');
    assert.equal(p.model, 'jev-1.13.0');
    assert.equal(p.id, 'openrouter');
  });
  test('resolveTimeoutMs defaults to 4000 and honours REA_JEV_TIMEOUT_MS', () => {
    assert.equal(resolveTimeoutMs({}), 4000);
    assert.equal(resolveTimeoutMs({ REA_JEV_TIMEOUT_MS: '2500' }), 2500);
    assert.equal(resolveTimeoutMs({ REA_JEV_TIMEOUT_MS: 'nope' }), 4000);
  });
});

describe('askJev', () => {
  test('no key → ok:false reason no_key, no request made', async () => {
    const s = await fake();
    const r = await askJev({ state: 'x', questions: { q: noul('Is it?') }, env: { JEV_BASE_URL: s.url } });
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'no_key');
    assert.equal(s.requests.length, 0);
  });

  test('happy path returns answers, usage, model, provider, latency', async () => {
    const s = await fake({ script: { is_re: 0.9, kind: 'native_binary', scope: 2 } });
    const r = await askJev({
      state: { prompt: 'decompile Notes.app' },
      questions: {
        is_re: noul('Is this an RE task?'),
        kind: choice('Which kind?', { native_binary: 'a', javascript_application: 'b', other: null }),
        scope: score('How broad?', ['one function', 'one feature', 'several features', 'whole app']),
      },
      env: envFor(s),
    });
    assert.equal(r.ok, true);
    assert.equal(r.provider, 'typesafe');
    assert.equal(r.attempts, 1);
    assert.equal(r.model, 'jev-1.13.0-fake');
    assert.ok(r.latencyMs >= 0);
    assert.equal(r.answers.is_re.noul, 0.9);
    assert.equal(r.answers.kind.choice, 'native_binary');
    assert.ok(r.answers.kind.confidence > 0.8);
    assert.equal(Math.round(r.answers.scope.score), 2);
    assert.equal(Object.keys(r.answers.scope.legend).length, 4);
    assert.ok(r.usage.input_tokens > 0);
    // request shape
    const req = s.requests[0];
    assert.equal(req.method, 'POST');
    assert.equal(req.headers.authorization, 'Bearer test-key-not-real');
    assert.equal(req.headers['content-type'], 'application/json');
    assert.deepEqual(Object.keys(req.body).sort(), ['model', 'questions', 'state']);
    assert.equal(req.body.model, 'jev-latest');
    assert.equal(req.headers['http-referer'], undefined);
  });

  test('OpenRouter adds HTTP-Referer and X-Title and uses its model', async () => {
    const s = await fake();
    const r = await askJev({ state: 'x', questions: { q: noul('Is it?') }, env: { OPENROUTER_API_KEY: 'or-key', JEV_BASE_URL: s.url } });
    assert.equal(r.ok, true);
    assert.equal(r.provider, 'openrouter');
    const req = s.requests[0];
    assert.equal(req.headers['http-referer'], 'https://github.com/juan-viox/rea-jev');
    assert.equal(req.headers['x-title'], 'rea-jev');
    assert.equal(req.body.model, 'typesafe/jev-1.13');
  });

  test('timeout → reason timeout within the budget', async () => {
    const s = await fake();
    const t0 = Date.now();
    const r = await askJev({ state: { __fake__: 'slow:3000' }, questions: { q: noul('Is it?') }, timeoutMs: 250, env: envFor(s) });
    const elapsed = Date.now() - t0;
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'timeout');
    assert.ok(elapsed < 2500, `took ${elapsed} ms`);
    assert.ok(r.latencyMs >= 200);
  });

  test('429 then 200 → ok with exactly one retry', async () => {
    const s = await fake();
    const r = await askJev({ state: { __fake__: '429-then-200' }, questions: { q: noul('Is it?') }, timeoutMs: 3000, env: envFor(s) });
    assert.equal(r.ok, true);
    assert.equal(r.attempts, 2);
    assert.equal(s.requests.length, 2);
  });

  test('529 then 200 → ok with one retry', async () => {
    const s = await fake();
    const r = await askJev({ state: { __fake__: '529-then-200' }, questions: { q: noul('Is it?') }, timeoutMs: 3000, env: envFor(s) });
    assert.equal(r.ok, true);
    assert.equal(r.attempts, 2);
  });

  test('persistent 429 → http_4xx with status after two attempts', async () => {
    const s = await fake();
    const r = await askJev({ state: { __fake__: '429' }, questions: { q: noul('Is it?') }, timeoutMs: 3000, env: envFor(s) });
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'http_4xx');
    assert.equal(r.status, 429);
    assert.equal(r.attempts, 2);
  });

  test('500 → http_5xx, no retry; 401 → http_4xx', async () => {
    const s = await fake();
    const r5 = await askJev({ state: { __fake__: '500' }, questions: { q: noul('Is it?') }, env: envFor(s) });
    assert.equal(r5.reason, 'http_5xx');
    assert.equal(r5.status, 500);
    assert.equal(r5.attempts, 1);
    const r4 = await askJev({ state: { __fake__: '401' }, questions: { q: noul('Is it?') }, env: envFor(s) });
    assert.equal(r4.reason, 'http_4xx');
    assert.equal(r4.status, 401);
  });

  test('malformed JSON → bad_json; non-object body → bad_json', async () => {
    const s = await fake();
    const r = await askJev({ state: { __fake__: 'malformed-json' }, questions: { q: noul('Is it?') }, env: envFor(s) });
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'bad_json');
    const r2 = await askJev({ state: { __fake__: 'not-object' }, questions: { q: noul('Is it?') }, env: envFor(s) });
    assert.equal(r2.reason, 'bad_json');
  });

  test('scenario via header works too (custom fetch injecting it)', async () => {
    const s = await fake();
    const fetchImpl = (url, init) => fetch(url, { ...init, headers: { ...init.headers, [FAKE_HEADER]: '500' } });
    const r = await askJev({ state: 'x', questions: { q: noul('Is it?') }, env: envFor(s), fetchImpl });
    assert.equal(r.reason, 'http_5xx');
  });

  test('connection refused → network', async () => {
    const s = await startFakeJev();
    const url = s.url;
    await s.close();
    const r = await askJev({ state: 'x', questions: { q: noul('Is it?') }, timeoutMs: 2000, env: { TYPESAFE_API_KEY: 'k', JEV_BASE_URL: url } });
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'network');
  });

  test('answers are validated against the questions: out-of-range or foreign values are dropped, all-invalid → bad_json', async () => {
    const s = await fake({
      script: {
        ok: 0.3,
        bad: { raw: { type: 'noul', noul: 7 } },
        proto: { raw: { type: 'choice', choice: '__proto__', probabilities: { a: 0.5, b: 0.5 } } },
        far: { raw: { type: 'score', score: 9, probabilities: { 0: 0.5, 1: 0.5 } } },
        dirty: { raw: { type: 'choice', choice: 'a', confidence: 4, probabilities: { a: 0.9, b: 2, zzz: 0.1 } } },
      },
    });
    const questions = {
      ok: noul('Is it?'),
      bad: noul('Is it?'),
      proto: choice('Which?', { a: null, b: null }),
      far: score('How?', ['lo', 'hi']),
      dirty: choice('Which?', { a: null, b: null }),
    };
    const r = await askJev({ state: 'x', questions, env: envFor(s) });
    assert.equal(r.ok, true);
    assert.deepEqual(Object.keys(r.answers).sort(), ['dirty', 'ok']);
    assert.deepEqual(r.dropped.sort(), ['bad', 'far', 'proto']);
    assert.deepEqual(r.answers.dirty, { type: 'choice', choice: 'a', probabilities: { a: 0.9 } }, 'bad probabilities and confidence are removed');
    const all = await askJev({ state: 'x', questions: { bad: noul('Is it?') }, env: envFor(s) });
    assert.equal(all.ok, false);
    assert.equal(all.reason, 'bad_json');
  });
  test('sanitizeAnswers (in-process) and isDecisive', () => {
    const { answers, dropped } = sanitizeAnswers({ a: { type: 'noul', noul: -0.1 }, b: { type: 'noul', noul: 1 }, extra: { type: 'noul', noul: 0.5 } }, { a: noul('?'), b: noul('?') });
    assert.deepEqual(answers, { b: { type: 'noul', noul: 1 } });
    assert.deepEqual(dropped, ['a']);
    assert.equal(isDecisive({ type: 'noul', noul: 0.29 }), false, 'confidence 0.42 is the escalate band');
    assert.equal(isDecisive({ type: 'noul', noul: 0.2 }), true);
    assert.equal(isDecisive({ type: 'noul', noul: 0.73 }), true);
    assert.equal(isDecisive(null), false);
  });
  test('local validation → invalid without a request', async () => {
    const s = await fake();
    const tooMany = Object.fromEntries(Array.from({ length: 256 }, (_, i) => [`o${i}`, null]));
    const r = await askJev({ state: 'x', questions: { c: choice('Which?', tooMany) }, env: envFor(s) });
    assert.equal(r.reason, 'invalid');
    assert.match(r.detail, /256 options/);
    const r2 = await askJev({ state: 'x', questions: {}, env: envFor(s) });
    assert.equal(r2.reason, 'invalid');
    const r3 = await askJev({ state: 'x', questions: { s: score('How?', ['only one']) }, env: envFor(s) });
    assert.equal(r3.reason, 'invalid');
    assert.equal(s.requests.length, 0);
    assert.equal(validateQuestions({ q: noul('ok?') }), null);
  });
});

describe('confidence math (TypeSafe formulas)', () => {
  const close = (a, b, eps = 1e-3) => assert.ok(Math.abs(a - b) < eps, `${a} ≠ ${b}`);
  test('choice: (0.6,0.3,0.1) → 0.4 and (0.6,0.2,0.2) → 0.4', () => {
    close(choiceConfidence([0.6, 0.3, 0.1]), 0.4);
    close(choiceConfidence([0.6, 0.2, 0.2]), 0.4);
    close(choiceConfidence({ a: 0.88, b: 0.12, c: 0 }), 0.82);
    close(choiceConfidence([1, 0, 0]), 1);
    close(choiceConfidence([1 / 3, 1 / 3, 1 / 3]), 0);
  });
  test('score: (0,0.57,0.43) → ≈0.35; adjacent split 0.25; opposite ends 0', () => {
    close(scoreConfidence([0, 0.57, 0.43]), 0.355, 2e-3);
    close(scoreConfidence({ 0: 0, 1: 0.5, 2: 0.5 }), 0.25);
    close(scoreConfidence([0.5, 0, 0.5]), 0);
    close(scoreConfidence([0, 0, 1, 0, 0]), 1);
  });
  test('noul: 0.5 → 0, 0.95 → 0.9, 0 → 1', () => {
    close(confidenceOf({ type: 'noul', noul: 0.5 }), 0);
    close(confidenceOf({ type: 'noul', noul: 0.95 }), 0.9);
    close(confidenceOf({ type: 'noul', noul: 0 }), 1);
  });
  test('confidenceOf prefers the answer confidence for choice/score, computes otherwise', () => {
    close(confidenceOf({ type: 'choice', choice: 'a', confidence: 0.81, probabilities: { a: 0.88, b: 0.12 } }), 0.81);
    close(confidenceOf({ type: 'choice', choice: 'a', probabilities: { a: 0.6, b: 0.3, c: 0.1 } }), 0.4);
    close(confidenceOf({ type: 'score', score: 1.43, probabilities: { 0: 0, 1: 0.57, 2: 0.43 } }), 0.355, 2e-3);
    assert.equal(confidenceOf(null), 0);
    assert.equal(confidenceOf({ type: 'choice' }), 0);
  });
  test('band defaults act≥0.75, confirm≥0.45, and accepts overrides', () => {
    assert.equal(band(0.9), 'act');
    assert.equal(band(0.75), 'act');
    assert.equal(band(0.6), 'confirm');
    assert.equal(band(0.45), 'confirm');
    assert.equal(band(0.2), 'escalate');
    assert.equal(band(NaN), 'escalate');
    assert.equal(band(0.6, { act: 0.5 }), 'act');
    assert.equal(band(0.4, { confirm: 0.3 }), 'confirm');
  });
});

describe('builders and estimates', () => {
  test('noul/choice/score build the documented shapes', () => {
    assert.deepEqual(noul('Q?'), { type: 'noul', instructions: 'Q?' });
    assert.deepEqual(noul('Q?', { true: 't', false: 'f' }), { type: 'noul', instructions: 'Q?', criteria: { true: 't', false: 'f' } });
    assert.deepEqual(choice('Which?', { a: 'A', b: null }), { type: 'choice', instructions: 'Which?', criteria: { a: 'A', b: null } });
    assert.deepEqual(score('How?', ['lo', 'hi']), { type: 'score', instructions: 'How?', criteria: ['lo', 'hi'] });
  });
  test('estimateCost: $0.042 per 1M input tokens, output free, provider cost preferred', () => {
    assert.ok(Math.abs(estimateCost({ input_tokens: 1_000_000, output_tokens: 999 }) - 0.042) < 1e-12);
    assert.ok(Math.abs(estimateCost({ input_tokens: 1222 }) - 0.000051324) < 1e-9);
    assert.equal(estimateCost({ input_tokens: 5, cost: 0.5 }), 0.5);
    assert.equal(estimateCost(null), 0);
  });
  test('estimateTokens ≈ chars/4 and topChoices sorts by probability', () => {
    assert.equal(estimateTokens('a'.repeat(400)), 100);
    assert.equal(estimateTokens({ k: 'vv' }), Math.ceil('{"k":"vv"}'.length / 4));
    assert.deepEqual(topChoices({ probabilities: { a: 0.1, b: 0.7, c: 0.2 } }, 2), [
      { option: 'b', p: 0.7 },
      { option: 'c', p: 0.2 },
    ]);
  });
});
