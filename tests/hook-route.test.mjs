/**
 * UserPromptSubmit hook (scripts/hook-route.mjs) against the fake Jev server.
 * DESIGN.md §9: non-RE prompt → no output and no Jev call; RE prompt with an
 * existing .app fixture → route block mentions open_binary; ambiguous target
 * (confidence 0.3) → asks; source_repository → silent; plus fail-open cases.
 */
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { startFakeJev } from './fake-jev.mjs';
import { ROOT, SAMPLE_APP, hookEnv, payload, newSession, runHook, seedLedger, ledgerEvents, makeTmp } from './hook-harness.mjs';

const ROUTE_KEYS = ['is_re_task', 'target_kind', 'workflow', 'scope', 'needs_runtime', 'wants_build'];

let tmp;
let fake;
let fake500;
let fakeSlow;
before(async () => {
  tmp = makeTmp('route');
  fake = await startFakeJev();
  fake500 = await startFakeJev({ scenario: '500' });
  fakeSlow = await startFakeJev({ scenario: 'slow:3000' });
});
after(async () => {
  await Promise.all([fake.close(), fake500.close(), fakeSlow.close()]);
  fs.rmSync(tmp, { recursive: true, force: true });
});

const env = (extra = {}) => hookEnv({ fakeUrl: fake.url, home: tmp, ...extra });
const rePrompt = (session, extra = {}) => payload('prompt-re.json', { cwd: ROOT, session_id: session, ...extra });
const context = (r) => r.json?.hookSpecificOutput?.additionalContext ?? null;

function script(overrides) {
  for (const k of Object.keys(fake.script)) delete fake.script[k];
  Object.assign(fake.script, overrides);
}

describe('pre-filter', () => {
  test('non-RE prompt → no output and no Jev call', async () => {
    const before = fake.requests.length;
    const session = newSession('route');
    const r = await runHook('hook-route', payload('prompt-non-re.json', { cwd: ROOT, session_id: session }), env());
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, '');
    assert.equal(fake.requests.length, before, 'no Jev request');
    assert.deepEqual(ledgerEvents(tmp, session), [], 'no ledger event');
  });
  test('REA activity in the ledger makes a keyword-free prompt reach Jev', async () => {
    const before = fake.requests.length;
    const session = newSession('route');
    seedLedger(tmp, session, [{ kind: 'pre', tool: 'open_binary', input_hash: 'sha256:x', decision: 'silent', source: 'local' }]);
    script({ is_re_task: 0.9, target_kind: 'native_binary' });
    const r = await runHook('hook-route', payload('prompt-non-re.json', { cwd: ROOT, session_id: session, prompt: 'And what did the second string table say?' }), env());
    assert.equal(r.code, 0, r.stderr);
    assert.equal(fake.requests.length, before + 1);
  });
  test('invalid stdin and an empty prompt are silent', async () => {
    const before = fake.requests.length;
    const bad = await runHook('hook-route', 'not json at all', env());
    assert.equal(bad.code, 0);
    assert.equal(bad.stdout, '');
    const empty = await runHook('hook-route', rePrompt(newSession('route'), { prompt: '   ' }), env());
    assert.equal(empty.code, 0);
    assert.equal(empty.stdout, '');
    assert.equal(fake.requests.length, before);
  });
});

describe('route block', () => {
  test('RE prompt with the existing .app fixture → route block mentions open_binary and the hint', async () => {
    const before = fake.requests.length;
    const session = newSession('route');
    script({ is_re_task: 0.92, target_kind: 'native_binary', workflow: 'investigate_feature', scope: 1, needs_runtime: 0.12, wants_build: 0.81 });
    const r = await runHook('hook-route', rePrompt(session), env());
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.json.hookSpecificOutput.hookEventName, 'UserPromptSubmit');
    const text = context(r);
    assert.match(text, /^\[rea-jev System 1 route · jev-1\.13\.0-fake · \d+ ms\]/);
    assert.match(text, /target: native_binary \(0\.90\) → first tool: open_binary\(path\), then binary_overview \/ search_strings \/ trace_feature/);
    assert.match(text, /workflow: investigate_feature \(0\.90\) · scope: 1\.0 "one feature in one subsystem" · runtime needed: 0\.12 · build after: 0\.81/);
    assert.match(text, /hint: path \S+Sample\.app is a macOS app bundle/);
    assert.match(text, /Use the reverse-engineer skill\. Keep observations, inferences, and unknowns separate; cite Evidence IDs\.$/);
    assert.ok(text.split('\n').length <= 12, 'at most 12 lines');
    assert.doesNotMatch(text, /fanning out|Static evidence will not suffice/);

    assert.equal(fake.requests.length, before + 1, 'exactly one Jev call');
    const body = fake.requests[before].body;
    assert.deepEqual(Object.keys(body.questions).sort(), [...ROUTE_KEYS].sort());
    assert.equal(body.questions.is_re_task.type, 'noul');
    assert.equal(body.questions.target_kind.type, 'choice');
    assert.equal(Object.keys(body.questions.target_kind.criteria).length, 9);
    assert.equal(body.questions.workflow.type, 'choice');
    assert.equal(Object.keys(body.questions.workflow.criteria).length, 9);
    assert.equal(body.questions.scope.type, 'score');
    assert.equal(body.questions.scope.criteria.length, 4);
    assert.equal(body.questions.needs_runtime.type, 'noul');
    assert.equal(body.questions.wants_build.type, 'noul');
    assert.deepEqual(Object.keys(body.state).sort(), ['active_target', 'prompt', 'sniff_hints'], 'every state field is referenced by a question');
    assert.ok(body.questions.target_kind.instructions.includes('`active_target`'));
    assert.equal(body.state.active_target, null);
    assert.ok(body.state.sniff_hints.some((h) => h.includes('Sample.app')));

    const events = ledgerEvents(tmp, session);
    assert.equal(events.length, 1);
    assert.equal(events[0].kind, 'route');
    assert.equal(events[0].declared_target, SAMPLE_APP);
    assert.equal(events[0].target_hint, 'native_binary');
    assert.ok(events[0].prompt_excerpt.length <= 200);
    assert.equal(events[0].prompt_for_jev, events[0].prompt_excerpt, 'a short prompt is kept whole in both fields');
    assert.equal(events[0].decision, 'route');
    assert.equal(events[0].answers.target_kind.choice, 'native_binary');
  });
  test('the route event keeps a 1200-char redacted prompt for the later hooks, next to the 200-char ledger excerpt', async () => {
    const session = newSession('route');
    script({ is_re_task: 0.9, target_kind: 'native_binary' });
    const deliverables = Array.from({ length: 12 }, (_, i) => `(${i + 1}) explain deliverable number ${i + 1} of the export feature in detail`).join('; ');
    const prompt = `How does ./tests/fixtures/Sample.app export? ${deliverables}`;
    assert.ok(prompt.length > 800 && prompt.length < 1200, `prompt is ${prompt.length} chars`);
    await runHook('hook-route', rePrompt(session, { prompt }), env());
    const [ev] = ledgerEvents(tmp, session);
    assert.ok(ev.prompt_excerpt.length <= 230 && ev.prompt_excerpt.includes('chars omitted'));
    assert.equal(ev.prompt_for_jev, prompt, 'the full request survives for the stop hook');
  });
  test('the scope shown is the expected level, the same quantity that triggers the fan-out line', async () => {
    script({ is_re_task: 0.9, target_kind: 'native_binary', scope: { probabilities: [0, 0, 0.5, 0.5] } });
    const r = await runHook('hook-route', rePrompt(newSession('route')), env());
    assert.match(context(r), /scope: 2\.5 "several features or one cross-layer trace"/);
    assert.match(context(r), /Consider fanning out/);
    script({ is_re_task: 0.9, target_kind: 'native_binary', scope: { probabilities: [0, 0.2, 0.8, 0] } });
    const r2 = await runHook('hook-route', rePrompt(newSession('route')), env());
    assert.match(context(r2), /scope: 1\.8 "several features or one cross-layer trace"/);
    assert.doesNotMatch(context(r2), /Consider fanning out/);
  });
  test('a non-first Choice option is honoured (the fake rejects unknown options)', async () => {
    script({ is_re_task: 0.9, target_kind: 'managed_assembly', workflow: 'compare_versions' });
    const r = await runHook('hook-route', rePrompt(newSession('route')), env());
    assert.match(context(r), /target: managed_assembly \(0\.90\) → first tool: inspect_managed_artifact\(path\)/);
    assert.match(context(r), /workflow: compare_versions \(0\.90\)/);
  });
  test('wide scope and runtime need add the fan-out and capture lines', async () => {
    script({ is_re_task: 0.9, target_kind: 'javascript_application', workflow: 'overview', scope: 3, needs_runtime: 0.9 });
    const r = await runHook('hook-route', rePrompt(newSession('route')), env());
    const text = context(r);
    assert.match(text, /target: javascript_application \(0\.90\) → first tool: analyze_javascript_application\(input_path\)/);
    assert.match(text, /Consider fanning out `rea-investigator` subagents, one per independent question\./);
    assert.match(text, /Static evidence will not suffice; plan a declared capture \(`capture_process_scenario` \/ browser \/ Electron\)/);
    assert.ok(text.split('\n').length <= 12);
  });
  test('ambiguous target (confidence ≈ 0.3) → asks the user, listing the top two candidates', async () => {
    script({
      is_re_task: 0.9,
      target_kind: { probabilities: { native_binary: 0.38, javascript_application: 0.31, package_archive: 0.31 } },
    });
    const r = await runHook('hook-route', payload('prompt-ambiguous.json', { cwd: ROOT, session_id: newSession('route') }), env());
    assert.equal(r.code, 0, r.stderr);
    const text = context(r);
    assert.match(text, /target: ambiguous \(top: native_binary 0\.38, (javascript_application|package_archive) 0\.31\) — ask the user which artifact to inspect before opening anything\./);
    assert.doesNotMatch(text, /first tool:/);
  });
  test('unknown_or_missing is ambiguous even when confident', async () => {
    script({ is_re_task: 0.9, target_kind: 'unknown_or_missing' });
    const r = await runHook('hook-route', payload('prompt-ambiguous.json', { cwd: ROOT, session_id: newSession('route') }), env());
    assert.match(context(r), /target: ambiguous/);
  });
});

describe('silence rules', () => {
  test('source_repository with confidence ≥ 0.6 → silent (Jev called, nothing emitted)', async () => {
    const before = fake.requests.length;
    script({ is_re_task: 0.6, target_kind: 'source_repository' });
    const r = await runHook('hook-route', rePrompt(newSession('route')), env());
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, '');
    assert.equal(fake.requests.length, before + 1);
  });
  test('is_re_task below T_ROUTE_RE → silent; the threshold reads REA_JEV_T_ROUTE_RE', async () => {
    script({ is_re_task: 0.2, target_kind: 'native_binary' });
    const low = await runHook('hook-route', rePrompt(newSession('route')), env());
    assert.equal(low.stdout, '');
    script({ is_re_task: 0.9, target_kind: 'native_binary' });
    const raised = await runHook('hook-route', rePrompt(newSession('route')), env({ extra: { REA_JEV_T_ROUTE_RE: '0.95' } }));
    assert.equal(raised.stdout, '', 'a 0.9 answer is below the raised threshold');
    const normal = await runHook('hook-route', rePrompt(newSession('route')), env());
    assert.match(context(normal), /target: native_binary/);
  });
  test('REA_JEV_T_ROUTE_MIN raises the bar for naming a target', async () => {
    script({ is_re_task: 0.9, target_kind: 'native_binary' });
    const r = await runHook('hook-route', rePrompt(newSession('route')), env({ extra: { REA_JEV_T_ROUTE_MIN: '0.95' } }));
    assert.match(context(r), /target: ambiguous/);
  });
  test('a non-RE follow-up keeps the previously declared target in the ledger', async () => {
    const session = newSession('route');
    seedLedger(tmp, session, [
      { kind: 'route', prompt_excerpt: 'first', answers: {}, declared_target: SAMPLE_APP },
      { kind: 'post', tool: 'open_binary', input_hash: 'sha256:x', ok: true, evidence_ids: [], limitations: [], bytes: 10 },
    ]);
    script({ is_re_task: 0.05, target_kind: 'source_repository' });
    const r = await runHook('hook-route', rePrompt(session, { prompt: 'Now tidy the docs in ./docs and commit.' }), env());
    assert.equal(r.stdout, '');
    const events = ledgerEvents(tmp, session);
    const last = events[events.length - 1];
    assert.equal(last.kind, 'route');
    assert.equal(last.declared_target, SAMPLE_APP, 'carried forward, not replaced by ./docs');
  });
});

describe('egress', () => {
  test('URL credentials and query strings never leave: not in the prompt, the hints, the target, nor the ledger', async () => {
    const before = fake.requests.length;
    const session = newSession('route');
    script({ is_re_task: 0.9, target_kind: 'website_in_browser' });
    const prompt = 'reverse engineer the login flow of the web app at https://admin:S3cretPass@10.0.0.7/portal?access_token=abcdef123456 and tell me how the session cookie is set';
    const r = await runHook('hook-route', rePrompt(session, { prompt }), env());
    assert.equal(r.code, 0, r.stderr);
    const body = JSON.stringify(fake.requests[before].body);
    assert.doesNotMatch(body, /S3cretPass|access_token=abcdef/);
    assert.ok(body.includes('https://10.0.0.7/portal'), body);
    const ledger = JSON.stringify(ledgerEvents(tmp, session));
    assert.doesNotMatch(ledger, /S3cretPass|access_token=abcdef/);
    assert.equal(ledgerEvents(tmp, session)[0].declared_target, 'https://10.0.0.7/portal');
    assert.doesNotMatch(r.stdout, /S3cretPass|access_token=abcdef/);
  });
});

describe('modes and fail-open', () => {
  test('429 then 200 → the retry happens in the real hook process and the route block is emitted', async () => {
    const s = await startFakeJev({ scenario: '429-then-200', script: { is_re_task: 0.9, target_kind: 'native_binary' } });
    try {
      const r = await runHook('hook-route', rePrompt(newSession('route')), env({ fakeUrl: s.url }));
      assert.equal(r.code, 0, r.stderr);
      assert.match(context(r) ?? '', /target: native_binary/);
      assert.equal(s.requests.length, 2, 'the hook retried once after the 429');
    } finally {
      await s.close();
    }
  });
  test('an out-of-range or malformed answer is dropped: the hook stays silent instead of routing on it', async () => {
    const before = fake.requests.length;
    script({ is_re_task: { raw: { type: 'noul', noul: 7 } }, target_kind: { raw: { type: 'choice', choice: '__proto__', probabilities: { native_binary: 0.9 } } } });
    const r = await runHook('hook-route', rePrompt(newSession('route')), env());
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, '');
    assert.equal(fake.requests.length, before + 1);
  });
  test('shadow → nothing on stdout, Jev called, route event logged', async () => {
    const before = fake.requests.length;
    const session = newSession('route');
    script({ is_re_task: 0.9, target_kind: 'native_binary' });
    const r = await runHook('hook-route', rePrompt(session), env({ mode: 'shadow' }));
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, '');
    assert.equal(fake.requests.length, before + 1);
    assert.equal(ledgerEvents(tmp, session)[0]?.kind, 'route');
  });
  test('mode off → nothing, no Jev call, no ledger', async () => {
    const before = fake.requests.length;
    const session = newSession('route');
    const r = await runHook('hook-route', rePrompt(session), env({ mode: 'off' }));
    assert.equal(r.code, 0);
    assert.equal(r.stdout, '');
    assert.equal(fake.requests.length, before);
    assert.deepEqual(ledgerEvents(tmp, session), []);
  });
  test('Jev 500 → exit 0, empty stdout, route event records the failure', async () => {
    const session = newSession('route');
    const r = await runHook('hook-route', rePrompt(session), env({ fakeUrl: fake500.url }));
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, '');
    const events = ledgerEvents(tmp, session);
    assert.equal(events[0]?.kind, 'route');
    assert.equal(events[0]?.jev_failure, 'http_5xx');
    assert.equal(events[0]?.declared_target, SAMPLE_APP);
  });
  test('no key → exit 0, empty stdout, no request', async () => {
    const before = fake.requests.length;
    const r = await runHook('hook-route', rePrompt(newSession('route')), env({ key: false }));
    assert.equal(r.code, 0);
    assert.equal(r.stdout, '');
    assert.equal(fake.requests.length, before);
  });
  test('slow server → gives up at REA_JEV_TIMEOUT_MS and exits 0 silently', async () => {
    const r = await runHook('hook-route', rePrompt(newSession('route')), env({ fakeUrl: fakeSlow.url, extra: { REA_JEV_TIMEOUT_MS: '400' } }));
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, '');
    assert.ok(r.ms < 2500, `took ${r.ms} ms`);
  });
  test('REA_JEV_DEBUG=1 explains the decision on stderr without leaking the key', async () => {
    script({ is_re_task: 0.9, target_kind: 'native_binary' });
    const r = await runHook('hook-route', rePrompt(newSession('route')), env({ extra: { REA_JEV_DEBUG: '1' } }));
    assert.match(r.stderr, /\[rea-jev\] route: route in \d+ ms/);
    assert.doesNotMatch(r.stderr, /test-key-not-real/);
  });
});
