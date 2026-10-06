/**
 * PreToolUse hook (scripts/hook-gate.mjs) against the fake Jev server.
 * DESIGN.md §9: identical inspect call after a prior post → deny; identical
 * after a mutation → silent; status tool repeated → silent; non-loopback CDP →
 * deny; capture with out-of-scope executable → ask; Jev failure → silent;
 * mode off → silent; plus the Jev gate policies and thresholds.
 */
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { startFakeJev } from './fake-jev.mjs';
import { hashInput } from '../scripts/lib/rea.mjs';
import { ROOT, SAMPLE_APP, hookEnv, payload, newSession, runHook, seedLedger, ledgerEvents, makeTmp } from './hook-harness.mjs';

const EV = (c) => `ev_${c.repeat(64)}`;

let tmp;
let fake;
let fake500;
before(async () => {
  tmp = makeTmp('gate');
  fake = await startFakeJev();
  fake500 = await startFakeJev({ scenario: '500' });
});
after(async () => {
  await Promise.all([fake.close(), fake500.close()]);
  fs.rmSync(tmp, { recursive: true, force: true });
});

const env = (extra = {}) => hookEnv({ fakeUrl: fake.url, home: tmp, ...extra });
const decision = (r) => r.json?.hookSpecificOutput?.permissionDecision ?? null;
const reason = (r) => r.json?.hookSpecificOutput?.permissionDecisionReason ?? '';
const lastPre = (session) => ledgerEvents(tmp, session).filter((e) => e.kind === 'pre').at(-1);

function script(overrides) {
  for (const k of Object.keys(fake.script)) delete fake.script[k];
  Object.assign(fake.script, overrides);
}

/** A route event so the Jev gate has a user request and a declared target. */
const routeEvent = { kind: 'route', prompt_excerpt: 'How does the export feature in Sample.app work?', answers: {}, target_hint: 'native_binary', declared_target: SAMPLE_APP };

function postFor(name, extra = {}) {
  const p = payload(name);
  return { kind: 'post', tool: p.tool_name.replace(/^mcp__(plugin_rea-jev_)?rea__/, ''), input_hash: hashInput(p.tool_name, p.tool_input), ok: true, evidence_ids: [EV('a')], limitations: [], bytes: 2048, ...extra };
}

describe('rule 1: not REA / mode off', () => {
  test('a non-REA tool is ignored entirely', async () => {
    const session = newSession('gate');
    const r = await runHook('hook-gate', payload('pre-search-strings.json', { session_id: session, tool_name: 'Bash', tool_input: { command: 'ls' } }), env());
    assert.equal(r.code, 0);
    assert.equal(r.stdout, '');
    assert.deepEqual(ledgerEvents(tmp, session), []);
  });
  test('mcp__area__x is not an REA tool', async () => {
    const session = newSession('gate');
    const r = await runHook('hook-gate', payload('pre-search-strings.json', { session_id: session, tool_name: 'mcp__area__search_strings' }), env());
    assert.equal(r.stdout, '');
    assert.deepEqual(ledgerEvents(tmp, session), []);
  });
  test('mode off → silent even for an identical call, and no ledger write', async () => {
    const before = fake.requests.length;
    const session = newSession('gate');
    seedLedger(tmp, session, [postFor('pre-search-strings.json')]);
    const r = await runHook('hook-gate', payload('pre-search-strings.json', { session_id: session }), env({ mode: 'off' }));
    assert.equal(r.code, 0);
    assert.equal(r.stdout, '');
    assert.equal(fake.requests.length, before);
    assert.equal(ledgerEvents(tmp, session).length, 1, 'only the seeded post');
  });
});

describe('rule 2: redundancy (local)', () => {
  test('first inspect call → silent, pre event recorded, no Jev call', async () => {
    const before = fake.requests.length;
    const session = newSession('gate');
    const r = await runHook('hook-gate', payload('pre-search-strings.json', { session_id: session }), env());
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, '');
    assert.equal(fake.requests.length, before, 'inspection calls never cost a Jev request');
    const pre = lastPre(session);
    assert.equal(pre.tool, 'search_strings');
    assert.equal(pre.decision, 'silent');
    assert.equal(pre.source, 'local');
    assert.match(pre.input_hash, /^sha256:[0-9a-f]{64}$/);
    assert.ok(pre.input_excerpt.length <= 200);
  });
  test('identical inspect call after a prior successful post → deny citing the Evidence ID', async () => {
    const session = newSession('gate');
    seedLedger(tmp, session, [postFor('pre-search-strings.json')]);
    const r = await runHook('hook-gate', payload('pre-search-strings.json', { session_id: session }), env());
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.json.hookSpecificOutput.hookEventName, 'PreToolUse');
    assert.equal(decision(r), 'deny');
    assert.equal(reason(r), `rea-jev: identical \`search_strings\` call already returned Evidence ${EV('a')}; reuse that result instead of repeating the call.`);
    assert.equal(lastPre(session).decision, 'deny');
    assert.equal(lastPre(session).source, 'local');
  });
  test('the same tool with different input is not redundant', async () => {
    const session = newSession('gate');
    seedLedger(tmp, session, [postFor('pre-search-strings.json')]);
    const r = await runHook('hook-gate', payload('pre-search-strings.json', { session_id: session, tool_input: { pattern: 'Import', case_sensitive: false } }), env());
    assert.equal(r.stdout, '');
  });
  test('the global registration form (mcp__rea__) hashes to the same key as the plugin form', async () => {
    const session = newSession('gate');
    seedLedger(tmp, session, [postFor('pre-search-strings.json')]);
    const r = await runHook('hook-gate', payload('pre-search-strings.json', { session_id: session, tool_name: 'mcp__rea__search_strings' }), env());
    assert.equal(decision(r), 'deny');
  });
  test('identical call after a mutation-class post → silent (window reset)', async () => {
    const session = newSession('gate');
    seedLedger(tmp, session, [postFor('pre-search-strings.json'), { kind: 'post', tool: 'set_comment', input_hash: 'sha256:m', ok: true, evidence_ids: [], limitations: [], bytes: 50 }]);
    const r = await runHook('hook-gate', payload('pre-search-strings.json', { session_id: session }), env());
    assert.equal(r.stdout, '');
    assert.equal(lastPre(session).decision, 'silent');
  });
  test('a failed prior call is not reused', async () => {
    const session = newSession('gate');
    seedLedger(tmp, session, [postFor('pre-search-strings.json', { ok: false, evidence_ids: [] })]);
    const r = await runHook('hook-gate', payload('pre-search-strings.json', { session_id: session }), env());
    assert.equal(r.stdout, '');
  });
  test('status tool repeated → silent', async () => {
    const session = newSession('gate');
    seedLedger(tmp, session, [postFor('pre-binary-session.json', { evidence_ids: [] })]);
    const r = await runHook('hook-gate', payload('pre-binary-session.json', { session_id: session }), env());
    assert.equal(r.code, 0);
    assert.equal(r.stdout, '');
    assert.equal(lastPre(session).decision, 'silent');
  });
  test('a prior result without Evidence IDs is described by size', async () => {
    const session = newSession('gate');
    seedLedger(tmp, session, [postFor('pre-search-strings.json', { evidence_ids: [], bytes: 777 })]);
    const r = await runHook('hook-gate', payload('pre-search-strings.json', { session_id: session }), env());
    assert.equal(decision(r), 'deny');
    assert.match(reason(r), /already returned a result \(777 bytes, no Evidence ID\)/);
  });
});

describe('rule 3: hard rules (local)', () => {
  test('non-loopback CDP endpoint → deny, no Jev call', async () => {
    const before = fake.requests.length;
    const session = newSession('gate');
    const r = await runHook('hook-gate', payload('pre-list-browser-targets-remote.json', { session_id: session }), env());
    assert.equal(decision(r), 'deny');
    assert.match(reason(r), /REA only supports loopback endpoints; a remote endpoint would observe another machine/);
    assert.equal(fake.requests.length, before);
    assert.equal(lastPre(session).decision, 'deny');
  });
  test('loopback CDP endpoint → silent (list_browser_targets is not runtime-class)', async () => {
    const before = fake.requests.length;
    const r = await runHook('hook-gate', payload('pre-list-browser-targets-remote.json', { session_id: newSession('gate'), tool_input: { cdp_endpoint: 'http://127.0.0.1:9222' } }), env());
    assert.equal(r.stdout, '');
    assert.equal(fake.requests.length, before);
  });
  test('nested non-loopback endpoint in capture_browser_scenario and a remote inspector_endpoint → deny', async () => {
    const browser = await runHook(
      'hook-gate',
      payload('pre-list-browser-targets-remote.json', {
        session_id: newSession('gate'),
        tool_name: 'mcp__rea__capture_browser_scenario',
        tool_input: { browser: { connect: { cdp_endpoint: 'ws://192.168.1.20:9222/devtools/browser/abc' } }, start_url: { url: 'https://example.com' }, actions: [] },
      }),
      env(),
    );
    assert.equal(decision(browser), 'deny');
    const inspector = await runHook(
      'hook-gate',
      payload('pre-list-browser-targets-remote.json', { session_id: newSession('gate'), tool_name: 'mcp__rea__list_javascript_runtime_targets', tool_input: { inspector_endpoint: 'ws://build-box.internal:9229' } }),
      env(),
    );
    assert.equal(decision(inspector), 'deny');
  });
  test('capture with an executable outside cwd and the declared target → ask, no Jev call', async () => {
    const before = fake.requests.length;
    const session = newSession('gate');
    seedLedger(tmp, session, [routeEvent]);
    const r = await runHook('hook-gate', payload('pre-capture-process-out-of-scope.json', { session_id: session, cwd: tmp }), env());
    assert.equal(decision(r), 'ask');
    assert.match(reason(r), /would run \/opt\/unrelated\/bin\/other-tool, which is outside the working directory and the declared target/);
    assert.equal(fake.requests.length, before);
    assert.equal(lastPre(session).source, 'local');
  });
  test('an executable inside the declared target passes the local rule and reaches Jev', async () => {
    const before = fake.requests.length;
    const session = newSession('gate');
    seedLedger(tmp, session, [routeEvent]);
    script({ within_scope: 0.9, irreversible: 0.1, runtime_requested: 0.9 });
    const exe = path.join(SAMPLE_APP, 'Contents', 'MacOS', 'Sample');
    const r = await runHook('hook-gate', payload('pre-capture-process-out-of-scope.json', { session_id: session, cwd: tmp, tool_input: { executable: exe, arguments: [] } }), env());
    assert.equal(r.stdout, '', 'in scope, reversible, runtime requested → normal permission flow');
    assert.equal(fake.requests.length, before + 1);
    assert.equal(lastPre(session).source, 'jev');
  });
  test('a relative executable is resolved against working_directory', async () => {
    const session = newSession('gate');
    const r = await runHook(
      'hook-gate',
      payload('pre-capture-process-out-of-scope.json', { session_id: session, cwd: ROOT, tool_input: { executable: './bin/other-tool', working_directory: '/opt/unrelated' } }),
      env(),
    );
    assert.equal(decision(r), 'ask');
    assert.match(reason(r), /\/opt\/unrelated\/bin\/other-tool/);
  });
  test('scenario environment with a credential → ask, and the ledger excerpt is redacted', async () => {
    const session = newSession('gate');
    const r = await runHook('hook-gate', payload('pre-capture-process-env-secret.json', { session_id: session, cwd: ROOT }), env());
    assert.equal(decision(r), 'ask');
    assert.match(reason(r), /scenario environment appears to contain a credential \(API_TOKEN\); REA records environment; confirm or remove it/);
    assert.doesNotMatch(reason(r), /sk-live/);
    assert.doesNotMatch(JSON.stringify(ledgerEvents(tmp, session)), /sk-live-0123456789/);
  });
  test('the shell variables PWD and OLDPWD are not credentials', async () => {
    const before = fake.requests.length;
    const session = newSession('gate');
    seedLedger(tmp, session, [routeEvent]);
    script({ within_scope: 0.9, irreversible: 0.1, runtime_requested: 0.9 });
    const r = await runHook(
      'hook-gate',
      payload('pre-capture-process-env-secret.json', { session_id: session, cwd: ROOT, tool_input: { executable: 'node', environment: { PWD: `${ROOT}/tests`, OLDPWD: '/tmp', PORT: '3000' } } }),
      env(),
    );
    assert.equal(r.stdout, '', 'no credential ask');
    assert.equal(fake.requests.length, before + 1, 'the call reached the Jev gate');
    const list = await runHook(
      'hook-gate',
      payload('pre-capture-process-env-secret.json', { session_id: newSession('gate'), cwd: ROOT, tool_input: { executable: 'node', environment: ['PWD=/home/user/project', 'DB_PWD=hunter22'] } }),
      env(),
    );
    assert.equal(decision(list), 'ask');
    assert.match(reason(list), /\(DB_PWD\)/);
  });
  test('environment as KEY=VALUE strings is checked too', async () => {
    const r = await runHook(
      'hook-gate',
      payload('pre-capture-process-env-secret.json', { session_id: newSession('gate'), cwd: ROOT, tool_input: { executable: 'node', environment: ['PORT=3000', 'GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123'] } }),
      env(),
    );
    assert.equal(decision(r), 'ask');
    assert.match(reason(r), /GITHUB_TOKEN/);
  });
});

describe('rule 4: Jev gate', () => {
  test('state and questions have the documented shape', async () => {
    const before = fake.requests.length;
    const session = newSession('gate');
    seedLedger(tmp, session, [routeEvent]);
    script({ within_scope: 0.9, irreversible: 0.1, runtime_requested: 0.9 });
    await runHook('hook-gate', payload('pre-capture-process-in-scope.json', { session_id: session, cwd: ROOT }), env());
    const body = fake.requests[before].body;
    assert.deepEqual(Object.keys(body.questions).sort(), ['irreversible', 'runtime_requested', 'within_scope']);
    for (const q of Object.values(body.questions)) assert.equal(q.type, 'noul');
    assert.deepEqual(Object.keys(body.state).sort(), ['declared_target', 'tool', 'tool_input', 'user_request']);
    assert.equal(body.state.tool, 'capture_process_scenario');
    assert.equal(body.state.user_request, routeEvent.prompt_excerpt);
    assert.equal(body.state.declared_target, SAMPLE_APP);
    assert.ok(typeof body.state.tool_input === 'string' && body.state.tool_input.includes('"executable":"node"'));
  });
  test('within_scope below T_GATE_SCOPE → ask in advise, deny in enforce', async () => {
    script({ within_scope: 0.1, irreversible: 0.1, runtime_requested: 0.9 });
    const sA = newSession('gate');
    seedLedger(tmp, sA, [routeEvent]);
    const advise = await runHook('hook-gate', payload('pre-capture-process-in-scope.json', { session_id: sA, cwd: ROOT }), env());
    assert.equal(decision(advise), 'ask');
    assert.match(reason(advise), /does not appear to act on the declared target \(within_scope 0\.10\)/);
    assert.equal(lastPre(sA).source, 'jev');
    assert.equal(lastPre(sA).answers.within_scope.noul, 0.1);
    const sE = newSession('gate');
    seedLedger(tmp, sE, [routeEvent]);
    const enforce = await runHook('hook-gate', payload('pre-capture-process-in-scope.json', { session_id: sE, cwd: ROOT }), env({ mode: 'enforce' }));
    assert.equal(decision(enforce), 'deny');
  });
  test('enforce denies only on a decisive within_scope: p 0.29 (confidence 0.42, escalate) asks, p 0.2 (0.60) denies', async () => {
    script({ within_scope: 0.29, irreversible: 0.1, runtime_requested: 0.9 });
    const s1 = newSession('gate');
    seedLedger(tmp, s1, [routeEvent]);
    const coinFlip = await runHook('hook-gate', payload('pre-capture-process-in-scope.json', { session_id: s1, cwd: ROOT }), env({ mode: 'enforce' }));
    assert.equal(decision(coinFlip), 'ask');
    assert.match(reason(coinFlip), /within_scope 0\.29\); confirm it belongs to the investigation/);
    script({ within_scope: 0.2, irreversible: 0.1, runtime_requested: 0.9 });
    const s2 = newSession('gate');
    seedLedger(tmp, s2, [routeEvent]);
    const clear = await runHook('hook-gate', payload('pre-capture-process-in-scope.json', { session_id: s2, cwd: ROOT }), env({ mode: 'enforce' }));
    assert.equal(decision(clear), 'deny');
  });
  test('user_request is the last reverse-engineering request (1200-char field), not a later follow-up prompt', async () => {
    const before = fake.requests.length;
    const session = newSession('gate');
    const longRequest = `${routeEvent.prompt_excerpt} ${'Also trace the PDF path. '.repeat(12)}`.trim();
    seedLedger(tmp, session, [
      { ...routeEvent, prompt_for_jev: longRequest, decision: 'route' },
      { kind: 'route', prompt_excerpt: 'thanks, format that as a table', prompt_for_jev: 'thanks, format that as a table', answers: { is_re_task: { type: 'noul', noul: 0.05 } }, declared_target: SAMPLE_APP, decision: 'silent' },
    ]);
    script({ within_scope: 0.9, irreversible: 0.1, runtime_requested: 0.1 });
    const r = await runHook('hook-gate', payload('pre-capture-process-in-scope.json', { session_id: session, cwd: ROOT }), env());
    assert.equal(fake.requests[before].body.state.user_request, longRequest);
    assert.equal(decision(r), 'ask', 'runtime_requested is judged against the RE request, so the rule still fires');
  });
  test('an out-of-range within_scope is dropped: enforce stays silent instead of denying on -2', async () => {
    script({ within_scope: { raw: { type: 'noul', noul: -2 } }, irreversible: 0.1, runtime_requested: 0.9 });
    const session = newSession('gate');
    seedLedger(tmp, session, [routeEvent]);
    const r = await runHook('hook-gate', payload('pre-capture-process-in-scope.json', { session_id: session, cwd: ROOT }), env({ mode: 'enforce' }));
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, '');
    assert.equal(lastPre(session).decision, 'silent');
  });
  test('429 then 200 → the retry happens in the real hook process and the verdict is emitted', async () => {
    const s = await startFakeJev({ scenario: '429-then-200', script: { within_scope: 0.1, irreversible: 0.1, runtime_requested: 0.9 } });
    try {
      const session = newSession('gate');
      seedLedger(tmp, session, [routeEvent]);
      const r = await runHook('hook-gate', payload('pre-capture-process-in-scope.json', { session_id: session, cwd: ROOT }), env({ fakeUrl: s.url }));
      assert.equal(r.code, 0, r.stderr);
      assert.equal(decision(r), 'ask');
      assert.equal(s.requests.length, 2);
    } finally {
      await s.close();
    }
  });
  test('a slow Jev never outlives the safety timer: the pre event is still written and the hook exits in time', async () => {
    const slow = await startFakeJev({ scenario: 'slow:30000' });
    try {
      const session = newSession('gate');
      seedLedger(tmp, session, [routeEvent]);
      const r = await runHook('hook-gate', payload('pre-capture-process-in-scope.json', { session_id: session, cwd: ROOT }), env({ fakeUrl: slow.url, extra: { REA_JEV_TIMEOUT_MS: '60000' } }));
      assert.equal(r.code, 0, r.stderr);
      assert.equal(r.stdout, '');
      assert.ok(r.ms < 9500, `took ${r.ms} ms`);
      const pre = lastPre(session);
      assert.equal(pre?.decision, 'silent');
      assert.equal(pre?.source, 'jev');
    } finally {
      await slow.close();
    }
  });
  test('irreversible above T_GATE_IRREV → ask; the threshold reads REA_JEV_T_GATE_IRREV', async () => {
    script({ within_scope: 0.9, irreversible: 0.9, runtime_requested: 0.9 });
    const s1 = newSession('gate');
    seedLedger(tmp, s1, [routeEvent]);
    const r = await runHook('hook-gate', payload('pre-capture-process-in-scope.json', { session_id: s1, cwd: ROOT }), env());
    assert.equal(decision(r), 'ask');
    assert.match(reason(r), /irreversible 0\.90/);
    script({ within_scope: 0.9, irreversible: 0.5, runtime_requested: 0.9 });
    const s2 = newSession('gate');
    seedLedger(tmp, s2, [routeEvent]);
    const lowered = await runHook('hook-gate', payload('pre-capture-process-in-scope.json', { session_id: s2, cwd: ROOT }), env({ extra: { REA_JEV_T_GATE_IRREV: '0.4' } }));
    assert.equal(decision(lowered), 'ask');
    const s3 = newSession('gate');
    seedLedger(tmp, s3, [routeEvent]);
    const normal = await runHook('hook-gate', payload('pre-capture-process-in-scope.json', { session_id: s3, cwd: ROOT }), env());
    assert.equal(normal.stdout, '');
  });
  test('runtime_requested below T_GATE_RUNTIME asks for capture_* tools only', async () => {
    script({ within_scope: 0.9, irreversible: 0.1, runtime_requested: 0.1 });
    const s1 = newSession('gate');
    seedLedger(tmp, s1, [routeEvent]);
    const capture = await runHook('hook-gate', payload('pre-capture-process-in-scope.json', { session_id: s1, cwd: ROOT }), env());
    assert.equal(decision(capture), 'ask');
    assert.match(reason(capture), /the user did not ask for runtime execution \(runtime_requested 0\.10\); confirm before launching/);
    const s2 = newSession('gate');
    seedLedger(tmp, s2, [routeEvent]);
    const observe = await runHook(
      'hook-gate',
      payload('pre-capture-process-in-scope.json', { session_id: s2, cwd: ROOT, tool_name: 'mcp__rea__observe_native_ui', tool_input: { pid: 4242, window_id: 7 } }),
      env(),
    );
    assert.equal(observe.stdout, '', 'observe_* is runtime-class but not a capture');
    assert.equal(lastPre(s2).source, 'jev');
  });
  test('without a route in the ledger the request-dependent rules do not fire', async () => {
    script({ within_scope: 0.1, irreversible: 0.1, runtime_requested: 0.1 });
    const session = newSession('gate');
    const r = await runHook('hook-gate', payload('pre-capture-process-in-scope.json', { session_id: session, cwd: ROOT }), env({ mode: 'enforce' }));
    assert.equal(r.stdout, '');
    assert.equal(lastPre(session).source, 'jev');
  });
  test('export_evidence_bundle outside cwd reaches Jev; inside cwd it does not', async () => {
    const before = fake.requests.length;
    script({ within_scope: 0.9, irreversible: 0.1, runtime_requested: 0.5 });
    const s1 = newSession('gate');
    seedLedger(tmp, s1, [routeEvent]);
    const outside = await runHook('hook-gate', payload('pre-export-evidence-bundle.json', { session_id: s1, cwd: ROOT }), env());
    assert.equal(outside.stdout, '');
    assert.equal(fake.requests.length, before + 1);
    assert.equal(lastPre(s1).source, 'jev');
    const s2 = newSession('gate');
    seedLedger(tmp, s2, [routeEvent]);
    const inside = await runHook('hook-gate', payload('pre-export-evidence-bundle.json', { session_id: s2, cwd: ROOT, tool_input: { path: './out/bundle.json' } }), env());
    assert.equal(inside.stdout, '');
    assert.equal(fake.requests.length, before + 1, 'no second Jev call');
    assert.equal(lastPre(s2).source, 'local');
  });
  test('Jev failure → silent, exit 0, pre event records source jev', async () => {
    const session = newSession('gate');
    seedLedger(tmp, session, [routeEvent]);
    const r = await runHook('hook-gate', payload('pre-capture-process-in-scope.json', { session_id: session, cwd: ROOT }), env({ fakeUrl: fake500.url }));
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, '');
    assert.equal(lastPre(session).decision, 'silent');
    assert.equal(lastPre(session).source, 'jev');
  });
  test('no key → silent, no request', async () => {
    const before = fake.requests.length;
    const session = newSession('gate');
    seedLedger(tmp, session, [routeEvent]);
    const r = await runHook('hook-gate', payload('pre-capture-process-in-scope.json', { session_id: session, cwd: ROOT }), env({ key: false }));
    assert.equal(r.stdout, '');
    assert.equal(fake.requests.length, before);
  });
});

describe('shadow mode', () => {
  test('redundancy → nothing on stdout, ledger says deny', async () => {
    const session = newSession('gate');
    seedLedger(tmp, session, [postFor('pre-search-strings.json')]);
    const r = await runHook('hook-gate', payload('pre-search-strings.json', { session_id: session }), env({ mode: 'shadow' }));
    assert.equal(r.code, 0);
    assert.equal(r.stdout, '');
    assert.equal(lastPre(session).decision, 'deny');
  });
  test('Jev scope verdict → nothing on stdout, ledger says ask', async () => {
    script({ within_scope: 0.1, irreversible: 0.1, runtime_requested: 0.9 });
    const session = newSession('gate');
    seedLedger(tmp, session, [routeEvent]);
    const r = await runHook('hook-gate', payload('pre-capture-process-in-scope.json', { session_id: session, cwd: ROOT }), env({ mode: 'shadow' }));
    assert.equal(r.stdout, '');
    assert.equal(lastPre(session).decision, 'ask');
  });
});
