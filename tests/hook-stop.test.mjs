/**
 * Stop hook (scripts/hook-stop.mjs) against the fake Jev server.
 * DESIGN.md §9: stop_hook_active → exit 0; no REA activity → exit 0; enforce +
 * claims_complete 0.9 + cites 0.1 + ids seen → decision block; advise →
 * systemMessage only; second block within 60 s → exit 0; plus transcript
 * fallback, local facts, thresholds and fail-open.
 */
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { startFakeJev } from './fake-jev.mjs';
import { FIXTURES, SAMPLE_APP, hookEnv, payload, newSession, runHook, seedLedger, ledgerEvents, makeTmp } from './hook-harness.mjs';

const EV = (c) => `ev_${c.repeat(64)}`;
const TRANSCRIPT = path.join(FIXTURES, 'transcript.jsonl');

let tmp;
let fake;
let fake500;
before(async () => {
  tmp = makeTmp('stop');
  fake = await startFakeJev();
  fake500 = await startFakeJev({ scenario: '500' });
});
after(async () => {
  await Promise.all([fake.close(), fake500.close()]);
  fs.rmSync(tmp, { recursive: true, force: true });
});

const env = (extra = {}) => hookEnv({ fakeUrl: fake.url, home: tmp, mode: 'enforce', ...extra });
const lastStop = (session) => ledgerEvents(tmp, session).filter((e) => e.kind === 'stop').at(-1);

function script(overrides) {
  for (const k of Object.keys(fake.script)) delete fake.script[k];
  Object.assign(fake.script, overrides);
}

/** A session with a route, an open binary and two Evidence IDs. */
function activity(extra = []) {
  return [
    { kind: 'route', prompt_excerpt: 'How does the export feature in Sample.app work? Also: which file formats does it support?', answers: {}, declared_target: SAMPLE_APP },
    { kind: 'pre', tool: 'open_binary', input_hash: 'sha256:o', decision: 'silent', source: 'local' },
    { kind: 'post', tool: 'open_binary', input_hash: 'sha256:o', ok: true, evidence_ids: [EV('a')], limitations: ['Swift metadata not fully demangled'], bytes: 900 },
    { kind: 'post', tool: 'search_strings', input_hash: 'sha256:s', ok: true, evidence_ids: [EV('b')], limitations: [], bytes: 6000 },
    ...extra,
  ];
}
const CLOSED = { kind: 'post', tool: 'close_binary', input_hash: 'sha256:c', ok: true, evidence_ids: [], limitations: [], bytes: 40 };
/** Answers that describe a careless "done". */
const CARELESS = { claims_complete: 0.9, separates_epistemics: 0.1, cites_evidence: 0.1, unaddressed_question: 0.1, outcome: 'complete' };
/** Answers that describe a careful "done". */
const CAREFUL = { claims_complete: 0.9, separates_epistemics: 0.9, cites_evidence: 0.9, unaddressed_question: 0.1, outcome: 'complete' };

describe('free exits', () => {
  test('stop_hook_active → exit 0, nothing, no Jev call', async () => {
    const before = fake.requests.length;
    const session = newSession('stop');
    seedLedger(tmp, session, activity());
    const r = await runHook('hook-stop', payload('stop-active.json', { session_id: session }), env());
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, '');
    assert.equal(fake.requests.length, before);
  });
  test('no REA activity → exit 0, nothing, no Jev call', async () => {
    const before = fake.requests.length;
    const session = newSession('stop');
    seedLedger(tmp, session, [{ kind: 'route', prompt_excerpt: 'hello', answers: {}, declared_target: null }]);
    const r = await runHook('hook-stop', payload('stop-complete.json', { session_id: session }), env());
    assert.equal(r.code, 0);
    assert.equal(r.stdout, '');
    assert.equal(fake.requests.length, before);
  });
  test('mode off → exit 0, nothing', async () => {
    const before = fake.requests.length;
    const session = newSession('stop');
    seedLedger(tmp, session, activity());
    const r = await runHook('hook-stop', payload('stop-complete.json', { session_id: session }), env({ mode: 'off' }));
    assert.equal(r.stdout, '');
    assert.equal(fake.requests.length, before);
  });
  test('a block within the last 60 s → exit 0, no Jev call', async () => {
    const before = fake.requests.length;
    const session = newSession('stop');
    seedLedger(tmp, session, activity([{ kind: 'stop', decision: 'block', answers: {}, reason: 'earlier', t: Date.now() - 10_000 }]));
    script(CARELESS);
    const r = await runHook('hook-stop', payload('stop-complete.json', { session_id: session }), env());
    assert.equal(r.code, 0);
    assert.equal(r.stdout, '');
    assert.equal(fake.requests.length, before);
  });
  test('two blocks already in the session → exit 0, no Jev call', async () => {
    const before = fake.requests.length;
    const session = newSession('stop');
    seedLedger(tmp, session, activity([
      { kind: 'stop', decision: 'block', answers: {}, reason: 'one', t: Date.now() - 3_600_000 },
      { kind: 'stop', decision: 'block', answers: {}, reason: 'two', t: Date.now() - 1_800_000 },
    ]));
    script(CARELESS);
    const r = await runHook('hook-stop', payload('stop-complete.json', { session_id: session }), env());
    assert.equal(r.stdout, '');
    assert.equal(fake.requests.length, before);
  });
  test('an old block (> 60 s) does not stop a new check', async () => {
    const before = fake.requests.length;
    const session = newSession('stop');
    seedLedger(tmp, session, activity([{ kind: 'stop', decision: 'block', answers: {}, reason: 'old', t: Date.now() - 120_000 }]));
    script(CARELESS);
    const r = await runHook('hook-stop', payload('stop-complete.json', { session_id: session }), env());
    assert.equal(r.json?.decision, 'block');
    assert.equal(fake.requests.length, before + 1);
  });
  test('no final message anywhere → exit 0, no Jev call', async () => {
    const before = fake.requests.length;
    const session = newSession('stop');
    seedLedger(tmp, session, activity());
    const r = await runHook('hook-stop', payload('stop-transcript.json', { session_id: session, transcript_path: path.join(tmp, 'missing.jsonl') }), env());
    assert.equal(r.code, 0);
    assert.equal(r.stdout, '');
    assert.equal(fake.requests.length, before);
  });
});

describe('enforce', () => {
  test('claims_complete 0.9 + cites 0.1 + ids seen → decision block with the documented reason shape', async () => {
    const before = fake.requests.length;
    const session = newSession('stop');
    seedLedger(tmp, session, activity());
    script(CARELESS);
    const r = await runHook('hook-stop', payload('stop-complete.json', { session_id: session }), env());
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.json.decision, 'block');
    assert.match(r.json.reason, /^rea-jev: the investigation reports completion \(0\.90\) but: conclusions do not cite Evidence IDs although 2 were returned; observations, inferences, and unknowns are not told apart; the native session is still open\. /);
    assert.match(r.json.reason, /Cite the Evidence IDs behind each conclusion, state what is inferred vs observed vs unknown, and call close_binary\. If something cannot be established, say so plainly instead of presenting it as done\.$/);
    assert.equal(fake.requests.length, before + 1);
    const stop = lastStop(session);
    assert.equal(stop.decision, 'block');
    assert.equal(stop.answers.claims_complete.noul, 0.9);
    assert.equal(stop.facts.open_session_not_closed, true);
    assert.equal(stop.facts.evidence_ids_seen, 2);
  });
  test('state and questions have the documented shape; facts are computed locally', async () => {
    const before = fake.requests.length;
    const session = newSession('stop');
    seedLedger(tmp, session, activity([CLOSED, { kind: 'post', tool: 'record_unknown', input_hash: 'sha256:u', ok: true, evidence_ids: [], limitations: [], bytes: 80 }]));
    script(CAREFUL);
    const msg = `Observed: ${EV('a')} shows ExportWriter. Inferred: the PDF path. Unknown: attachments.`;
    const r = await runHook('hook-stop', payload('stop-complete.json', { session_id: session, last_assistant_message: msg }), env());
    assert.equal(r.stdout, '');
    const body = fake.requests[before].body;
    assert.deepEqual(Object.keys(body.questions).sort(), ['cites_evidence', 'claims_complete', 'outcome', 'separates_epistemics', 'unaddressed_question']);
    assert.equal(body.questions.outcome.type, 'choice');
    assert.deepEqual(Object.keys(body.questions.outcome.criteria), ['complete', 'partial_with_open_questions', 'blocked', 'not_an_investigation']);
    assert.deepEqual(Object.keys(body.state).sort(), ['final_message', 'user_request'], 'facts stay local; every state field is referenced by a question');
    assert.equal(body.state.final_message, msg);
    assert.match(body.state.user_request, /^How does the export feature/);
    assert.deepEqual(lastStop(session).facts, {
      open_session_not_closed: false,
      evidence_ids_seen: 2,
      evidence_ids_cited: 1,
      limitations_flagged: 1,
      unknowns_recorded: 1,
      tool_calls: 4,
    });
    assert.equal(lastStop(session).decision, 'allow');
  });
  test('a message that cites the returned Evidence IDs is never told it does not cite them, whatever the Noul says', async () => {
    const session = newSession('stop');
    seedLedger(tmp, session, activity([CLOSED]));
    script({ ...CAREFUL, cites_evidence: 0.1 });
    const msg = `Done. ExportWriter (${EV('a')}) writes the file; the PDF path is ${EV('b')}. Observed vs inferred vs unknown are marked above.`;
    const r = await runHook('hook-stop', payload('stop-complete.json', { session_id: session, last_assistant_message: msg }), env());
    assert.equal(r.stdout, '', 'evidence_ids_cited is 2, so the citation item cannot fire');
    assert.equal(lastStop(session).facts.evidence_ids_cited, 2);
    assert.equal(lastStop(session).decision, 'allow');
  });
  test('cites_evidence at p 0.29 (confidence 0.42, escalate) is not decisive: the item is dropped', async () => {
    const session = newSession('stop');
    seedLedger(tmp, session, activity([CLOSED]));
    script({ ...CAREFUL, cites_evidence: 0.29 });
    const r = await runHook('hook-stop', payload('stop-complete.json', { session_id: session }), env());
    assert.equal(r.stdout, '');
    assert.equal(lastStop(session).decision, 'allow');
    script({ ...CAREFUL, cites_evidence: 0.2 });
    const s2 = newSession('stop');
    seedLedger(tmp, s2, activity([CLOSED]));
    const r2 = await runHook('hook-stop', payload('stop-complete.json', { session_id: s2 }), env());
    assert.equal(r2.json?.decision, 'block', 'p 0.20 (confidence 0.60) is decisive');
  });
  test('claims_complete at p 0.72 (escalate band) degrades an enforce block to a systemMessage', async () => {
    const session = newSession('stop');
    seedLedger(tmp, session, activity());
    script({ ...CARELESS, claims_complete: 0.72 });
    const r = await runHook('hook-stop', payload('stop-complete.json', { session_id: session }), env());
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.json.decision, undefined);
    assert.match(r.json.systemMessage, /^rea-jev would have asked for: rea-jev: the investigation reports completion \(0\.72\)/);
    assert.equal(lastStop(session).decision, 'shadow_block');
  });
  test('user_request is the last reverse-engineering request, not a later follow-up prompt', async () => {
    const before = fake.requests.length;
    const session = newSession('stop');
    seedLedger(tmp, session, activity([
      CLOSED,
      { kind: 'route', prompt_excerpt: 'thanks, format that as a table', prompt_for_jev: 'thanks, format that as a table', answers: { is_re_task: { type: 'noul', noul: 0.05 } }, declared_target: SAMPLE_APP, decision: 'silent' },
    ]));
    script(CAREFUL);
    await runHook('hook-stop', payload('stop-complete.json', { session_id: session }), env());
    assert.match(fake.requests[before].body.state.user_request, /^How does the export feature/);
  });
  test('an out-of-range answer is dropped and the hook stays silent (fail open on a malformed provider)', async () => {
    const session = newSession('stop');
    seedLedger(tmp, session, activity());
    script({ ...CARELESS, claims_complete: { raw: { type: 'noul', noul: 7 } }, cites_evidence: { raw: { type: 'noul', noul: -2 } } });
    const r = await runHook('hook-stop', payload('stop-complete.json', { session_id: session }), env());
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, '');
  });
  test('a non-first outcome option is honoured: partial_with_open_questions still blocks a careless message', async () => {
    const session = newSession('stop');
    seedLedger(tmp, session, activity());
    script({ ...CARELESS, outcome: 'partial_with_open_questions' });
    const r = await runHook('hook-stop', payload('stop-complete.json', { session_id: session }), env());
    assert.equal(r.json?.decision, 'block');
  });
  test('only the triggered items are listed: open session alone', async () => {
    const session = newSession('stop');
    seedLedger(tmp, session, activity());
    script(CAREFUL);
    const r = await runHook('hook-stop', payload('stop-complete.json', { session_id: session }), env());
    assert.equal(r.json.decision, 'block');
    assert.equal(r.json.reason, 'rea-jev: the investigation reports completion (0.90) but: the native session is still open. call close_binary. If something cannot be established, say so plainly instead of presenting it as done.');
  });
  test('unaddressed_question 0.9 alone triggers a block', async () => {
    const session = newSession('stop');
    seedLedger(tmp, session, activity([CLOSED]));
    script({ ...CAREFUL, unaddressed_question: 0.9 });
    const r = await runHook('hook-stop', payload('stop-complete.json', { session_id: session }), env());
    assert.equal(r.json.decision, 'block');
    assert.match(r.json.reason, /part of the request is neither answered nor marked unresolved/);
  });
  test('cites_evidence low without any Evidence IDs seen does not trigger', async () => {
    const session = newSession('stop');
    seedLedger(tmp, session, [
      { kind: 'route', prompt_excerpt: 'q', answers: {}, declared_target: null },
      { kind: 'post', tool: 'search_strings', input_hash: 'sha256:s', ok: true, evidence_ids: [], limitations: [], bytes: 500 },
    ]);
    script({ ...CAREFUL, cites_evidence: 0.1 });
    const r = await runHook('hook-stop', payload('stop-complete.json', { session_id: session }), env());
    assert.equal(r.stdout, '');
    assert.equal(lastStop(session).decision, 'allow');
  });
  test('outcome blocked or not_an_investigation → never blocks', async () => {
    for (const outcome of ['blocked', 'not_an_investigation']) {
      const session = newSession('stop');
      seedLedger(tmp, session, activity());
      script({ ...CARELESS, outcome });
      const r = await runHook('hook-stop', payload('stop-complete.json', { session_id: session }), env());
      assert.equal(r.stdout, '', outcome);
      assert.equal(lastStop(session).decision, 'allow');
    }
  });
  test('claims_complete below T_STOP_DONE → allow; the threshold reads REA_JEV_T_STOP_DONE', async () => {
    const s1 = newSession('stop');
    seedLedger(tmp, s1, activity());
    script({ ...CARELESS, claims_complete: 0.5 });
    const low = await runHook('hook-stop', payload('stop-complete.json', { session_id: s1 }), env());
    assert.equal(low.stdout, '');
    const s2 = newSession('stop');
    seedLedger(tmp, s2, activity());
    script(CARELESS);
    const raised = await runHook('hook-stop', payload('stop-complete.json', { session_id: s2 }), env({ extra: { REA_JEV_T_STOP_DONE: '0.95' } }));
    assert.equal(raised.stdout, '');
  });
});

describe('advise and shadow', () => {
  test('advise → systemMessage only, no decision, ledger shadow_block', async () => {
    const session = newSession('stop');
    seedLedger(tmp, session, activity());
    script(CARELESS);
    const r = await runHook('hook-stop', payload('stop-complete.json', { session_id: session }), env({ mode: 'advise' }));
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.json.decision, undefined);
    assert.match(r.json.systemMessage, /^rea-jev would have asked for: rea-jev: the investigation reports completion \(0\.90\) but: /);
    assert.equal(lastStop(session).decision, 'shadow_block');
  });
  test('shadow → systemMessage with the would-have verdict', async () => {
    const session = newSession('stop');
    seedLedger(tmp, session, activity());
    script(CARELESS);
    const r = await runHook('hook-stop', payload('stop-complete.json', { session_id: session }), env({ mode: 'shadow' }));
    assert.match(r.json.systemMessage, /would have asked for/);
    assert.equal(lastStop(session).decision, 'shadow_block');
  });
  test('advise with a careful message → nothing', async () => {
    const session = newSession('stop');
    seedLedger(tmp, session, activity([CLOSED]));
    script(CAREFUL);
    const r = await runHook('hook-stop', payload('stop-complete.json', { session_id: session }), env({ mode: 'advise' }));
    assert.equal(r.stdout, '');
  });
});

describe('transcript fallback', () => {
  test('without last_assistant_message the last assistant text is read from transcript_path, joined across lines, sidechains ignored', async () => {
    const before = fake.requests.length;
    const session = newSession('stop');
    seedLedger(tmp, session, activity());
    script(CARELESS);
    const r = await runHook('hook-stop', payload('stop-transcript.json', { session_id: session, transcript_path: TRANSCRIPT }), env());
    assert.equal(r.json?.decision, 'block');
    const sent = fake.requests[before].body.state.final_message;
    assert.equal(sent, 'FROM TRANSCRIPT: The export feature runs ExportDocumentCommand and writes via ExportWriter.\nThe investigation is complete.');
    assert.doesNotMatch(sent, /SUBAGENT|Opening the binary first/);
  });
  test('an unreadable or malformed transcript → exit 0, no Jev call', async () => {
    const before = fake.requests.length;
    const session = newSession('stop');
    seedLedger(tmp, session, activity());
    const garbage = path.join(tmp, 'garbage.jsonl');
    fs.writeFileSync(garbage, 'not json\n{"type":"user","message":{"role":"user","content":"hi"}}\n');
    const r = await runHook('hook-stop', payload('stop-transcript.json', { session_id: session, transcript_path: garbage }), env());
    assert.equal(r.code, 0);
    assert.equal(r.stdout, '');
    const dir = await runHook('hook-stop', payload('stop-transcript.json', { session_id: session, transcript_path: tmp }), env());
    assert.equal(dir.stdout, '');
    assert.equal(fake.requests.length, before);
  });
});

describe('fail-open', () => {
  test('Jev 500 → exit 0, nothing, no stop event', async () => {
    const session = newSession('stop');
    seedLedger(tmp, session, activity());
    const r = await runHook('hook-stop', payload('stop-complete.json', { session_id: session }), env({ fakeUrl: fake500.url }));
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, '');
    assert.equal(lastStop(session), undefined);
  });
  test('no key → exit 0, nothing, no request', async () => {
    const before = fake.requests.length;
    const session = newSession('stop');
    seedLedger(tmp, session, activity());
    const r = await runHook('hook-stop', payload('stop-complete.json', { session_id: session }), env({ key: false }));
    assert.equal(r.stdout, '');
    assert.equal(fake.requests.length, before);
  });
  test('secrets in the final message are redacted before they leave the machine', async () => {
    const before = fake.requests.length;
    const session = newSession('stop');
    seedLedger(tmp, session, activity([CLOSED]));
    script(CAREFUL);
    await runHook('hook-stop', payload('stop-complete.json', { session_id: session, last_assistant_message: 'Done. The app sends Authorization: Bearer abcdefghijklmnopqrstuvwxyz to its API.' }), env());
    const sent = fake.requests[before].body.state.final_message;
    assert.doesNotMatch(sent, /abcdefghijklmnopqrstuvwxyz/);
    assert.match(sent, /REDACTED/);
  });
  test('invalid stdin → exit 0, nothing', async () => {
    const r = await runHook('hook-stop', '[]', env());
    assert.equal(r.code, 0);
    assert.equal(r.stdout, '');
  });
});
