/**
 * Ledger (scripts/lib/ledger.mjs): the derived facts the hooks depend on, the
 * request that follows the last reverse-engineering route, non-reusable empty
 * posts, and the tail read that keeps the route event of an oversize file.
 */
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { appendEvent, readEvents, summarize, sessionPath } from '../scripts/lib/ledger.mjs';
import { salvageOversize } from '../scripts/lib/hookio.mjs';

let home;
let env;
before(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'rea-jev-ledger-'));
  env = { ...process.env, REA_JEV_HOME: home };
  delete env.CLAUDE_PLUGIN_DATA;
});
after(() => fs.rmSync(home, { recursive: true, force: true }));

const RE = { kind: 'route', prompt_excerpt: 'How does export work in Sample.app?', prompt_for_jev: 'How does export work in Sample.app? Trace it to the writer.', answers: { is_re_task: { type: 'noul', noul: 0.9 } }, declared_target: '/Applications/Sample.app', decision: 'route' };
const FOLLOW_UP = { kind: 'route', prompt_excerpt: 'thanks, format that as a table', prompt_for_jev: 'thanks, format that as a table', answers: { is_re_task: { type: 'noul', noul: 0.05 } }, declared_target: '/Applications/Sample.app', decision: 'silent' };

describe('summarize', () => {
  test('lastReRoute / userRequest skip non-RE follow-ups; lastRoute and declaredTarget still see them', () => {
    const s = summarize([RE, FOLLOW_UP]);
    assert.equal(s.lastRoute, FOLLOW_UP);
    assert.equal(s.lastReRoute, RE);
    assert.equal(s.userRequest, RE.prompt_for_jev);
    assert.equal(s.declaredTarget, '/Applications/Sample.app');
    const belowThreshold = { ...RE, decision: 'route', answers: { is_re_task: { type: 'noul', noul: 0.2 } } };
    assert.equal(summarize([RE, belowThreshold]).lastReRoute, RE, 'is_re_task below T_ROUTE_RE is not an RE route even without decision silent');
    assert.equal(summarize([RE, { ...belowThreshold, prompt_for_jev: 'x' }], { routeRe: 0.1 }).userRequest, 'x', 'the cutoff is tunable');
  });
  test('userRequest falls back to prompt_excerpt for old route events and is empty without a route', () => {
    assert.equal(summarize([{ kind: 'route', prompt_excerpt: 'old style', answers: {}, declared_target: null }]).userRequest, 'old style');
    assert.equal(summarize([{ kind: 'route', prompt_excerpt: 'old style', answers: {}, declared_target: null }]).lastReRoute.prompt_excerpt, 'old style');
    assert.equal(summarize([]).userRequest, '');
    assert.equal(summarize([FOLLOW_UP]).userRequest, '');
  });
  test('a post with no body (0 bytes, no Evidence ID) or ok:false is never a reusable identical call', () => {
    const base = { kind: 'post', tool: 'search_strings', input_hash: 'sha256:h', limitations: [] };
    assert.equal(summarize([{ ...base, ok: true, bytes: 0, evidence_ids: [] }]).identicalCallSeen('search_strings', 'sha256:h'), false);
    assert.equal(summarize([{ ...base, ok: false, bytes: 500, evidence_ids: [] }]).identicalCallSeen('search_strings', 'sha256:h'), false);
    assert.equal(summarize([{ ...base, ok: true, bytes: 500, evidence_ids: [] }]).identicalCallSeen('search_strings', 'sha256:h'), true);
    assert.equal(summarize([{ ...base, ok: true, bytes: 0, evidence_ids: [`ev_${'a'.repeat(64)}`] }]).identicalCallSeen('search_strings', 'sha256:h'), true);
    assert.equal(summarize([{ ...base, ok: true, bytes: 500, evidence_ids: [] }, { kind: 'post', tool: 'set_comment', input_hash: 'sha256:m', ok: true, bytes: 10 }]).identicalCallSeen('search_strings', 'sha256:h'), false, 'a mutation resets the window');
  });
});

describe('readEvents', () => {
  test('a file over maxBytes is read from the tail, but the latest route event from the dropped head is kept', () => {
    const session = `tail-${process.pid}-${Date.now()}`;
    appendEvent(session, { kind: 'route', prompt_excerpt: 'first', answers: {}, declared_target: '/a' }, env);
    appendEvent(session, { kind: 'route', prompt_excerpt: 'second', prompt_for_jev: 'second long', answers: {}, declared_target: '/b' }, env);
    const bulk = 'x'.repeat(4000);
    for (let i = 0; i < 40; i += 1) appendEvent(session, { kind: 'post', tool: 'search_strings', input_hash: `sha256:${i}`, ok: true, evidence_ids: [], limitations: [bulk], bytes: 1 }, env);
    const size = fs.statSync(sessionPath(session, env)).size;
    const events = readEvents(session, env, { maxBytes: Math.floor(size / 4) });
    assert.ok(events.length < 42 && events.length > 5, `tail read returned ${events.length} events`);
    assert.equal(events[0].kind, 'route');
    assert.equal(events[0].prompt_excerpt, 'second', 'the latest route, not the first');
    const s = summarize(events);
    assert.equal(s.declaredTarget, '/b');
    assert.equal(s.userRequest, 'second long');
    assert.equal(summarize(readEvents(session, env)).events.length, 42, 'a full read is unchanged');
  });
  test('a route inside the tail is not duplicated', () => {
    const session = `tail2-${process.pid}-${Date.now()}`;
    for (let i = 0; i < 20; i += 1) appendEvent(session, { kind: 'post', tool: 't', input_hash: `sha256:${i}`, ok: true, evidence_ids: [], limitations: ['y'.repeat(2000)], bytes: 1 }, env);
    appendEvent(session, { kind: 'route', prompt_excerpt: 'late', answers: {}, declared_target: '/c' }, env);
    const size = fs.statSync(sessionPath(session, env)).size;
    const events = readEvents(session, env, { maxBytes: Math.floor(size / 3) });
    assert.equal(events.filter((e) => e.kind === 'route').length, 1);
    assert.equal(summarize(events).declaredTarget, '/c');
  });
});

describe('salvageOversize', () => {
  test('recovers the fields before the oversize key and marks the total size', () => {
    const head = '{"session_id":"s1","cwd":"/p","tool_name":"mcp__rea__search_strings","tool_input":{"pattern":"Export"},"tool_use_id":"t1","tool_response":{"content":[{"type":"text","text":"xxxxxxxxxxxxx';
    const out = salvageOversize(head, 'tool_response', 99_000_000);
    assert.deepEqual(out, { session_id: 's1', cwd: '/p', tool_name: 'mcp__rea__search_strings', tool_input: { pattern: 'Export' }, tool_use_id: 't1', __oversize_bytes__: 99_000_000 });
    assert.equal(salvageOversize('{"a":1,"huge":"' + 'x'.repeat(100), 'tool_response', 5), null, 'key not in the head');
    assert.equal(salvageOversize('{"tool_input":{"nested":"', 'tool_response', 5), null);
  });
});
