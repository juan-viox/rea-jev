import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { startFakeJev } from './fake-jev.mjs';
import { parseItems, normalizeItems, balancedChunks, verdictOf, RANK_CHUNK, CLASSIFY_BATCH, MAX_CONCURRENCY } from '../scripts/jev.mjs';

const CLI = fileURLToPath(new URL('../scripts/jev.mjs', import.meta.url));

let tmp;
let fake;
before(async () => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rea-jev-cli-'));
  fake = await startFakeJev();
});
after(async () => {
  await fake.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

/** Environment with every real key stripped, pointed at the fake and a temp ledger dir. */
function cleanEnv(extra = {}) {
  const env = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (/^(TYPESAFE_API_KEY|OPENROUTER_API_KEY|JEV_BASE_URL|REA_JEV_|CLAUDE_PLUGIN_)/.test(k)) continue;
    env[k] = v;
  }
  return { ...env, REA_JEV_HOME: tmp, REA_JEV_LOG: '0', REA_JEV_TIMEOUT_MS: '5000', ...extra };
}

function withKey(extra = {}) {
  return cleanEnv({ TYPESAFE_API_KEY: 'test-key-not-real', JEV_BASE_URL: fake.url, ...extra });
}

function run(args, { env = withKey(), input } = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { env, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('close', (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(input ?? '');
  });
}

function writeTmp(name, text) {
  const p = path.join(tmp, name);
  fs.writeFileSync(p, text);
  return p;
}

const parse = (r) => {
  try {
    return JSON.parse(r.stdout);
  } catch (err) {
    throw new Error(`stdout is not JSON (exit ${r.code}): ${r.stdout.slice(0, 300)} / stderr: ${r.stderr.slice(0, 300)}`);
  }
};

describe('usage and help', () => {
  test('no command → exit 1 with usage; --help → exit 0; --version prints version', async () => {
    const none = await run([]);
    assert.equal(none.code, 1);
    assert.match(none.stderr, /Usage:/);
    const help = await run(['--help']);
    assert.equal(help.code, 0);
    assert.match(help.stdout, /jev rank/);
    const ver = await run(['--version']);
    assert.equal(ver.code, 0);
    assert.match(ver.stdout, /^\d+\.\d+\.\d+/);
  });
  test('unknown command / unknown flag / missing args → exit 1', async () => {
    assert.equal((await run(['bogus'])).code, 1);
    assert.equal((await run(['ask', '--nope'])).code, 1);
    const r = await run(['rank', '--items', '/dev/null']);
    assert.equal(r.code, 1);
    assert.match(r.stderr, /rank needs a query/);
  });
});

describe('ask', () => {
  test('inline state and questions → answers with confidence and band, exit 0', async () => {
    fake.script.is_urgent = 0.95;
    const r = await run(['ask', '--json', '--state', '{"msg":"payouts failing for 3 days"}', '--questions', '{"is_urgent":{"type":"noul","instructions":"Does `msg` convey urgency?"}}']);
    assert.equal(r.code, 0, r.stderr);
    const j = parse(r);
    assert.equal(j.ok, true);
    assert.equal(j.command, 'ask');
    assert.equal(j.answers.is_urgent.noul, 0.95);
    assert.ok(Math.abs(j.answers.is_urgent.confidence - 0.9) < 1e-6);
    assert.equal(j.answers.is_urgent.band, 'act');
    assert.equal(j.provider, 'typesafe');
    assert.ok(j.cost_usd >= 0);
    delete fake.script.is_urgent;
  });
  test('human output lists each key with conf and band', async () => {
    const r = await run(['ask', '--state', 'plain text state', '--questions', '{"q":{"type":"noul","instructions":"Is it?"}}']);
    assert.equal(r.code, 0, r.stderr);
    assert.match(r.stdout, /^q\s+noul\s+p=0\.500\s+conf=0\.000 band=escalate/m);
    assert.match(r.stdout, /typesafe jev-1\.13\.0-fake/);
  });
  test('state from stdin (-) and secrets are redacted before sending', async () => {
    const before = fake.requests.length;
    const r = await run(['ask', '--json', '--state', '-', '--questions', '{"q":{"type":"noul","instructions":"Is it?"}}'], {
      input: '{"cmd":"curl -H \'Authorization: Bearer abcdefghijklmnop\' https://user:pw@host/x", "key":"sk-abcdefghijklmnopqrstuvwxyz"}',
    });
    assert.equal(r.code, 0, r.stderr);
    const sent = JSON.stringify(fake.requests[before].body.state);
    assert.doesNotMatch(sent, /abcdefghijklmnop|user:pw|sk-abcdefghijklmnopqrstuvwxyz/);
    assert.match(sent, /REDACTED/);
  });
  test('provider failure → exit 2 with reason (human and json)', async () => {
    const r = await run(['ask', '--state', '{"__fake__":"500"}', '--questions', '{"q":{"type":"noul","instructions":"Is it?"}}']);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /http_5xx/);
    const j = await run(['ask', '--json', '--state', '{"__fake__":"500"}', '--questions', '{"q":{"type":"noul","instructions":"Is it?"}}']);
    assert.equal(j.code, 2);
    assert.equal(parse(j).reason, 'http_5xx');
    assert.equal(parse(j).status, 500);
  });
  test('no key → exit 2 no_key', async () => {
    const r = await run(['ask', '--json', '--state', 'x', '--questions', '{"q":{"type":"noul","instructions":"Is it?"}}'], { env: cleanEnv({ JEV_BASE_URL: fake.url }) });
    assert.equal(r.code, 2);
    assert.equal(parse(r).reason, 'no_key');
  });
  test('429 then 200 → the retry really happens in a child process (exit 0, two requests seen)', async () => {
    const s = await startFakeJev({ scenario: '429-then-200' });
    try {
      const r = await run(['ask', '--json', '--state', '{"a":1}', '--questions', '{"q":{"type":"noul","instructions":"Is it?"}}'], { env: withKey({ JEV_BASE_URL: s.url }) });
      assert.equal(r.code, 0, `exit ${r.code}: ${r.stderr}`);
      assert.equal(parse(r).ok, true);
      assert.equal(s.requests.length, 2, 'one retry after the 429');
    } finally {
      await s.close();
    }
  });
  test('permanent 429 → exit 2 with http_4xx after two attempts, not a silent exit 0', async () => {
    const s = await startFakeJev({ scenario: '429' });
    try {
      const r = await run(['ask', '--json', '--state', '{"a":1}', '--questions', '{"q":{"type":"noul","instructions":"Is it?"}}'], { env: withKey({ JEV_BASE_URL: s.url }) });
      assert.equal(r.code, 2);
      const j = parse(r);
      assert.equal(j.reason, 'http_4xx');
      assert.equal(j.status, 429);
      assert.equal(j.attempts, 2);
      assert.match(r.stderr, /429/);
    } finally {
      await s.close();
    }
  });
  test('a numeric credential value is redacted structurally and the state stays an object', async () => {
    const before = fake.requests.length;
    const r = await run(['ask', '--json', '--state', '{"token": 12345, "nested": {"api_key": 7, "PWD": "/home/u"}, "x": 1}', '--questions', '{"q":{"type":"noul","instructions":"Is it?"}}']);
    assert.equal(r.code, 0, r.stderr);
    const sent = fake.requests[before].body.state;
    assert.equal(typeof sent, 'object');
    assert.deepEqual(sent, { token: '[REDACTED:kv]', nested: { api_key: '[REDACTED:kv]', PWD: '/home/u' }, x: 1 });
  });
});

describe('rank', () => {
  test('450 JSON-lines items → 3 balanced requests of ≤200, one Choice + match_exists each, merged by probability', async () => {
    const lines = Array.from({ length: 450 }, (_, i) => JSON.stringify({ id: `item-${i}`, text: `string number ${i} from the binary` }));
    const file = writeTmp('items450.jsonl', lines.join('\n') + '\n');
    fake.script.best = (q) => ('item-437' in q.criteria ? 'item-437' : 'item-3' in q.criteria ? 'item-3' : undefined);
    fake.script.match_exists = (q, state) => ('item-437' in (state.items ?? {}) ? 0.9 : 0.2);
    const before = fake.requests.length;
    const r = await run(['rank', 'the license check string', '--items', file, '--top', '5', '--json']);
    assert.equal(r.code, 0, r.stderr);
    const reqs = fake.requests.slice(before);
    assert.equal(reqs.length, 3);
    const sizes = reqs.map((x) => Object.keys(x.body.questions.best.criteria).length).sort((a, b) => a - b);
    assert.deepEqual(sizes, [150, 150, 150], 'balanced chunks: a small last chunk would inflate its p_in_chunk');
    for (const x of reqs) {
      assert.deepEqual(Object.keys(x.body.questions).sort(), ['best', 'match_exists']);
      assert.equal(x.body.questions.best.type, 'choice');
      assert.equal(x.body.questions.match_exists.type, 'noul');
      assert.ok(Object.keys(x.body.questions.best.criteria).length <= RANK_CHUNK);
      assert.equal(x.body.state.query, 'the license check string');
    }
    const j = parse(r);
    assert.equal(j.ok, true);
    assert.equal(j.items_total, 450);
    assert.equal(j.chunks, 3);
    assert.equal(j.requests, 3);
    assert.equal(j.items.length, 5);
    assert.deepEqual(j.items.map((x) => x.rank), [1, 2, 3, 4, 5]);
    assert.equal(j.items[0].id, 'item-437');
    assert.ok(Math.abs(j.items[0].p - 0.9 * 0.9) < 1e-6, `p=${j.items[0].p}`);
    assert.equal(j.items[1].id, 'item-3', 'the other chunk winner, scaled down by its low match_exists');
    assert.ok(Math.abs(j.items[1].p - 0.9 * 0.2) < 1e-6);
    assert.equal(j.match_exists, 0.9);
    assert.ok(j.usage.input_tokens > 0);
    delete fake.script.best;
    delete fake.script.match_exists;
  });
  test('plain lines and a JSON array work; human output has rank/p/id/preview columns', async () => {
    const plain = writeTmp('plain.txt', 'alpha string\nbeta string\ngamma string\n');
    const r = await run(['rank', 'beta', '--items', plain, '--top', '2']);
    assert.equal(r.code, 0, r.stderr);
    assert.match(r.stdout, /^rank\s+p\s+id\s+preview/m);
    assert.match(r.stdout, /^\s+1\s+0\.\d{3}\s+\S+\s+\S/m);
    assert.match(r.stdout, /3 items in 1 request/);
    const arr = writeTmp('arr.json', JSON.stringify([{ address: '0x1000', name: 'sub_1000' }, { address: '0x2000', name: 'checkLicense' }]));
    const j = await run(['rank', 'license', '--items', arr, '--json']);
    assert.equal(j.code, 0, j.stderr);
    assert.deepEqual(parse(j).items.map((x) => x.id).sort(), ['0x1000', '0x2000']);
  });
  test('an REA result envelope object is accepted (first array inside)', async () => {
    const env = writeTmp('rea.json', JSON.stringify({ result: { strings: [{ address: '0x10', value: 'hello' }, { address: '0x20', value: 'world' }] }, evidence_id: `ev_${'a'.repeat(64)}` }));
    const r = await run(['rank', 'greeting', '--items', env, '--json']);
    assert.equal(r.code, 0, r.stderr);
    assert.equal(parse(r).items_total, 2);
  });
  test('a single item still forms a valid Choice (sentinel option) and stdin works', async () => {
    const r = await run(['rank', 'x', '--items', '-', '--json'], { input: 'only one\n' });
    assert.equal(r.code, 0, r.stderr);
    assert.equal(parse(r).items.length, 1);
  });
  test('items file over 2 MB is refused without --force', async () => {
    const big = writeTmp('big.txt', 'x'.repeat(2 * 1024 * 1024 + 10));
    const r = await run(['rank', 'q', '--items', big]);
    assert.equal(r.code, 1);
    assert.match(r.stderr, /--force/);
  });
  test('provider failure (unreachable endpoint) → exit 2 with ok:false', async () => {
    const file = writeTmp('fail.txt', 'a\nb\n');
    const bad = await run(['rank', 'q', '--items', file, '--json'], { env: withKey({ JEV_BASE_URL: 'http://127.0.0.1:9/' }) });
    assert.equal(bad.code, 2);
    assert.equal(parse(bad).ok, false);
    assert.equal(parse(bad).command, 'rank');
  });
  test('chunks are sent at most MAX_CONCURRENCY at a time', async () => {
    const slow = await startFakeJev({ latencyMs: 60 });
    try {
      const lines = Array.from({ length: 2000 }, (_, i) => `candidate string ${i}`);
      const file = writeTmp('items2000.txt', lines.join('\n'));
      const r = await run(['rank', 'q', '--items', file, '--json'], { env: withKey({ JEV_BASE_URL: slow.url }) });
      assert.equal(r.code, 0, r.stderr);
      assert.equal(parse(r).requests, 10);
      assert.equal(slow.requests.length, 10);
      assert.ok(slow.maxInflight <= MAX_CONCURRENCY, `max in flight ${slow.maxInflight}`);
      assert.ok(slow.maxInflight >= 2, 'requests do run concurrently');
    } finally {
      await slow.close();
    }
  });
  test('one failed chunk degrades to a partial answer (exit 0, partial:true) instead of failing the command', async () => {
    const lines = Array.from({ length: 300 }, (_, i) => JSON.stringify({ id: `item-${i}`, text: `string ${i}` }));
    const file = writeTmp('partial.jsonl', lines.join('\n'));
    fake.script.best = (q) => {
      if ('item-5' in q.criteria) throw new Error('boom');
      return 'item-299' in q.criteria ? 'item-299' : undefined;
    };
    const r = await run(['rank', 'q', '--items', file, '--json']);
    assert.equal(r.code, 0, r.stderr);
    const j = parse(r);
    assert.equal(j.partial, true);
    assert.equal(j.failed_chunks, 1);
    assert.equal(j.unranked_items, 150);
    assert.equal(j.items[0].id, 'item-299');
    assert.ok(j.items.every((it) => Number(it.id.slice(5)) >= 150), 'items from the failed chunk are not ranked');
    const human = await run(['rank', 'q', '--items', file]);
    assert.match(human.stdout, /PARTIAL: 1 of 2 requests failed/);
    delete fake.script.best;
  });
  test('balancedChunks (in-process) keeps sizes within one of each other and under the budget', () => {
    const items = Array.from({ length: 450 }, (_, i) => ({ id: `i${i}`, text: 'x'.repeat(380) }));
    const chunks = balancedChunks(items, 200, 300, 2);
    const sizes = chunks.map((c) => c.length);
    assert.ok(chunks.length >= 4, `token budget forces ≥ 4 chunks, got ${chunks.length}`);
    assert.ok(Math.max(...sizes) - Math.min(...sizes) <= 1, `unbalanced: ${sizes}`);
    assert.equal(sizes.reduce((a, b) => a + b, 0), 450);
    assert.deepEqual(balancedChunks(items.slice(0, 10), 200, 300, 2).map((c) => c.length), [10]);
  });
});

describe('classify', () => {
  test('95 items → 3 batches (40,40,15), keys item_<i>, one Choice per item, labels applied', async () => {
    const items = Array.from({ length: 95 }, (_, i) => `proc_${i}`);
    const file = writeTmp('procs.txt', items.join('\n'));
    fake.script.item_7 = 'network';
    fake.script.item_94 = 'crypto';
    const before = fake.requests.length;
    const r = await run(['classify', '--items', file, '--labels', 'parser,network,storage=Persists data,ui,crypto,other', '--instructions', 'What role does this procedure play?', '--json']);
    assert.equal(r.code, 0, r.stderr);
    const reqs = fake.requests.slice(before);
    assert.equal(reqs.length, 3);
    assert.deepEqual(reqs.map((x) => Object.keys(x.body.questions).length).sort((a, b) => a - b), [15, 40, 40]);
    const allKeys = reqs.flatMap((x) => Object.keys(x.body.questions)).sort((a, b) => Number(a.slice(5)) - Number(b.slice(5)));
    assert.deepEqual(allKeys, items.map((_, i) => `item_${i}`));
    for (const x of reqs) {
      for (const [k, q] of Object.entries(x.body.questions)) {
        assert.equal(q.type, 'choice');
        assert.deepEqual(Object.keys(q.criteria), ['parser', 'network', 'storage', 'ui', 'crypto', 'other']);
        assert.equal(q.criteria.storage, 'Persists data');
        assert.ok(q.instructions.startsWith('What role does this procedure play?'), 'the judgment lives in the question, not in the state');
        assert.ok(q.instructions.includes(`\`items.${k}\``));
        assert.ok(k in x.body.state.items);
      }
      assert.deepEqual(Object.keys(x.body.state), ['items'], 'state holds only the content');
      assert.ok(Object.keys(x.body.questions).length <= CLASSIFY_BATCH);
    }
    const j = parse(r);
    assert.equal(j.items.length, 95);
    assert.equal(j.batches, 3);
    assert.equal(j.added_label, undefined, 'an explicit other label is kept as is');
    assert.equal(j.items[7].label, 'network');
    assert.equal(j.items[7].id, '8');
    assert.equal(j.items[94].label, 'crypto');
    assert.equal(j.items[0].label, 'parser');
    assert.ok(j.items[0].p > 0.5 && j.items[0].confidence > 0 && ['act', 'confirm', 'escalate'].includes(j.items[0].band));
    assert.equal(j.counts.network, 1);
    assert.equal(j.counts.parser, 93);
    delete fake.script.item_7;
    delete fake.script.item_94;
  });
  test('a label set without other/none gets `other` appended and says so', async () => {
    const file = writeTmp('two-labels.txt', 'a\nb');
    const before = fake.requests.length;
    const r = await run(['classify', '--items', file, '--labels', 'parser,network', '--instructions', 'Which role?', '--json']);
    assert.equal(r.code, 0, r.stderr);
    const j = parse(r);
    assert.deepEqual(j.labels, ['parser', 'network', 'other']);
    assert.equal(j.added_label, 'other');
    assert.deepEqual(Object.keys(fake.requests[before].body.questions.item_0.criteria), ['parser', 'network', 'other']);
    const human = await run(['classify', '--items', file, '--labels', 'parser,network', '--instructions', 'Which role?']);
    assert.match(human.stdout, /note: added label "other"/);
    const none = await run(['classify', '--items', file, '--labels', 'parser,none', '--instructions', 'Which role?', '--json']);
    assert.deepEqual(parse(none).labels, ['parser', 'none']);
  });
  test('missing --labels / --instructions / fewer than two labels → exit 1', async () => {
    const file = writeTmp('two.txt', 'a\nb');
    assert.equal((await run(['classify', '--items', file, '--instructions', 'q'])).code, 1);
    assert.equal((await run(['classify', '--items', file, '--labels', 'a,b'])).code, 1);
    assert.equal((await run(['classify', '--items', file, '--labels', 'onlyone', '--instructions', 'q'])).code, 1);
  });
});

describe('verify', () => {
  const evidence = writeTmpLater();
  function writeTmpLater() {
    return () => writeTmp('evidence.txt', 'search_strings found "LicenseCheckFailed" at 0x100045a0; xrefs from sub_10000f3a0.');
  }
  const cases = [
    { name: 'supported', script: { supported: 0.9, contradicted: 0.05, needs_runtime: 0.1, overstated: 0.1 }, verdict: 'supported', band: 'act' },
    { name: 'contradicted wins', script: { supported: 0.6, contradicted: 0.8, needs_runtime: 0.1, overstated: 0.1 }, verdict: 'contradicted', band: 'confirm' },
    { name: 'needs runtime when not supported', script: { supported: 0.2, contradicted: 0.1, needs_runtime: 0.9, overstated: 0.2 }, verdict: 'needs_runtime', band: 'act' },
    { name: 'weakly supported → insufficient', script: { supported: 0.3, contradicted: 0.1, needs_runtime: 0.1, overstated: 0.2 }, verdict: 'insufficient' },
    { name: 'supported but overstated → insufficient', script: { supported: 0.9, contradicted: 0.1, needs_runtime: 0.1, overstated: 0.8 }, verdict: 'insufficient' },
    { name: 'supported and runtime-flagged → supported (static evidence suffices)', script: { supported: 0.9, contradicted: 0.1, needs_runtime: 0.9, overstated: 0.1 }, verdict: 'supported' },
    { name: 'contradicted at p 0.60 is a coin flip → insufficient, never categorical', script: { supported: 0.65, contradicted: 0.6, needs_runtime: 0.1, overstated: 0.1 }, verdict: 'insufficient' },
    { name: 'supported at p 0.72 (confidence 0.44, escalate) → insufficient', script: { supported: 0.72, contradicted: 0.1, needs_runtime: 0.1, overstated: 0.1 }, verdict: 'insufficient' },
    { name: 'supported at p 0.75 (confidence 0.50, confirm) → supported in the confirm band', script: { supported: 0.75, contradicted: 0.1, needs_runtime: 0.1, overstated: 0.1 }, verdict: 'supported', band: 'confirm' },
  ];
  for (const c of cases) {
    test(`verdict: ${c.name} → ${c.verdict}`, async () => {
      Object.assign(fake.script, c.script);
      const r = await run(['verify', '--claim', 'The license check lives in sub_10000f3a0', '--evidence', evidence(), '--json']);
      assert.equal(r.code, 0, r.stderr);
      const j = parse(r);
      assert.equal(j.verdict, c.verdict);
      if (c.band) assert.equal(j.verdict_band, c.band);
      assert.ok(typeof j.verdict_confidence === 'number' && ['act', 'confirm', 'escalate'].includes(j.verdict_band));
      assert.deepEqual(Object.keys(j.answers).sort(), ['contradicted', 'needs_runtime', 'overstated', 'supported']);
      assert.equal(j.evidence_truncated, false);
      for (const k of Object.keys(c.script)) delete fake.script[k];
    });
  }
  test('verdictOf (in-process) reports the deciding Noul, its confidence and band, and the downgrade', () => {
    const n = (p) => ({ type: 'noul', noul: p });
    const v = verdictOf({ supported: n(0.9), contradicted: n(0.05), needs_runtime: n(0.1), overstated: n(0.1) });
    assert.deepEqual(v, { verdict: 'supported', decidedBy: 'supported', confidence: 0.8, band: 'act' });
    const low = verdictOf({ supported: n(0.72), contradicted: n(0.1), needs_runtime: n(0.1), overstated: n(0.1) });
    assert.equal(low.verdict, 'insufficient');
    assert.equal(low.decidedBy, 'supported');
    assert.equal(low.band, 'escalate');
    assert.equal(verdictOf({ supported: n(0.3), contradicted: n(0.1), needs_runtime: n(0.1), overstated: n(0.1) }).downgradedFrom, undefined);
  });
  test('human output prints the verdict with p, confidence and band; long evidence is truncated to 20k chars', async () => {
    Object.assign(fake.script, { supported: 0.9, contradicted: 0.05, needs_runtime: 0.1, overstated: 0.1 });
    const ok = await run(['verify', '--claim', 'c', '--evidence', evidence()]);
    assert.match(ok.stdout, /^verdict: supported \(decided by supported at p 0\.900, confidence 0\.800, band act\)/m);
    for (const k of ['supported', 'contradicted', 'needs_runtime', 'overstated']) delete fake.script[k];
    const long = writeTmp('long.txt', 'y'.repeat(30000));
    const before = fake.requests.length;
    const r = await run(['verify', '--claim', 'c', '--evidence', long]);
    assert.equal(r.code, 0, r.stderr);
    assert.match(r.stdout, /^verdict: insufficient/m);
    assert.match(r.stdout, /evidence truncated to 20000 chars/);
    const sent = fake.requests[before].body.state.evidence;
    assert.ok(sent.length < 20100 && sent.includes('chars omitted'));
    assert.equal(fake.requests[before].body.state.claim, 'c');
  });
  test('--claim-file reads the claim from a file (or stdin) so tool output is never interpolated into a shell line', async () => {
    const before = fake.requests.length;
    const nasty = 'The string "$(rm -rf /)" and `whoami` appear in the binary';
    const claimFile = writeTmp('claim.txt', `${nasty}\n`);
    const r = await run(['verify', '--claim-file', claimFile, '--evidence', evidence(), '--json']);
    assert.equal(r.code, 0, r.stderr);
    assert.equal(fake.requests[before].body.state.claim, nasty);
    const viaStdin = await run(['verify', '--claim-file', '-', '--evidence', evidence(), '--json'], { input: nasty });
    assert.equal(viaStdin.code, 0, viaStdin.stderr);
    assert.equal(parse(viaStdin).claim, nasty);
    assert.equal((await run(['verify', '--claim', 'x', '--claim-file', claimFile, '--evidence', evidence()])).code, 1, 'not both');
    assert.equal((await run(['verify', '--claim-file', '-', '--evidence', '-'])).code, 1, 'stdin only once');
    assert.equal((await run(['verify', '--claim-file', path.join(tmp, 'missing.txt'), '--evidence', evidence()])).code, 1);
  });
  test('missing --claim or --evidence → exit 1', async () => {
    assert.equal((await run(['verify', '--evidence', evidence()])).code, 1);
    assert.equal((await run(['verify', '--claim', 'x'])).code, 1);
  });
});

describe('doctor', () => {
  test('without a key → reports no_key and exits 2 (json)', async () => {
    const r = await run(['doctor', '--json', '--offline'], { env: cleanEnv() });
    assert.equal(r.code, 2);
    const j = parse(r);
    assert.equal(j.ok, false);
    assert.equal(j.provider, null);
    assert.equal(j.round_trip.reason, 'no_key');
    assert.ok(j.problems.some((p) => /TYPESAFE_API_KEY/.test(p)));
    assert.equal(j.rea.pin, '4.0.1');
    assert.equal(j.rea.npx.status, 'skipped');
    assert.equal(j.ledger.dir, tmp);
    assert.equal(j.mode, 'advise');
  });
  test('without a key, human output exits 2 and names the problem', async () => {
    const r = await run(['doctor', '--offline'], { env: cleanEnv() });
    assert.equal(r.code, 2);
    assert.match(r.stdout, /round trip\s+no_key/);
    assert.match(r.stdout, /problems:/);
  });
  test('with a key → round trip ok, latency and model reported, exit 0', async () => {
    const r = await run(['doctor', '--json', '--offline'], { env: withKey({ REA_JEV_MODE: 'enforce' }) });
    assert.equal(r.code, 0, r.stderr);
    const j = parse(r);
    assert.equal(j.round_trip.ok, true);
    assert.equal(j.round_trip.model, 'jev-1.13.0-fake');
    assert.ok(j.round_trip.latency_ms >= 0);
    assert.equal(j.provider.id, 'typesafe');
    assert.equal(j.provider.key_source, 'TYPESAFE_API_KEY');
    assert.equal(j.provider.endpoint_override, true);
    assert.equal(j.mode, 'enforce');
    assert.equal(j.rea.catalog_tools, 116);
    assert.equal(j.ledger.writable, true);
    assert.doesNotMatch(r.stdout, /test-key-not-real/, 'the key must never be printed');
  });
  test('with a key but the endpoint down → exit 2 with the failure reason', async () => {
    const r = await run(['doctor', '--json', '--offline'], { env: withKey({ JEV_BASE_URL: 'http://127.0.0.1:9/', REA_JEV_TIMEOUT_MS: '1500' }) });
    assert.equal(r.code, 2);
    assert.equal(parse(r).round_trip.ok, false);
    assert.ok(['network', 'timeout'].includes(parse(r).round_trip.reason));
  });
});

describe('stats', () => {
  test('no log → friendly message, exit 0', async () => {
    const r = await run(['stats'], { env: withKey({ REA_JEV_HOME: path.join(tmp, 'empty-home') }) });
    assert.equal(r.code, 0, r.stderr);
    assert.match(r.stdout, /no decisions/);
  });
  test('summarises decisions.jsonl: counts, latency percentiles, cost, bands', async () => {
    const home = path.join(tmp, 'stats-home');
    fs.mkdirSync(home, { recursive: true });
    const now = Date.now();
    const rows = [
      { t: now - 1000, hook: 'route', decision: 'inject', latency_ms: 300, usage: { input_tokens: 1000 }, bands: { is_re_task: 'act', target_kind: 'confirm' } },
      { t: now - 2000, hook: 'pre', decision: 'deny', source: 'local' },
      { t: now - 3000, hook: 'post', latency_ms: 500, usage: { input_tokens: 2000 }, confidences: { relevance: 0.9 } },
      { t: now - 4000, hook: 'stop', decision: 'block', latency_ms: 700, usage: { input_tokens: 3000 } },
      { t: now - 30 * 86_400_000, hook: 'route', decision: 'inject', latency_ms: 9999, usage: { input_tokens: 1_000_000 } },
      'not json at all',
    ];
    fs.writeFileSync(path.join(home, 'decisions.jsonl'), rows.map((r) => (typeof r === 'string' ? r : JSON.stringify(r))).join('\n') + '\n');
    const r = await run(['stats', '--json', '--days', '7'], { env: withKey({ REA_JEV_HOME: home }) });
    assert.equal(r.code, 0, r.stderr);
    const j = parse(r);
    assert.equal(j.total, 4);
    assert.deepEqual(j.by_hook, { route: 1, pre: 1, post: 1, stop: 1 });
    assert.deepEqual(j.by_decision, { inject: 1, deny: 1, block: 1 });
    assert.equal(j.latency_ms.p50, 500);
    assert.equal(j.latency_ms.max, 700);
    assert.equal(j.input_tokens, 6000);
    assert.ok(Math.abs(j.cost_usd - 0.000252) < 1e-9);
    assert.deepEqual(j.bands, { act: 2, confirm: 1, escalate: 0 });
    const human = await run(['stats'], { env: withKey({ REA_JEV_HOME: home }) });
    assert.match(human.stdout, /4 decisions/);
    assert.match(human.stdout, /p50 500/);
  });
  test('REA_JEV_LOG=1 makes the CLI append its own decisions', async () => {
    const home = path.join(tmp, 'log-home');
    const r = await run(['ask', '--state', 'x', '--questions', '{"q":{"type":"noul","instructions":"Is it?"}}'], { env: withKey({ REA_JEV_HOME: home, REA_JEV_LOG: '1' }) });
    assert.equal(r.code, 0, r.stderr);
    const lines = fs.readFileSync(path.join(home, 'decisions.jsonl'), 'utf8').trim().split('\n');
    assert.equal(lines.length, 1);
    const rec = JSON.parse(lines[0]);
    assert.equal(rec.hook, 'cli');
    assert.equal(rec.command, 'ask');
    assert.ok(rec.t > 0 && rec.latency_ms >= 0);
    const st = fs.statSync(path.join(home, 'decisions.jsonl'));
    assert.equal(st.mode & 0o777, 0o600);
  });
});

describe('item parsing (in-process)', () => {
  test('parseItems handles arrays, envelopes, JSON lines and plain lines', () => {
    assert.deepEqual(parseItems('[1,2]'), [1, 2]);
    assert.deepEqual(parseItems('{"result":{"strings":["a","b"]}}'), ['a', 'b']);
    assert.deepEqual(parseItems('{"a":1}\n{"a":2}\n'), [{ a: 1 }, { a: 2 }]);
    assert.deepEqual(parseItems('one\ntwo\n\nthree'), ['one', 'two', 'three']);
    assert.deepEqual(parseItems('{"a":1}\nnot json'), ['{"a":1}', 'not json']);
    assert.deepEqual(parseItems('   '), []);
  });
  test('normalizeItems picks ids/texts, dedupes ids, redacts and caps text', () => {
    const out = normalizeItems([{ id: 'x', text: 'hello' }, { id: 'x', text: 'again' }, { address: '0x1', value: 'token=abcdef12345' }, 'plain', null, { foo: 'bar' }]);
    assert.deepEqual(out.map((o) => o.id), ['x', 'x#2', '0x1', '4', '6']);
    assert.equal(out[2].text, 'token=[REDACTED:kv]');
    assert.equal(out[3].text, 'plain');
    assert.equal(out[4].text, '{"foo":"bar"}');
    const long = normalizeItems([{ id: 'l', text: 'z'.repeat(1000) }])[0].text;
    assert.ok(long.length < 450 && long.includes('chars omitted'));
    const custom = normalizeItems([{ addr: '0x9', s: 'txt' }], 'addr', 's');
    assert.deepEqual(custom, [{ id: '0x9', text: 'txt' }]);
  });
});
