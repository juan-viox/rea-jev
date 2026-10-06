/**
 * Secret redaction (scripts/lib/redact.mjs): the spec-named shapes, the added
 * token families, the `PWD` exception, structural redaction of parsed values,
 * and the linear-time guarantee the hooks' time budgets depend on.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { redact, hasSecret, truncate, excerpt, redactObject, isCredentialKey } from '../scripts/lib/redact.mjs';

describe('redact', () => {
  const masked = [
    ['sk-abcdefghijklmnopqrstuvwxyz', 'sk'],
    ['ghp_abcdefghijklmnopqrstuvwxyz0123', 'github'],
    ['github_pat_abcdefghijklmnopqrstuvwxyz', 'github'],
    ['AKIAIOSFODNN7EXAMPLE', 'aws'],
    ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk', 'jwt'],
    ['Authorization: Bearer abcdefghijklmnopqrstuvwxyz', 'bearer'],
    ['-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----', 'private_key'],
    ['https://user:pw@host/x', 'userinfo'],
    ['sk_live_51H1234567890abcdefghijklmn', 'stripe'],
    ['sk_test_51H1234567890abcdefghijklmn', 'stripe'],
    ['xoxb-123456789012-abcdefghijklmnop', 'slack'],
    ['AIzaSyA1234567890abcdefghijklmnopqrstuv', 'google'],
    ['glpat-abcdefghijklmnopqrst', 'gitlab'],
  ];
  for (const [input, kind] of masked) {
    test(`masks ${kind}`, () => {
      const out = redact(input);
      assert.ok(out.includes(`[REDACTED:${kind}]`), out);
      assert.equal(hasSecret(input), true);
    });
  }
  test('key=value pairs keep the key and mask the value', () => {
    assert.equal(redact('API_TOKEN=sk-live-0123456789abcdefghijklmnop'), 'API_TOKEN=[REDACTED:sk]', 'an already-masked value is not masked twice');
    assert.equal(redact('API_TOKEN=plain0123456789abcdefghijklmnop'), 'API_TOKEN=[REDACTED:kv]');
    assert.equal(redact('export OPENROUTER_API_KEY=abcdefghij'), 'export OPENROUTER_API_KEY=[REDACTED:kv]');
    assert.equal(redact('"client_secret": "zzzzzz"'), '"client_secret": "[REDACTED:kv]"');
    assert.equal(redact('password=hunter2&x=1'), 'password=[REDACTED:kv]&x=1');
    assert.equal(redact('my-token: abcdef'), 'my-token: [REDACTED:kv]');
    assert.equal(redact('Set-Cookie: session=abcdef0123456789; HttpOnly'), 'Set-Cookie: [REDACTED:kv]; HttpOnly');
    assert.equal(redact('"token": 12345'), '"token": [REDACTED:kv]');
    assert.equal(redact('Pwd=hunter2;'), 'Pwd=[REDACTED:kv];');
    assert.equal(redact('db_pwd=abc123'), 'db_pwd=[REDACTED:kv]');
  });
  test('scope operators are not key/value pairs: `Name::member` identifiers stay intact', () => {
    for (const s of ['NetworkSession::send', 'Auth::verify', 'Settings::Kind::Secret', 'KeychainStore::read -> Session::open()']) {
      assert.equal(redact(s), s, s);
      assert.equal(hasSecret(s), false, s);
    }
    assert.equal(redact('session: abcdef0123'), 'session: [REDACTED:kv]', 'a single colon separator is still an assignment');
    assert.equal(redact('"Session": "abcdef"'), '"Session": "[REDACTED:kv]"');
  });
  test('the shell variables PWD and OLDPWD and ordinary words are left alone', () => {
    for (const s of ['PWD=/home/user/project', 'OLDPWD=/tmp', 'PWD=~/work', 'author: Juan', 'the password policy', 'token count: 12']) {
      assert.equal(redact(s), s, s);
      assert.equal(hasSecret(s), false, s);
    }
  });
  test('is linear: 200k and 1M character identifier runs take milliseconds, not minutes', () => {
    for (const s of ['A'.repeat(200_000), 'a'.repeat(200_000), 'deadbeef'.repeat(125_000), '-'.repeat(200_000)]) {
      const t = Date.now();
      redact(s);
      assert.ok(Date.now() - t < 250, `${s.length} chars took ${Date.now() - t} ms`);
    }
  });
  test('non-string input is stringified; null and undefined become empty', () => {
    assert.equal(redact(null), '');
    assert.equal(redact(undefined), '');
    assert.equal(redact({ a: 'sk-abcdefghijklmnopqrstuvwxyz' }), '{"a":"[REDACTED:sk]"}');
  });
});

describe('redactObject', () => {
  test('redacts string leaves and any leaf under a credential key, keeping the object shape', () => {
    const value = { token: 12345, nested: { api_key: 7, GITHUB_TOKEN: 'ghp_x', PWD: '/home/u', db_pwd: 'secret!' }, list: ['sk-abcdefghijklmnopqrstuvwxyz', 3], note: 'plain', flag: true, nothing: null };
    assert.deepEqual(redactObject(value), {
      token: '[REDACTED:kv]',
      nested: { api_key: '[REDACTED:kv]', GITHUB_TOKEN: '[REDACTED:kv]', PWD: '/home/u', db_pwd: '[REDACTED:kv]' },
      list: ['[REDACTED:sk]', 3],
      note: 'plain',
      flag: true,
      nothing: null,
    });
    assert.equal(redactObject('Bearer abcdefghijklmnop'), 'Bearer [REDACTED:bearer]');
    assert.equal(redactObject(42), 42);
  });
  test('isCredentialKey', () => {
    for (const k of ['token', 'GITHUB_TOKEN', 'api_key', 'apikey', 'client-secret', 'password', 'cookie', 'auth', 'my.pwd']) assert.equal(isCredentialKey(k, 'x'), true, k);
    for (const k of ['tokens', 'author', 'PWD', 'path', 'name']) assert.equal(isCredentialKey(k, '/x'), false, k);
    assert.equal(isCredentialKey('PWD', 'hunter2'), true, 'a PWD with a non-path value is treated as a credential');
  });
});

describe('truncate and excerpt', () => {
  test('keeps head and tail with the omission marker', () => {
    const s = truncate('a'.repeat(100) + 'b'.repeat(100), 40, { head: 30, tail: 10 });
    assert.ok(s.startsWith('a'.repeat(30)) && s.endsWith('b'.repeat(10)));
    assert.match(s, /…\[160 chars omitted\]…/);
    assert.equal(truncate('short', 40), 'short');
  });
  test('excerpt redacts before truncating', () => {
    const e = excerpt(`prefix sk-abcdefghijklmnopqrstuvwxyz ${'x'.repeat(500)}`, 60);
    assert.doesNotMatch(e, /abcdefghijklmnopqrstuvwxyz/);
    assert.ok(e.includes('[REDACTED:sk]'));
  });
});
