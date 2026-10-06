import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { sniffPrompt, magicOf, dirKind, isLoopback, extractEndpoints, KEYWORD_RE, describePath, targetKindFor } from '../scripts/lib/sniff.mjs';

// All fixtures are built at runtime in a temp dir; nothing binary is committed.
let dir;
before(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rea-jev-sniff-'));
});
after(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

/** Minimal PE image: MZ header, e_lfanew, PE signature, COFF, optional header with 16 data dirs. */
function buildPe({ managed, plus = false }) {
  const lfanew = 0x80;
  const optSize = plus ? 240 : 224;
  const buf = Buffer.alloc(lfanew + 24 + optSize, 0);
  buf.write('MZ', 0, 'latin1');
  buf.writeUInt32LE(lfanew, 0x3c);
  buf.write('PE\0\0', lfanew, 'latin1');
  buf.writeUInt16LE(plus ? 0x8664 : 0x14c, lfanew + 4); // Machine
  buf.writeUInt16LE(optSize, lfanew + 20); // SizeOfOptionalHeader
  const opt = lfanew + 24;
  buf.writeUInt16LE(plus ? 0x20b : 0x10b, opt); // Magic
  const dirBase = opt + (plus ? 112 : 96);
  buf.writeUInt32LE(16, dirBase - 4); // NumberOfRvaAndSizes
  if (managed) {
    buf.writeUInt32LE(0x2008, dirBase + 14 * 8); // CLI header RVA
    buf.writeUInt32LE(72, dirBase + 14 * 8 + 4); // size
  }
  return buf;
}

function asarBuffer() {
  const json = Buffer.from('{"files":{"main.js":{"size":1,"offset":"0"}}}');
  const header = Buffer.alloc(16);
  header.writeUInt32LE(4, 0);
  header.writeUInt32LE(json.length + 8, 4);
  header.writeUInt32LE(json.length + 4, 8);
  header.writeUInt32LE(json.length, 12);
  return Buffer.concat([header, json]);
}

function write(name, bytes) {
  const p = path.join(dir, name);
  fs.writeFileSync(p, bytes);
  return p;
}

describe('magic detection', () => {
  test('MZ without CLI directory → native_pe; with CLI directory → managed_pe (PE32 and PE32+)', () => {
    assert.equal(magicOf(write('native.exe', buildPe({ managed: false }))), 'native_pe');
    assert.equal(magicOf(write('managed.dll', buildPe({ managed: true }))), 'managed_pe');
    assert.equal(magicOf(write('managed64.dll', buildPe({ managed: true, plus: true }))), 'managed_pe');
    assert.equal(magicOf(write('native64.exe', buildPe({ managed: false, plus: true }))), 'native_pe');
  });
  test('MZ with an unparsable PE header → pe', () => {
    assert.equal(magicOf(write('stub.exe', Buffer.concat([Buffer.from('MZ'), Buffer.alloc(70, 0)]))), 'pe');
  });
  test('ELF, Mach-O (both byte orders), fat Mach-O', () => {
    assert.equal(magicOf(write('a.out', Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(16)]))), 'elf');
    assert.equal(magicOf(write('lib.dylib', Buffer.concat([Buffer.from([0xcf, 0xfa, 0xed, 0xfe]), Buffer.alloc(16)]))), 'macho');
    assert.equal(magicOf(write('lib32.dylib', Buffer.concat([Buffer.from([0xce, 0xfa, 0xed, 0xfe]), Buffer.alloc(16)]))), 'macho');
    assert.equal(magicOf(write('be.bin', Buffer.concat([Buffer.from([0xfe, 0xed, 0xfa, 0xcf]), Buffer.alloc(16)]))), 'macho');
    assert.equal(magicOf(write('fat.bin', Buffer.concat([Buffer.from([0xca, 0xfe, 0xba, 0xbe]), Buffer.alloc(16)]))), 'fat_macho');
  });
  test('zip containers refined by extension', () => {
    const pk = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.alloc(26)]);
    assert.equal(magicOf(write('x.zip', pk)), 'zip');
    assert.equal(magicOf(write('x.apk', pk)), 'apk');
    assert.equal(magicOf(write('x.ipa', pk)), 'ipa');
    assert.equal(magicOf(write('x.msix', pk)), 'msix');
    assert.equal(magicOf(write('x.appx', pk)), 'appx');
  });
  test('ASAR header → asar', () => {
    assert.equal(magicOf(write('app.asar', asarBuffer())), 'asar');
  });
  test('text file → null; missing file → null; tiny file → null', () => {
    assert.equal(magicOf(write('notes.txt', Buffer.from('hello world, nothing to see'))), null);
    assert.equal(magicOf(path.join(dir, 'does-not-exist.bin')), null);
    assert.equal(magicOf(write('tiny', Buffer.from('M'))), null);
  });
});

describe('directory heuristics', () => {
  test('Contents/MacOS → app_bundle', () => {
    const app = path.join(dir, 'Notes.app');
    fs.mkdirSync(path.join(app, 'Contents', 'MacOS'), { recursive: true });
    assert.equal(dirKind(app), 'app_bundle');
  });
  test('package.json / main.js / app.asar → javascript_application', () => {
    const js = path.join(dir, 'electron-app');
    fs.mkdirSync(js, { recursive: true });
    fs.writeFileSync(path.join(js, 'package.json'), '{}');
    assert.equal(dirKind(js), 'javascript_application');
    const js2 = path.join(dir, 'unpacked');
    fs.mkdirSync(path.join(js2, 'resources'), { recursive: true });
    fs.writeFileSync(path.join(js2, 'resources', 'app.asar'), asarBuffer());
    assert.equal(dirKind(js2), 'javascript_application');
  });
  test('AndroidManifest.xml → android; plain dir → null', () => {
    const an = path.join(dir, 'apk-extracted');
    fs.mkdirSync(an, { recursive: true });
    fs.writeFileSync(path.join(an, 'AndroidManifest.xml'), '<manifest/>');
    assert.equal(dirKind(an), 'android');
    const plain = path.join(dir, 'plain');
    fs.mkdirSync(plain, { recursive: true });
    assert.equal(dirKind(plain), null);
  });
  test('an Electron .app bundle is an app_bundle first', () => {
    const app = path.join(dir, 'Slack.app');
    fs.mkdirSync(path.join(app, 'Contents', 'MacOS'), { recursive: true });
    fs.mkdirSync(path.join(app, 'Contents', 'Resources'), { recursive: true });
    fs.writeFileSync(path.join(app, 'Contents', 'Resources', 'app.asar'), asarBuffer());
    assert.equal(dirKind(app), 'app_bundle');
  });
});

describe('sniffPrompt', () => {
  test('existing .app bundle path → token with exists, isDir, magic app_bundle, native_binary hint', () => {
    const app = path.join(dir, 'Notes.app');
    const s = sniffPrompt(`How does the sync feature in ${app} work?`, dir);
    assert.equal(s.keywordHit, true);
    assert.equal(s.pathTokens.length, 1);
    const t = s.pathTokens[0];
    assert.equal(t.abs, app);
    assert.equal(t.exists, true);
    assert.equal(t.isDir, true);
    assert.equal(t.ext, 'app');
    assert.equal(t.magic, 'app_bundle');
    assert.equal(t.targetKind, 'native_binary');
    assert.ok(s.hints.some((h) => h.includes('macOS app bundle')), s.hints.join('|'));
    assert.equal(s.declaredTarget, app);
  });
  test('relative, ~ and quoted paths resolve; trailing punctuation is stripped; quoted spans are not re-matched', () => {
    fs.writeFileSync(path.join(dir, 'My App.dll'), buildPe({ managed: true }));
    const s = sniffPrompt(`inspect "./My App.dll", ~/nothing.dylib and ./managed.dll.`, dir);
    const raws = s.pathTokens.map((t) => t.raw);
    assert.deepEqual(raws, ['./My App.dll', '~/nothing.dylib', './managed.dll']);
    assert.equal(s.pathTokens[0].exists, true);
    assert.equal(s.pathTokens[0].magic, 'managed_pe');
    assert.equal(s.pathTokens[0].targetKind, 'managed_assembly');
    assert.equal(s.pathTokens[1].abs, path.join(os.homedir(), 'nothing.dylib'));
    assert.equal(s.pathTokens[1].exists, false);
    assert.equal(s.pathTokens[2].abs, path.join(dir, 'managed.dll'));
    assert.ok(s.hints.some((h) => h.includes('.NET')));
    assert.ok(s.hints.some((h) => h.includes('was not found on disk')));
  });
  test('bare filenames with target extensions are tokens; ordinary words are not', () => {
    const s = sniffPrompt('what does libfoo.so export, and compare with plugin.asar; also fix utils.ts', dir);
    assert.deepEqual(s.pathTokens.map((t) => t.raw), ['libfoo.so', 'plugin.asar']);
    assert.equal(s.pathTokens[0].targetKind, 'native_binary');
    assert.equal(s.pathTokens[1].targetKind, 'javascript_application');
    assert.equal(s.pathTokens[1].exists, false);
  });
  test('URLs, CDP and inspector endpoints, loopback classification', () => {
    const s = sniffPrompt(
      'look at https://example.com/pricing, attach to ws://127.0.0.1:9222/devtools/browser/abc and http://10.0.0.5:9222/json, node is on ws://localhost:9229/5f1a1c6e-1111-2222-3333-444444444444, also run with --remote-debugging-port=9333',
      dir,
    );
    assert.deepEqual(s.urls.slice(0, 1), ['https://example.com/pricing']);
    assert.equal(s.urls.length, 4);
    assert.deepEqual(s.cdpEndpoints, ['ws://127.0.0.1:9222/devtools/browser/abc', 'http://10.0.0.5:9222/json', 'http://127.0.0.1:9333']);
    assert.deepEqual(s.inspectorEndpoints, ['ws://localhost:9229/5f1a1c6e-1111-2222-3333-444444444444']);
    assert.ok(s.hints.includes('url https://example.com/pricing'));
    assert.ok(s.hints.includes('CDP endpoint ws://127.0.0.1:9222/devtools/browser/abc (loopback)'));
    assert.ok(s.hints.includes('CDP endpoint http://10.0.0.5:9222/json (remote)'));
    assert.equal(s.pathTokens.length, 0, 'URL path segments must not become path tokens');
    assert.equal(s.declaredTarget, 'https://example.com/pricing');
  });
  test('host:port shorthands become endpoints', () => {
    const e = extractEndpoints('chrome is at localhost:9222 and node at 127.0.0.1:9229, but mysql on db.internal:3306');
    assert.deepEqual(e.cdpEndpoints, ['localhost:9222']);
    assert.deepEqual(e.inspectorEndpoints, ['127.0.0.1:9229']);
  });
  test('empty / non-string prompt → empty result', () => {
    const s = sniffPrompt(null);
    assert.equal(s.keywordHit, false);
    assert.deepEqual(s.pathTokens, []);
    assert.equal(s.declaredTarget, null);
  });
  test('describePath on a missing file still reports ext-based targetKind', () => {
    const t = describePath('/nope/thing.apk', dir);
    assert.equal(t.exists, false);
    assert.equal(t.targetKind, 'android_apk');
    assert.equal(targetKindFor({ exists: true, isDir: true, ext: 'app', magic: null }), null);
  });
});

describe('keyword pre-filter', () => {
  const hits = [
    'decompile this function',
    'can you reverse-engineer Notes.app',
    'how does the sync feature work',
    'trace the login flow in the binary',
    'list the strings in the executable',
    'inspect the .NET assembly',
    'the bundle is minified; find the source map',
    'open it in Hopper and look at the xrefs',
    'what does libfoo.so do',
    'understand how the app talks to the server',
  ];
  const misses = [
    'fix the failing unit test in src/utils.ts',
    'write a README for this project',
    'add a button to the settings page',
    'rename the variable and run prettier',
    'summarize this meeting transcript',
    'help me with a regex for dates',
  ];
  for (const p of hits) test(`hit: ${p}`, () => assert.equal(KEYWORD_RE.test(p), true));
  for (const p of misses) test(`miss: ${p}`, () => assert.equal(KEYWORD_RE.test(p), false));
  test('sniffPrompt.keywordHit mirrors the regex', () => {
    assert.equal(sniffPrompt('disassemble the loader').keywordHit, true);
    assert.equal(sniffPrompt('update the changelog').keywordHit, false);
  });
});

describe('isLoopback', () => {
  test('loopback forms', () => {
    for (const e of ['ws://127.0.0.1:9222/x', 'http://localhost:9222/json', 'localhost:9229', '[::1]:9229', 'ws://[::1]:9229/abc', 'http://127.5.6.7:9222', 'http://app.localhost:9222', '0.0.0.0:9222']) {
      assert.equal(isLoopback(e), true, e);
    }
  });
  test('remote and garbage forms', () => {
    for (const e of ['http://10.0.0.5:9222/json', 'ws://192.168.1.20:9229/x', 'example.com:9222', 'http://127.0.0.1.evil.com:9222', '', null, 'not an endpoint at all', 42]) {
      assert.equal(isLoopback(e), false, String(e));
    }
  });
});
