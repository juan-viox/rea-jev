import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import {
  sniffPrompt, magicOf, dirKind, isLoopback, extractEndpoints, safeUrl, KEYWORD_RE, describePath, targetKindFor, isHarnessEnvelope,
  webRecordingFormat, FIRMWARE_EXTENSIONS, TARGET_EXTENSIONS,
} from '../scripts/lib/sniff.mjs';
import { buildZip } from './hook-harness.mjs';

// All fixtures are built at runtime in a temp dir; nothing binary is committed.
let dir;
before(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rea-jev-sniff-'));
});
after(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

/** Minimal 64-byte ELF64 header with the given `e_type` (1 = ET_REL, 2 = ET_EXEC, 3 = ET_DYN). */
function buildElf({ type, bigEndian = false }) {
  const buf = Buffer.alloc(64, 0);
  buf.write('\x7fELF', 0, 'latin1');
  buf[4] = 2; // ELFCLASS64
  buf[5] = bigEndian ? 2 : 1;
  buf[6] = 1;
  if (bigEndian) buf.writeUInt16BE(type, 16);
  else buf.writeUInt16LE(type, 16);
  if (bigEndian) buf.writeUInt16BE(0xb7, 18);
  else buf.writeUInt16LE(0xb7, 18); // aarch64
  return buf;
}

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

describe('magic detection (artifact kinds rea-agents 6.5.0 reads)', () => {
  test('WebAssembly, SQLite, pcap in all four byte orders, pcapng', () => {
    assert.equal(magicOf(write('m.wasm', Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0, 0, 0]))), 'wasm');
    assert.equal(magicOf(write('c.sqlite', Buffer.concat([Buffer.from('SQLite format 3\0', 'latin1'), Buffer.alloc(84)]))), 'sqlite');
    for (const m of ['a1b2c3d4', 'd4c3b2a1', 'a1b23c4d', '4d3cb2a1']) {
      assert.equal(magicOf(write(`${m}.pcap`, Buffer.concat([Buffer.from(m, 'hex'), Buffer.alloc(20)]))), 'pcap', m);
    }
    const shb = Buffer.alloc(28);
    shb.write('0a0d0d0a', 0, 'hex');
    shb.writeUInt32LE(28, 4);
    shb.write('4d3c2b1a', 8, 'hex');
    assert.equal(magicOf(write('x.pcapng', shb)), 'pcapng');
    assert.equal(magicOf(write('not.pcapng', Buffer.concat([Buffer.from('0a0d0d0a', 'hex'), Buffer.alloc(20)]))), null, 'the block type alone is not pcapng');
  });
  test('zip containers: .saz → saz; a .apk whose central directory names libflutter.so → flutter_apk, otherwise apk', () => {
    const pk = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.alloc(26)]);
    assert.equal(magicOf(write('traffic.saz', pk)), 'saz');
    const flutter = buildZip([
      { name: 'AndroidManifest.xml', data: '<manifest/>' },
      { name: 'lib/arm64-v8a/libflutter.so', data: Buffer.alloc(16) },
      { name: 'lib/arm64-v8a/libapp.so', data: Buffer.alloc(16) },
    ]);
    assert.equal(magicOf(write('shop.apk', flutter)), 'flutter_apk');
    const plain = buildZip([{ name: 'AndroidManifest.xml', data: '<manifest/>' }, { name: 'classes.dex', data: Buffer.alloc(16) }]);
    assert.equal(magicOf(write('plain.apk', plain)), 'apk');
    assert.equal(magicOf(write('shop.zip', flutter)), 'zip', 'the central directory is read for .apk only');
    assert.equal(magicOf(write('headless.apk', pk)), 'apk', 'no central directory → a plain apk');
  });
  test('HAR and qlog from the JSON head; a .har whose head shows no log object has no magic', () => {
    assert.equal(magicOf(write('a.har', '{"log":{"version":"1.2","creator":{"name":"x"},"entries":[]}}')), 'har');
    assert.equal(magicOf(write('pretty.har', '{\n  "log": {\n    "version": "1.2",\n    "creator": {}\n  }\n}')), 'har');
    assert.equal(magicOf(write('export.json', '﻿{"log":{"version":"1.2"}}')), 'har', 'a BOM and a .json name do not hide a HAR');
    assert.equal(magicOf(write('other.json', '{"log":{"entries":[]}}')), null, 'without "version" only a .har name makes it a HAR');
    assert.equal(magicOf(write('named.har', '{"log":{"entries":[]}}')), 'har');
    assert.equal(magicOf(write('odd.har', `{${' '.repeat(80)}"log":{}}`)), null, 'nothing within the 64-byte head');
    assert.equal(magicOf(write('t.qlog', '{"qlog_version":"0.3","qlog_format":"JSON","traces":[]}')), 'qlog');
    assert.equal(magicOf(write('t.sqlog', '\x1e{"qlog_format":"JSON-SEQ","qlog_version":"0.3"}\n')), 'qlog');
    assert.equal(magicOf(write('seq.txt', '\x1e{"a":1}\n')), null);
  });
  test('firmware container and filesystem magics', () => {
    const cases = [
      ['uimage', '27051956'], ['squashfs', '68737173'], ['squashfs', '73717368'], ['cramfs', '453dcd28'], ['cramfs', '28cd3d45'],
      ['ubi', '55424923'], ['ubifs', '31181006'], ['trx', '48445230'], ['dtb', 'd00dfeed'], ['uf2', '5546320a'],
      ['jffs2', '851901e0'], ['jffs2', '1985e001'],
    ];
    for (const [kind, hex] of cases) {
      assert.equal(magicOf(write(`${kind}-${hex}.bin`, Buffer.concat([Buffer.from(hex, 'hex'), Buffer.alloc(28)]))), kind, `${kind} ${hex}`);
    }
    assert.equal(magicOf(write('boot.img', Buffer.concat([Buffer.from('ANDROID!', 'latin1'), Buffer.alloc(24)]))), 'android_boot');
    assert.equal(magicOf(write('fw.dfu', Buffer.concat([Buffer.from('DfuSe', 'latin1'), Buffer.alloc(24)]))), 'dfuse');
    assert.equal(magicOf(write('fw.hex', ':10000000000102030405060708090A0B0C0D0E0F78\n:00000001FF\n')), 'intel_hex');
    assert.equal(magicOf(write('fw.srec', 'S00F000068656C6C6F202020202000003C\nS70500000000FA\n')), 'srec');
    assert.equal(magicOf(write('smiley.txt', ':) see you at 10:00')), null);
  });
  test('a compressed stream is only compressed; the extension decides whether it is firmware', () => {
    for (const [name, hex] of [['gz', '1f8b0800'], ['xz', 'fd377a585a00'], ['zst', '28b52ffd'], ['lz4', '04224d18'], ['bz2', '425a6839'], ['lzma', '5d000080']]) {
      assert.equal(magicOf(write(`blob.${name}`, Buffer.concat([Buffer.from(hex, 'hex'), Buffer.alloc(28)]))), 'compressed', name);
    }
    const gz = Buffer.concat([Buffer.from('1f8b0800', 'hex'), Buffer.alloc(28)]);
    const fw = write('router.fw', gz);
    assert.equal(describePath(fw, dir).targetKind, 'firmware_image');
    assert.equal(describePath(write('router.bin', gz), dir).targetKind, null, '.bin alone is not firmware');
    assert.equal(describePath(write('disk.img', Buffer.alloc(64)), dir).targetKind, null, '.img alone is not firmware');
    const s = sniffPrompt(`what is in ${fw}`, dir);
    assert.ok(s.hints.includes(`path ${fw} is a compressed stream (gzip, xz, lzma, bzip2, zstd or lz4), firmware by its .fw extension`), s.hints.join('|'));
  });
});

describe('magic detection (artifact kinds rea-agents 6.8.0 reads)', () => {
  test('BEAM, GGUF, safetensors, IL2CPP metadata, CUDA fatbin, Godot PCK, CPython pyc', () => {
    assert.equal(magicOf(write('m.beam', Buffer.concat([Buffer.from('FOR1', 'latin1'), Buffer.from([0, 0, 0, 40]), Buffer.from('BEAM', 'latin1'), Buffer.alloc(40)]))), 'beam');
    assert.equal(magicOf(write('iff.bin', Buffer.concat([Buffer.from('FOR1', 'latin1'), Buffer.from([0, 0, 0, 40]), Buffer.from('AIFF', 'latin1'), Buffer.alloc(40)]))), null, 'an IFF form that is not BEAM');
    assert.equal(magicOf(write('model.gguf', Buffer.concat([Buffer.from('GGUF', 'latin1'), Buffer.from([3, 0, 0, 0]), Buffer.alloc(56)]))), 'gguf');
    const st = Buffer.alloc(64);
    st.writeBigUInt64LE(24n, 0);
    st.write('{"__metadata__":{"a":"b"}}', 8, 'latin1');
    assert.equal(magicOf(write('model.safetensors', st)), 'safetensors');
    const huge = Buffer.alloc(64);
    huge.writeBigUInt64LE(1n << 40n, 0);
    huge.write('{', 8, 'latin1');
    assert.equal(magicOf(write('not.safetensors', huge)), null, 'an implausible header length is not a safetensors header');
    assert.equal(magicOf(write('global-metadata.dat', Buffer.concat([Buffer.from('af1bb1fa', 'hex'), Buffer.from([24, 0, 0, 0]), Buffer.alloc(56)]))), 'il2cpp_metadata');
    assert.equal(magicOf(write('kernel.fatbin', Buffer.concat([Buffer.from('50ed55ba', 'hex'), Buffer.from([1, 0, 0, 0]), Buffer.alloc(56)]))), 'cuda_fatbin');
    assert.equal(magicOf(write('game.pck', Buffer.concat([Buffer.from('GDPC', 'latin1'), Buffer.from([2, 0, 0, 0]), Buffer.alloc(56)]))), 'pck');
    const pyc = Buffer.alloc(32);
    pyc.writeUInt16LE(3571, 0); // CPython 3.13
    pyc.write('\r\n', 2, 'latin1');
    assert.equal(magicOf(write('mod.cpython-313.pyc', pyc)), 'pyc');
    assert.equal(magicOf(write('mod.bin', pyc)), null, 'the pyc header is read for .pyc only');
  });
  test('an ELF whose e_type is ET_REL is elf_rel in either byte order; an executable stays elf', () => {
    assert.equal(magicOf(write('mod.ko', buildElf({ type: 1 }))), 'elf_rel');
    assert.equal(magicOf(write('mod-be.ko', buildElf({ type: 1, bigEndian: true }))), 'elf_rel');
    assert.equal(magicOf(write('prog.elf', buildElf({ type: 2 }))), 'elf');
    assert.equal(magicOf(write('lib.so', buildElf({ type: 3 }))), 'elf');
    assert.equal(magicOf(write('short.elf', Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]))), 'elf', 'a header too short to read e_type is elf');
  });
  test('an Apple .ips crash report from its JSON head or its name', () => {
    assert.equal(magicOf(write('crash.ips', '{"app_name":"Notes","timestamp":"2026-10-20 10:00:00.00 -0400","app_version":"4.11","bug_type":"309"}\n{"uptime":100}')), 'ips');
    assert.equal(magicOf(write('report.txt', '{"app_name":"Notes","timestamp":"2026-10-20 10:00:00.00 -0400"}')), 'ips', 'the head names the report');
    assert.equal(magicOf(write('named.ips', '{"other":1}')), 'ips');
    assert.equal(magicOf(write('plain.json', '{"other":1}')), null);
  });
});

describe('target kinds and hints (artifact kinds rea-agents 6.8.0 reads)', () => {
  test('magic → target kind', () => {
    const byMagic = {
      ips: 'crash_report', beam: 'beam_module', pyc: 'python_bytecode', gguf: 'model_artifact', safetensors: 'model_artifact',
      il2cpp_metadata: 'il2cpp_metadata', cuda_fatbin: 'gpu_code_object', pck: 'package_archive', desktop_application: 'desktop_application',
    };
    for (const [magic, kind] of Object.entries(byMagic)) assert.equal(targetKindFor({ exists: true, isDir: magic === 'desktop_application', ext: 'bin', magic }), kind, magic);
    assert.equal(targetKindFor({ exists: true, isDir: false, ext: 'ko', magic: 'elf_rel' }), 'kernel_module');
    assert.equal(targetKindFor({ exists: true, isDir: false, ext: 'o', magic: 'elf_rel' }), 'native_binary', 'a relocatable object that is not a .ko is a native binary');
  });
  test('extension fallback for a file that is missing or unrecognized', () => {
    const byExt = {
      ips: 'crash_report', ko: 'kernel_module', beam: 'beam_module', pyc: 'python_bytecode', gguf: 'model_artifact', safetensors: 'model_artifact',
      cubin: 'gpu_code_object', ptx: 'gpu_code_object', fatbin: 'gpu_code_object', pck: 'package_archive', dat: null,
    };
    for (const [ext, kind] of Object.entries(byExt)) {
      assert.equal(targetKindFor({ exists: false, isDir: false, ext, magic: null }), kind, ext);
      assert.equal(describePath(`/nope/thing.${ext}`, dir).targetKind, kind, ext);
      if (kind) assert.ok(TARGET_EXTENSIONS.includes(ext), `${ext} makes a bare token a path candidate`);
    }
  });
  test('bare filenames with the 6.8.0 extensions are path tokens', () => {
    const s = sniffPrompt('read crash-2026.ips, nf_tables.ko, cowboy_router.beam, settings.cpython-313.pyc and llama.gguf', dir);
    assert.deepEqual(
      s.pathTokens.map((t) => [t.raw, t.exists, t.targetKind]),
      [
        ['crash-2026.ips', false, 'crash_report'], ['nf_tables.ko', false, 'kernel_module'], ['cowboy_router.beam', false, 'beam_module'],
        ['settings.cpython-313.pyc', false, 'python_bytecode'], ['llama.gguf', false, 'model_artifact'],
      ],
    );
  });
  test('existing files carry their format in the hint', () => {
    const ko = write('hello.ko', buildElf({ type: 1 }));
    const gguf = write('tiny.gguf', Buffer.concat([Buffer.from('GGUF', 'latin1'), Buffer.from([3, 0, 0, 0]), Buffer.alloc(56)]));
    const s = sniffPrompt(`inspect ${ko} and ${gguf}`, dir);
    assert.ok(s.hints.includes(`path ${ko} is a relocatable ELF object (ET_REL; a kernel module when named .ko)`), s.hints.join('|'));
    assert.ok(s.hints.includes(`path ${gguf} is a GGUF model file`), s.hints.join('|'));
    assert.equal(s.pathTokens[0].targetKind, 'kernel_module');
    assert.equal(s.declaredTarget, ko);
  });
  test('the new keywords pass the pre-filter', () => {
    for (const p of ['read this crash report', 'what does the kernel module do', 'decode the bytecode', 'inspect the il2cpp metadata', 'what is in the safetensors']) assert.ok(KEYWORD_RE.test(p), p);
    assert.equal(KEYWORD_RE.test('a beam of light'), false);
  });
});

describe('target kinds and hints (artifact kinds rea-agents 6.5.0 reads)', () => {
  test('magic → target kind', () => {
    const byMagic = {
      wasm: 'wasm_module', sqlite: 'sqlite_database', pcap: 'packet_capture', pcapng: 'packet_capture', har: 'packet_capture', saz: 'packet_capture', qlog: 'packet_capture',
      flutter_apk: 'flutter_app', apk: 'android_apk', uimage: 'firmware_image', squashfs: 'firmware_image', cramfs: 'firmware_image', jffs2: 'firmware_image', ubi: 'firmware_image',
      ubifs: 'firmware_image', trx: 'firmware_image', dtb: 'firmware_image', uf2: 'firmware_image', dfuse: 'firmware_image', android_boot: 'firmware_image', intel_hex: 'firmware_image', srec: 'firmware_image',
    };
    for (const [magic, kind] of Object.entries(byMagic)) assert.equal(targetKindFor({ exists: true, isDir: false, ext: 'bin', magic }), kind, magic);
    assert.equal(targetKindFor({ exists: true, isDir: false, ext: 'fw', magic: 'compressed' }), 'firmware_image');
    assert.equal(targetKindFor({ exists: true, isDir: false, ext: 'gz', magic: 'compressed' }), null);
  });
  test('extension fallback for a file that is missing or unrecognized; .bin and .img name nothing', () => {
    const byExt = {
      wasm: 'wasm_module', sqlite: 'sqlite_database', sqlite3: 'sqlite_database', db: 'sqlite_database', db3: 'sqlite_database',
      pcap: 'packet_capture', pcapng: 'packet_capture', har: 'packet_capture', saz: 'packet_capture', qlog: 'packet_capture', sqlog: 'packet_capture', mitm: 'packet_capture',
      fw: 'firmware_image', rom: 'firmware_image', hex: 'firmware_image', ihex: 'firmware_image', srec: 'firmware_image', uf2: 'firmware_image', ubi: 'firmware_image', squashfs: 'firmware_image', trx: 'firmware_image', dfu: 'firmware_image',
      bin: null, img: null, json: null,
    };
    for (const [ext, kind] of Object.entries(byExt)) {
      assert.equal(targetKindFor({ exists: false, isDir: false, ext, magic: null }), kind, ext);
      assert.equal(describePath(`/nope/thing.${ext}`, dir).targetKind, kind, ext);
    }
    for (const ext of FIRMWARE_EXTENSIONS) assert.ok(TARGET_EXTENSIONS.includes(ext), `${ext} makes a bare token a path candidate`);
    assert.ok(!TARGET_EXTENSIONS.includes('bin') && !TARGET_EXTENSIONS.includes('img'));
  });
  test('bare filenames with the new extensions are path tokens', () => {
    // Names no other test writes into `dir`, so every token is a missing file.
    const s = sniffPrompt('decode tele.pcapng, then compare core.wasm with state.db and the dump in dump.fw', dir);
    assert.deepEqual(
      s.pathTokens.map((t) => [t.raw, t.exists, t.targetKind]),
      [['tele.pcapng', false, 'packet_capture'], ['core.wasm', false, 'wasm_module'], ['state.db', false, 'sqlite_database'], ['dump.fw', false, 'firmware_image']],
    );
    assert.equal(s.hints.filter((h) => h.includes('was not found on disk')).length, 4);
  });
  test('existing files carry their format in the hint and the first one is the declared target', () => {
    const wasm = write('engine.wasm', Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0, 0, 0]));
    const db = write('cache.sqlite', Buffer.concat([Buffer.from('SQLite format 3\0', 'latin1'), Buffer.alloc(84)]));
    const har = write('login.har', '{"log":{"version":"1.2","entries":[]}}');
    const s = sniffPrompt(`inspect ${wasm}, ${db} and ${har}`, dir);
    assert.ok(s.hints.includes(`path ${wasm} is a WebAssembly module`), s.hints.join('|'));
    assert.ok(s.hints.includes(`path ${db} is a SQLite 3 database`), s.hints.join('|'));
    assert.ok(s.hints.includes(`path ${har} is a HAR web-traffic recording (JSON)`), s.hints.join('|'));
    assert.equal(s.declaredTarget, wasm);
  });
});

describe('webRecordingFormat', () => {
  test('magic first, extension second, never for a pcap', () => {
    assert.equal(webRecordingFormat({ ext: 'har', magic: 'har' }), 'har');
    assert.equal(webRecordingFormat({ ext: 'json', magic: 'har' }), 'har');
    assert.equal(webRecordingFormat({ ext: 'har', magic: null }), 'har');
    assert.equal(webRecordingFormat({ ext: 'saz', magic: 'saz' }), 'saz');
    assert.equal(webRecordingFormat({ ext: 'qlog', magic: 'qlog' }), 'qlog');
    assert.equal(webRecordingFormat({ ext: 'sqlog', magic: null }), 'qlog');
    assert.equal(webRecordingFormat({ ext: 'mitm', magic: null }), 'mitmproxy');
    assert.equal(webRecordingFormat({ ext: 'pcap', magic: 'pcap' }), null);
    assert.equal(webRecordingFormat({ ext: 'har', magic: 'pcap' }), null, 'a pcap wearing a .har name is a pcap');
    assert.equal(webRecordingFormat({ ext: 'bin', magic: null }), null);
    assert.equal(webRecordingFormat(null), null);
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
  test('a folder with a top-level .exe, UnityPlayer.dll, a .pck or a *_Data directory → desktop_application', () => {
    const game = path.join(dir, 'Game');
    fs.mkdirSync(path.join(game, 'Game_Data'), { recursive: true });
    assert.equal(dirKind(game), 'desktop_application');
    const win = path.join(dir, 'WinApp');
    fs.mkdirSync(win, { recursive: true });
    fs.writeFileSync(path.join(win, 'App.exe'), buildPe({ managed: false }));
    assert.equal(dirKind(win), 'desktop_application');
    const electronWin = path.join(dir, 'ElectronWin');
    fs.mkdirSync(path.join(electronWin, 'resources'), { recursive: true });
    fs.writeFileSync(path.join(electronWin, 'App.exe'), buildPe({ managed: false }));
    fs.writeFileSync(path.join(electronWin, 'resources', 'app.asar'), asarBuffer());
    assert.equal(dirKind(electronWin), 'javascript_application', 'an unpacked Electron app is a JavaScript application first');
    assert.equal(describePath(game, dir).targetKind, 'desktop_application');
    assert.ok(sniffPrompt(`what engine does ${game} use`, dir).hints.includes(`path ${game} is an installed desktop application directory (.exe, UnityPlayer.dll, .pck or *_Data present)`));
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
  test('host:port shorthands become endpoints; --inspect flags yield the HTTP form REA takes', () => {
    const e = extractEndpoints('chrome is at localhost:9222 and node at 127.0.0.1:9229, but mysql on db.internal:3306');
    assert.deepEqual(e.cdpEndpoints, ['localhost:9222']);
    assert.deepEqual(e.inspectorEndpoints, ['127.0.0.1:9229']);
    assert.deepEqual(extractEndpoints('run it with --inspect-brk=9230').inspectorEndpoints, ['http://127.0.0.1:9230']);
  });
  test('URL credentials, query strings and fragments are stripped from urls, hints and the declared target', () => {
    const s = sniffPrompt('look at https://admin:S3cretPass@10.0.0.7/portal?access_token=abcdef123456#frag please', dir);
    assert.deepEqual(s.urls, ['https://10.0.0.7/portal']);
    assert.equal(s.declaredTarget, 'https://10.0.0.7/portal');
    assert.doesNotMatch(JSON.stringify(s), /S3cretPass|access_token/);
    assert.equal(safeUrl('https://example.com'), 'https://example.com');
    assert.equal(safeUrl('https://example.com/a/b/'), 'https://example.com/a/b/');
    assert.equal(safeUrl('not a url token=abcdef'), 'not a url token=[REDACTED:kv]');
  });
  test('a FIFO mentioned in the prompt is stat-ed but never opened (no blocking read)', () => {
    const fifo = path.join(dir, 'myfifo');
    try {
      execFileSync('mkfifo', [fifo]);
    } catch {
      return; // mkfifo unavailable on this host; nothing to test
    }
    const started = Date.now();
    const t = describePath(fifo, dir);
    assert.ok(Date.now() - started < 1000, 'returned without blocking');
    assert.equal(t.exists, true);
    assert.equal(t.isDir, false);
    assert.equal(t.magic, null);
    const s = sniffPrompt(`reverse engineer the binary at ${fifo} please`, dir);
    assert.equal(s.pathTokens[0].abs, fifo);
    assert.equal(describePath('/dev/null', dir).magic, null);
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
  test('XML tag names are not paths; a path inside an element still is', () => {
    const s = sniffPrompt('<task-notification>\n<task-id>abc</task-id>\n<output-file>/nope/tasks/abc.output</output-file>\n<status>completed</status>\n</task-notification>', dir);
    assert.deepEqual(
      s.pathTokens.map((t) => t.raw),
      ['/nope/tasks/abc.output'],
    );
  });
  test('a leading slash command is not a path; what follows it still is', () => {
    const s = sniffPrompt('/rea-jev:reverse-engineer https://example.com/app', dir);
    assert.deepEqual(s.pathTokens, []);
    assert.deepEqual(s.urls, ['https://example.com/app']);
    assert.deepEqual(s.hints, ['url https://example.com/app']);
    assert.deepEqual(sniffPrompt('/reverse-engineer ~/nothing.dylib', dir).pathTokens.map((t) => t.raw), ['~/nothing.dylib']);
    assert.deepEqual(sniffPrompt('/Applications/Notes.app is the target', dir).pathTokens.map((t) => t.raw), ['/Applications/Notes.app'], 'a path, not a command');
    assert.deepEqual(sniffPrompt('open /nope.app', dir).pathTokens.map((t) => t.raw), ['/nope.app'], 'only the first token can be a command');
  });
});

describe('isHarnessEnvelope', () => {
  test('whole-prompt envelopes the host injects', () => {
    for (const p of [
      '<task-notification>\n<task-id>w3a37azco</task-id>\n<status>completed</status>\n</task-notification>',
      '<agent-message from="aad0cbcc6044d3cea">\n[Subagent hand-back] The report.\n</agent-message>',
      '<command-message>workflow-authoring</command-message>\n<command-name>workflow-authoring</command-name>\n<command-args></command-args>',
      '  <system-reminder>\nThe user opened the file.\n</system-reminder>\n',
      '<local-command-stdout>ok</local-command-stdout>',
    ]) {
      assert.equal(isHarnessEnvelope(p), true, p.slice(0, 40));
    }
  });
  test('a user prompt is not an envelope, even when it quotes or mentions tags', () => {
    for (const p of [
      'how does the sync feature in Notes.app work?',
      'decompile this: <manifest package="x"/> says the app id',
      '<binary> is what the docs call it; where is the loader?',
      'analyze <task-notification>…</task-notification> and tell me what it is', // ends with text
      '/rea-jev:reverse-engineer https://example.com/',
      '',
      null,
    ]) {
      assert.equal(isHarnessEnvelope(p), false, String(p).slice(0, 40));
    }
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
    'unpack the firmware for this router',
    'what is in this pcap',
    'what does the wasm module export',
    'read the packet capture from the device',
  ];
  const misses = [
    'fix the failing unit test in src/utils.ts',
    'write a README for this project',
    'add a button to the settings page',
    'rename the variable and run prettier',
    'summarize this meeting transcript',
    'help me with a regex for dates',
    'add a sqlite table for sessions',
    'fix the flutter widget padding',
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
    for (const e of ['ws://127.0.0.1:9222/x', 'http://localhost:9222/json', 'localhost:9229', '[::1]:9229', 'ws://[::1]:9229/abc', 'http://127.5.6.7:9222', 'http://app.localhost:9222', '0.0.0.0:9222', 'http://[::ffff:127.0.0.1]:9222', 'http://[::ffff:7f00:1]:9222', '[::ffff:7f00:0001]:9222']) {
      assert.equal(isLoopback(e), true, e);
    }
  });
  test('remote and garbage forms', () => {
    for (const e of ['http://10.0.0.5:9222/json', 'ws://192.168.1.20:9229/x', 'example.com:9222', 'http://127.0.0.1.evil.com:9222', 'http://127.0.0.1@evil.com:9222', 'http://localhost.evil.com:9222', 'http://127.0.0.1.nip.io:9222', 'http://[::]:9222', 'http://[::ffff:a00:1]:9222', '', null, 'not an endpoint at all', 42]) {
      assert.equal(isLoopback(e), false, String(e));
    }
  });
});
