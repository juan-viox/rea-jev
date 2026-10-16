/**
 * Effect classes and the static/runtime predicate against the pinned catalog
 * (rea-agents 6.5.0): the debugger, instrumentation and ADB tools added since
 * 4.0.1, the lifecycle tools, live inventories, the Android route, and
 * agreement between scripts/lib/rea.mjs and the validator's local copy over
 * every catalog tool.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { effectClass, isStaticTool, firstToolFor, loadCatalog, reaPin } from '../scripts/lib/rea.mjs';
import { effectClass as validatorEffectClass } from '../scripts/validate.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const catalog = JSON.parse(readFileSync(join(ROOT, 'data', 'rea-tool-catalog.json'), 'utf8'));
const names = new Set(catalog.tools.map((t) => t.name));

const RUNTIME = [
  'start_frida_session', 'instrument_with_frida', 'load_frida_script', 'resume_frida_session',
  'start_gdb_session', 'gdb_console', 'start_rizin_debug_session', 'rizin_debug_command', 'execute_rizin_command', 'cutter_command',
  'install_adb_package', 'uninstall_adb_package', 'push_adb_file', 'start_adb_app', 'start_adb_activity', 'stop_adb_app',
  'observe_native_calls', 'observe_web_execution', 'capture_adb_screen',
  'capture_process_scenario', 'capture_browser_scenario', 'capture_electron_scenario', 'capture_native_ui_scenario', 'observe_native_ui',
];
const MUTATION = [
  'open_binary', 'close_binary', 'open_jeb_project', 'close_frida_session', 'close_gdb_session', 'close_rizin_debug_session', 'unload_frida_script',
  'extract_artifact', 'extract_firmware', 'recover_javascript_sources', 'export_web_scripts', 'export_evidence_bundle', 'import_evidence_bundle',
  'pull_adb_file', 'pull_adb_package', 'collect_adb_bugreport', 'annotate_native_function', 'set_comment', 'unset_bookmark', 'record_unknown', 'update_unknown',
];
const STATUS = [
  'binary_session', 'list_unknowns', 'get_navigation_context', 'get_evidence_bundle', 'verify_unknown_resolution', 'list_documents', 'current_address',
  'frida_session_status', 'gdb_session_status', 'rizin_debug_session_status', 'list_cutter_sessions', 'list_frida_devices', 'list_frida_processes', 'list_adb_devices',
];
const PASSIVE_INSPECT = [
  'observe_web_session', 'observe_javascript_runtime', 'capture_web_screenshot', 'inspect_web_page', 'list_browser_targets', 'inspect_web_event_listeners',
  'inspect_adb_device', 'list_adb_packages', 'read_adb_logcat', 'inspect_android_package', 'decode_android_resources', 'search_strings', 'inspect_pcap_capture',
];

describe('catalog (rea-agents 6.5.0)', () => {
  test('pin, count, and every tool named in these tests exists', () => {
    assert.equal(reaPin(), '6.5.0');
    assert.equal(loadCatalog().toolCount, 207);
    assert.equal(catalog.tool_count, catalog.tools.length);
    for (const n of [...RUNTIME, ...MUTATION, ...STATUS, ...PASSIVE_INSPECT]) assert.ok(names.has(n), `${n} is not in the catalog`);
    assert.ok(!names.has('set_current_document'), 'set_current_document left the catalog in 6.x');
  });
  test('the Android route resolves to inspect_android_package with no fallback note', () => {
    const a = firstToolFor('android_apk');
    assert.equal(a.first, 'inspect_android_package');
    assert.equal(a.arg, 'path');
    assert.equal(a.available, true);
    assert.equal(a.note, undefined);
    assert.ok(a.then.includes('search_android_classes'));
  });
});

describe('effect classes', () => {
  test('runtime: debugger, instrumentation, device-control and active capture tools', () => {
    for (const t of RUNTIME) assert.equal(effectClass(t), 'runtime', t);
    assert.equal(effectClass('mcp__plugin_rea-jev_rea__start_gdb_session'), 'runtime');
  });
  test('every tool whose effects say executesForeignCode or mutatesDevice is runtime, or a close_* lifecycle mutation', () => {
    for (const t of catalog.tools) {
      if (!t.effects.executesForeignCode && !t.effects.mutatesDevice) continue;
      const cls = effectClass(t.name);
      assert.ok(cls === 'runtime' || (t.name.startsWith('close_') && cls === 'mutation'), `${t.name} is ${cls}`);
    }
  });
  test('mutation: lifecycle and file-producing tools', () => {
    for (const t of MUTATION) assert.equal(effectClass(t), 'mutation', t);
  });
  test('status: session state and live inventories', () => {
    for (const t of STATUS) assert.equal(effectClass(t), 'status', t);
  });
  test('passive attach and file-reading tools stay inspect', () => {
    for (const t of PASSIVE_INSPECT) assert.equal(effectClass(t), 'inspect', t);
  });
  test('a capture_/observe_ tool missing from the catalog is runtime by name; an unknown tool is inspect', () => {
    assert.equal(effectClass('capture_something_new'), 'runtime');
    assert.equal(effectClass('mcp__rea__observe_whatever'), 'runtime');
    assert.equal(effectClass('inspect_something_new'), 'inspect');
  });
  test('the validator classifies every catalog tool exactly as the library does', () => {
    for (const t of catalog.tools) assert.equal(validatorEffectClass(t), effectClass(t.name), t.name);
    const counts = { runtime: 0, mutation: 0, status: 0, inspect: 0 };
    for (const t of catalog.tools) counts[effectClass(t.name)] += 1;
    assert.equal(counts.runtime + counts.mutation + counts.status + counts.inspect, 207);
    assert.ok(counts.runtime >= RUNTIME.length, `runtime class has ${counts.runtime} tools`);
  });
});

describe('isStaticTool', () => {
  test('runtime, live-session and device tools are not static', () => {
    for (const t of [...RUNTIME, 'list_adb_devices', 'inspect_adb_device', 'read_adb_logcat', 'frida_session_status', 'gdb_session_status', 'list_frida_processes', 'list_cutter_sessions', 'close_gdb_session', 'unload_frida_script', 'inspect_web_event_listeners', 'observe_web_session', 'list_browser_targets', 'inspect_electron_page', 'observe_javascript_runtime']) {
      assert.equal(isStaticTool(t), false, t);
    }
  });
  test('recordings and capture comparisons are not static (their results describe observed behavior)', () => {
    for (const t of ['inspect_web_network_capture', 'inspect_packet_capture', 'inspect_packet_fields', 'inspect_pcap_capture', 'inspect_recorded_crash', 'decode_signal_recording', 'compare_process_captures', 'correlate_static_and_runtime', 'find_changed_behavior', 'compare_web_captures', 'compare_web_screenshots', 'reconcile_javascript_runtime']) {
      assert.equal(isStaticTool(t), false, t);
    }
  });
  test('file-reading analysis stays static', () => {
    for (const t of ['analyze_javascript_application', 'inspect_android_package', 'decode_android_resources', 'search_android_classes', 'inspect_firmware_regions', 'inspect_go_binary', 'inspect_wasm_artifact', 'inspect_sqlite_database', 'decompile_jeb_item', 'inspect_adb_client', 'inspect_apktool_client', 'search_strings', 'analyze_function', 'inspect_managed_artifact']) {
      assert.equal(isStaticTool(t), true, t);
    }
  });
  test('without a catalog entry, *_adb_* names and the live fallbacks are not static', () => {
    assert.equal(isStaticTool('list_adb_something_new'), false);
    assert.equal(isStaticTool('inspect_something_new'), true);
  });
});
