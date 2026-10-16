# Changelog

All notable changes to rea-jev are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [0.3.0] - 2026-10-16

The route hook now names the artifact kinds rea-agents 6.5.0 reads with a
format-aware tool. A firmware image, a packet capture or web recording, a
WebAssembly module, a SQLite database or a Flutter APK used to route as
`native_binary` or `package_archive` and leave the tool choice to Claude once
the file was open; each now has its own `target_kind`, its own sniff rules and
its own first tool in the route note.

### Added

- Five `target_kind` options in `scripts/hook-route.mjs` (the nine existing
  ones are unchanged): `firmware_image`, `packet_capture` (pcap/pcapng, plus
  recorded web traffic: HAR, mitmproxy, Fiddler SAZ, qlog), `wasm_module`,
  `sqlite_database`, `flutter_app`. The Jev choice has fourteen options.
- `FIRST_TOOL_BY_TARGET` in `scripts/lib/rea.mjs`: `firmware_image` →
  `inspect_firmware_regions(path)` then `extract_firmware` / `open_binary`;
  `packet_capture` → `inspect_pcap_capture(path)` then
  `inspect_packet_capture` / `inspect_packet_fields`, with a `web_recording`
  variant → `inspect_web_network_capture(capture_path, format)` then
  `export_web_scripts` / `analyze_javascript_application`; `wasm_module` →
  `inspect_wasm_artifact(path)` then `inspect_analysis_view` /
  `compare_wasm_interfaces`; `sqlite_database` → `inspect_sqlite_database(path)`;
  `flutter_app` → `identify_flutter_build(path)` then `inspect_dart_aot` /
  `inspect_android_package`. `firstToolFor(kind, variant)` and
  `describeFirstTool(kind, variant)` take the variant; a variant another kind
  lacks is ignored. Every name and printed input is checked against the
  207-tool catalog by `tests/rea-catalog.test.mjs`.
- Deterministic sniff rules in `scripts/lib/sniff.mjs`. Magic: `\0asm` → WASM;
  `SQLite format 3\0` → SQLite; the four pcap magics and the pcapng section
  header; a JSON head with `"log"` and `"version"` (or `"log"` on a `.har`) →
  HAR; `"qlog_version"`/`"qlog_format"` or a JSON-SEQ `.qlog`/`.sqlog` → qlog;
  `PK` + `.saz` → SAZ; a `.apk` whose central directory names `libflutter.so`
  → Flutter (one bounded read, ≤ 1 MiB, of the directory; ZIP64 or an
  oversized directory stays a plain APK); the firmware container and
  filesystem magics (uImage, SquashFS, CramFS, JFFS2, UBI, UBIFS, TRX,
  device tree / FIT, UF2, DfuSe, `ANDROID!`, Intel HEX, S-record); a gzip /
  xz / lzma / bzip2 / zstd / lz4 stream is `compressed` and firmware only
  when its extension says so. Extensions: `.wasm .sqlite .sqlite3 .db .db3
  .pcap .pcapng .har .saz .qlog .sqlog .mitm` and the firmware extensions
  `.fw .rom .hex .ihex .srec .uf2 .ubi .squashfs .trx .dfu` make a bare token
  a path candidate and resolve a missing or unrecognized file; `.bin` and
  `.img` alone name nothing. `targetKindFor` maps each to its kind;
  `webRecordingFormat(token)` gives the `format` value
  `inspect_web_network_capture` takes (`har`, `mitmproxy`, `saz`, `qlog`),
  magic first, extension second, never for a pcap. Hints name the format
  (`path … is a pcapng packet capture`, `… is an Android package built with
  Flutter (apk with libflutter.so)`). The keyword pre-filter adds `firmware`,
  `pcap`/`pcapng`, `packet capture`, `wasm`, `webassembly`; `sqlite` and
  `flutter` stay out (ordinary coding words).
- The route note's variant is decided by the sniffed file, not by Jev: when
  Jev names `packet_capture` and the first existing capture token (or, absent
  one, the first named) is a HAR, mitmproxy, SAZ or qlog recording, the line
  prints `inspect_web_network_capture(capture_path, format)`; otherwise the
  pcap tool. The format itself is in the hint line.
- Tests: `tests/sniff.test.mjs` covers every new magic, extension fallback,
  hint and `webRecordingFormat`; `tests/hook-route.test.mjs` builds a pcap, a
  HAR, a WASM module, a SQLite file, a uImage and a Flutter APK at runtime and
  checks each reaches Jev with its sniff hint and gets its first tool, plus the
  pcap-next-to-HAR and HAR-alone variant cases; `tests/hook-harness.mjs` gains
  `buildZip` (a stored zip with a central directory; nothing binary is
  committed).

### Changed

- `references/route-table.md`: the five kinds move from "Other targets added
  in rea-agents 6.5.0" into the main table with their sniff rules, first
  tools, follow-ups and what static evidence cannot establish; the sniff
  section lists the new magics, extensions and the APK directory read; the
  remaining other targets (sigrok, EVM, Go/Rust, PE resources, crash reports,
  Electron fuses, JEB, app graphs) keep their table. DESIGN.md §5.1 and
  `docs/decision-points.md` carry the fourteen options and the first-tool
  table; `commands/investigate.md` and the skill's routing paragraph name the
  new first tools; `references/system1-decision-points.md` says fourteen
  kinds.
- The sniffer reads the first 64 bytes of a regular file (as before) plus, for
  a `.apk`, the zip end-of-central-directory record and at most 1 MiB of the
  central directory. Nothing else about its bounds changes.

## [0.2.0] - 2026-10-16

REA pin bumped from `rea-agents@4.0.1` to `rea-agents@6.5.0`: 207 tools, up
from 116; `set_current_document` is gone, 92 tools are new. With the global
`rea setup` registration also at 6.5.0, the plugin's bundled server and the
global one expose the same catalog, so a session that loads both no longer
sees two REA versions.

### Changed

- `data/rea-tool-catalog.json` regenerated from rea-agents 6.5.0 by the new
  `scripts/import-rea-catalog.mjs` (`npm run catalog:import -- <package dir>`).
  It reads the package's `dist/contracts/toolContracts.js`, since the flat
  `generatedMcpToolCatalog.js` module the old procedure named no longer ships,
  and resolves local `$defs` references so property enums survive. The catalog
  shape drops `requiresSession` and `analysisOperation` (gone upstream) and
  adds `returnsTargetContent`. `references/tool-catalog.md` regenerated: 17
  catalog kinds, seven of them new (android, apktool, pcap, flutter, jeb, adb,
  firmware providers). `docs/upstream-rea.md` describes the new procedure.
- Effect classes cover the 92 new tools. `runtime` now includes the debugger,
  instrumentation and device-control tools by name (`start_gdb_session`,
  `gdb_console`, `start_rizin_debug_session`, `rizin_debug_command`,
  `execute_rizin_command`, `cutter_command`, `start_frida_session`,
  `instrument_with_frida`, `load_frida_script`, `resume_frida_session`,
  `install_adb_package`, `uninstall_adb_package`, `push_adb_file`,
  `start_adb_app`, `start_adb_activity`, `stop_adb_app`), every tool whose
  catalog effects say `executesForeignCode` or `mutatesDevice`, and a
  `capture_*`/`observe_*` tool that launches a process, mutates the target or
  executes foreign code (`observe_web_execution`, `observe_native_calls` and
  `capture_adb_screen` join; the passive `observe_web_session`,
  `observe_javascript_runtime` and `capture_web_screenshot` stay `inspect`).
  In 6.5.0 `launchesProcess` alone no longer means "runs the target": plutil,
  lipo, apktool and adb set it on plain inspections, so it is no longer the
  runtime signal by itself. `mutation` adds the `open_*`/`close_*` lifecycle
  prefixes (`open_jeb_project`, `close_frida_session`, `close_gdb_session`,
  `close_rizin_debug_session`), `unload_frida_script`, and the file-producing
  `extract_firmware`, `recover_javascript_sources`, `pull_adb_file`,
  `pull_adb_package`, `collect_adb_bugreport`. `status` adds
  `*_session_status`, `list_cutter_sessions`, `list_frida_devices`,
  `list_frida_processes`, `list_adb_devices`: live inventories that change
  without an REA mutation, so a repeat is never denied as redundant.
  `scripts/validate.mjs` carries the same rules; `tests/rea-catalog.test.mjs`
  checks the two agree over all 207 tools.
- Gate hard rule: the out-of-scope program check that applied to
  `capture_process_scenario.executable` now reads `executable`, `program`,
  `path`, `executable_path` and `application_path` on every runtime-class tool
  (a Frida spawn, a Rizin debug session, an Electron scenario), resolved
  against `working_directory`. The Jev path gate for files leaving `cwd` adds
  `extract_firmware`, `export_web_scripts`, `recover_javascript_sources`,
  `pull_adb_file`, `pull_adb_package`, `collect_adb_bugreport`; `device_*`
  inputs name paths on the device and are not local paths.
- `isStaticTool` is false for the runtime-class tools above and their session
  tools, for `adb-provider` tools that reach a device, and for tools that read
  recordings (`inspect_web_network_capture`, `inspect_pcap_capture`,
  `inspect_packet_capture`, `inspect_packet_fields`, `inspect_recorded_crash`,
  `decode_signal_recording`) or compare runtime captures
  (`compare_process_captures`, `correlate_static_and_runtime`,
  `find_changed_behavior`), so the evidence hook no longer tells Claude that
  static analysis cannot establish execution on results that are runtime
  evidence.
- The `android_apk` route resolves to `inspect_android_package` (then
  `decode_android_resources`, `search_android_classes`,
  `inspect_android_class`, `trace_android_references`); the Android allowlist
  in `validate.mjs` and the 4.0.1 caveats in the skill, route table, user
  guide and upstream notes are gone. The route table gains the device, debugger
  and recording tools and a table of the other artifact kinds 6.5.0 reads
  (firmware, pcap, HAR, WASM, EVM, SQLite, Flutter, Go, Rust, PE resources,
  JEB). The route hook's `target_kind` options are unchanged: those artifacts
  still route as `native_binary` or `package_archive` by sniff.
- `references/evidence-ledger.md` documents `record_unknown`'s required
  `relationships` field (required since 4.0.1, missing from the table).

### Not re-verified on 6.5.0

- The launch-mode proxy allow-list behavior of `capture_browser_scenario`
  (0.1.3) was observed on 4.0.1; the connect-mode workaround stays documented
  with that caveat.

## [0.1.4] - 2026-10-07

Hook noise found while mapping landonorris.com with the plugin active (48
route events and 40 evidence events in one session), fixed with a measurement
behind each change.

### Fixed

- The route hook routed the host's own messages. Claude Code delivers task
  notifications and subagent hand-backs through `UserPromptSubmit` too, and
  once a session had REA activity every one of them reached Jev; one even
  replaced the declared target with a workflow
  script path, and the sniffer read closing XML tags (`</task-id>`,
  `</output-file>`) as paths that "were not found on disk". A prompt that is
  nothing but XML elements is now recognized as a harness envelope and skipped
  before the pre-filter: no Jev call, no ledger event, the declared target
  carries forward (27 of that session's 48 route events). A closing tag is no
  longer a path candidate, and a leading slash command
  (`/rea-jev:reverse-engineer`) is no longer a path hint.
- The evidence hook asked for `record_unknown` on every result of a tool whose
  limitations never change. REA repeats the same disclaimers on every
  `inspect_web_page` ("Observation starts when REA attaches…") and
  `analyze_web_bundle`; the old question scored them 0.8–0.98 and the note
  quoted the first one each time. The question now asks for a gap specific to
  this result and names fixed disclaimers and "coverage is complete" statements
  as false (on 23 recorded results, `list_browser_targets`'s "All page targets
  … are listed" fell from 0.83 to 0.25, while results that report a missing or
  policy-filtered section stayed at 0.86–0.97), and the note is emitted only
  when the result carries a limitation sentence no earlier note this session
  covered, quoting that sentence; a limitation recorded without a note (Jev
  skipped or failed, or the answer was below the bar) stays eligible. A
  `completeness` object whose status is not complete now becomes a limitation
  sentence of its own (`completeness incomplete; missing_sections: events`),
  ahead of the tool's fixed disclaimers, so the note quotes the result's
  actual gap. Replayed over the recorded session: 4 notes instead of 23, one
  per tool. The answer is still recorded on every call; the decision log
  marks a withheld note.

## [0.1.3] - 2026-10-06

### Added

- Skill guidance for `capture_browser_scenario` behind an outbound proxy,
  found while capturing landonorris.com from a cloud sandbox. In launch mode
  rea-agents 4.0.1 starts Chromium with an environment allow-list that leaves
  out `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`, so the browser cannot reach
  the site and the call fails with a bare `execution_failure` (reproduced: the
  same Chromium with REA's allow-list loads nothing, with the proxy variables
  it loads the page). The route table now gives the connect-mode workaround: a
  browser you start on `about:blank` with a fresh profile, its target id read
  from `/json/list` (`list_browser_targets` does not list `about:blank`), and
  REA navigating from the first byte. `SKILL.md` points to it.

## [0.1.2] - 2026-10-06

Two false positives found while reverse-engineering a live website with the
plugin active, both fixed with a measurement behind them.

### Fixed

- The evidence hook warned "text that reads as instructions to an assistant"
  on results it never saw: when a result is too large for the context, Claude
  Code hands the hook its own notice ("Output has been saved to <file>" plus
  reading instructions) in place of the result. The hook now recognizes that
  notice (both wordings, with and without "across M lines"), reads back
  the file Claude Code saved for this call (only from Claude Code's own
  `tool-results` directory under `$CLAUDE_CONFIG_DIR`, real path checked,
  symlinks refused, only an REA envelope with an `evidence_id`, at most 64
  MB) and judges the real result, so its Evidence IDs also reach the ledger and the Stop
  hook. The notice itself never reaches Jev; an unreadable file is recorded
  as `oversize_notice: true, recovered: false` and skips Jev.
- The route hook routed "fix the false positive warning" as a website
  investigation because the session had an active target. Measured on
  jev-1.13: `is_re_task` for that prompt was 0.06 alone and 0.55 with the
  target in the state. Two changes: the question now says to judge the prompt
  alone and names code changes, tests, merges and formatting during an active
  investigation as not reverse engineering (0.55 → 0.24), and a prompt that
  reached Jev only through the ledger's REA activity, with no keyword, path,
  or endpoint of its own, must clear the new `T_ROUTE_RE_FOLLOWUP` (0.5,
  `REA_JEV_T_ROUTE_RE_FOLLOWUP`) instead of `T_ROUTE_RE` (0.35). Real
  follow-ups still route ("and the login flow?" measured 0.83).

## [0.1.1] - 2026-10-06

First run against the live TypeSafe API (`jev-1.13.0`): round trip 299 ms,
hook latency p50 283 ms / p90 338 ms, 7,154 input tokens for a full fixture
session (route, gate, evidence, stop) at an estimated $0.0003. Every hook
behaved as designed; two defects surfaced and are fixed here.

### Fixed

- Redaction treated the scope operator in identifiers such as
  `NetworkSession::send` as a credential assignment and masked the member
  name. The key/value pattern now requires `=` or a single `:` as the
  separator, and the value may not begin with `:`.
- The gate could `deny` a runtime capture as out of scope in `enforce` mode
  when the session had no declared target (an ambiguous route). Scope cannot
  be established without a target, so that case now asks the user instead.

## [0.1.0] - 2026-10-06

Initial release.

### Added

- Claude Code plugin manifest and single-repo marketplace
  (`claude plugin marketplace add juan-viox/rea-jev`,
  `claude plugin install rea-jev@rea-jev`).
- Bundled REA MCP server pinned to `rea-agents@4.0.1`, with a tool catalog
  (`data/rea-tool-catalog.json`, 116 tools) generated from the same release.
- Four System 1 decision points as Claude Code hooks, all failing open:
  `UserPromptSubmit` route (target kind, workflow, scope, runtime need),
  `PreToolUse` gate (local redundancy and hard rules, then Jev scope/risk for
  runtime-class tools), `PostToolUse` evidence scoring (relevance, untracked
  limitations, agent-directed text, runtime claims from static tools), and a
  `Stop` completeness check (claims vs ledger). Plus a `SessionStart` status
  line.
- Per-session JSONL ledger of hashes, Evidence IDs, and short redacted
  excerpts; optional `decisions.jsonl` log.
- `jev` CLI for System 2 to ask System 1: `ask`, `rank`, `classify`,
  `verify`, `doctor`, `stats`; TypeSafe direct or OpenRouter provider.
- `reverse-engineer` skill with route table, generated tool catalog,
  decision-point guide, Jev recipes, evidence-ledger rules, and
  reconstruction notes.
- `rea-investigator` and `rea-verifier` subagents; `/rea-jev:setup` and
  `/rea-jev:investigate` commands.
- Modes `off`, `shadow`, `advise` (default), `enforce`; env-tunable
  thresholds (`REA_JEV_T_*`).
- Offline test suite against a fake Jev server, repository validator
  (`scripts/validate.mjs`, with `--write-catalog`), and GitHub Actions CI.
- Review fixes before release: the 429/529 retry now happens in real hook and
  CLI processes (the retry timer no longer lets Node exit); provider answers
  are validated against the questions; hard actions (`deny`, `block`,
  categorical `verify` verdicts) require a decisive answer; the gate, evidence
  and stop hooks judge against the last reverse-engineering request (kept at
  1200 chars) rather than a later follow-up prompt; limitations are read from
  REA's envelope only; passive live-process tools are never told static
  analysis cannot establish execution; linear-time redaction with more token
  shapes and a `PWD` exception; URL credentials stripped at the sniffer;
  Evidence IDs capped per result; empty results are not reusable; `jev verify
  --claim-file`; balanced `rank` chunks, bounded concurrency and partial
  results; `classify` puts the instructions in each question and appends
  `other`.

[0.1.0]: https://github.com/juan-viox/rea-jev/releases/tag/v0.1.0
[0.1.1]: https://github.com/juan-viox/rea-jev/compare/v0.1.0...v0.1.1
[0.1.2]: https://github.com/juan-viox/rea-jev/compare/v0.1.1...v0.1.2
[0.1.3]: https://github.com/juan-viox/rea-jev/compare/v0.1.2...v0.1.3
[0.1.4]: https://github.com/juan-viox/rea-jev/compare/v0.1.3...v0.1.4
[0.2.0]: https://github.com/juan-viox/rea-jev/compare/v0.1.4...v0.2.0
