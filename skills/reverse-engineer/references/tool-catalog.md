# REA tool catalog (rea-agents 6.5.0)

Generated from rea-agents 6.5.0 (207 tools). Source: `data/rea-tool-catalog.json`. Do not edit by hand; regenerate with `node scripts/validate.mjs --write-catalog` after bumping the pin.

Tool names are bare. In Claude Code they appear as `mcp__rea__<tool>` (REA registered globally by `rea setup`) or `mcp__plugin_rea-jev_rea__<tool>` (REA bundled by this plugin). Required inputs are the schema's `required` list; optional inputs are in the JSON catalog.

**Effect class** is what the rea-jev gate (`scripts/lib/rea.mjs`) uses, derived from the name and the catalog effect flags (`launchesProcess`, `mutatesTarget`, `executesForeignCode`, `mutatesDevice`):

| Class | Rule | Gate behavior |
|---|---|---|
| `runtime` (24) | the debugger, instrumentation and device-control tools (`start_frida_session`, `instrument_with_frida`, `load_frida_script`, `resume_frida_session`, `start_gdb_session`, `gdb_console`, `start_rizin_debug_session`, `rizin_debug_command`, `execute_rizin_command`, `cutter_command`, `install_adb_package`, `uninstall_adb_package`, `push_adb_file`, `start_adb_app`, `start_adb_activity`, `stop_adb_app`); a `capture_*` or `observe_*` tool that launches a process, mutates the target or executes foreign code; any tool whose effects say `executesForeignCode` or `mutatesDevice` | local hard rules, then a Jev scope/risk check; may `ask` or `deny` |
| `mutation` (26) | `set_*`, `annotate_*`, `import_*`, `export_*`, `open_*`, `close_*`, `unset_bookmark`, `record_unknown`, `update_unknown`, `extract_artifact`, `extract_firmware`, `recover_javascript_sources`, `pull_adb_file`, `pull_adb_package`, `collect_adb_bugreport`, `unload_frida_script` | never deduplicated; resets the redundancy window |
| `status` (16) | `binary_session`, `list_unknowns`, `get_navigation_context`, `current_*`, `*_session_status`, `get_evidence_bundle`, `verify_unknown_resolution`, `list_documents`, `list_cutter_sessions`, `list_frida_devices`, `list_frida_processes`, `list_adb_devices` | never deduplicated, never sent to Jev |
| `inspect` (141) | everything else | an identical repeated call (same tool + same input) is denied until a mutation happens; results are scored by the evidence hook |

Contents: [official-proxy](#official-proxy-41-tools) · [enhanced](#enhanced-14-tools) · [native-provider](#native-provider-32-tools) · [application](#application-20-tools) · [artifact-provider](#artifact-provider-16-tools) · [managed-provider](#managed-provider-3-tools) · [android-provider](#android-provider-5-tools) · [apktool-provider](#apktool-provider-2-tools) · [pcap-provider](#pcap-provider-2-tools) · [flutter-provider](#flutter-provider-2-tools) · [jeb-provider](#jeb-provider-4-tools) · [adb-provider](#adb-provider-24-tools) · [firmware-provider](#firmware-provider-2-tools) · [browser-provider](#browser-provider-12-tools) · [electron-provider](#electron-provider-5-tools) · [runtime-provider](#runtime-provider-2-tools) · [session](#session-21-tools)

## official-proxy (41 tools)

Official proxy — Hopper/Ghidra provider primitives.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `annotate_native_function` | Atomically update one function name and/or entry comments, read them back, and return a refreshed complete function dossier. | `procedure` | mutation |
| `inspect_native_load_image` | Verify the provider's loaded DOS MZ or explicitly selected COM image against its immutable target snapshot: complete original/modified… | — | inspect |
| `inspect_native_data_type` | Inspect one recovered type by exact database category path or defined typed data address. | — | inspect |
| `inspect_native_instruction` | Inspect one exact code or data address: decoded bytes, mnemonic, ordered operand tokens, flow, outgoing instruction references and typed… | `address` | inspect |
| `resolve_native_call_targets` | Resolve one explicit static call site using typed provider call references. | `address` | inspect |
| `address_name` | Resolve the primary analyzed name at a code or data address. | — | inspect |
| `comment` | Read the regular analysis comment at an address, defaulting to the current cursor. | — | inspect |
| `current_address` | Return Hopper's current cursor address for the selected document. | — | status |
| `current_procedure` | Return the analyzed procedure containing Hopper's current cursor. | — | status |
| `current_document` | Return the document currently selected by REA's Hopper bridge. | — | status |
| `goto_address` | Move Hopper's GUI cursor to a mapped address and return the observed cursor address. | `address` | inspect |
| `inline_comment` | Read the inline instruction comment at an address, defaulting to the current cursor. | — | inspect |
| `list_bookmarks` | List every bookmark in the selected Hopper document as address and name pairs; unnamed bookmarks retain a null name. | — | inspect |
| `list_documents` | List provider program or document identities. | — | status |
| `list_names` | List every analyzed memory and external symbol as address/value pairs. | — | inspect |
| `list_procedures` | List every analyzed procedure as address/value pairs after provider analysis. | — | inspect |
| `list_segments` | List segments or memory blocks using exclusive end addresses. | — | inspect |
| `list_strings` | List every provider-defined string object, or filter to one address, as address/value pairs with encoding, terminator status, and byte… | — | inspect |
| `next_address` | Return the next analyzed object address after an explicit address or current cursor. | — | inspect |
| `prev_address` | Return the previous analyzed object start before an explicit address or current cursor. | — | inspect |
| `procedure_address` | Resolve an unambiguous procedure symbol name or provider-normalized address to its canonical entry address. | `procedure` | inspect |
| `procedure_assembly` | Return assembly for one analyzed procedure identified by symbol or hexadecimal address. | `procedure` | inspect |
| `procedure_callees` | Return the provider's resolved direct callees for one procedure identified by symbol or address. | `procedure` | inspect |
| `procedure_callers` | Return the provider's resolved direct callers for one procedure identified by symbol or address. | `procedure` | inspect |
| `procedure_info` | Return provider metadata for one procedure identified by symbol or address: entrypoint, signature, locals, size, block count, and complete… | `procedure` | inspect |
| `read_function_instructions` | Return every raw instruction for one analyzed procedure. | `procedure` | inspect |
| `search_bytes` | Find masked byte signatures in initialized analyzed memory. | `pattern` | inspect |
| `read_bytes` | Read analyzed bytes from one provider-normalized virtual address. | `address` | inspect |
| `address_to_file_offset` | Map one provider-normalized virtual address to its original nonnegative file offset. | `address` | inspect |
| `procedure_references` | Return every raw incoming or outgoing reference edge for one procedure. | `procedure` | inspect |
| `procedure_pseudo_code` | Decompile one analyzed procedure by symbol name or provider-normalized address. | `procedure` | inspect |
| `resolve_containing_procedure` | Resolve an arbitrary address, including an interior instruction or exact external entry, to its provider-analyzed containing procedure. | `address` | inspect |
| `search_procedures` | Search every analyzed procedure name using literal matching by default or regex when requested. | `pattern` | inspect |
| `search_strings` | Search every provider-defined string object using literal matching by default or regex when requested. | `pattern` | inspect |
| `set_address_name` | Assign an analyst name to one mapped hexadecimal address and report whether the native edit succeeded and exact readback matched. | `address`, `name` | mutation |
| `set_addresses_names` | Assign analyst names to multiple mapped addresses in one call and return per-address edit/readback success booleans. | `names` | mutation |
| `set_bookmark` | Create or replace a bookmark at a mapped hexadecimal address and report success. | `address` | mutation |
| `set_comment` | Write a regular analysis comment at a hexadecimal address and return whether readback matched. | `address`, `comment` | mutation |
| `set_inline_comment` | Write an inline instruction comment at a hexadecimal address and return whether readback matched. | `address`, `comment` | mutation |
| `unset_bookmark` | Remove the bookmark at a mapped hexadecimal address and return whether it is absent. | `address` | mutation |
| `xrefs` | Return analyzed references to a code or data address. | — | inspect |

## enhanced (14 tools)

Enhanced — composed native analysis.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `inspect_native_dispatch_metadata` | Inspect the bound provider's name inventory for Objective-C class/method symbols and Swift mangled symbols, returning at most max_records… | — | inspect |
| `get_objc_classes` | Discover and deduplicate Objective-C class labels, optionally filtering by literal substring. | — | inspect |
| `get_objc_protocols` | Discover and deduplicate Objective-C and Swift protocol labels. | — | inspect |
| `batch_decompile` | Decompile each explicit procedure symbol or address concurrently. | — | inspect |
| `get_call_graph` | Resolve one symbol or address to its canonical procedure entry, then traverse the bound provider's caller or callee relationships until… | `address` | inspect |
| `analyze_swift_types` | Categorize analyzed Swift procedure names using their manglings or same-address Swift symbol aliases. | — | inspect |
| `find_xrefs_to_name` | Resolve an exact name against the bound provider's name inventory and return a resolved or unresolved result. | `name` | inspect |
| `binary_overview` | Return the bound document and exhaustive procedure/string counts, plus every segment and segment_count when the provider supports segment… | — | inspect |
| `analyze_function` | Build a dossier for one native function identified by symbol or provider-returned address. | `procedure` | inspect |
| `inspect_native_api` | Analyze a native API boundary in one function identified by symbol or provider-returned address. | `procedure` | inspect |
| `trace_feature` | Trace the complete literal query, preserving spaces, through every matching string and procedure, their xrefs, and truthful… | `query` | inspect |
| `trace_call_path` | Resolve start and optional goal symbols or addresses to canonical procedure entries, then trace direct callers or callees until the graph… | `start` | inspect |
| `trace_native_ui_action` | Trace one unique compiled UI action, object ID, native symbol or exact function address through authored connections, encoded… | `action` | inspect |
| `trace_native_values` | Trace a bounded static dependency graph from one explicit native procedure. | `procedure` | inspect |

## native-provider (32 tools)

Native provider — Mach-O metadata and native UI.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `observe_native_ui` | Observe an already-running native app by PID and window ID, bound to the active Mach-O target. | `pid`, `window_id` | runtime |
| `capture_native_ui_scenario` | Run selected-element press, increment/decrement scroll, AXValue text entry and bounded wait steps in one exact native app window. | `pid`, `window_id`, `steps` | runtime |
| `observe_native_calls` | Launch the active Mach-O as an owned process under LLDB and record each entry into caller-selected functions or Objective-C methods… | `breakpoints` | runtime |
| `inspect_macho` | Inspect Mach-O slices, load commands, imports, exports, dependencies, build metadata, segments, sections, permissions, and exact command… | — | inspect |
| `inspect_signature` | Inspect the active Mach-O executable's code-signing identity, hashes, authorities, requirements, entitlements, hardened-runtime state,… | — | inspect |
| `inspect_plist` | Parse Info.plist from the active artifact by default, or pass any local plist path. | — | inspect |
| `list_architectures` | List thin or universal Mach-O slices with offsets, sizes, alignment, explicit coverage, and native-tool provenance. | — | inspect |
| `demangle_swift` | Demangle an ordered list of single-line Swift symbols without requiring Hopper. | `symbols` | inspect |
| `inspect_pe_resources` | Inspect one explicit local PE32/PE32+ image's complete bounded type/name/language resource tree without executing it or opening… | `path` | inspect |
| `inspect_binary_layout` | Inspect an explicit local binary without launching it as a host process. | `path` | inspect |
| `inspect_recorded_crash` | Inspect a supplied Linux ELF64 amd64 or AArch64 little-endian core without launching its target or attaching to any live PID. | `path` | inspect |
| `list_cutter_sessions` | List live REA bridge sessions hosted by upstream Cutter instances, including observed document identity and bridge-directory security… | — | status |
| `cutter_command` | Run one arbitrary Rizin command in a selected live Cutter session. | `session_id`, `expected_generation`, `command` | runtime |
| `inspect_with_objdump` | Run caller-selected GNU objdump inspection against a local artifact, or request operation=architectures without a path to list BFD targets… | `operation` | inspect |
| `execute_rizin_command` | Execute one caller-selected Rizin command against a local artifact using the Rizin CLI profile that suppresses user settings and scripts… | `path`, `command` | runtime |
| `start_gdb_session` | Start a BYO GDB process in MI3 mode when available, suppress startup files, and disable auto-loading. | — | runtime |
| `gdb_console` | Run one unrestricted GDB CLI command through MI interpreter-exec console and return raw MI, console, target, and log records inline… | `session_id`, `command` | runtime |
| `gdb_session_status` | Return the observed lifecycle state and bounded recent MI records and process diagnostics for one persistent REA GDB session; truncation… | `session_id` | status |
| `close_gdb_session` | Close the owned GDB process after verifying the inferior state. | `session_id` | mutation |
| `start_rizin_debug_session` | Start a persistent Rizin debugger session using `-N` to suppress user settings and scripts while retaining plugins, `-0` for NUL framing… | `path`, `inferior_tty` | runtime |
| `rizin_debug_command` | Execute one unrestricted command in a persistent Rizin debugger session. | `session_id`, `command` | runtime |
| `rizin_debug_session_status` | Return observed lifecycle state and bounded recent NUL-framed output and process diagnostics for one Rizin debugger session; truncation… | `session_id` | status |
| `close_rizin_debug_session` | Close the REA-owned Rizin debugger only after verifying no inferior remains or detaching one with a verified caller-selected TTY output… | `session_id` | mutation |
| `list_frida_devices` | List Frida devices currently available to this host, optionally connecting to the caller-selected remote Frida endpoint. | — | status |
| `list_frida_processes` | List processes observed on a selected Frida device or caller-supplied remote endpoint. | — | status |
| `start_frida_session` | Attach Frida to one selected process or spawn one selected target. | `mode` | runtime |
| `load_frida_script` | Load caller-supplied JavaScript into a Frida session. | `session_id`, `source_kind` | runtime |
| `resume_frida_session` | Resume the process created by a paused Frida spawn session. | `session_id` | runtime |
| `unload_frida_script` | Unload one caller-selected Frida script from a live session. | `session_id`, `script_id` | mutation |
| `frida_session_status` | Return observed Frida session state and queued script messages. | `session_id` | status |
| `close_frida_session` | Unload session scripts and detach REA's Frida session. | `session_id` | mutation |
| `instrument_with_frida` | Run one caller-authored Frida script against an explicitly selected process and detach when the observation window ends. | `mode`, `source_kind` | runtime |

## application (20 tools)

Application workflows — managed and JavaScript graphs, reconstruction.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `inspect_analysis_view` | Inspect selected views of completed binary-layout, JavaScript application, native analyze_function, inspect_artifact, inventory_artifact… | `source`, `view` | inspect |
| `compare_wasm_interfaces` | Compare typed core WASM import/export names, kinds and exact signatures from two authenticated inspect_wasm_artifact Evidence records. | `left`, `right`, `scope` | inspect |
| `compare_managed_members` | Compare two authenticated inspect_managed_members Evidence records using unique-only tiers: exact declared type, name, and CIL/signature… | `left`, `right` | inspect |
| `verify_managed_native_boundaries` | Verify managed P/Invoke/native-boundary declarations against authenticated native export or function Evidence without executing managed… | `managed_boundaries`, `native_observations` | inspect |
| `import_managed_reconstruction` | Import decompiler-produced managed reconstruction against authenticated inspect_managed_members Evidence. | `static_members`, `decompiler`, `methods` | mutation |
| `project_managed_application_graph` | Project authenticated managed artifact, member, and native-boundary Evidence into the provider-neutral application graph without executing… | — | inspect |
| `trace_application_feature` | Trace a typed literal seed through every reachable part of an authenticated JavaScript Application Graph supplied as inline Evidence… | `seed`, `application` | inspect |
| `trace_javascript_semantics` | Trace static JavaScript data-flow, direct call/return, and closure relations from inline application Evidence or an exact same-session… | `application`, `query` | inspect |
| `compare_application_versions` | Compare two authenticated JavaScript Application Graph versions supplied as inline Evidence or exact same-session retained references. | `left`, `right` | inspect |
| `compare_source_to_bundle` | Compare a cryptographically committed HistoricalSourceGraph with authenticated JavaScript Application Graph Evidence supplied inline… | `reference`, `application` | inspect |
| `compare_javascript_export_shapes` | Compare static return shapes for one exact module/export selector on each authenticated JavaScript Application Graph supplied as inline… | `left_module_path`, `left_export_name`, `right_module_path`, `right_export_name`, `left`, `right` | inspect |
| `build_reconstruction_obligation_ledger` | Generate the complete deterministic ReconstructionObligationLedger from an authenticated Evidence bundle, reviewed obligations,… | `evidence_bundle`, `reviewed_obligations`, `manifest` | inspect |
| `evaluate_reconstruction_coverage` | Evaluate inline evidence-backed reconstruction coverage against one named boundary. | `coverage`, `boundary_id` | inspect |
| `project_android_application_graph` | Project authenticated APK inventory_artifact Evidence into an execution-free Android application inventory. | `inventory_evidence` | inspect |
| `project_apple_application_graph` | Project authenticated IPA, macOS .app directory, ZIP, or DMG inventory Evidence into an execution-free Apple application inventory. | `inventory_evidence` | inspect |
| `project_harmony_application_graph` | Project authenticated HarmonyOS HAP, HSP, or App Pack inventory Evidence into an execution-free application inventory. | `inventory_evidence` | inspect |
| `trace_web_source_location` | Trace one generated position in an exported website script through an explicitly paired local source map. | `manifest_path`, `script_index`, `source_map`, `generated_position` | inspect |
| `trace_web_module_imports` | Trace one exported website script's outgoing native ES imports/re-exports, using exact URL and optional selected import-map context. | `manifest_path`, `script_index` | inspect |
| `export_web_scripts` | Export JavaScript bytes already retained in one local inspect_web_page or capture_browser_scenario JSON capture (normalized result… | `capture_path`, `output_directory` | mutation |
| `recover_javascript_sources` | Recover readable modules from local UTF-8 JavaScript scripts/bundles into an absent directory, using caller-supplied Wakaru ^1.13.0… | `path`, `output_directory` | mutation |

## artifact-provider (16 tools)

Artifact provider — packages, archives, bundles.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `inspect_artifact` | Inspect an active archive or application package in one call. | — | inspect |
| `extract_artifact` | Extract all regular files from the active archive or application package into a fresh temporary directory chosen by REA. | — | mutation |
| `decode_interface_builder` | Decode compiled storyboard and nib archives inside the active Apple app bundle, including keyed property lists and NIBArchive object… | — | inspect |
| `inspect_keyed_archive` | Inspect one Foundation NSKeyedArchiver plist in the active app bundle as original object-table nodes, class descriptors, named roots,… | — | inspect |
| `inspect_asset_catalog` | Inspect compiled Assets.car metadata in an active Apple app bundle. | — | inspect |
| `trace_dylib_resolution` | Trace how dyld would resolve each Mach-O dylib load for the active Mach-O, or for every executable in the active .app bundle (the main… | — | inspect |
| `inspect_evm_interface` | Inspect explicit local flat EVM bytecode without target execution or chain/RPC access. | `path`, `encoding` | inspect |
| `inspect_go_binary` | Inspect embedded Go compiler version, main module, dependency/replacement versions and build settings in an explicit local ELF, PE or thin… | `path` | inspect |
| `inspect_rust_binary` | Inspect the cargo-auditable crate dependency list embedded in an explicit local ELF, PE or thin Mach-O image. | `path` | inspect |
| `inspect_wasm_artifact` | Validate an explicit local WASM artifact with caller-supplied WABT 1.0.42. | `path` | inspect |
| `inspect_sqlite_database` | Inspect an explicit local SQLite database snapshot and its existing sibling WAL without modifying source files or opening a native… | `path` | inspect |
| `inspect_packet_fields` | Discover protocols or field names/types registered in the installed TShark 4.x. | — | inspect |
| `inspect_packet_capture` | Inspect caller-selected fields in an existing local packet capture with TShark 4.x. | `path`, `fields` | inspect |
| `inspect_signal_decoders` | Discover installed sigrok protocol decoders or inspect one decoder's channel/option help on Linux. | — | inspect |
| `decode_signal_recording` | Decode an existing local logic/signal recording on Linux with sigrok-cli 0.7.2 and util-linux prlimit. | `path`, `decoders` | inspect |
| `inspect_electron_fuses` | Inspect packaged Electron fuse bytes in one local macOS app bundle, Electron Framework binary, Windows PE executable, or Linux ELF… | `path` | inspect |

## managed-provider (3 tools)

Managed provider — .NET PE/CLI.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `inspect_managed_artifact` | Inspect an explicit PE/CLI path, or the selected managed target, without loading or executing target code. | — | inspect |
| `inspect_managed_members` | Inspect PE/CLI metadata members, signatures, raw CIL hashes, decoded-instruction-tuple hashes, separately reported exception regions, call… | — | inspect |
| `inspect_managed_native_boundaries` | Inspect PE/CLI ModuleRef, ImplMap/PInvoke declarations, CLI native-header indicators, and non-IL method implementation flags… | — | inspect |

## android-provider (5 tools)

Android provider — APK classes, members and references.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `inspect_android_package` | Inspect a local APK's package, SDK and permission declarations, decoded manifest and class/resource counts. | `path` | inspect |
| `search_android_classes` | Search complete decompiler class-name rows in an explicit local APK by case-sensitive substring. | `path`, `query` | inspect |
| `inspect_android_class` | Inspect one exact Android class's parsed methods, fields and inner classes, including synthetic members. | `path`, `class_name` | inspect |
| `inspect_android_method` | Decompile one Android method with smali fallback. | `path`, `class_name`, `method_name` | inspect |
| `trace_android_references` | Trace incoming static using nodes to an exact Android class or selected method overload. | `path`, `class_name` | inspect |

## apktool-provider (2 tools)

Apktool provider — decoded manifest and resources.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `inspect_apktool_client` | Inspect the caller-selected apktool launcher: resolved command, selection source, and version. | — | inspect |
| `decode_android_resources` | Decode one local APK's resources with `apktool d --no-src` in a provider-owned workspace that is removed after projection: the readable… | `path` | inspect |

## pcap-provider (2 tools)

Packet-capture provider — pcap and pcapng files.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `inspect_pcap_client` | Inspect the caller-selected tshark and capinfos binaries: selected commands, selection sources, and versions. | — | inspect |
| `inspect_pcap_capture` | Request detail summary for capture identity/counts, then page retained facts with inspect_analysis_view kind pcap. | `path` | inspect |

## flutter-provider (2 tools)

Flutter provider — build identification and Dart AOT snapshots.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `identify_flutter_build` | Identify a Flutter app's build facts by pure parsing: the Dart VM snapshot hash from every lib/<abi>/libapp.so AOT section (vm… | `path` | inspect |
| `inspect_dart_aot` | Inspect one ABI's Dart AOT snapshot inside an APK: the four snapshot symbols located through the ELF dynamic symbol table with their… | `path` | inspect |

## jeb-provider (4 tools)

JEB provider — projects, units and decompilation through a running JEB.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `inspect_jeb_client` | Inspect the running JEB client serving MCP: engine version, GUI or headless mode, and startup time. | — | inspect |
| `open_jeb_project` | Open or create a JEB project from an artifact file or existing .jdb2 database on the engine host. | `path` | mutation |
| `list_jeb_units` | List project units by stable unit path and type, with optional wildcard filter, parent restriction, and pagination. | — | inspect |
| `decompile_jeb_item` | Decompile one type or method to engine pseudo-code using its decompiler (Dalvik, Java, or native). | `item_address`, `item_kind` | inspect |

## adb-provider (24 tools)

ADB provider — attached Android devices and emulators.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `inspect_adb_client` | Inspect the caller-selected adb client: resolved binary, version, and install path. | — | inspect |
| `list_adb_devices` | List attached devices exactly as `adb devices -l` reports them: serial, state, transport, model metadata, and an inferred… | — | status |
| `inspect_adb_device` | Inspect one device's build identity through a fixed `getprop` whitelist: Android and SDK versions, security patch, fingerprint, product… | `serial` | inspect |
| `list_adb_packages` | List installed packages on one device with each base APK's device path, optionally scoped to third-party or system packages. | `serial` | inspect |
| `pull_adb_package` | Pull one installed package's complete APK set (base plus every split, as `pm path` reports) from the device into a caller-selected output… | `serial`, `package`, `output_directory` | mutation |
| `read_adb_logcat` | Read a bounded dump of the device log (`logcat -d -t`) for one buffer, optionally restricted to a process id. | `serial` | inspect |
| `inspect_adb_package` | Inspect one installed package through `dumpsys package`: version name/code, install and update times, installer, user id, flags,… | `serial`, `package` | inspect |
| `pull_adb_file` | Pull one absolute device path (a database, shared-preferences XML, or any readable file) into a caller-selected output directory… | `serial`, `device_path`, `output_directory` | mutation |
| `push_adb_file` | Push one local file to an absolute device path. | `serial`, `local_path`, `device_path` | runtime |
| `capture_adb_screen` | Capture one frame of the device screen as a PNG (`screencap -p` through exec-out, no device-side file) into a caller-selected output… | `serial`, `output_directory` | runtime |
| `list_adb_processes` | List running processes exactly as `ps -A` reports them: user, pid, ppid, rss, state, and name. | `serial` | inspect |
| `list_adb_directory` | List the immediate children of one absolute device directory, including hidden entries: names, kinds, permissions, owner, group, sizes… | `serial`, `device_path` | inspect |
| `list_adb_features` | List the device's declared hardware and software features (`pm list features`) for device fingerprinting. | `serial` | inspect |
| `list_adb_services` | List the device's binder services with their interfaces (`service list`). | `serial` | inspect |
| `inspect_adb_display` | Report the display's physical and any overridden size (`wm size`) and density (`wm density`) as the device declares them. | `serial` | inspect |
| `inspect_adb_window` | Report the window manager's current focus declarations (mCurrentFocus and mFocusedApp from `dumpsys window windows`, or from `dumpsys… | `serial` | inspect |
| `read_adb_setting` | Read one settings value (`settings get`) from the system, secure, or global namespace. | `serial`, `namespace`, `key` | inspect |
| `collect_adb_bugreport` | Collect one device-generated bugreport archive (`adb bugreport`) into a caller-selected output directory, digesting the zip. | `serial`, `output_directory` | mutation |
| `resolve_adb_packages` | Find installed packages by case-insensitive substring of the package name (e.g. | `serial`, `query` | inspect |
| `install_adb_package` | Install one local APK on the device (`adb install [-r]`), recording the APK's host digest and byte size. | `serial`, `apk_path` | runtime |
| `uninstall_adb_package` | Uninstall one package from the device (`adb uninstall`), removing its data for user 0. | `serial`, `package` | runtime |
| `start_adb_app` | Start one installed app's resolved launcher activity with `am start -W -n`. | `serial`, `package` | runtime |
| `start_adb_activity` | Start an intent with `am start -W`: one action, optional data URI, optional explicit component, and up to 16 typed extras (string… | `serial`, `action` | runtime |
| `stop_adb_app` | Force-stop every process of one package (`am force-stop`), ending a dynamic-analysis run. | `serial`, `package` | runtime |

## firmware-provider (2 tools)

Firmware provider — image regions and extraction.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `inspect_firmware_regions` | Inspect signature candidates in a local firmware file with Binwalk 3.1.x (verified with 3.1.0). | `path` | inspect |
| `extract_firmware` | Extract caller-selected firmware bytes with Unblob 26.6.x (verified with 26.6.4) into an absent output directory. | `path`, `output_directory` | mutation |

## browser-provider (12 tools)

Browser provider — Chrome DevTools Protocol.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `list_browser_targets` | List page targets exposed by the selected loopback Chrome DevTools Protocol endpoint. | `cdp_endpoint` | inspect |
| `inspect_web_page` | Passively inspect one selected page target through CDP without evaluating JavaScript, navigating, clicking, closing, or mutating the page. | `cdp_endpoint`, `target_id` | inspect |
| `analyze_web_bundle` | Capture JavaScript source from one selected CDP page and statically derive a chunk graph, route and endpoint candidates, vendor… | `cdp_endpoint`, `target_id` | inspect |
| `observe_web_session` | Arm a CDP observation window of the requested duration while the user operates the page. | `cdp_endpoint`, `target_id` | inspect |
| `discover_webmcp_tools` | Passively inventory every page-registered WebMCP tool and its complete structural input-schema summary using the experimental CDP WebMCP… | `cdp_endpoint`, `target_id` | inspect |
| `compare_web_captures` | Compare passive web captures by providing before and after, each with the complete inspect_web_page normalized_result in inspection… | — | inspect |
| `capture_web_screenshot` | Capture the current visible viewport of one configured page as an inline, content-addressed PNG artifact. | `cdp_endpoint`, `target_id` | inspect |
| `compare_web_screenshots` | Compare two self-verifying PNG screenshot artifacts with local pixel metrics. | `before`, `after` | inspect |
| `capture_browser_scenario` | Run a controlled browser scenario when passive observation cannot exercise the application. | `browser`, `start_url`, `actions` | runtime |
| `observe_web_execution` | Instrument one selected CDP page for a finite, externally driven precise coverage window. | `cdp_endpoint`, `target_id` | runtime |
| `inspect_web_event_listeners` | Inspect listeners registered directly on the first main-document CSS match in one selected CDP page. | `cdp_endpoint`, `target_id`, `selector` | inspect |
| `inspect_web_network_capture` | Request detail summary for capture identity and counts; then page retained records with inspect_analysis_view kind capture (preview… | `capture_path`, `format` | inspect |

## electron-provider (5 tools)

Electron provider.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `list_electron_targets` | List every Electron file:// page target from a selected loopback CDP endpoint. | `cdp_endpoint` | inspect |
| `inspect_electron_page` | Passively inspect one Electron file page by supplying its loopback CDP endpoint and target ID. | `cdp_endpoint`, `target_id` | inspect |
| `analyze_javascript_application` | Reconstruct one local ASAR or extracted JavaScript application as an inline application graph without executing it. | `input_path` | inspect |
| `reconcile_javascript_runtime` | Reconcile verified static JavaScript application graphs with existing passive web/Electron CDP, passive V8 Inspector, or provider-owned… | `static_layers`, `runtime_observations` | inspect |
| `capture_electron_scenario` | Use this for a provider-owned Electron run when passive CDP or Inspector observation cannot exercise application behavior. | `executable_path`, `application_path` | runtime |

## runtime-provider (2 tools)

Runtime provider — V8 Inspector.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `list_javascript_runtime_targets` | List every eligible Node/Electron V8 Inspector target from an explicit literal-loopback endpoint. | `inspector_endpoint` | inspect |
| `observe_javascript_runtime` | Attach passively to one Node/Electron V8 Inspector target by supplying its loopback Inspector endpoint and target ID. | `inspector_endpoint`, `target_id` | inspect |

## session (21 tools)

Session — target lifecycle, Evidence, unknowns, comparisons.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `open_binary` | Open a local executable, application bundle, archive, JavaScript, source map, plist, or analysis database after validation. | `path` | mutation |
| `close_binary` | Drain earlier provider requests, optionally write a provider-neutral analysis snapshot atomically to the caller-supplied path, then close… | — | mutation |
| `binary_session` | Report the complete current target, provider, capability availability, client-feature, analysis, and server-identity status… | — | status |
| `export_evidence_bundle` | Atomically write the session's deterministic Evidence bundle to the requested local path. | `path` | mutation |
| `import_evidence_bundle` | Read the JSON bundle at the supplied local path, validate every Evidence ID and canonical manifest, then atomically merge it. | `path` | mutation |
| `capture_process_scenario` | Run one caller-selected command under a PTY and return process capture Evidence with residual unknowns. | `executable` | runtime |
| `compare_process_captures` | Compare two compatible process capture observations across terminal, interaction, lifecycle, process, filesystem, command-shim, HTTP,… | `left`, `right` | inspect |
| `compare_artifacts` | Compare complete artifact inventories by logical occurrence path, content identity, metadata, and graph relations. | `left`, `right` | inspect |
| `compare_functions` | Compare two explicit sets of analyze_function Evidence across identity, exact provider text, calls, references, strings,… | `left`, `right` | inspect |
| `compare_bundles` | Compare two canonical Evidence bundles by exact record membership, explicit one-to-one observation pairs, and complete residual-unknown… | `left_bundle_path`, `right_bundle_path` | inspect |
| `find_changed_behavior` | Aggregate validated process and artifact comparison Evidence. | `comparisons` | inspect |
| `build_call_path` | Build every shortest direct-callee path inline from complete analyze_function Evidence records using exact canonical addresses. | `functions`, `start`, `goal` | inspect |
| `correlate_static_and_runtime` | Evaluate every explicit caller-declared hypothesis between exact static comparison findings and runtime comparison dimensions. | `static_comparisons`, `runtime_comparisons`, `mappings` | inspect |
| `verify_reconstruction` | Verify a finite typed behavioral and structural specification against a canonical Evidence bundle. | `specification` | inspect |
| `list_unknowns` | List current residual-unknown heads in deterministic ID order, with optional exact status, severity, and domain filters. | — | status |
| `record_unknown` | Create one deterministic residual unknown and immutable mutation evidence. | `question`, `severity`, `domain`, `required_authority`, `required_confidence`, `required_environment`, `recommended_probes`, `relationships` | mutation |
| `update_unknown` | Append one immutable full-state revision and mutation evidence. | `unknown_id`, `expected_revision`, `status`, `severity`, `supporting_evidence_ids`, `contradicting_evidence_ids`, `required_authority`, `required_confidence`, `required_environment`, `recommended_probes`, `relationships`, `resolution` | mutation |
| `verify_unknown_resolution` | Revalidate the current residual-unknown head against live bundled evidence, exact authority/confidence/environment requirements,… | `unknown_id` | status |
| `get_evidence_bundle` | Return every retained Evidence record and residual unknown as a complete canonical bundle by default. | — | status |
| `get_navigation_context` | Return the selected document, current address, and containing/current procedure in one provider-neutral result. | — | status |
| `inspect_address_context` | Inspect one explicit reproducible address for its analyzed name, containing procedure, regular and inline comments, and matching bookmarks. | `address` | inspect |
