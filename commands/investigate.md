---
description: Start a System 1-guided REA investigation of one shipped artifact or site for one feature or question.
argument-hint: "<target path or URL> <feature or question>"
---

Arguments: `$ARGUMENTS`

Follow the `reverse-engineer` skill for the whole investigation. Start like this.

## 1. Split the arguments

The first token is the target: a path (possibly quoted), a URL, or a loopback
CDP or inspector endpoint. Everything after it is the feature or question. If
there is no target, ask which artifact to inspect; never pick an example app on
the user's behalf. If there is no question, treat the workflow as an overview
and say so.

## 2. Route the target deterministically, before any tool call

Look at the path on disk (extension, directory contents, first bytes) or the URL
shape and pick the first tool from this table. Do not call `open_binary` for a
JavaScript tree or a .NET assembly.

| Target looks like | Kind | First tool | Then |
|---|---|---|---|
| Mach-O, ELF, or PE file; native `.dylib`, `.so`, `.dll`; `.app` bundle; `.hop` database | native_binary | `open_binary` | `binary_overview`, `search_strings`, `trace_feature`, `find_xrefs_to_name`; decompile only what a hypothesis needs |
| Directory with `package.json`, `main.js`, or `app.asar`; an `.asar`; extracted or minified JS | javascript_application | `analyze_javascript_application` with `input_path` | `trace_application_feature`, `trace_javascript_semantics`, `compare_application_versions` |
| PE with a CLI header (.NET `.dll` or `.exe`) | managed_assembly | `inspect_managed_artifact` | `inspect_managed_members`, `inspect_managed_native_boundaries` |
| `.apk` | android_apk | `inspect_android_package` when the REA tool list has it; otherwise `open_binary` then `inspect_artifact` | `inspect_android_class`, `inspect_android_method` |
| `.zip`, `.ipa`, `.dmg`, `.msix`, `.appx`, or another container | package_archive | `open_binary` | `inspect_artifact`, then re-route the inner artifact |
| Firmware image or flash dump (uImage, SquashFS, UBI, TRX, device tree, UF2, Intel HEX, S-record, Android boot image; `.fw`, `.rom`, `.hex`, …; a `.bin` only when its magic says so) | firmware_image | `inspect_firmware_regions` | `extract_firmware` into an absent directory, then re-route each extracted member |
| `.pcap` or `.pcapng` packet capture | packet_capture | `inspect_pcap_capture` | `inspect_packet_capture` with `fields`, `inspect_packet_fields` |
| `.har`, mitmproxy, `.saz` or `.qlog` web recording | packet_capture | `inspect_web_network_capture` with `capture_path` and `format` (`har`, `mitmproxy`, `saz`, `qlog`) | `export_web_scripts`, then `analyze_javascript_application` on the result |
| `.wasm` module | wasm_module | `inspect_wasm_artifact` | `inspect_analysis_view` for WAT pages; `compare_wasm_interfaces` across two inspections |
| `.sqlite`, `.db` (SQLite magic) | sqlite_database | `inspect_sqlite_database` | the same tool with `table` and `columns` |
| `.apk` whose central directory lists `lib/*/libflutter.so` | flutter_app | `identify_flutter_build` | `inspect_dart_aot`; `inspect_android_package` for the rest of the package |
| Apple `.ips` crash report (a JSON object with `app_name` and `bug_type`) | crash_report | `inspect_apple_ips` | `open_binary` on the crashing image for the frames it names |
| `.ko` Linux kernel module (relocatable ELF, `ET_REL`) | kernel_module | `inspect_kernel_module` | `inspect_elf_notes`; `open_binary` for procedure-level work |
| `.beam` Erlang/Elixir module (`FOR1` … `BEAM`) | beam_module | `inspect_erlang_beam` | the same tool with a chunk or atom selection |
| `.pyc` CPython bytecode (16-bit magic, `\r\n`) | python_bytecode | `inspect_python_pyc` | the same tool with a code-object selection |
| `.gguf` (`GGUF`) or `.safetensors` (8-byte header length, then JSON) model file | model_artifact | `inspect_model_artifact` | `inspect_byte_entropy` |
| Unity `global-metadata.dat` (`0xFAB11BAF`) | il2cpp_metadata | `inspect_il2cpp_metadata`, with the GameAssembly binary when it is next to it | `open_binary` on the GameAssembly |
| CUDA fatbin (`0xBA55ED50`), `.cubin`, `.ptx`, or an ELF/PE host with GPU code objects | gpu_code_object | `inspect_gpu_code_objects` | the same tool with an object selection |
| An installed desktop application folder (a top-level `.exe`, `UnityPlayer.dll`, a `.pck` or a `*_Data` directory) | desktop_application | `inspect_desktop_application` | the tool its candidates name: `open_binary`, `inspect_managed_artifact`, `inspect_il2cpp_metadata`, `analyze_javascript_application` |
| Godot `.pck` (`GDPC`), PyInstaller archive, Node.js SEA carrier | package_archive | `open_binary` | `inspect_artifact`, `extract_artifact`, then re-route the inner artifact |
| A page the user has open in a browser started with remote debugging (a loopback CDP endpoint such as `http://127.0.0.1:9222`; a bare page URL is not enough, ask for the endpoint) | website_in_browser | `list_browser_targets` | `inspect_web_page`, `analyze_web_bundle`; `observe_web_session` only if asked |
| Running Electron or Node with an inspector endpoint | electron_or_node_runtime | `list_electron_targets` or `list_javascript_runtime_targets` | `inspect_electron_page`; `observe_javascript_runtime` only if asked |
| A source repository the user already has | source_repository | none | Use ordinary repository tools; REA is not needed |

If the rea-jev route note that arrived with the prompt disagrees with what the
file on disk says, trust the file and say so in one line.

## 3. Hypothesize, probe, classify

State the hypothesis the question implies, run the first tool, then the literal
probes it suggests. Never repeat an identical call. When a listing has more than
about 30 items, rank or classify it with
`node "${CLAUDE_PLUGIN_ROOT}/scripts/jev.mjs" rank` or
`node "${CLAUDE_PLUGIN_ROOT}/scripts/jev.mjs" classify` instead of reading it
all. Keep runtime captures out unless the question needs them, and keep any
capture inside the declared target.

## 4. Ledger and finish

Keep observations, inferences, and unknowns apart. Cite `ev_` IDs for every
conclusion. Use `record_unknown` for material gaps. Close a native session with
`close_binary`. Before writing a conclusion down, check it with
`node "${CLAUDE_PLUGIN_ROOT}/scripts/jev.mjs" verify --claim-file <file> --evidence <file>`
(write the claim to a file; never paste strings from a tool result into the
command line). Finish with
Observations, Inferences, Unknowns, and Next steps. When the user asked to
build, follow the skill's reconstruction notes to separate observed behavior
from design choices before writing code.
