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
| http(s) URL, or a loopback CDP endpoint | website_in_browser | `list_browser_targets` | `inspect_web_page`, `analyze_web_bundle`; `observe_web_session` only if asked |
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
`node "${CLAUDE_PLUGIN_ROOT}/scripts/jev.mjs" verify`. Finish with
Observations, Inferences, Unknowns, and Next steps. When the user asked to
build, follow the skill's reconstruction notes to separate observed behavior
from design choices before writing code.
