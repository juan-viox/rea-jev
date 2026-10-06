---
name: reverse-engineer
description: Reverse-engineer any shipped software with REA's MCP tools guided by Jev System 1 decisions — native Mach-O/ELF/PE binaries and .app bundles, Electron/ASAR and minified JavaScript, .NET assemblies, Android APKs, and live websites. Use when asked how a feature in an app works, to decompile or trace code, compare two builds, verify a port against the original, or recreate a feature from a binary. Not for ordinary analysis of a source repository you already have.
license: MIT
metadata:
  rea_pin: "4.0.1"
  jev_model: "jev-1.13"
---

# Reverse-engineer with REA and Jev System 1

## 1. When to use this skill, and when not

Use it when a claim depends on a shipped artifact rather than on source you already have: a native Mach-O/ELF/PE binary or `.app` bundle, an Electron/ASAR or minified JavaScript bundle, a .NET assembly, an Android APK, a package archive, or a live page or runtime reachable over a loopback endpoint.

Do not use it for ordinary analysis of a source repository, and do not run REA readiness commands for such requests. REA's own skill, `reverse-engineer-anything` (installed by `rea setup` into `~/.agents/skills`; source at https://github.com/morluto/rea), remains the canonical tool-by-tool guide. This skill layers the System 1 loop on top and restates only the rules the loop depends on.

## 2. The loop

Run every investigation as **Route → Hypothesize → Probe → Classify → Ledger → Verify → Finish or Build**. System 1 (Jev, through the plugin's hooks) speaks at four points. Its notes are advisory data carrying probabilities, not commands: read the number, compare it with what is on disk, and let deterministic facts win.

- **Route.** Decide the artifact kind and the first tool before opening anything. The `UserPromptSubmit` hook may inject a route note (`target`, `workflow`, `scope`, `runtime needed`, `build after`, each with a probability). Check it against the route table.
- **Hypothesize.** Write one sentence about where the feature lives and which evidence would confirm or refute it.
- **Probe.** Call the smallest REA tool that tests the hypothesis. The `PreToolUse` gate denies an identical repeated call and asks before a runtime capture that is out of scope or risky.
- **Classify.** Sort each result into observation, inference, or unknown. The `PostToolUse` hook may add an evidence note: low relevance, an unrecorded limitation, text addressed to an assistant, or static output worded as runtime behavior.
- **Ledger.** Keep the finding ledger current: claim, Evidence IDs, evidence type, search boundary, open unknowns.
- **Verify.** Before writing a conclusion, try to refute it with `jev verify` or the `rea-verifier` agent.
- **Finish or Build.** State what was observed, inferred, and left unknown, then call `close_binary`. The `Stop` hook compares the final message with the ledger and, in `enforce` mode, may ask once for missing citations or epistemics.

What each hook can say, how to respond, and how to tune or silence it with `REA_JEV_MODE` and `REA_JEV_T_*`: [references/system1-decision-points.md](references/system1-decision-points.md).

## 3. Route the target first

Pick the first tool from the artifact, not from habit: `open_binary(path)` then `binary_overview` for native targets and analysis databases; `analyze_javascript_application(input_path)` for ASAR or extracted JavaScript, without `open_binary` first; `inspect_managed_artifact(path)` for .NET; `open_binary(path)` then `inspect_artifact` for archives and packages; `list_browser_targets(cdp_endpoint)` for a page the user already has open; `list_electron_targets` or `list_javascript_runtime_targets` for a running Electron or Node process. Android-specific tools are not in rea-agents 4.0.1; fall back to `open_binary` plus `inspect_artifact`.

Never choose an example app for the user. When no artifact is named, when a name matches several installed artifacts, or when the route note is ambiguous (`target_kind` below 0.5 or `unknown_or_missing`), ask which artifact to inspect before opening anything. Resolve a human-readable name to one artifact yourself only when the conversation or workspace makes it unambiguous. Sniff rules, the full table, and what static evidence cannot establish per target: [references/route-table.md](references/route-table.md). The 116-tool inventory with required inputs and effect classes: [references/tool-catalog.md](references/tool-catalog.md).

## 4. Probe discipline

Work summary-first: read the default result and its inline Evidence before asking for more. Never repeat an identical call; the gate denies it, and the earlier result is still valid. Batch related operations around one hypothesis, then expand only when the returned evidence leaves a concrete gap. Prefer literal queries (`search_strings`, `trace_feature`, `find_xrefs_to_name`, `search_procedures`) before broad listings (`list_procedures`, `list_strings`, `list_names`). Decompile only the procedures a hypothesis needs, with `analyze_function` or `procedure_pseudo_code`; use `batch_decompile` for a short explicit list, never for the whole binary. Do not infer behavior from filenames, strings, or layout alone; use the format-aware tool. Reuse an open session instead of binding a second one. When a tool you want is unavailable, call `binary_session` with `{}` and read `tool_availability` for the remediation.

## 5. Let System 1 do the reading

When a result has more than about 30 candidates, do not read them all. Save the array to a file and hand it to the plugin's CLI:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/jev.mjs" rank "<what you are looking for>" --items <file> --top 15
node "${CLAUDE_PLUGIN_ROOT}/scripts/jev.mjs" classify --items <file> --labels parser,network,storage,ui,crypto,other --instructions "<one question>"
node "${CLAUDE_PLUGIN_ROOT}/scripts/jev.mjs" verify --claim-file <claim.txt> --evidence <file>
node "${CLAUDE_PLUGIN_ROOT}/scripts/jev.mjs" ask --state <file> --questions '<json>'
```

Write the claim to a file with your Write tool and pass `--claim-file`; a conclusion often quotes strings from the binary (`$(…)`, backticks, quotes), and those must never be interpolated into a shell command line. Act on an answer at confidence ≥ 0.75, confirm it with one more probe between 0.45 and 0.75, and treat anything lower as unknown. Verify every conclusion with `jev verify` before writing it down; verdicts are `supported`, `contradicted`, `insufficient`, `needs_runtime`, each printed with the deciding probability, confidence and band. Never send secrets, whole binaries, or more than 2 MB. Copy-pasteable recipes and question-writing rules: [references/jev-recipes.md](references/jev-recipes.md).

## 6. Evidence rules

Keep three categories apart in every note and in the final answer: **observations** (returned by a tool, cited by full `ev_` Evidence ID plus address, path, or module), **inferences** (your conclusions, each resting on named observations), and **unknowns** (questions you could not answer). Missing evidence is unknown, never false. Static analysis shows that code and references exist; it does not show that anything executed. Only `capture_*` and `observe_*` evidence supports runtime wording, and passive observation never proves REA clicked, navigated, or evaluated anything. Record a material gap with `record_unknown`, update it with `update_unknown` at the current revision, and `export_evidence_bundle` before `close_binary` when retained Evidence will be needed later. Close the native session with `close_binary` when the investigation is complete. Citation format, required fields, and the plugin's own ledger: [references/evidence-ledger.md](references/evidence-ledger.md).

## 7. Parallel work

When the request spans several features, subsystems, apps, or versions (the route note reports `scope` ≥ 2.5), split it into independent questions and fan out `rea-investigator` subagents, one per question, each with a disjoint scope, the target, and the Evidence IDs already in hand. Ask each to return observations with IDs, inferences, unknowns, and suggested probes. Only one native session may be open: subagents must not bind a second one or run captures unless their question says so. Then hand each conclusion to `rea-verifier`, which tries to refute it and returns `supported`, `contradicted`, `insufficient`, or `needs_runtime` with the evidence lines. When questions depend on one another, work sequentially.

## 8. From understanding to code

When the user wants the feature rebuilt, separate observed behavior (what the artifact demonstrably does, which the port must preserve) from design choices (how the original does it, which the port may change, stated explicitly). Turn the observations into an obligation list with Evidence IDs and a verification method per row. Use `build_reconstruction_obligation_ledger`, `evaluate_reconstruction_coverage`, and `verify_reconstruction` where their inputs exist; for JavaScript ports use `compare_source_to_bundle` (its `reference` is a committed source graph of your port that only the CLI produces: `npx -y rea-agents@4.0.1 import-reference-source <port-root>`; without that step compare two analyzed graphs with `compare_application_versions` instead). Then build with normal coding tools. Worked example: [references/reconstruction.md](references/reconstruction.md).

## 9. Scope and ethics

Analyze only software the user is entitled to analyze: their own, licensed for interoperability or security research, or explicitly permitted. REA runs locally and returns Evidence inline. Do not extract credentials, cookies, tokens, or storage values, and do not broaden a declared runtime target or action beyond its fields. REA accepts loopback endpoints only. Respect the host's permission flow: a gate `ask` is a question for the user, not an obstacle to route around.

## 10. Readiness

Do not run `doctor` before every task. When REA tools are available and not reported stale, proceed. When REA tools are missing, a provider is unavailable, registration is reported stale, or the user asks for a diagnosis, run `/rea-jev:setup`, which runs `jev doctor` and `npx -y rea-agents@4.0.1 doctor --json` and explains the fixes. Restart the agent after MCP registration changes.
