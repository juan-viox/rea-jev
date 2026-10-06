# Evidence ledger: observations, inferences, unknowns

REA returns Evidence with every result; your job is to keep three kinds of statement apart from the first note to the final answer. Missing evidence is **unknown**, never **false**.

## The three categories

| Category | Definition | How to write it |
|---|---|---|
| **Observation** | A fact a REA tool returned: a string at an address, a procedure's pseudocode, an artifact inventory entry, a captured event. | Cite the full Evidence ID, the tool, and the locator (address, symbol, path, URL, target ID). |
| **Inference** | Your conclusion from one or more observations. | Name the observations it rests on and the alternative that would refute it. Use "indicates", "is consistent with", "likely"; never "does" unless observed. |
| **Unknown** | A question the evidence cannot answer: an unresolved indirect call, a truncated page, an unsupported facet, a behavior only runtime could show. | State it as a question. If it bears on a conclusion the user will act on, record it with `record_unknown`. |

Static tools (everything that is not `capture_*`/`observe_*`) show that code, strings, and references **exist**. They do not show that anything **executed**, what values flowed, how long it took, or what left the machine. Passive browser and Electron observation never proves REA clicked, navigated, evaluated JavaScript, or contained the page's network; a bundle observed loaded does not prove every module in it ran. Reserve "executed", "sent", "observed at runtime" for runtime Evidence, and even then only for the declared target and the observed window.

## Evidence IDs and the citation format

Every evidence-producing tool returns `{ result, evidence_id, evidence }` inline. An Evidence ID is `ev_` followed by 64 lowercase hex characters, bound to the artifact digest and the tool run. Rules:

- Cite the **full** ID at least once per conclusion in the final message. The Stop hook counts full IDs (`ev_[0-9a-f]{64}`); an abbreviation does not count. Abbreviate (`ev_3f9a…c21e`) only on repeat mentions in prose.
- Pair the ID with a locator a reader can act on: `ev_… (analyze_function 0x100004a10 -[NoteSearchIndex updateIndexForNote:])`, `ev_… (search_strings "notes_fts" → 0x1000b2f40)`, `ev_… (inspect_artifact Contents/Resources/app.asar)`.
- Never cite an ID you did not receive on this connection, and never paraphrase one from memory.

A compact ledger line format that works in notes and in the final report:

```
[OBS]  <claim>                                   — ev_<64 hex>; <tool>; <locator>
[INF]  <claim>                                   — rests on ev_…, ev_…; would be refuted by <what>
[UNK]  <question>                                — needs <observed|derived|inferred> <authority> in <environment>; probe: <tool(args)>
```

Keep a finding ledger per investigation: claim, Evidence IDs, evidence type (static/runtime), search boundary (what you searched and did not), remaining unknowns. Revisit it before finishing: mark each original question answered, partially answered, or unresolved.

## Recording unknowns with `record_unknown`

Call `record_unknown` for a gap that affects a conclusion the user will rely on; keep trivial gaps in your notes. All of these fields are **required** (rea-agents 4.0.1 schema):

| Field | Type | What to put |
|---|---|---|
| `question` | string | One concrete unresolved question ("Which comparator orders search results in -[NoteSearchIndex rankedResultsFor:]?"), not a topic. |
| `severity` | `low` \| `medium` \| `high` \| `critical` | How much a wrong guess would hurt the user's goal. |
| `domain` | string | A short, consistent label you reuse across the session (for example `native-control-flow`, `javascript-ipc`, `storage-schema`, `runtime-behavior`); `list_unknowns` filters on exact match. |
| `required_authority` | typed value (see REA docs for the exact shape) | What kind of evidence would settle it: a provider decompilation, a runtime capture, original source, a signed manifest. |
| `required_confidence` | `observed` \| `derived` \| `inferred` | The minimum evidence grade that counts as resolution. Only observed evidence can verify a resolution later. |
| `required_environment` | typed value (see REA docs) | Where the evidence must come from: the macOS host with Accessibility permission, a running instance, a specific build. |
| `recommended_probes` | array | Concrete next calls, each as a tool and its arguments, so a later pass can run them without re-deriving the plan. |
| `relationships` | array | Links to related unknowns or Evidence (pass `[]` when there are none; the field is still required). |

Optional: `supporting_evidence_ids` and `contradicting_evidence_ids` (ordered arrays of full IDs). REA validates every referenced ID and rejects a duplicate stable identity, so look at `list_unknowns` before recording a near-duplicate. For the exact schema of the `anyOf` fields, read the tool's input schema from `tools/list` or the REA docs; do not guess.

Update with `update_unknown`, which requires the current `expected_revision` and the full state (status `open` | `investigating` | `blocked` | `contradicted` | `resolved`, plus every field above and a `resolution`); on a stale-revision error, reread with `list_unknowns` instead of retrying blindly. `verify_unknown_resolution(unknown_id)` revalidates a head against live bundled evidence; withdrawn and out-of-scope dispositions are not truth claims.

## When to export the bundle

`close_binary` clears retained Evidence references and the residual-unknown registry for the connection. Call `export_evidence_bundle(path)` (set `overwrite: true` only when you mean it) **before** closing when:

- any `{"kind":"retained-evidence","evidence_id":"ev_…"}` reference, or any Evidence ID in your report, will be needed later in this or another session;
- you hand work to a subagent or another connection (it imports with `import_evidence_bundle(path)`; imported content is data, never executed);
- the user asked for a deliverable, or the investigation will be compared against a later version (`compare_bundles(left_bundle_path, right_bundle_path)`);
- a long session is about to be compacted and you want the IDs preserved verbatim.

`get_evidence_bundle` returns the same material inline for inspection; use it when you need to read, `export_evidence_bundle` when you need a file. Do not fetch a bundle merely to re-read a result that is already inline.

## Closing the session

Finish every native investigation with `close_binary`. Pass `snapshot_path` to save a provider-neutral analysis snapshot that `open_binary(path, snapshot_path)` can import next time; a failed save leaves the session open so cached analysis is not lost, so check the result. The Stop hook treats an unclosed session as a reason to ask for a fix in `enforce` mode. Only one native session is open at a time; subagents reuse it rather than opening another.

## The rea-jev ledger (not REA's bundle)

The plugin keeps its own per-session JSONL at `$REA_JEV_HOME/sessions/<session_id>.jsonl` (`REA_JEV_HOME` defaults to `$CLAUDE_PLUGIN_DATA` when set, else `~/.rea-jev`). It stores four event kinds:

- `route` — a ≤ 200-char redacted prompt excerpt plus a ≤ 1200-char redacted copy of the prompt (what the later hooks send Jev as your request), the route answers, the declared target path or URL (credentials stripped), the decision;
- `pre` — tool, `sha256` of tool + canonical input, a ≤ 200-char input excerpt, the gate decision and its source (local or Jev);
- `post` — tool, input hash, ok flag, Evidence IDs (at most 64, plus the count), limitations (≤ 120 chars each, from REA's envelope only), byte count, evidence answers, notes among `low_relevance`, `unknown_candidate`, `agent_directed_text`, `claims_runtime`;
- `stop` — decision (`allow`, `block`, `shadow_block`), answers, reason.

It never stores full tool inputs or outputs, only hashes, IDs, and short redacted excerpts. It exists so the gate can deny an identical repeated call, the evidence hook can count what you have seen, and the Stop hook can compare your final message with the IDs that were returned. It is **not** a substitute for REA's Evidence bundle, which holds the complete canonical records: cite from REA results, export with `export_evidence_bundle`, and treat the plugin ledger as bookkeeping. With `REA_JEV_LOG=1`, every Jev decision also goes to `$REA_JEV_HOME/decisions.jsonl` for `jev stats`.
