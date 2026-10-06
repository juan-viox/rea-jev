# Reconstruction: from understanding to code

When the user wants the feature rebuilt, the investigation's output is not prose but an **obligation list**: the behaviors the port must preserve, each tied to Evidence, each with a way to check it. Build with normal coding tools afterwards.

## 1. Separate observed behavior from design choices

Sort every finding into one of three buckets before writing code:

| Bucket | Meaning | In the port |
|---|---|---|
| **Must match** | Observed behavior a user or caller can notice: inputs accepted, outputs produced, ordering, persistence, error cases. | Preserve it. Each item becomes an obligation with a test. |
| **May differ** | How the original achieves it: language, library, data structure, threading, file format internals. Also observed, but the user did not ask for a replica. | Choose freely, but *say* you diverged and from what Evidence. |
| **Unknown** | Behavior the evidence did not establish: ranking rules, edge cases, timing, locale handling. | Implement a labeled assumption and keep the `record_unknown` open, or probe before building. |

Never promote an inference to "must match" without the observation behind it, and never promote an unknown to either bucket silently.

## 2. The obligation list

One row per behavior the port claims to preserve:

```
| id | behavior (one sentence)                     | kind      | evidence (full ev_ IDs + locator)       | verified by                  | status |
| O1 | A note is found when its body contains all  | observed  | ev_… (search_strings "MATCH"), ev_…     | unit test + verify_reconstruction | open |
|    | query tokens                                |           | (analyze_function tokenize:)            |                              |        |
```

`kind` is `observed`, `inferred`, or `unknown`; `verified by` names a test, a REA comparison tool, or a runtime capture. Review the list with the user before building when it is long or when the unknowns touch core behavior.

## 3. REA tools for reconstruction (rea-agents 4.0.1)

Inputs are listed as the catalog requires them; for the exact typed shapes of manifest, coverage, and specification objects read the tool's input schema from `tools/list` or the REA docs rather than guessing. All of these are static workflows over Evidence; none executes the original or the port.

- `build_reconstruction_obligation_ledger(evidence_bundle, reviewed_obligations, manifest)` — turns an authenticated Evidence bundle (from `get_evidence_bundle` or an exported file), your reviewed obligations, and an explicit reconstruction manifest (which original claims map to which reconstruction cases) into the deterministic ReconstructionObligationLedger. It fails closed on duplicate ownership, missing original or reconstruction cases, missing parser/type, weak verifier authority, unenumerated claims, contradictions, dependencies, and residual unknowns; read its per-obligation diagnostics to see what is missing and fix the list, not the tool call.
- `evaluate_reconstruction_coverage(coverage, boundary_id)` — evaluates one named boundary. Missing ownership or inventory is *partial*; stale, weak, truncated, skipped, or unresolved proof is *unknown*; contradictions and failed proof fail closed.
- `verify_reconstruction(specification)` — checks a finite typed behavioral and structural specification against the canonical Evidence bundle. A pass means every declared claim has complete comparable authority, not global source equivalence; changed claims fail; missing evidence stays unknown. Declare only claims you can back.
- JavaScript ports: analyze each side once, then `compare_source_to_bundle(reference, application)` compares a cryptographically committed source graph of your port (the `reference`) with the original's application graph Evidence, classifying unchanged, modified, removed, split, merged, duplicated, unknown; incomplete coverage never becomes absence. `compare_application_versions(left, right)` compares two shipped versions; accept only digest, source-map, structural-fingerprint, or semantic-key matches, since module ordinals and minified names are not identity. `compare_javascript_export_shapes` compares one export's return shape between two graphs. `application`, `left`, and `right` accept `{"kind":"retained-evidence","evidence_id":"ev_…"}` on the same connection.
- Native: `compare_functions(left, right)` over two `analyze_function` Evidence records; `build_call_path(functions, start, goal)` over complete dossiers from one artifact.
- Managed: `import_managed_reconstruction(static_members, decompiler, methods)` locks decompiler output to the artifact and marks it as analyst inference.
- Runtime, when the port can be run beside the original: `compare_process_captures(left, right)`, then `correlate_static_and_runtime(static_comparisons, runtime_comparisons, mappings)` with explicit hypotheses; `find_changed_behavior(comparisons)` aggregates. Co-change is never causality.

Before `close_binary`, `export_evidence_bundle(path)` so the IDs in the obligation list stay resolvable.

## 4. Worked mini example: offline search in a notes app → TypeScript + SQLite

Hypothetical target: `/Applications/Notes.app`, an Objective-C/Swift macOS app the user is entitled to analyze. Request: "recreate the offline note search in my TypeScript app". IDs below are placeholders (`ev_[A]`…); real ones are 64 hex characters.

**Route.** Directory contains `Contents/MacOS` → `native_binary` → `open_binary(path: "/Applications/Notes.app")`, `binary_overview`.

**Probe and classify.**

```
[OBS] trace_feature(query: "search") resolves strings "Search", "notes_fts", "CREATE VIRTUAL TABLE notes_fts USING fts5(body, tokenize='unicode61')"
      and procedures -[NoteSearchIndex updateIndexForNote:], -[NoteSearchIndex tokenize:], -[NoteSearchIndex rankedResultsFor:]
                                                                     — ev_[A]; trace_feature; 0x1000b2f40, 0x100004a10
[OBS] analyze_function(procedure: "-[NoteSearchIndex tokenize:]") shows calls to CFStringTokenizerCreate and
      CFStringTokenizerAdvanceToNextToken; no lowercasing or diacritic folding visible in pseudocode
                                                                     — ev_[B]; analyze_function; 0x100004c80
[OBS] xrefs(address: 0x100004a10) → one caller, -[NoteStore saveNote:], resolved by the provider
                                                                     — ev_[C]; xrefs; 0x100004a10
[OBS] analyze_function("-[NoteSearchIndex rankedResultsFor:]") decompiles with one unresolved indirect call and no
      referenced strings; `jev verify --claim "results are ranked by bm25()"` → insufficient
                                                                     — ev_[D]; analyze_function; 0x100005120
[INF] The index is an SQLite FTS5 table over note bodies, rebuilt for a note when it is saved
                                                                     — rests on ev_[A], ev_[C]; refuted if saveNote: never reaches updateIndexForNote: at runtime
[INF] Matching is token-based with the unicode61 tokenizer semantics declared in the DDL; the ObjC tokenizer only
      feeds terms                                                    — rests on ev_[A], ev_[B]; refuted if a custom FTS tokenizer is registered elsewhere
[UNK] Which function orders results, and by what key?               — needs observed native-control-flow evidence on macOS;
      probe: trace_native_values(procedure: "-[NoteSearchIndex rankedResultsFor:]"), then capture_native_ui_scenario typing a query
[UNK] Are diacritics folded and is the search case-insensitive?     — needs runtime; probe: capture_native_ui_scenario(pid, window_id, steps)
[UNK] Debounce or minimum query length before searching              — needs runtime; UI timing is not static evidence
```

`record_unknown` for the first two unknowns (`severity: medium`, `domain: "native-control-flow"` and `"runtime-behavior"`, `required_confidence: "observed"`, `recommended_probes` as above, `relationships: []`).

**Obligations.**

| id | behavior | kind | evidence | verified by | bucket |
|---|---|---|---|---|---|
| O1 | A note is returned when its body contains every query token | observed | ev_[A], ev_[B] | unit test over a fixture corpus; `verify_reconstruction` claim | must match |
| O2 | Saving a note updates its index entry before the next search | observed | ev_[C] | unit test: save then search | must match |
| O3 | Tokenization follows unicode61 (word boundaries, ASCII case folding) | inferred | ev_[A], ev_[B] | test against FTS5 `unicode61` behavior; divergence noted for CJK where CFStringTokenizer and unicode61 differ | may differ (document) |
| O4 | Result ordering | unknown | ev_[D] | none yet; keep the unknown open | unknown |
| O5 | Diacritic folding | unknown | — | none yet | unknown |

**Build (TypeScript + SQLite).** `better-sqlite3` with `CREATE VIRTUAL TABLE notes_fts USING fts5(body, tokenize='unicode61')`; an `upsertNote()` that writes the row inside the same transaction as the save (O2); `search(q)` that issues `MATCH` with every token (O1). Order results with `bm25()` and label it in code and README: "ordering is an assumption; the original's ranking was not established (open unknown)". Add `remove_diacritics` only if the user wants it, noting it is unverified against the original.

**Verify.** Run the tests; write a finite specification covering O1 and O2 and call `verify_reconstruction(specification)` against the exported bundle; run `jev verify` on each sentence of the README that describes the original. Then `export_evidence_bundle(path: "<project>/docs/rea-evidence.json")` and `close_binary`.

**Report.** Three sections, in this order and with these labels: observed (with full IDs), inferred (with the IDs each rests on), unknown (with the recorded unknown IDs and probes). State the design choices you made and what they diverge from.
