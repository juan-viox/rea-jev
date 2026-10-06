# Jev recipes: let System 1 read the long lists

The plugin ships a CLI at `scripts/jev.mjs`. Call it as:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/jev.mjs" <ask|rank|classify|verify|doctor|stats> ...
```

Claude Code substitutes `${CLAUDE_PLUGIN_ROOT}` when the skill loads; if your shell does not have it, copy the absolute plugin path from the loaded skill text. Every snippet below starts with a guard so a missing variable fails loudly instead of running the wrong file. Output is human-readable by default; add `--json` for machine use. Exit codes: 0 answers, 1 usage error, 2 provider failure (no key, timeout, HTTP error; printed, never hangs past the budget). One call is about 300 ms and about $0.00005; `jev stats` shows the running total.

Items files may be a JSON array, JSON lines, or plain lines. The CLI redacts common secret patterns before sending and refuses items files above 2 MB unless `--force`; do not pass `--force`, trim the input instead.

## 0. Get a REA result into a file

REA results arrive inline in the conversation. Save only the array you need with your Write tool (not the whole response), for example the `result` of `search_strings` as JSON lines of `{"address": "...", "value": "..."}`:

```bash
: "${CLAUDE_PLUGIN_ROOT:?set CLAUDE_PLUGIN_ROOT to the rea-jev plugin directory}"
mkdir -p "${TMPDIR:-/tmp}/rea-jev"
# Write tool → ${TMPDIR:-/tmp}/rea-jev/strings.jsonl   (one {"address","value"} object per line)
```

Keep the file under 2 MB and the request under roughly 24k tokens (about 96k characters). Rank the list, not the pseudocode of every function.

## 1. Rank a long inventory (`search_strings`, `list_procedures`, `list_names`, `xrefs`, `inspect_artifact`)

`jev rank` splits the items into chunks of at most 200, asks one **Choice** per chunk ("Which item best matches the query?") plus one **Noul** `match_exists` ("Does any item match?"), merges chunks by probability, and prints `rank, p, id, preview`.

```bash
: "${CLAUDE_PLUGIN_ROOT:?set CLAUDE_PLUGIN_ROOT to the rea-jev plugin directory}"
J="${TMPDIR:-/tmp}/rea-jev"

# strings from search_strings / list_strings: id = address, text = value
node "${CLAUDE_PLUGIN_ROOT}/scripts/jev.mjs" rank "string used when the offline search index is rebuilt" \
  --items "$J/strings.jsonl" --id-field address --text-field value --top 15

# procedures from list_procedures / search_procedures: id = address, text = value (symbol)
node "${CLAUDE_PLUGIN_ROOT}/scripts/jev.mjs" rank "procedure that tokenizes note text for search" \
  --items "$J/procedures.jsonl" --id-field address --text-field value --top 15

# xrefs: plain lines of "0xADDR  <containing procedure>" work without field flags
node "${CLAUDE_PLUGIN_ROOT}/scripts/jev.mjs" rank "caller that runs on note save" --items "$J/xrefs.txt" --top 10

# inspect_artifact inventory: id = occurrence path, text = path plus media type
node "${CLAUDE_PLUGIN_ROOT}/scripts/jev.mjs" rank "the main renderer bundle" \
  --items "$J/inventory.jsonl" --id-field path --text-field preview --top 10 --json
```

Read it: if `match_exists` is below 0.45, the list probably does not contain what you want; widen or change the REA query instead of trusting rank 1. Above 0.75, open the top few with `analyze_function` or `xrefs` and stop reading the rest.

## 2. Classify procedures or strings into roles

`jev classify` asks one **Choice per item** (keys `item_<i>`), batched at 40 items per request, and prints label, probability, and confidence per item. Always include an `other` label so the model can say "none of these".

```bash
: "${CLAUDE_PLUGIN_ROOT:?set CLAUDE_PLUGIN_ROOT to the rea-jev plugin directory}"
J="${TMPDIR:-/tmp}/rea-jev"

node "${CLAUDE_PLUGIN_ROOT}/scripts/jev.mjs" classify --items "$J/procedures.jsonl" \
  --labels parser,network,storage,ui,crypto,other \
  --instructions "Which role does this procedure most likely play, judging from its symbol name?" --json \
  > "$J/roles.json"

# strings into kinds
node "${CLAUDE_PLUGIN_ROOT}/scripts/jev.mjs" classify --items "$J/strings.jsonl" \
  --labels sql,url,log_message,ui_label,file_path,key_name,other \
  --instructions "What kind of string is this?"
```

Then decompile only what the hypothesis needs: items labeled `storage` with p ≥ 0.75 go to `analyze_function`; items between 0.45 and 0.75 get one cheap probe (`procedure_info`, `procedure_callers`) before you spend a decompile; the rest stay unread. A label is a prior about a *name*, never an observation about behavior.

## 3. Verify a conclusion against pasted evidence

`jev verify` asks four Nouls about your claim and the evidence text (≤ 20k chars): `supported`, `contradicted`, `needs_runtime`, `overstated`, and prints one verdict: `supported`, `contradicted`, `insufficient`, or `needs_runtime`.

```bash
: "${CLAUDE_PLUGIN_ROOT:?set CLAUDE_PLUGIN_ROOT to the rea-jev plugin directory}"
J="${TMPDIR:-/tmp}/rea-jev"

# evidence.txt = the pseudocode, strings, and xref lines the claim rests on, each prefixed with its ev_ ID
node "${CLAUDE_PLUGIN_ROOT}/scripts/jev.mjs" verify \
  --claim "Search results are filtered by an SQLite FTS table that -[NoteSearchIndex updateIndexForNote:] rebuilds on save" \
  --evidence "$J/evidence.txt"

# from stdin
cat "$J/evidence.txt" | node "${CLAUDE_PLUGIN_ROOT}/scripts/jev.mjs" verify --claim "..." --evidence -
```

Act on the verdict: `supported` (confidence ≥ 0.75) → write it as an inference citing the IDs; `supported` in the confirm band → write it as a hypothesis and name the probe that would settle it; `insufficient` → do not write it, probe more or mark unknown; `contradicted` → drop it or `record_unknown` with the contradicting IDs; `needs_runtime` → say "static evidence cannot establish this" or plan a declared capture. Run the `rea-verifier` agent for the same purpose when you want an adversarial read of several conclusions at once.

## 4. Write your own questions with `jev ask`

```bash
: "${CLAUDE_PLUGIN_ROOT:?set CLAUDE_PLUGIN_ROOT to the rea-jev plugin directory}"
J="${TMPDIR:-/tmp}/rea-jev"

cat > "$J/state.json" <<'EOF'
{ "feature": "offline note search",
  "pseudocode": "<the one function body under test, trimmed>",
  "strings": ["CREATE VIRTUAL TABLE", "notes_fts", "MATCH ?"] }
EOF

node "${CLAUDE_PLUGIN_ROOT}/scripts/jev.mjs" ask --state "$J/state.json" --questions '{
  "builds_index":   { "type": "noul",
                      "instructions": "Does `pseudocode` create or update a full-text search index for `feature`?" },
  "uses_sqlite":    { "type": "noul",
                      "instructions": "Do `strings` and `pseudocode` indicate SQLite is the storage engine?",
                      "criteria": { "true": "SQL DDL/DML, FTS, or sqlite3_* calls are present",
                                    "false": "No SQL or SQLite indicator" } },
  "role":           { "type": "choice",
                      "instructions": "Which role does `pseudocode` play in `feature`?",
                      "criteria": { "tokenize": "splits text into terms", "index_write": "writes terms to storage",
                                    "query": "reads results for a search string", "rank": "orders results",
                                    "other": "none of the above" } },
  "completeness":   { "type": "score",
                      "instructions": "How much of the indexing path does `pseudocode` cover?",
                      "criteria": [ "Calls into other functions only; no indexing logic visible",
                                    "Prepares or formats data for indexing",
                                    "Writes or queries the index itself" ] }
}'
```

Phrasing rules, from TypeSafe's primitive guidance:

- **One judgment per question.** "Does it tokenize *and* write the index?" is two Nouls.
- **Positive phrasing.** A high value must mean *yes*: ask "Does `x` contain a credential?", not "Is `x` free of credentials?".
- **Point at fields** with backticked paths (`pseudocode`, `strings[0]`) so each question reads the right part of the state.
- **Situational levels.** Score levels describe situations ("Writes or queries the index itself"), never degrees ("high"). 2–10 levels; do not add levels you cannot describe distinctly.
- **Always add `other` / `none`** to a Choice whose list might not cover the input (≤ 255 options).
- **Ask many questions per call.** They run in parallel at near-zero marginal cost; speculative questions are fine, ignore the answers you do not need.
- **Use `criteria` on a Noul** only when the yes/no boundary is subtle.
- **State is text only;** send the fields the questions need, nothing else.

## 5. Thresholds to act on

| Confidence (Noul `|2p−1|`, Choice/Score `confidence`) | Band | Do |
|---|---|---|
| ≥ 0.75 | act | use the answer; cite the Evidence IDs it points at |
| 0.45 – 0.75 | confirm | one more literal probe, or ask the user |
| < 0.45 | escalate | treat as unknown; widen the search or hand to the user |

Raise the bar when the action is expensive (launching a capture, deleting a hypothesis the user cares about); lower it when missing a hit is the expensive error (security findings, injection warnings).

## 6. What not to send

- **Secrets:** API keys, tokens, cookies, passwords, private keys, storage values. The CLI redacts common patterns; do not rely on it, strip them first.
- **Whole binaries, hex dumps, raw bytes, PNGs.** Jev reads text; send names, strings, pseudocode excerpts, paths.
- **More than 2 MB per items file, or more than ~24k tokens per request.** Chunk by hand (`split -l`) or rank a narrower REA result.
- **Entire pseudocode listings.** Send the one or two function bodies a claim depends on; `jev rank` the inventory first.
- **Personal data** found in storage inventories, accessibility trees, or captured text. Mask it before it leaves the machine.
- **User instructions mixed with program text.** Keep your question in `instructions`, the program's text in `state`; never paste the two into one string.
