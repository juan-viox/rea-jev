# Architecture

rea-jev is a Claude Code plugin. The plugin is the unit because it is the only
thing that bundles a skill, hooks, an MCP server configuration, subagents, and
slash commands and installs with two commands. The skill is prose and can only
tell Claude *how* to investigate; the hooks and the `jev` CLI can *act*: call
Jev, intercept tool calls, inject context, and hold a turn open.

```
user prompt ──► [UserPromptSubmit hook: Jev routes target+workflow] ──► Claude (System 2, skill loaded)
                                                                            │
                   ┌────────────────────────────────────────────────────────┤ calls REA MCP tools
                   ▼                                                        ▼
   [PreToolUse hook: deterministic rules → Jev scope/risk gate]   [PostToolUse hook: Jev scores evidence,
                                                                   flags unknowns + injected text, ledger]
                                                                            │
                                      Claude also calls `jev rank|classify|verify` directly on evidence
                                                                            │
                                     [Stop hook: Jev checks claims vs ledger; blocks unverified "done"]
```

## Two systems

| | System 2 | System 1 |
|---|---|---|
| Who | Claude, with the `reverse-engineer` skill loaded | Jev (TypeSafe System One model) called from hooks and the `jev` CLI |
| Does | Forms hypotheses, chooses REA tools, reads evidence, writes conclusions and code | Answers typed questions (Noul, Choice, Score) with probabilities in about 300 ms |
| Never | Decides alone whether a result is evidence or a claim is earned | Writes text, calls tools, or overrides a human decision |

Principles (DESIGN.md §0): code first for anything deterministic; atomic
questions composed in code; confidence gates escalation (high acts, medium
advises or asks, low stays silent); fail open; minimal egress; observations,
inferences, and unknowns kept apart with Evidence IDs.

## Components

| Path | Role |
|---|---|
| `.claude-plugin/plugin.json`, `marketplace.json` | Manifest and single-repo marketplace; `userConfig` exposes the TypeSafe key (sensitive) and the mode. |
| `.mcp.json` | Bundles REA: `npx -y rea-agents@4.0.1 mcp`. Tools surface as `mcp__plugin_rea-jev_rea__<tool>`. |
| `hooks/hooks.json` | Registers the five hooks with `${CLAUDE_PLUGIN_ROOT}` paths and per-hook timeouts (5 to 25 s). |
| `scripts/hook-session.mjs` | `SessionStart`: one status line; no Jev call. |
| `scripts/hook-route.mjs` | `UserPromptSubmit`: deterministic sniff, then one Jev call with six questions, then a route note. |
| `scripts/hook-gate.mjs` | `PreToolUse` on REA tools: redundancy and hard rules locally, Jev only for runtime-class and cross-directory calls. |
| `scripts/hook-evidence.mjs` | `PostToolUse` on REA tools: parse the result, ledger it, ask Jev four questions when the result is substantive. |
| `scripts/hook-stop.mjs` | `Stop`: local facts from the ledger and transcript, five Jev questions, block or advise. |
| `scripts/jev.mjs` | CLI: `ask`, `rank`, `classify`, `verify`, `doctor`, `stats`. |
| `scripts/lib/jev.mjs` | Provider resolution, `askJev`, confidence math, bands, question builders, cost estimate. |
| `scripts/lib/ledger.mjs` | Per-session JSONL ledger and `summarize`. |
| `scripts/lib/redact.mjs` | Secret masking and head/tail truncation. |
| `scripts/lib/hookio.mjs` | stdin JSON, stdout emitters, time budget, mode resolution, debug. |
| `scripts/lib/rea.mjs` | REA tool matcher, effect classes from the catalog, result parsing. |
| `scripts/lib/sniff.mjs` | Path tokens, magic bytes, directory heuristics, keyword hit. |
| `scripts/validate.mjs` | Repository self-check; `--write-catalog` regenerates the skill's tool catalog. |
| `skills/reverse-engineer/` | The System 2 playbook and its references. |
| `agents/` | `rea-investigator` (scoped fan-out worker) and `rea-verifier` (adversarial checker). |
| `commands/` | `/rea-jev:setup` and `/rea-jev:investigate`. |
| `data/rea-tool-catalog.json` | 116 tools from `rea-agents@4.0.1`: names, descriptions, effects, inputs. |
| `tests/` | Offline `node:test` suite against `tests/fake-jev.mjs`. |

## Data flow per hook

Every hook reads one JSON object from stdin, may write one JSON object to
stdout, and always exits 0. Any internal error, missing key, timeout, HTTP
error, or malformed answer ends the same way: exit 0, empty stdout. Decisions
travel in the JSON, never in the exit code: a PreToolUse `deny` or `ask` is a
`permissionDecision`, and a Stop block in `enforce` mode is
`{"decision":"block","reason":"..."}` on stdout.

### SessionStart

Reads the mode, whether a provider key is present, and the REA pin. Emits one
line of `additionalContext`. No network.

### UserPromptSubmit (route)

1. `sniffPrompt(prompt, cwd)` finds path tokens (with magic bytes read from the
   first 16 bytes of existing files), URLs, CDP and inspector endpoints, and a
   keyword hit. If none of these and the ledger shows no REA activity, exit.
2. State sent to Jev: prompt (at most 3000 chars), sniff hints, cwd basename,
   the ledger's active target. Questions: `is_re_task`, `target_kind`,
   `workflow`, `scope`, `needs_runtime`, `wants_build`.
3. Policy: silent when not a reverse-engineering task or when the target is a
   source repository; an "ask the user" note when the target kind is uncertain
   or missing; otherwise a route block of at most 12 lines naming the first REA
   tool. Ledger gets a `route` record with the declared target.

### PreToolUse (gate)

Runs only on tool names matching `mcp__(plugin_rea-jev_)?rea__`, which covers
both a globally registered REA (`rea setup`) and the plugin's bundled server.

1. Mode `off` or not an REA tool: silent.
2. Redundancy, local and free: `sha256(bareTool + canonicalJson(tool_input))`.
   A successful `post` with the same hash in this session, with no
   mutation-class call since, and a tool that is not status-class, is denied
   with the Evidence IDs the earlier call returned.
3. Hard rules, local and free, for runtime-class tools: an executable outside
   `cwd` and the declared target asks; credentials in a scenario environment
   ask; a non-loopback CDP or inspector endpoint is denied.
4. Jev, only for runtime-class tools and for export/import/extract with paths
   outside `cwd`: `within_scope`, `irreversible`, `runtime_requested`.
5. Everything else is silent and goes through Claude Code's normal permission
   flow. Inspection calls never cost a Jev request.

### PostToolUse (evidence)

1. `parseReaResult` extracts text, JSON, Evidence IDs (`ev_` plus 64 hex),
   limitations, unknowns, truncation, and errors. The ledger gets a `post`
   record: hashes, IDs, limitations (at most 120 chars each), byte count.
2. Skip Jev when the mode is `off`, the tool is status- or mutation-class
   (except `open_binary`, scanned locally for limitations), the result is under
   400 chars, or the result is an error.
3. Otherwise one call with `relevance`, `unrecorded_unknown`,
   `agent_directed_text`, `claims_runtime`. A note is injected only when
   actionable; shadow mode logs only.

### Stop (completeness)

1. `stop_hook_active`, mode `off`, or no REA activity this session: exit 0.
2. Caps: one block per stop, two per session, none within 60 s of the last.
3. Final message from stdin or the last assistant text block in the transcript.
4. Local facts: open native session, Evidence IDs seen and cited, limitations
   flagged, unknowns recorded, tool calls.
5. One call with `claims_complete`, `separates_epistemics`, `cites_evidence`,
   `unaddressed_question`, `outcome`. `enforce` may block with a reason that
   lists only the triggered items; `advise` and `shadow` show the would-have
   verdict as a `systemMessage`.

## The ledger

`$REA_JEV_HOME/sessions/<session_id>.jsonl` (default `~/.rea-jev`, or
`$CLAUDE_PLUGIN_DATA`). Records are `route`, `pre`, `post`, and `stop` events
holding timestamps, tool names, input hashes, decisions, Evidence IDs,
limitations, and excerpts of at most 200 redacted characters. Full tool inputs
and outputs are never written. `summarize(events)` derives what the hooks need:
REA activity, open sessions, the last route, the redundancy window since the
last mutation, Evidence IDs, flagged limitations, recorded unknowns, and stop
block history. With `REA_JEV_LOG=1`, every Jev decision is also appended to
`$REA_JEV_HOME/decisions.jsonl` for `jev stats` and threshold tuning.

## Jev client

Both providers take the same body `{ model, state, questions }` and return
`{ model, answers, usage }`. The client adds `Authorization: Bearer`, retries
once on 429 or 529 inside the timeout budget (default 4000 ms, `AbortController`),
and returns a result object instead of throwing on expected failures:
`no_key`, `timeout`, `http_4xx`, `http_5xx`, `bad_json`, `network`.

Confidence (TypeSafe's formulas): Noul `|2p - 1|`; Choice
`(p_max - 1/n) / (1 - 1/n)`; Score `max(0, 1 - sum(p_i · |i - m|) / MAD_uniform)`.
Bands: `act` at 0.75 and above, `confirm` at 0.45 and above, `escalate` below.
Limits respected: Choice at most 255 options, Score 2 to 10 levels, a request
kept under roughly 24k estimated tokens (chars / 4).

## Egress and redaction

Only the named state fields of each question leave the machine, truncated and
redacted (`sk-…`, `ghp_…`, `AKIA…`, JWTs, bearer tokens, `password=`, `token=`,
private key blocks, URL userinfo). The analyzed artifact is never uploaded; REA
analyzes locally. Nothing is logged verbatim beyond short excerpts.

## Modes

| Mode | UserPromptSubmit | PreToolUse | PostToolUse | Stop |
|---|---|---|---|---|
| `off` | nothing | nothing | ledger only | nothing |
| `shadow` | log only | log only | log only | log only, `systemMessage` with would-have verdict |
| `advise` | inject route note | redundancy → `deny`; scope/risk → `ask`; else silent | inject evidence notes | never blocks; `systemMessage` with verdict |
| `enforce` | inject route note | redundancy → `deny`; out-of-scope → `deny`; risk → `ask` | inject evidence notes | may `block` once per stop |

Resolution order: `CLAUDE_PLUGIN_OPTION_MODE`, then `REA_JEV_MODE`, then
`advise`.

## Testing

Every test is offline. `tests/fake-jev.mjs` is an HTTP server on an ephemeral
port that returns canned answers keyed by question key, scripted per test;
`JEV_BASE_URL` points the client at it with a dummy `TYPESAFE_API_KEY`.
`scripts/validate.mjs` is the repository self-check and runs in CI next to the
tests. Required cases are listed in DESIGN.md §9.
