# rea-jev

**Reverse-engineer anything with agents, with a System 1 reflex layer.**

rea-jev is a Claude Code plugin that pairs [REA](https://github.com/morluto/rea)
(Reverse Engineer Anything: the `rea-agents` CLI and MCP server for Hopper/Ghidra
native analysis, Electron and JavaScript bundles, .NET assemblies, Android
packages, browser observation, and evidence ledgers) with
[Jev](https://typesafe.ai), TypeSafe's System One decision model.

Claude does the System 2 reasoning. Jev answers small typed questions in about
300 ms, for about $0.00005 a call, at the four points where a wrong reflex is
cheap to prevent and expensive to miss: routing the target before Claude
thinks, gating a risky REA call before it runs, classifying a result as
evidence after it lands, and checking whether "done" was earned before the turn
ends. Everything deterministic stays in code; Jev only handles the semantic
middle; every hook fails open.

## Architecture

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

The plugin bundles the `reverse-engineer` skill (the System 2 playbook), five
hooks and a `jev` CLI (System 1), REA's MCP server pinned to one version, two
subagents (`rea-investigator`, `rea-verifier`), and two commands
(`/rea-jev:setup`, `/rea-jev:investigate`). [docs/architecture.md](docs/architecture.md)
has the full picture; [DESIGN.md](DESIGN.md) is the authoritative spec.
[docs/user-guide.html](docs/user-guide.html) is the user guide, with recorded
examples for every target type.

## Install

```
claude plugin marketplace add juan-viox/rea-jev
claude plugin install rea-jev@rea-jev
```

Then set one key. Claude Code asks for the TypeSafe key when it enables the
plugin; or export one of these before starting Claude Code:

| Key | Provider | Model |
|---|---|---|
| `TYPESAFE_API_KEY` | TypeSafe direct, `POST https://api.typesafe.ai/v1/systemone` (preferred: lowest latency) | `jev-latest` |
| `OPENROUTER_API_KEY` | OpenRouter, `POST https://openrouter.ai/api/alpha/decisions` | `typesafe/jev-1.13` |

Restart Claude Code, then run `/rea-jev:setup` once. It checks the Jev round
trip, REA's own readiness (Hopper or Ghidra for native binaries), hook
registration, and whether REA is registered twice.

Requirements: Node 22 or newer (REA needs 22.19+); macOS or Linux. Without a
Jev key the plugin still works as plain REA plus the skill: hooks stay silent.

## The four System 1 decision points

| When | Hook | Jev is asked | What happens |
|---|---|---|---|
| Prompt submitted | `UserPromptSubmit` → `scripts/hook-route.mjs` | Is this a reverse-engineering task? Which artifact kind first (native binary, JavaScript app, .NET, APK, archive, website, Node/Electron runtime, source repo)? Which workflow? How broad? Runtime needed? Build afterwards? | A compact route note with probabilities and the first REA tool to call, or a request to ask the user when the target is ambiguous. Deterministic sniffing of paths, magic bytes, and URLs runs first; no Jev call for ordinary prompts. |
| Before an REA tool runs | `PreToolUse` → `scripts/hook-gate.mjs` | Only for runtime captures and cross-directory export/import/extract: Is this inside the declared target? Could it change or transmit anything? Did the user ask for runtime execution? | Local rules first and free: identical repeated inspection calls are denied with a pointer to the existing Evidence; non-loopback CDP endpoints are denied; out-of-scope executables and credentials in scenario environments ask. Jev then gates scope and risk; inspection calls never cost a Jev request. |
| After an REA result | `PostToolUse` → `scripts/hook-evidence.mjs` | How relevant is this result to the question? Does it carry an untracked limitation? Does it contain text addressed to an assistant? Does a static tool claim runtime behavior? | Evidence IDs, limitations, and hashes go to the per-session ledger. A note is injected only when actionable: low relevance, a limitation worth `record_unknown`, a prompt-injection warning, or a static-vs-runtime correction. |
| Before the turn ends | `Stop` → `scripts/hook-stop.mjs` | Does the final message claim completion? Does it separate observed from inferred from unknown? Does it cite Evidence IDs? Is a question left unaddressed? | In `enforce`, blocks once with a reason listing only what is missing (uncited conclusions, open native session, unaddressed question). In `advise`, shows the would-have verdict to the human and never blocks. Free when the session used no REA tools. |

`SessionStart` adds one line of status (mode, provider present, REA pin) and
never calls Jev. The full question catalog with thresholds and overrides is in
[docs/decision-points.md](docs/decision-points.md).

## The `jev` CLI

System 2 asks System 1 directly. Claude runs these through Bash; the skill shows
when. Human-readable output by default, `--json` for machines. Exit 0 on
answers, 1 on usage error, 2 on provider failure.

| Command | What it does |
|---|---|
| `jev ask --state <file\|-\|json> --questions <json\|file>` | Raw request; prints answers with confidence and band. |
| `jev rank "<query>" --items <file\|-> [--top 15] [--id-field id --text-field text]` | Ranks items (JSON lines, a JSON array, or plain lines) against a query, in balanced chunks of at most 200 as one Choice per chunk plus a `match_exists` Noul; at most 4 requests in flight; a failed chunk leaves its items unranked (`partial: true`) instead of failing the command. Use on `search_strings`, `list_procedures`, `list_names`, `xrefs`, and `inspect_artifact` inventories. |
| `jev classify --items <file\|-> --labels a,b,c[,other] --instructions "<q>"` | One Choice per item, batched 40 per request; `other` is appended when the label set has no "none of these". Sort procedures into roles or strings into kinds. |
| `jev verify (--claim "<text>" \| --claim-file <file\|->) --evidence <file\|->` | Nouls `supported`, `contradicted`, `needs_runtime`, `overstated` against the evidence text; prints a verdict with the deciding probability, confidence and band (an escalate-band verdict is `insufficient`). Use `--claim-file` when the claim quotes strings from the program. |
| `jev doctor [--offline]` | Provider and key resolution, one-question round trip with latency and model version, REA pin and whether `npx rea-agents` resolves (`--offline` skips that probe), hook hints, ledger directory. |
| `jev stats [--days 7]` | Counts, cost estimate, latency percentiles, and bands from `decisions.jsonl`. |

Invoke as `node "${CLAUDE_PLUGIN_ROOT}/scripts/jev.mjs" <command>` from inside
Claude Code. All commands redact secrets before sending and refuse item files
over 2 MB unless `--force`.

## Modes

Set with the plugin option **mode** or `REA_JEV_MODE`.

| Mode | UserPromptSubmit | PreToolUse | PostToolUse | Stop |
|---|---|---|---|---|
| `off` | nothing | nothing | ledger only | nothing |
| `shadow` | log only | log only | log only | log only, `systemMessage` with the would-have verdict |
| `advise` (default) | inject route note | redundancy → `deny`; scope/risk → `ask`; else silent | inject evidence notes | never blocks; `systemMessage` with verdict |
| `enforce` | inject route note | redundancy → `deny`; out-of-scope → `deny`; risk → `ask` | inject evidence notes | may `block` once per stop, twice per session, never within 60 s of the last block |

## Environment variables

| Variable | Purpose |
|---|---|
| `TYPESAFE_API_KEY` | Direct TypeSafe API, model `jev-latest`. |
| `OPENROUTER_API_KEY` | Fallback through OpenRouter, model `typesafe/jev-1.13`. |
| `CLAUDE_PLUGIN_OPTION_TYPESAFE_API_KEY`, `CLAUDE_PLUGIN_OPTION_MODE` | Set by Claude Code from the plugin options; win over the plain variables. |
| `JEV_BASE_URL` | Override the endpoint (tests point it at `tests/fake-jev.mjs`). |
| `REA_JEV_MODEL` | Override the model id. |
| `REA_JEV_MODE` | `off` \| `shadow` \| `advise` (default) \| `enforce`. |
| `REA_JEV_TIMEOUT_MS` | Per-call budget including one retry on 429/529. Hooks default to `4000` and clamp it below their own safety ceiling (route/gate 5.5 s, evidence 10.5 s, stop 20.5 s); the `jev` CLI defaults to `20000` when it is unset, or takes `--timeout <ms>`. |
| `REA_JEV_HOME` | Ledger directory (default `$CLAUDE_PLUGIN_DATA` if set, else `~/.rea-jev`). |
| `REA_JEV_LOG` | `1` appends every decision to `$REA_JEV_HOME/decisions.jsonl`. |
| `REA_JEV_DEBUG` | `1` prints why each hook did what it did, on stderr. |
| `REA_JEV_T_*` | Threshold overrides, for example `REA_JEV_T_ROUTE_MIN=0.5`; see [docs/decision-points.md](docs/decision-points.md). |
| `REA_JEV_REA_COMMAND` | Tells `/rea-jev:setup` to diagnose a fork or local build of REA instead of the pinned npm package; see [docs/upstream-rea.md](docs/upstream-rea.md). |

## How this relates to REA

- REA is consumed as the published npm package `rea-agents`, pinned in
  `.mcp.json` and in `data/rea-tool-catalog.json` (116 tools from 4.0.1). The
  plugin does not vendor REA's source; bumping the pin is a documented procedure
  in [docs/upstream-rea.md](docs/upstream-rea.md).
- If you already ran `rea setup` for Claude Code, REA is registered twice (the
  global `rea` server and the plugin's bundled one). The hooks match both tool
  name forms, so either works alone; keep exactly one. `/rea-jev:setup` walks
  through it.
- REA's own skill, `reverse-engineer-anything` (installed by `rea setup`), stays
  the canonical tool-by-tool guide. The `reverse-engineer` skill here is the
  System 1 loop on top of it: route, hypothesize, probe, classify, ledger,
  verify, finish or build. It links to REA's guide rather than duplicating it,
  and its [tool catalog](skills/reverse-engineer/references/tool-catalog.md) is
  generated from REA's own descriptions.

## Limits and honesty

- **Jev is a System One model.** It does not write code, generate text, or
  explain anything. It returns probabilities for typed questions (Noul, Choice,
  Score). Every route note, gate question, and evidence note here is advisory
  data with a confidence attached; code, and then Claude, decide what to do with
  it. Jev will be wrong sometimes, and the thresholds in v0.1.0 are defaults,
  not calibrated on a labeled corpus. `REA_JEV_LOG=1` and `jev stats` exist so
  you can tune them on your own decisions.
- **Hooks fail open.** No key, a timeout, a 4xx or 5xx, or a malformed answer
  means the hook exits 0 and emits nothing (answers are validated against the
  questions; an out-of-range or foreign value counts as no opinion). A hook
  that blocks by accident costs more trust than one that misses a case. In
  `advise` the only denies are local and deterministic: an identical repeated
  inspection call, and a non-loopback `cdp_endpoint`/`inspector_endpoint` on
  any REA tool. `enforce` adds one Jev-based deny: a runtime or extraction call
  whose `within_scope` falls below `T_GATE_SCOPE` with a decisive answer
  (confidence at or above the confirm band) while a target is declared; a
  near-coin-flip, or a session with no declared target, only asks. The
  Stop hook likewise blocks only on decisive answers and never when your
  message cites the Evidence IDs that were returned.
- **What leaves the machine.** Only the fields each question needs: a prompt
  excerpt (at most 3000 chars), the REA tool name with a redacted input excerpt
  (1500), a redacted result excerpt (6000, head and tail), the final message
  (4000), and your last reverse-engineering request (at most 1200 chars).
  Secrets (`sk-…`, `sk_live_…`, `ghp_…`, `glpat-…`, `AKIA…`, `AIza…`, `xox?-…`,
  JWTs, bearer tokens, `password=`/`token=`/`cookie=` pairs, private key blocks,
  URL userinfo) are masked before sending, and URLs in prompts lose their
  credentials and query strings before they reach a hint, the ledger, or Jev.
  The analyzed binary is never uploaded; REA itself analyzes locally. With
  OpenRouter, requests transit OpenRouter. The ledger on disk holds hashes,
  Evidence IDs (at most 64 per result), excerpts of at most 200 chars, and one
  1200-char redacted copy of your request per prompt, never full tool inputs or
  outputs. The PostToolUse hook reads at most 32 MB of a result; a larger one is
  recorded from its prefix (tool, input hash, size) and not judged.
- **Cost and latency.** About $0.042 per million input tokens, output free;
  one call is roughly 1 to 3k tokens, so a few hundredths of a cent, in about
  300 ms. Inspection calls never cost a Jev request.
- **Not in v1.** Compaction of REA outputs, model or effort routing,
  auto-approval of REA inspection calls, Windows hooks (untested), running REA
  itself in tests. The roadmap is in [DESIGN.md](DESIGN.md#10-non-goals-v1-and-roadmap).
- **Scope and ethics.** Analyze only software you are entitled to analyze (your
  own, licensed for interoperability or security research, or explicitly
  permitted). The skill says so and the gate asks when a scenario reaches
  outside the declared target.

## Development

Zero runtime dependencies, Node 22+, ESM `.mjs`, no build step.

```
npm test            # node --test "tests/*.test.mjs"   (offline, against tests/fake-jev.mjs)
npm run validate    # node scripts/validate.mjs
node scripts/validate.mjs --write-catalog   # regenerate the skill's tool catalog from data/
```

`validate.mjs` checks that the manifests parse, every hook command points at an
existing script, the hook matcher accepts both REA tool-name forms, the skill
frontmatter is well formed, the `.mcp.json` pin equals the catalog version,
every backticked tool name in the skill and agents exists in the catalog (with
a documented allowlist for REA's Android tools), and the generated catalog is
current. CI runs both commands on Ubuntu with Node 22.

## License

MIT. See [LICENSE](LICENSE).

## Credits

- [morluto/rea](https://github.com/morluto/rea), Reverse Engineer Anything, for
  the tools, the evidence model, and the `reverse-engineer-anything` skill this
  one builds on.
- [TypeSafe](https://typesafe.ai) for Jev and the System One guidance on atomic
  questions, confidence routing, and state design.
- The Jev hook projects whose patterns informed this one:
  jev-auto-approve (allow-or-silent
  PreToolUse that never denies, hard deny-lists before the model),
  [jev-axi](https://github.com/shiftynick/jev-axi) (local rules first, Jev for the
  semantic middle, `guard` for text that reads as instructions), and
  [jev-belay](https://github.com/valentynkit/jev-belay) (an evidence-gated Stop
  hook that establishes facts before asking whether "done" is earned).
