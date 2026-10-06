---
description: Diagnose rea-jev end to end (Jev provider and key, REA readiness, hook registration, duplicate REA servers) and explain the fix for each finding.
---

Run both diagnostics with Bash, read them, then report. Do not change any
configuration yourself: propose the exact command for each fix and let the user
run or approve it.

1. `node "${CLAUDE_PLUGIN_ROOT}/scripts/jev.mjs" doctor --json`
2. `npx -y rea-agents@4.0.1 doctor --json`
   (If the environment sets `REA_JEV_REA_COMMAND`, the user runs REA from a fork
   or a local build. Run `$REA_JEV_REA_COMMAND doctor --json` instead and say
   which binary you used.)

Never print an API key or any value that looks like one, not even a prefix.

## What each report tells you

`jev doctor` (exit 0: Jev answered; exit 2: provider failure, reason included):

- which provider was resolved (`typesafe` through `TYPESAFE_API_KEY` or the
  plugin option, `openrouter` through `OPENROUTER_API_KEY`, or none) and where
  the key came from;
- the one-question round trip: latency and the model version that answered, or
  the failure reason (`no_key`, `timeout`, `http_4xx` with status, `http_5xx`,
  `bad_json`, `network`);
- the REA version this plugin pins and whether `npx rea-agents` resolves;
- hints on whether the plugin hooks are registered in this Claude Code;
- the ledger directory and whether `decisions.jsonl` logging is on.

`rea doctor --json` (`healthy`, then `scope_checks[]` with `classification` and
`remediation`): node and host, `hopper` and `ghidra`
(`missing_analysis_engine`), agent registrations, and REA's own skill identity
(`config_drift`).

## Fixes, by finding

### No Jev key (`no_key`)

System 1 is off: every hook fails open and the `jev` CLI exits 2. Set one of:

- the plugin option **TypeSafe API key** (asked when the plugin is enabled and
  stored by Claude Code; it wins over the environment), or
- `export TYPESAFE_API_KEY=…` (direct, lowest latency; keys at
  https://console.typesafe.ai), or
- `export OPENROUTER_API_KEY=…` (model `typesafe/jev-1.13` through OpenRouter).

Restart Claude Code after setting an environment variable so hooks inherit it.

### Jev answered with an error

- `401`: key rejected; check which provider the key belongs to.
- `422`: request rejected, usually a question outside the limits (Choice at most
  255 options, Score 2 to 10 levels, about 32k tokens of context). Report it as a
  rea-jev bug with the `jev doctor` output.
- `429` or `529`: rate limited or overloaded; the client retries once inside
  `REA_JEV_TIMEOUT_MS` (default 4000). Transient.
- `timeout` or `network`: raise `REA_JEV_TIMEOUT_MS` or check proxy settings.
  Hooks keep failing open meanwhile; nothing is blocked.

### Hopper or Ghidra missing (`missing_analysis_engine`)

Native analysis (`open_binary` on Mach-O, ELF, or PE) needs one deep provider;
JavaScript, managed, artifact, browser, and Electron tools work without it.

- Hopper: `npx -y rea-agents@4.0.1 setup` shows its plan first and installs
  Hopper only with explicit consent (`--install-hopper` together with `--yes`),
  or set `HOPPER_LAUNCHER_PATH` to an existing install.
- Ghidra: set `GHIDRA_INSTALL_DIR` to an extracted Ghidra 12.1.4 directory with
  a 64-bit JDK 21 available, then rerun `rea doctor`.

### REA registered twice

This plugin bundles REA through its `.mcp.json`; its tools appear as
`mcp__plugin_rea-jev_rea__<tool>`. If the user also ran `rea setup` for Claude
Code, a second server named `rea` is registered globally with tools
`mcp__rea__<tool>`. Two servers mean two REA processes, a duplicated tool list,
and doubled permission prompts. The hooks match both forms, so either one works
alone; keep exactly one:

- **Recommended:** keep the plugin's server and remove the global one with
  `claude mcp remove rea` (add `-s user`, `-s project`, or `-s local` to match
  the scope `claude mcp list` shows), or run `npx -y rea-agents@4.0.1 uninstall`,
  which removes REA-owned registrations and REA's managed skill but keeps
  Hopper, Evidence files, and unrelated servers.
- **Alternative** (users of a fork, or anyone who wants `rea setup` to keep
  REA's own skill synced): keep the global server and disable the plugin's
  bundled one in the `/mcp` menu (select the server provided by the rea-jev
  plugin and disable it).

Restart Claude Code afterwards.

### REA skill identity drift (`skill:identity`, `config_drift`)

REA's own `reverse-engineer-anything` skill is older than the installed package.
It does not affect rea-jev. `npx -y rea-agents@4.0.1 setup` realigns it if the
user wants REA's canonical tool guide current.

### Hooks not firing

- `/plugin` (or `claude plugin list`) must show `rea-jev` enabled; restart Claude
  Code after installing.
- `REA_JEV_MODE` or the plugin option **mode** must not be `off`.
- `REA_JEV_DEBUG=1` makes every hook explain its decision on stderr.
- The gate and evidence hooks only run on tools matching
  `mcp__(plugin_rea-jev_)?rea__`; an REA server registered under another name
  is invisible to them.

## Report

End with a short table: check, status, fix (or "ok"). State the mode in effect
and which provider answered. Do not rerun these diagnostics in later turns
unless REA tools go missing or the user asks.
