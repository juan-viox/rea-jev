# Changelog

All notable changes to rea-jev are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [0.1.3] - 2026-10-06

### Added

- Skill guidance for `capture_browser_scenario` behind an outbound proxy,
  found while capturing landonorris.com from a cloud sandbox. In launch mode
  rea-agents 4.0.1 starts Chromium with an environment allow-list that leaves
  out `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`, so the browser cannot reach
  the site and the call fails with a bare `execution_failure` (reproduced: the
  same Chromium with REA's allow-list loads nothing, with the proxy variables
  it loads the page). The route table now gives the connect-mode workaround: a
  browser you start on `about:blank` with a fresh profile, its target id read
  from `/json/list` (`list_browser_targets` does not list `about:blank`), and
  REA navigating from the first byte. `SKILL.md` points to it.

## [0.1.2] - 2026-10-06

Two false positives found while reverse-engineering a live website with the
plugin active, both fixed with a measurement behind them.

### Fixed

- The evidence hook warned "text that reads as instructions to an assistant"
  on results it never saw: when a result is too large for the context, Claude
  Code hands the hook its own notice ("Output has been saved to <file>" plus
  reading instructions) in place of the result. The hook now recognizes that
  notice (both wordings, with and without "across M lines"), reads back
  the file Claude Code saved for this call (only from Claude Code's own
  `tool-results` directory under `$CLAUDE_CONFIG_DIR`, real path checked,
  symlinks refused, only an REA envelope with an `evidence_id`, at most 64
  MB) and judges the real result, so its Evidence IDs also reach the ledger and the Stop
  hook. The notice itself never reaches Jev; an unreadable file is recorded
  as `oversize_notice: true, recovered: false` and skips Jev.
- The route hook routed "fix the false positive warning" as a website
  investigation because the session had an active target. Measured on
  jev-1.13: `is_re_task` for that prompt was 0.06 alone and 0.55 with the
  target in the state. Two changes: the question now says to judge the prompt
  alone and names code changes, tests, merges and formatting during an active
  investigation as not reverse engineering (0.55 → 0.24), and a prompt that
  reached Jev only through the ledger's REA activity, with no keyword, path,
  or endpoint of its own, must clear the new `T_ROUTE_RE_FOLLOWUP` (0.5,
  `REA_JEV_T_ROUTE_RE_FOLLOWUP`) instead of `T_ROUTE_RE` (0.35). Real
  follow-ups still route ("and the login flow?" measured 0.83).

## [0.1.1] - 2026-10-06

First run against the live TypeSafe API (`jev-1.13.0`): round trip 299 ms,
hook latency p50 283 ms / p90 338 ms, 7,154 input tokens for a full fixture
session (route, gate, evidence, stop) at an estimated $0.0003. Every hook
behaved as designed; two defects surfaced and are fixed here.

### Fixed

- Redaction treated the scope operator in identifiers such as
  `NetworkSession::send` as a credential assignment and masked the member
  name. The key/value pattern now requires `=` or a single `:` as the
  separator, and the value may not begin with `:`.
- The gate could `deny` a runtime capture as out of scope in `enforce` mode
  when the session had no declared target (an ambiguous route). Scope cannot
  be established without a target, so that case now asks the user instead.

## [0.1.0] - 2026-10-06

Initial release.

### Added

- Claude Code plugin manifest and single-repo marketplace
  (`claude plugin marketplace add juan-viox/rea-jev`,
  `claude plugin install rea-jev@rea-jev`).
- Bundled REA MCP server pinned to `rea-agents@4.0.1`, with a tool catalog
  (`data/rea-tool-catalog.json`, 116 tools) generated from the same release.
- Four System 1 decision points as Claude Code hooks, all failing open:
  `UserPromptSubmit` route (target kind, workflow, scope, runtime need),
  `PreToolUse` gate (local redundancy and hard rules, then Jev scope/risk for
  runtime-class tools), `PostToolUse` evidence scoring (relevance, untracked
  limitations, agent-directed text, runtime claims from static tools), and a
  `Stop` completeness check (claims vs ledger). Plus a `SessionStart` status
  line.
- Per-session JSONL ledger of hashes, Evidence IDs, and short redacted
  excerpts; optional `decisions.jsonl` log.
- `jev` CLI for System 2 to ask System 1: `ask`, `rank`, `classify`,
  `verify`, `doctor`, `stats`; TypeSafe direct or OpenRouter provider.
- `reverse-engineer` skill with route table, generated tool catalog,
  decision-point guide, Jev recipes, evidence-ledger rules, and
  reconstruction notes.
- `rea-investigator` and `rea-verifier` subagents; `/rea-jev:setup` and
  `/rea-jev:investigate` commands.
- Modes `off`, `shadow`, `advise` (default), `enforce`; env-tunable
  thresholds (`REA_JEV_T_*`).
- Offline test suite against a fake Jev server, repository validator
  (`scripts/validate.mjs`, with `--write-catalog`), and GitHub Actions CI.
- Review fixes before release: the 429/529 retry now happens in real hook and
  CLI processes (the retry timer no longer lets Node exit); provider answers
  are validated against the questions; hard actions (`deny`, `block`,
  categorical `verify` verdicts) require a decisive answer; the gate, evidence
  and stop hooks judge against the last reverse-engineering request (kept at
  1200 chars) rather than a later follow-up prompt; limitations are read from
  REA's envelope only; passive live-process tools are never told static
  analysis cannot establish execution; linear-time redaction with more token
  shapes and a `PWD` exception; URL credentials stripped at the sniffer;
  Evidence IDs capped per result; empty results are not reusable; `jev verify
  --claim-file`; balanced `rank` chunks, bounded concurrency and partial
  results; `classify` puts the instructions in each question and appends
  `other`.

[0.1.0]: https://github.com/juan-viox/rea-jev/releases/tag/v0.1.0
[0.1.1]: https://github.com/juan-viox/rea-jev/compare/v0.1.0...v0.1.1
[0.1.2]: https://github.com/juan-viox/rea-jev/compare/v0.1.1...v0.1.2
[0.1.3]: https://github.com/juan-viox/rea-jev/compare/v0.1.2...v0.1.3
