# Changelog

All notable changes to rea-jev are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

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

[0.1.0]: https://github.com/juan-viox/rea-jev/releases/tag/v0.1.0
