# VioX OS integration

VioX OS syncs `skills/*/SKILL.md` from registered repositories into its skill
registry, and agents declare the skills they load in their YAML. This plugin's
skill is at `skills/reverse-engineer/SKILL.md`, so once the `rea-jev`
repository is registered as a skill source, the skill appears in the registry
as `reverse-engineer` with its `references/` directory alongside.

## Listing the skill in an agent

Add `reverse-engineer` to the agent's `skills:` list:

```yaml
name: binary-analyst
description: Explains how a feature in a shipped app works, with REA evidence.
model: inherit
skills:
  - reverse-engineer
```

The skill body references `${CLAUDE_PLUGIN_ROOT}/scripts/jev.mjs` for the
`jev rank|classify|verify` recipes. That variable is set by Claude Code when the
plugin is installed. Outside Claude Code the recipes still run; invoke the CLI
by path (`node /path/to/rea-jev/scripts/jev.mjs …`) or set
`CLAUDE_PLUGIN_ROOT` to the checkout in the agent's environment.

## What the sync does and does not carry

| Carried by the skill sync | Needs the plugin installed |
|---|---|
| The System 2 playbook: route table, probe discipline, evidence rules, reconstruction notes | The four System 1 hooks (route note, gate, evidence notes, stop check) |
| The generated REA tool catalog and the `jev` recipes (prose) | The `jev` CLI itself and the bundled REA MCP server |
| The decision-point guide, so the agent can read a hook note when one appears | The `rea-investigator` and `rea-verifier` subagents and the two slash commands |

Hooks are a Claude Code mechanism. They only fire when the `rea-jev` plugin is
installed in the Claude Code instance that the VioX OS gateway drives:

```
claude plugin marketplace add juan-viox/rea-jev
claude plugin install rea-jev@rea-jev
```

A gateway that runs Claude Code headless (`claude -p …`) gets the same hooks as
an interactive session, provided the plugin is installed for the user the
gateway runs as and REA is registered once (see `/rea-jev:setup` for the
duplicate-registration case). The skill alone, synced into an agent that runs
somewhere else, gives the loop without the reflexes: no route note, no
redundancy denies, no evidence notes, no stop check.

## Keys and configuration

Keep the Jev key in the VioX vault or the gateway's `.env`, never in agent
YAML or the skill registry. The hooks read, in this order:
`CLAUDE_PLUGIN_OPTION_TYPESAFE_API_KEY` (set by Claude Code from the plugin
option), `TYPESAFE_API_KEY`, `OPENROUTER_API_KEY`. Mode comes from
`CLAUDE_PLUGIN_OPTION_MODE` or `REA_JEV_MODE` (`off`, `shadow`, `advise`,
`enforce`). For an unattended gateway, `shadow` first, with `REA_JEV_LOG=1`,
gives a decision log to review before switching to `advise` or `enforce`.
Point `REA_JEV_HOME` at a writable per-gateway directory; it holds the session
ledgers and `decisions.jsonl`, both of which are in `.gitignore`.

## REA on the gateway host

REA analyzes locally, so the gateway host needs what REA needs: Node 22.19+,
and Hopper or Ghidra for native binaries (`npx -y rea-agents@4.0.1 doctor
--json` reports what is missing). JavaScript, managed, artifact, browser, and
Electron tools work without a deep provider.

## Roadmap

A VioX OS agent preset that lists `reverse-engineer` together with REA's own
`reverse-engineer-anything` skill is on the roadmap (DESIGN.md §10). Until
then, add the skill to agents by hand as shown above.
