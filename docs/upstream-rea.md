# Relationship to upstream REA

[morluto/rea](https://github.com/morluto/rea) ("Reverse Engineer Anything") is
consumed as the published npm package `rea-agents`. This repository does not
vendor REA's source. Two files pin the version:

| File | What it holds |
|---|---|
| `.mcp.json` | `npx -y rea-agents@6.5.0 mcp`, the server Claude Code starts for the plugin |
| `data/rea-tool-catalog.json` | The MCP tool catalog extracted from the same release by `scripts/import-rea-catalog.mjs`: `version`, `tool_count`, and for every tool its `name`, `title`, `kind`, `description`, `annotations`, `effects`, `returnsTargetContent`, `required`, and `props` (each prop: `type`, `description`, `enum` when the schema has one) |

`scripts/validate.mjs` fails when the two versions differ, and
`skills/reverse-engineer/references/tool-catalog.md` is generated from the JSON
so the skill never documents a tool the pinned release does not have. The
hooks' effect classes (`runtime`, `mutation`, `status`, `inspect`) are derived
from the catalog's `effects` and tool names at runtime; `scripts/validate.mjs`
carries the same rules so the generated Markdown shows the class the gate will
apply.

REA's own skill, `reverse-engineer-anything`, is installed by `rea setup` and
remains the canonical tool-by-tool guide (route the target first, work
summary-first, cite Evidence IDs, close the session). The `reverse-engineer`
skill here layers the System 1 loop on top and links to REA's guide rather
than repeating it.

## Bumping the REA pin

1. Find the release: `npm view rea-agents version` (or a specific version from
   `npm view rea-agents versions --json`). Read REA's CHANGELOG for tool
   additions, removals, and renamed inputs.
2. Install it in a scratch directory, outside this repository, and regenerate
   the JSON catalog from the package's own tool contracts with the importer:

   ```bash
   mkdir -p /tmp/rea-bump && cd /tmp/rea-bump
   npm init -y >/dev/null && npm install --no-save rea-agents@<VERSION>
   cd <REPO>
   node scripts/import-rea-catalog.mjs /tmp/rea-bump/node_modules/rea-agents
   ```

   A global install works too: `node scripts/import-rea-catalog.mjs
   "$(npm root -g)/rea-agents"`. The importer reads
   `dist/contracts/toolContracts.js` (`TOOL_CONTRACTS`) and renders each input
   schema with `dist/contracts/toolSchemaMetadata.js`
   (`advertisedInputJsonSchema`), resolving local `$defs` references so the
   `enum` on a property survives; releases before 6.0 shipped a flat
   `dist/generatedMcpToolCatalog.js`, which it still reads. Keep the output
   shape; `validate.mjs`, the hooks' effect classes, and the generated Markdown
   read exactly these fields. The `enum` on a property (`format`,
   `integrity_policy`, `direction`, `severity`, `detail`, `mode`, …) is what
   `references/route-table.md` cites as the optional values; after a bump,
   check those lists against the regenerated enums. Diff the old and new
   `tools[]` names; a removed tool that the skill, the agents, or the route
   table still name is caught by `validate.mjs`.
3. Update the pin in `.mcp.json` to `rea-agents@<VERSION>`.
4. Regenerate the skill's catalog page:
   `node scripts/validate.mjs --write-catalog`.
5. Update the version in `skills/reverse-engineer/SKILL.md` frontmatter
   (`metadata.rea_pin`), the `/rea-jev:setup` command (`npx -y rea-agents@<VERSION>`),
   the README, `docs/architecture.md`, `docs/user-guide.html`, the status-line
   examples (`REA pinned <VERSION>` in DESIGN.md, `docs/decision-points.md`,
   `references/system1-decision-points.md`, `scripts/hook-session.mjs`), and
   the pin and tool count asserted in `tests/cli.test.mjs`.
6. Review the diff of `references/tool-catalog.md`. A removed tool that the
   skill, the agents, or the route table still name is caught by
   `validate.mjs` (every backticked tool name must exist in the catalog). A new
   tool may deserve a line in `references/route-table.md`. Then review the
   effect classes: a new tool that runs, attaches to, instruments or changes
   the target or a device must land in `runtime` (by name in `RUNTIME_EXACT` in
   `scripts/lib/rea.mjs` and `RUNTIME_TOOLS` in `scripts/validate.mjs` when its
   effect flags do not say `executesForeignCode` or `mutatesDevice`), a tool
   that writes files outside REA's temp directory in `mutation` and, when it
   takes an output path, in the gate's `PATH_GATED_TOOLS`, and a tool whose
   result describes observed behavior (captures, recordings, debugger output)
   in `RUNTIME_EVIDENCE_TOOLS` so the evidence hook never tells Claude that
   static analysis cannot establish execution. `tests/rea-catalog.test.mjs`
   checks the library and the validator agree over the whole catalog; check
   `docs/decision-points.md` and DESIGN.md §3 still describe the gate correctly.
7. Run `npm test` and `npm run validate`. Add a CHANGELOG entry and bump the
   plugin version in `.claude-plugin/plugin.json`, `package.json`, and the
   version strings in `docs/user-guide.html`.
8. Users pick up the new pin on their next plugin update; Claude Code restarts
   the bundled server with the new `npx` spec.

## Using a fork of morluto/rea

`.mcp.json` stays pinned to the npm package so that installs are reproducible.
To run a fork or a local build instead:

1. Build the fork (`npm install && npm run build` in its checkout; the CLI is
   `scripts/rea.mjs` and `rea mcp` or `rea --mcp` starts the stdio server).
2. Register it with Claude Code yourself under the name `rea`, so the hooks'
   matcher (`mcp__(plugin_rea-jev_)?rea__`) still sees its tools:

   ```bash
   claude mcp add rea -s user -- node /path/to/fork/scripts/rea.mjs mcp
   ```

   or let the fork do it: `node /path/to/fork/scripts/rea.mjs mcp add --agent claude-code --command "node /path/to/fork/scripts/rea.mjs --mcp"`.
3. Disable the plugin's bundled server in Claude Code's `/mcp` menu so REA is
   not registered twice (two servers mean two processes and a doubled tool
   list).
4. Export `REA_JEV_REA_COMMAND="node /path/to/fork/scripts/rea.mjs"`. The
   hooks do not use it; `/rea-jev:setup` does, to run the fork's `doctor`
   instead of `npx -y rea-agents@6.5.0 doctor` and to say which binary it
   diagnosed. Nothing else in rea-jev changes.
5. If the fork adds or renames tools, regenerate `data/rea-tool-catalog.json`
   from the fork's build with `node scripts/import-rea-catalog.mjs
   /path/to/fork` and run `node scripts/validate.mjs --write-catalog`. `validate.mjs` will then
   report the pin mismatch between `.mcp.json` and the catalog; that is
   expected for a fork, and a fork maintainer should either publish to npm
   under a version and pin it, or carry a one-line patch to `.mcp.json`.

The hooks, the ledger, and the `jev` CLI are indifferent to where REA runs;
they only read tool names, inputs, and results. Hopper, Ghidra, and the
platform requirements are REA's, not this plugin's.

## Android tools

rea-agents 6.5.0 ships the Android family (`inspect_android_package`,
`search_android_classes`, `inspect_android_class`, `inspect_android_method`,
`trace_android_references`, `decode_android_resources`,
`project_android_application_graph`) and the ADB device tools
(`list_adb_devices`, `inspect_adb_device`, `pull_adb_package`, …). The
`android_apk` route now resolves to `inspect_android_package`; the fallback to
`open_binary` plus `inspect_artifact` in `scripts/lib/rea.mjs`
(`FIRST_TOOL_BY_TARGET.android_apk.fallback`) stays for a catalog generated
from a release that lacks them. The `ANDROID_TOOL_ALLOWLIST` that `validate.mjs`
carried while the pin was 4.0.1 is gone: every backticked tool name in the
skill must now exist in the catalog.
