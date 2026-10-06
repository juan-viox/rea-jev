# Relationship to upstream REA

[morluto/rea](https://github.com/morluto/rea) ("Reverse Engineer Anything") is
consumed as the published npm package `rea-agents`. This repository does not
vendor REA's source. Two files pin the version:

| File | What it holds |
|---|---|
| `.mcp.json` | `npx -y rea-agents@4.0.1 mcp`, the server Claude Code starts for the plugin |
| `data/rea-tool-catalog.json` | The MCP tool catalog extracted from the same release: `version`, `tool_count`, and for every tool its `name`, `title`, `kind`, `requiresSession`, `analysisOperation`, `description`, `annotations`, `effects`, `required`, and `props` |

`scripts/validate.mjs` fails when the two versions differ, and
`skills/reverse-engineer/references/tool-catalog.md` is generated from the JSON
so the skill never documents a tool the pinned release does not have. The
hooks' effect classes (`runtime`, `mutation`, `status`, `inspect`) are derived
from the catalog's `effects` and tool names at runtime.

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
   the JSON catalog from the package's generated MCP catalog module:

   ```bash
   mkdir -p /tmp/rea-bump && cd /tmp/rea-bump
   npm init -y >/dev/null && npm install --no-save rea-agents@<VERSION>
   node --input-type=module -e '
     import { GENERATED_MCP_TOOL_CATALOG as tools } from "./node_modules/rea-agents/dist/generatedMcpToolCatalog.js";
     import { readFileSync, writeFileSync } from "node:fs";
     const version = JSON.parse(readFileSync("./node_modules/rea-agents/package.json", "utf8")).version;
     const out = {
       source: "rea-agents",
       version,
       generated_from: "node_modules/rea-agents/dist/generatedMcpToolCatalog.js (GENERATED_MCP_TOOL_CATALOG)",
       tool_count: tools.length,
       tools: tools.map((t) => ({
         name: t.name, title: t.title, kind: t.kind, requiresSession: t.requiresSession,
         analysisOperation: t.analysisOperation, description: t.description,
         annotations: t.annotations, effects: t.effects,
         required: t.inputSchema?.required ?? [],
         props: Object.fromEntries(Object.entries(t.inputSchema?.properties ?? {}).map(([k, v]) => [k, { type: v.type, description: v.description, ...(v.enum && { enum: v.enum }) }])),
       })),
     };
     writeFileSync("rea-tool-catalog.json", JSON.stringify(out, null, 2) + "\n");
   '
   cp rea-tool-catalog.json <REPO>/data/rea-tool-catalog.json
   ```

   Keep the shape above; `validate.mjs`, the hooks' effect classes, and the
   generated Markdown read exactly these fields. The `enum` on a property
   (`format`, `integrity_policy`, `direction`, `severity`, `status`, …) is what
   `references/route-table.md` cites as the optional values; after a bump,
   check those lists against the regenerated enums.
3. Update the pin in `.mcp.json` to `rea-agents@<VERSION>`.
4. Regenerate the skill's catalog page:
   `node scripts/validate.mjs --write-catalog`.
5. Update the version in `skills/reverse-engineer/SKILL.md` frontmatter
   (`metadata.rea_pin`), the `/rea-jev:setup` command (`npx -y rea-agents@<VERSION>`),
   the README, and `docs/architecture.md`.
6. Review the diff of `references/tool-catalog.md`. A removed tool that the
   skill, the agents, or the route table still name is caught by
   `validate.mjs` (every backticked tool name must exist in the catalog). A new
   tool may deserve a line in `references/route-table.md`. A tool whose
   `effects.launchesProcess` or name prefix changed moves between effect
   classes; check `docs/decision-points.md` still describes the gate correctly.
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
   instead of `npx -y rea-agents@4.0.1 doctor` and to say which binary it
   diagnosed. Nothing else in rea-jev changes.
5. If the fork adds or renames tools, regenerate `data/rea-tool-catalog.json`
   from the fork's `dist/generatedMcpToolCatalog.js` with the script above and
   run `node scripts/validate.mjs --write-catalog`. `validate.mjs` will then
   report the pin mismatch between `.mcp.json` and the catalog; that is
   expected for a fork, and a fork maintainer should either publish to npm
   under a version and pin it, or carry a one-line patch to `.mcp.json`.

The hooks, the ledger, and the `jev` CLI are indifferent to where REA runs;
they only read tool names, inputs, and results. Hopper, Ghidra, and the
platform requirements are REA's, not this plugin's.

## Android tools

REA documents Android analysis (`inspect_android_package`,
`search_android_classes`, `inspect_android_class`, `inspect_android_method`,
`trace_android_references` in `docs/android-analysis.md`), but the
`rea-agents@4.0.1` MCP catalog does not list them. The skill and the route
table name `inspect_android_package` with that caveat, and `validate.mjs`
carries them as a documented allowlist (`ANDROID_TOOL_ALLOWLIST`). When a bump
brings them into the catalog, remove the allowlist entries and the caveat.
