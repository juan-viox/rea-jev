#!/usr/bin/env node
/**
 * Regenerate `data/rea-tool-catalog.json` from an installed `rea-agents` package.
 *
 * Usage:
 *   node scripts/import-rea-catalog.mjs <rea-agents package dir> [--out <file>]
 *
 * The package dir is the directory holding rea-agents' package.json, for
 * example `/tmp/rea-bump/node_modules/rea-agents` after
 * `npm install --no-save rea-agents@<VERSION>` in a scratch directory, or
 * `$(npm root -g)/rea-agents` for a global install. Only the package's own
 * catalog modules are imported; nothing else in it runs.
 *
 * rea-agents 6.x keeps its tool contracts in `dist/contracts/toolContracts.js`
 * (`TOOL_CONTRACTS`) and renders the advertised input schema with
 * `dist/contracts/toolSchemaMetadata.js` (`advertisedInputJsonSchema`).
 * Releases before 6.0 shipped a flat `dist/generatedMcpToolCatalog.js`
 * (`GENERATED_MCP_TOOL_CATALOG`); both are read. The output keeps the shape
 * `scripts/validate.mjs`, `scripts/lib/rea.mjs` and the generated
 * `references/tool-catalog.md` depend on: `version`, `tool_count`, and per
 * tool `name`, `title`, `kind`, `description`, `annotations`, `effects`,
 * `returnsTargetContent`, `required`, `props` (each prop: `type`,
 * `description`, optional `enum`). Run `node scripts/validate.mjs
 * --write-catalog` afterwards.
 *
 * @module import-rea-catalog
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import process from 'node:process';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_OUT = join(ROOT, 'data', 'rea-tool-catalog.json');

function usage(code) {
  const out = code ? console.error : console.log;
  out('usage: node scripts/import-rea-catalog.mjs <rea-agents package dir> [--out <file>]');
  process.exit(code);
}

function parseArgs(argv) {
  const opts = { pkgDir: null, out: DEFAULT_OUT };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--out') { opts.out = resolve(argv[i + 1] ?? ''); i += 1; }
    else if (a === '-h' || a === '--help') usage(0);
    else if (a.startsWith('-')) { console.error(`unknown argument: ${a}`); usage(1); }
    else if (opts.pkgDir) { console.error(`unexpected argument: ${a}`); usage(1); }
    else opts.pkgDir = resolve(a);
  }
  if (!opts.pkgDir) usage(1);
  return opts;
}

/**
 * Resolve a local `#/$defs/<name>` reference (one hop) so a property advertised
 * through a shared definition still reports its `type` and `enum`.
 */
function deref(schema, defs) {
  const ref = schema && typeof schema === 'object' && typeof schema.$ref === 'string' ? schema.$ref : null;
  const m = ref ? /^#\/\$defs\/([^/]+)$/.exec(ref) : null;
  const target = m && defs && typeof defs[m[1]] === 'object' ? defs[m[1]] : null;
  return target ? { ...target, ...(typeof schema.description === 'string' && { description: schema.description }) } : schema;
}

/** `{ type, description, enum? }` for one JSON-schema property, as the doc shape prescribes. */
function compactProp(schema, defs) {
  const v = deref(schema && typeof schema === 'object' ? schema : {}, defs);
  let type = v.type;
  let enumValues = Array.isArray(v.enum) ? v.enum : undefined;
  if (type === undefined || enumValues === undefined) {
    const alts = v.anyOf ?? v.oneOf;
    if (Array.isArray(alts)) {
      const resolved = alts.map((s) => deref(s, defs));
      if (type === undefined) {
        const types = [...new Set(resolved.map((s) => s?.type).filter((t) => typeof t === 'string'))];
        if (types.length) type = types.length === 1 ? types[0] : types;
      }
      if (enumValues === undefined) {
        const consts = resolved.map((s) => (Array.isArray(s?.enum) ? s.enum : 'const' in (s ?? {}) ? [s.const] : null));
        if (consts.length && consts.every(Boolean)) enumValues = consts.flat();
      }
    }
  }
  const out = {};
  if (type !== undefined) out.type = type;
  if (typeof v.description === 'string') out.description = v.description;
  if (enumValues !== undefined) out.enum = enumValues;
  return out;
}

function toCatalogTool(t, inputSchema) {
  const schema = inputSchema && typeof inputSchema === 'object' ? inputSchema : {};
  return {
    name: t.name,
    title: t.title,
    kind: t.kind,
    description: t.description,
    annotations: t.annotations ?? {},
    effects: t.effects ?? {},
    ...(typeof t.returnsTargetContent === 'boolean' && { returnsTargetContent: t.returnsTargetContent }),
    required: Array.isArray(schema.required) ? [...schema.required] : [],
    props: Object.fromEntries(Object.entries(schema.properties ?? {}).map(([k, v]) => [k, compactProp(v, schema.$defs)])),
  };
}

async function loadTools(pkgDir) {
  const contracts = join(pkgDir, 'dist', 'contracts', 'toolContracts.js');
  const metadata = join(pkgDir, 'dist', 'contracts', 'toolSchemaMetadata.js');
  if (existsSync(contracts)) {
    const { TOOL_CONTRACTS } = await import(pathToFileURL(contracts).href);
    if (!Array.isArray(TOOL_CONTRACTS)) throw new Error(`${contracts} does not export TOOL_CONTRACTS[]`);
    let schemaOf = (t) => (t.inputSchema && typeof t.inputSchema === 'object' && t.inputSchema.type === 'object' ? t.inputSchema : {});
    if (existsSync(metadata)) {
      const { advertisedInputJsonSchema } = await import(pathToFileURL(metadata).href);
      if (typeof advertisedInputJsonSchema === 'function') schemaOf = (t) => advertisedInputJsonSchema(t);
    }
    return {
      generatedFrom: `${relative(pkgDir, contracts)} (TOOL_CONTRACTS) + ${relative(pkgDir, metadata)} (advertisedInputJsonSchema)`,
      tools: TOOL_CONTRACTS.map((t) => toCatalogTool(t, schemaOf(t))),
    };
  }
  const legacy = join(pkgDir, 'dist', 'generatedMcpToolCatalog.js');
  if (existsSync(legacy)) {
    const { GENERATED_MCP_TOOL_CATALOG } = await import(pathToFileURL(legacy).href);
    if (!Array.isArray(GENERATED_MCP_TOOL_CATALOG)) throw new Error(`${legacy} does not export GENERATED_MCP_TOOL_CATALOG[]`);
    return {
      generatedFrom: `${relative(pkgDir, legacy)} (GENERATED_MCP_TOOL_CATALOG)`,
      tools: GENERATED_MCP_TOOL_CATALOG.map((t) => toCatalogTool(t, t.inputSchema)),
    };
  }
  throw new Error(`no tool catalog module found under ${join(pkgDir, 'dist')}`);
}

async function main() {
  const { pkgDir, out } = parseArgs(process.argv.slice(2));
  const pkgJson = join(pkgDir, 'package.json');
  if (!existsSync(pkgJson)) { console.error(`${pkgDir}: no package.json`); process.exit(1); }
  const pkg = JSON.parse(readFileSync(pkgJson, 'utf8'));
  if (pkg.name !== 'rea-agents') { console.error(`${pkgDir}: package is ${JSON.stringify(pkg.name)}, expected rea-agents`); process.exit(1); }
  if (!/^\d+\.\d+\.\d+/.test(String(pkg.version))) { console.error(`${pkgDir}: version ${JSON.stringify(pkg.version)} is not semver`); process.exit(1); }

  const { generatedFrom, tools } = await loadTools(pkgDir);
  const names = new Set();
  for (const t of tools) {
    if (typeof t.name !== 'string' || !t.name) throw new Error('a tool contract has no name');
    if (names.has(t.name)) throw new Error(`duplicate tool name ${t.name}`);
    names.add(t.name);
  }
  const catalog = { source: 'rea-agents', version: pkg.version, generated_from: generatedFrom, tool_count: tools.length, tools };
  writeFileSync(out, `${JSON.stringify(catalog, null, 2)}\n`);
  console.log(`wrote ${relative(process.cwd(), out) || out}: rea-agents ${pkg.version}, ${tools.length} tools`);
}

main().catch((err) => {
  console.error(err?.stack ?? String(err));
  process.exit(1);
});
