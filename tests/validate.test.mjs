/**
 * Runs scripts/validate.mjs as a child process (DESIGN.md §9, "validate").
 * Every check is enforced: manifests, hooks, pin, matcher, skill frontmatter,
 * tool names in the skill and agents, and the generated tool catalog.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const VALIDATE = join(ROOT, 'scripts', 'validate.mjs');

function runValidate(args = []) {
  return spawnSync(process.execPath, [VALIDATE, ...args], { cwd: ROOT, encoding: 'utf8' });
}

test('validate.mjs exits 0 and prints ok for this repository', () => {
  const r = runValidate();
  assert.equal(r.status, 0, `validate.mjs exited ${r.status}\nstdout:\n${r.stdout}\nstderr:\n${r.stderr}`);
  assert.match(r.stdout.trim(), /(^|\n)ok$/);
});

test('validate.mjs lists failures and exits 1 on a broken tree', () => {
  const dir = mkdtempSync(join(tmpdir(), 'rea-jev-validate-'));
  mkdirSync(join(dir, '.claude-plugin'));
  writeFileSync(join(dir, '.claude-plugin', 'plugin.json'), '{ not json');
  writeFileSync(join(dir, '.mcp.json'), JSON.stringify({ mcpServers: { rea: { command: 'npx', args: ['-y', 'rea-agents@latest', 'mcp'] } } }));
  const r = runValidate(['--root', dir]);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /FAIL: \.claude-plugin\/plugin\.json: invalid JSON/);
  assert.match(r.stdout, /FAIL: \.mcp\.json: rea-agents pin must be an exact version/);
  assert.match(r.stdout, /FAIL: hooks\/hooks\.json: missing/);
  assert.match(r.stdout, /FAIL: skills\/reverse-engineer\/SKILL\.md: missing/);
  assert.match(r.stdout, /\d+ failure\(s\)/);
  assert.doesNotMatch(r.stdout, /(^|\n)ok$/);
});

test('generated tool catalog has one table per catalog kind and the documented columns', async () => {
  const { generateToolCatalogMarkdown, effectClass } = await import(VALIDATE);
  const catalog = JSON.parse(readFileSync(join(ROOT, 'data', 'rea-tool-catalog.json'), 'utf8'));
  const md = generateToolCatalogMarkdown(catalog);
  const kinds = new Set(catalog.tools.map((t) => t.kind));
  assert.equal((md.match(/^\| Tool \| Description \| Required inputs \| Effect \|$/gm) || []).length, kinds.size);
  for (const t of catalog.tools) assert.ok(md.includes(`| \`${t.name}\` |`), `${t.name} missing from catalog markdown`);
  assert.equal(effectClass({ name: 'open_binary', effects: {} }), 'mutation');
  assert.equal(effectClass({ name: 'binary_session', effects: {} }), 'status');
  assert.equal(effectClass({ name: 'capture_process_scenario', effects: { launchesProcess: true } }), 'runtime');
  assert.equal(effectClass({ name: 'search_strings', effects: {} }), 'inspect');
  for (const line of md.split('\n')) {
    const m = /^\| `[^`]+` \| (.*?) \| .*? \| (?:inspect|mutation|status|runtime) \|$/.exec(line);
    if (m) assert.ok(m[1].replace(/\\\|/g, '|').length <= 140, `description cell over 140 chars: ${m[1]}`);
  }
});
