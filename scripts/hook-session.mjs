#!/usr/bin/env node
/**
 * SessionStart hook (DESIGN.md §5.5): one status line, no Jev call.
 *
 *   rea-jev 0.1.0 · mode advise · Jev key: present (typesafe) · REA pinned 4.0.1 · /rea-jev:setup for diagnostics
 *
 * Reads stdin only to honour the hook contract; the output does not depend on
 * it. Fails open: any error → exit 0 with empty stdout. Never prints the key.
 *
 * @module hook-session
 */

import { readFileSync } from 'node:fs';
import { readStdinJson, emitAndExit, exitSilently, mode, debug } from './lib/hookio.mjs';
import { resolveProvider } from './lib/jev.mjs';
import { reaPin } from './lib/rea.mjs';

const SAFETY_MS = 4000;

/**
 * Plugin version from package.json next to scripts/, or '0.0.0'.
 *
 * @returns {string}
 */
function pluginVersion() {
  try {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    return typeof pkg.version === 'string' && pkg.version ? pkg.version : '0.0.0';
  } catch {
    return '0.0.0';
  }
}

/**
 * Build the status line for an environment.
 *
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {string}
 */
function statusLine(env = process.env) {
  const provider = resolveProvider(env);
  const key = provider ? `present (${provider.id})` : 'missing (set TYPESAFE_API_KEY or OPENROUTER_API_KEY)';
  const pin = reaPin() ?? 'unknown';
  return `rea-jev ${pluginVersion()} · mode ${mode(env)} · Jev key: ${key} · REA pinned ${pin} · /rea-jev:setup for diagnostics`;
}

async function main() {
  const safety = setTimeout(() => exitSilently(0), SAFETY_MS);
  safety.unref?.();
  await readStdinJson({ timeoutMs: 1500 });
  const line = statusLine();
  debug(`session: ${line}`);
  emitAndExit({ hookSpecificOutput: { hookEventName: 'SessionStart', additionalContext: line } });
}

main().catch((err) => {
  debug(`session hook failed open: ${err?.name ?? 'Error'}`);
  exitSilently(0);
});
