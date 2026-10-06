#!/usr/bin/env node
/**
 * PreToolUse hook on REA tools (DESIGN.md §5.2): deterministic rules first,
 * then a Jev scope/risk gate for the few calls that can run or move things.
 *
 * Order of evaluation; the first rule that fires decides:
 *   1. not an REA tool / mode off            → silent
 *   2. redundancy (local): identical inspect call already answered → deny
 *   3. hard rules (local): a non-loopback CDP/inspector endpoint on any REA
 *      tool → deny; for runtime-class tools an out-of-scope executable or a
 *      credential in the scenario environment → ask
 *   4. Jev gate, only for runtime-class tools and for extract/export/import
 *      with paths outside cwd: within_scope / irreversible / runtime_requested.
 *      A `deny` (enforce) needs the deciding answer at or above the `confirm`
 *      band and a declared target; otherwise the decision degrades to `ask`.
 *   5. everything else → silent (normal permission flow)
 *
 * Decisions go to stdout as `hookSpecificOutput.permissionDecision`; the hook
 * always exits 0. Shadow mode logs the would-be decision and stays silent.
 * A `pre` ledger event is appended for every REA call (except in mode off),
 * also when the safety timer pre-empts a Jev call.
 *
 * @module hook-gate
 */

import fs from 'node:fs';
import path from 'node:path';
import { readStdinJson, emitAndExit, exitSilently, mode, threshold, debug } from './lib/hookio.mjs';
import { askJev, noul, resolveTimeoutMs, isDecisive } from './lib/jev.mjs';
import { excerpt, hasSecret } from './lib/redact.mjs';
import { readEvents, summarize, appendEvent, logDecision } from './lib/ledger.mjs';
import { isReaTool, bareToolName, effectClass, hashInput, canonicalJson } from './lib/rea.mjs';
import { isLoopback } from './lib/sniff.mjs';

/** Hard ceiling for the whole hook, under the 10 s hooks.json timeout. */
const SAFETY_MS = 9000;
/** Jev gets at most this much of the budget, so it always returns before the safety timer. */
const JEV_MAX_MS = SAFETY_MS - 3500;
/** `user_request` characters sent to Jev. */
const USER_REQUEST_MAX = 600;
/** Tools whose file-moving inputs trigger the Jev gate when they leave cwd. */
const PATH_GATED_TOOLS = new Set(['extract_artifact', 'export_evidence_bundle', 'import_evidence_bundle']);
const ENDPOINT_KEYS = new Set(['cdp_endpoint', 'inspector_endpoint']);
const PATH_KEY_RE = /(^|_)(path|paths|dir|directory|destination|output|root|file|files|target)$/i;

/**
 * The three gate questions, exactly as DESIGN.md §5.2 specifies.
 *
 * @returns {Record<string, object>}
 */
function gateQuestions() {
  return {
    within_scope: noul(
      'Does `tool_input` act on the same artifact, or a component of the same application, that `user_request` and `declared_target` ask to investigate?',
    ),
    irreversible: noul(
      'Could executing `tool_input` change, delete, or transmit data outside a temporary analysis directory, or affect anything other than the inspected program?',
    ),
    runtime_requested: noul('Does `user_request` ask for, or clearly require, running or interacting with the program rather than static inspection?'),
  };
}

async function main() {
  /** Set once the pre event can be written; flushed by the safety timer if Jev never returns. */
  let pending = null;
  const safety = setTimeout(() => {
    if (pending) appendEvent(pending.sessionId, { ...pending.event, decision: 'silent', source: 'jev', reason: 'timeout' });
    exitSilently(0);
  }, SAFETY_MS);
  safety.unref?.();

  const input = await readStdinJson();
  if (!input) return exitSilently(0);
  const toolName = input.tool_name;
  if (!isReaTool(toolName)) return exitSilently(0);
  const m = mode();
  if (m === 'off') return exitSilently(0);

  const tool = bareToolName(toolName);
  const toolInput = input.tool_input && typeof input.tool_input === 'object' ? input.tool_input : {};
  const effect = effectClass(tool);
  const hash = hashInput(tool, toolInput);
  const sessionId = String(input.session_id ?? 'unknown');
  const cwd = typeof input.cwd === 'string' && input.cwd ? input.cwd : process.cwd();
  const summary = summarize(readEvents(sessionId));
  const inputExcerpt = excerpt(canonicalJson(toolInput), 200);

  /** Record the pre event, log, and emit (unless shadow). Never returns. */
  const finish = (decision, source, reason, extra = {}) => {
    pending = null;
    appendEvent(sessionId, { kind: 'pre', tool, input_hash: hash, input_excerpt: inputExcerpt, decision, source, ...(extra.answers && { answers: extra.answers }) });
    logDecision({
      hook: 'pre',
      session_id: sessionId,
      tool,
      decision: m === 'shadow' && decision !== 'silent' ? `shadow_${decision}` : decision,
      source,
      reason: reason ? excerpt(reason, 200) : undefined,
      latency_ms: extra.latencyMs,
      usage: extra.usage,
      confidences: extra.confidences,
    });
    debug(`gate: ${tool} → ${decision} (${source})${reason ? `: ${reason}` : ''}`);
    if (decision === 'silent' || m === 'shadow') return exitSilently(0);
    return emitAndExit({
      hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: decision, permissionDecisionReason: reason },
    });
  };

  // 2. Redundancy: identical inspect call already answered in this session.
  if (effect === 'inspect') {
    const prior = summary.findIdenticalCall(tool, hash);
    if (prior) {
      const ids = Array.isArray(prior.evidence_ids) ? prior.evidence_ids.filter((x) => typeof x === 'string') : [];
      const what = ids.length
        ? `Evidence ${ids.slice(0, 3).join(', ')}${ids.length > 3 ? ` (+${ids.length - 3} more)` : ''}`
        : `a result (${Number(prior.bytes) || 0} bytes, no Evidence ID)`;
      return finish('deny', 'local', `rea-jev: identical \`${tool}\` call already returned ${what}; reuse that result instead of repeating the call.`);
    }
  }

  // 3. Hard rules (local, free).
  const remote = findRemoteEndpoint(toolInput);
  if (remote) {
    return finish('deny', 'local', `rea-jev: REA only supports loopback endpoints; a remote endpoint would observe another machine (${remote.key} = ${excerpt(remote.value, 80)}).`);
  }
  if (effect === 'runtime') {
    if (tool === 'capture_process_scenario') {
      const exe = typeof toolInput.executable === 'string' ? toolInput.executable.trim() : '';
      const base = typeof toolInput.working_directory === 'string' && toolInput.working_directory ? resolveFrom(cwd, toolInput.working_directory) : cwd;
      if (exe && !isBareCommand(exe)) {
        const abs = resolveFrom(base, exe);
        if (!isInside(abs, cwd) && !isInside(abs, declaredTargetDir(summary.declaredTarget))) {
          return finish('ask', 'local', `rea-jev: capture_process_scenario would run ${abs}, which is outside the working directory${summary.declaredTarget ? ' and the declared target' : ''}; confirm this is the program under investigation.`);
        }
      }
    }
    const secretKey = findSecretInEnvironment(toolInput.environment);
    if (secretKey) {
      return finish('ask', 'local', `rea-jev: scenario environment appears to contain a credential (${secretKey}); REA records environment; confirm or remove it.`);
    }
  }

  // 4. Jev gate.
  const outsidePaths = PATH_GATED_TOOLS.has(tool) ? collectPaths(toolInput).filter((p) => !isInside(resolveFrom(cwd, p), cwd)) : [];
  const needsJev = effect === 'runtime' || outsidePaths.length > 0;
  if (!needsJev) return finish('silent', 'local');

  // The request comes from the last reverse-engineering route (never a follow-up
  // such as "format that as a table"); every field is redacted before it leaves.
  const userRequest = excerpt(summary.userRequest, USER_REQUEST_MAX);
  const state = {
    user_request: userRequest,
    declared_target: summary.declaredTarget ? excerpt(summary.declaredTarget, 300) : null,
    tool,
    tool_input: excerpt(canonicalJson(toolInput), 1500),
  };
  pending = { sessionId, event: { kind: 'pre', tool, input_hash: hash, input_excerpt: inputExcerpt } };
  const result = await askJev({ state, questions: gateQuestions(), timeoutMs: Math.min(resolveTimeoutMs(), JEV_MAX_MS) });
  if (!result.ok) {
    debug(`gate: jev ${result.reason}; silent`);
    return finish('silent', 'jev', result.reason, { latencyMs: result.latencyMs });
  }
  const a = result.answers;
  const pScope = num(a.within_scope?.noul);
  const pIrrev = num(a.irreversible?.noul);
  const pRuntime = num(a.runtime_requested?.noul);
  const confidences = { within_scope: conf(pScope), irreversible: conf(pIrrev), runtime_requested: conf(pRuntime) };
  const extra = { answers: a, latencyMs: result.latencyMs, usage: result.usage, confidences };
  const tScope = threshold('GATE_SCOPE', 0.3);
  const tIrrev = threshold('GATE_IRREV', 0.8);
  const tRuntime = threshold('GATE_RUNTIME', 0.3);
  const hasRequest = userRequest.length > 0;

  if (hasRequest && pScope !== null && pScope < tScope) {
    // A hard deny needs a decisive answer (confidence ≥ confirm band); a
    // near-coin-flip within_scope only asks, even in enforce.
    // Without a declared target, scope cannot be established: the decision is the human's (ask).
    const hasTarget = Boolean(summary.declaredTarget);
    const decision = m === 'enforce' && hasTarget && isDecisive(a.within_scope) ? 'deny' : 'ask';
    const why = decision === 'deny'
      ? 'keep runtime and extraction inside the artifact under investigation'
      : hasTarget
        ? 'confirm it belongs to the investigation'
        : 'no artifact has been declared for this investigation yet, so confirm it belongs to the investigation';
    return finish(decision, 'jev', `rea-jev: \`${tool}\` does not appear to act on the declared target (within_scope ${pScope.toFixed(2)}); ${why}.`, extra);
  }
  if (pIrrev !== null && pIrrev > tIrrev) {
    return finish('ask', 'jev', `rea-jev: \`${tool}\` may change, delete, or transmit data beyond a temporary analysis directory (irreversible ${pIrrev.toFixed(2)}); confirm before running it.`, extra);
  }
  if (hasRequest && tool.startsWith('capture_') && pRuntime !== null && pRuntime < tRuntime) {
    return finish('ask', 'jev', `rea-jev: the user did not ask for runtime execution (runtime_requested ${pRuntime.toFixed(2)}); confirm before launching.`, extra);
  }
  return finish('silent', 'jev', undefined, extra);
}

/** Non-loopback `cdp_endpoint` / `inspector_endpoint` anywhere in the input (depth ≤ 3), or null. */
function findRemoteEndpoint(value, depth = 0) {
  if (depth > 3 || value == null || typeof value !== 'object') return null;
  if (Array.isArray(value)) {
    for (const v of value) {
      const hit = findRemoteEndpoint(v, depth + 1);
      if (hit) return hit;
    }
    return null;
  }
  for (const [k, v] of Object.entries(value)) {
    if (ENDPOINT_KEYS.has(k) && typeof v === 'string' && v.trim() && !isLoopback(v)) return { key: k, value: v };
    const hit = findRemoteEndpoint(v, depth + 1);
    if (hit) return hit;
  }
  return null;
}

/** Name of the first environment entry that looks like a credential, or null. */
function findSecretInEnvironment(environment) {
  if (environment == null) return null;
  if (Array.isArray(environment)) {
    for (const item of environment) {
      if (typeof item === 'string' && hasSecret(item)) return item.split('=')[0].slice(0, 60);
      if (item && typeof item === 'object') {
        const hit = findSecretInEnvironment(item);
        if (hit) return hit;
      }
    }
    return null;
  }
  if (typeof environment === 'object') {
    for (const [k, v] of Object.entries(environment)) {
      const value = typeof v === 'string' ? v : safeJson(v);
      if (hasSecret(value) || hasSecret(`${k}=${value}`)) return k.slice(0, 60);
    }
  }
  return null;
}

/** String values that look like filesystem paths or sit under a path-like key (depth ≤ 3). */
function collectPaths(value, out = [], key = '', depth = 0) {
  if (depth > 3 || value == null) return out;
  if (typeof value === 'string') {
    const s = value.trim();
    if (s && (PATH_KEY_RE.test(key) || /^(?:\/|~\/|~$|\.{1,2}\/|[A-Za-z]:[\\/])/.test(s))) out.push(s);
    return out;
  }
  if (Array.isArray(value)) {
    for (const v of value) collectPaths(v, out, key, depth + 1);
    return out;
  }
  if (typeof value === 'object') for (const [k, v] of Object.entries(value)) collectPaths(v, out, k, depth + 1);
  return out;
}

function isBareCommand(exe) {
  return !/[\\/]/.test(exe) && !exe.startsWith('~');
}

function resolveFrom(base, p) {
  let s = String(p ?? '');
  if (s === '~' || s.startsWith('~/')) s = path.join(homeDir(), s.slice(1));
  try {
    return path.isAbsolute(s) ? path.normalize(s) : path.resolve(base, s);
  } catch {
    return s;
  }
}

function homeDir() {
  return process.env.HOME || process.env.USERPROFILE || '/';
}

/** The directory a declared target lives in: the target itself when it is a directory, else its parent. Null for URLs/none. */
function declaredTargetDir(target) {
  if (typeof target !== 'string' || !target || /^[a-z][a-z0-9+.-]*:\/\//i.test(target)) return null;
  try {
    const st = fs.statSync(target, { throwIfNoEntry: false });
    if (st?.isDirectory()) return target;
  } catch {
    /* fall through */
  }
  return path.dirname(target);
}

function isInside(abs, dir) {
  if (!dir || !abs) return false;
  const rel = path.relative(path.resolve(dir), path.resolve(abs));
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

function num(v) {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

function conf(p) {
  return p === null ? 0 : Math.abs(2 * p - 1);
}

function safeJson(v) {
  try {
    return JSON.stringify(v) ?? '';
  } catch {
    return String(v);
  }
}

main().catch((err) => {
  debug(`gate hook failed open: ${err?.name ?? 'Error'}`);
  exitSilently(0);
});
