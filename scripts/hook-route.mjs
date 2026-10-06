#!/usr/bin/env node
/**
 * UserPromptSubmit hook (DESIGN.md §5.1): route the target before Claude thinks.
 *
 * 1. Deterministic pre-filter (free): the prompt hits the RE keyword regex, a
 *    path token exists on disk, a URL/CDP/inspector endpoint is present, or the
 *    ledger already shows REA activity in this session. Otherwise: silent.
 * 2. One Jev call with six questions (is_re_task, target_kind, workflow, scope,
 *    needs_runtime, wants_build).
 * 3. Policy: not an RE task → silent; ambiguous target → ask the user which
 *    artifact; otherwise inject a compact route block (≤ 12 lines).
 * 4. Ledger: a `route` event with `declared_target`.
 *
 * Fails open: any error, timeout, or Jev failure → exit 0, empty stdout.
 *
 * @module hook-route
 */

import { readStdinJson, emitAndExit, exitSilently, mode, threshold, debug } from './lib/hookio.mjs';
import { askJev, confidenceOf, topChoices, noul, choice, score, resolveTimeoutMs } from './lib/jev.mjs';
import { excerpt } from './lib/redact.mjs';
import { readEvents, summarize, appendEvent, logDecision } from './lib/ledger.mjs';
import { describeFirstTool } from './lib/rea.mjs';
import { sniffPrompt } from './lib/sniff.mjs';

/** Hard ceiling for the whole hook, under the 10 s hooks.json timeout. */
const SAFETY_MS = 9000;
/** Jev gets at most this much of the budget, so it always returns before the safety timer. */
const JEV_MAX_MS = SAFETY_MS - 3500;
/** Prompt characters sent to Jev. */
const PROMPT_MAX = 3000;
/** Redacted prompt kept in the route event for the gate, evidence and stop hooks (`prompt_for_jev`). */
const PROMPT_FOR_JEV_MAX = 1200;
/** Lines of `hint:` included in the route block. */
const MAX_HINT_LINES = 3;

/** Short labels for the `scope` levels, used in the route block. */
const SCOPE_SHORT = Object.freeze([
  'one function, string, symbol, or file',
  'one feature in one subsystem',
  'several features or one cross-layer trace',
  'several apps/versions or a whole-app map',
]);

/**
 * The six route questions, exactly as DESIGN.md §5.1 specifies.
 *
 * @returns {Record<string, object>}
 */
function routeQuestions() {
  return {
    is_re_task: noul(
      'Does `prompt` ask to understand, inspect, decompile, trace, compare, or recreate the behavior of software from a shipped artifact, a running application, or a website rather than from source code the user already has?',
      {
        true: 'Names an app, binary, package, bundle, page, or runtime to inspect, or asks how a feature works without source',
        false: 'Ordinary coding, repository, or conversational request',
      },
    ),
    target_kind: choice('Which kind of artifact should be inspected first, using `prompt`, `sniff_hints`, and `active_target` (the artifact already under investigation in this session, or null)?', {
      native_binary: 'Mach-O/ELF/PE executable or library, macOS .app bundle, Hopper .hop database',
      javascript_application: 'Electron app, .asar archive, extracted or minified JavaScript bundle, source maps',
      managed_assembly: '.NET PE/CLI .dll or .exe',
      android_apk: 'Android .apk package',
      package_archive: '.zip, .ipa, .dmg, .msix, .appx or other container that must be inventoried before choosing a deeper tool',
      website_in_browser: 'A web page or site, or a Chrome DevTools endpoint',
      electron_or_node_runtime: 'A running Electron or Node process exposing an inspector endpoint',
      source_repository: 'Ordinary source code the user already has; REA is not needed',
      unknown_or_missing: 'No concrete artifact is named or it cannot be told apart from the text',
    }),
    workflow: choice('Which investigation outcome does `prompt` ask for?', {
      investigate_feature: 'Explain how one feature or behavior works',
      compare_versions: 'Find what changed between two builds or versions',
      verify_reconstruction: 'Check a rebuilt or ported implementation against the original',
      trace_crash_or_bug: 'Find the code path behind a crash, error, or suspicious behavior',
      audit_unknowns: 'Review and resolve open questions from an earlier investigation',
      capture_runtime_behavior: 'Observe or record the program while it runs',
      build_from_findings: "Recreate the feature in the user's own project",
      overview: 'Map or summarize an app without a specific feature in mind',
      other: 'None of these',
    }),
    scope: score('How broad is the investigation `prompt` asks for?', [
      'One function, string, symbol, or file',
      'One feature inside one subsystem of one app',
      'Several features, or one feature traced across layers of one app',
      'Several apps or versions, or a map of an entire application',
    ]),
    needs_runtime: noul(
      'Can `prompt` only be answered by observing the program while it runs, such as network traffic, UI timing, or live state, rather than by static inspection?',
    ),
    wants_build: noul("Does `prompt` ask to build, port, or recreate the feature in the user's own project after it is understood?"),
  };
}

/**
 * True when the deterministic pre-filter says the prompt deserves a Jev call.
 *
 * @param {import('./lib/sniff.mjs').Sniff} sniff
 * @param {{hasReaActivity: boolean}} summary
 * @returns {boolean}
 */
function prefilterHolds(sniff, summary) {
  return Boolean(
    sniff.keywordHit ||
      sniff.pathTokens.some((t) => t.exists) ||
      sniff.urls.length ||
      sniff.cdpEndpoints.length ||
      sniff.inspectorEndpoints.length ||
      summary.hasReaActivity,
  );
}

/**
 * Apply the §5.1 policy to a set of answers.
 *
 * @param {Record<string, any>} answers
 * @param {{sniff: import('./lib/sniff.mjs').Sniff, model: string, latencyMs: number, env?: NodeJS.ProcessEnv}} ctx
 * @returns {{decision: 'silent'|'ambiguous'|'route', text: string|null, confidences: Record<string, number>}}
 */
function decideRoute(answers, ctx) {
  const env = ctx.env ?? process.env;
  const tRe = threshold('ROUTE_RE', 0.35, env);
  const tMin = threshold('ROUTE_MIN', 0.5, env);
  const a = answers ?? {};
  const pRe = num(a.is_re_task?.noul, 0);
  const target = a.target_kind ?? {};
  const targetConf = confidenceOf(target);
  const confidences = {
    is_re_task: confidenceOf(a.is_re_task),
    target_kind: targetConf,
    workflow: confidenceOf(a.workflow),
    scope: confidenceOf(a.scope),
    needs_runtime: confidenceOf(a.needs_runtime),
    wants_build: confidenceOf(a.wants_build),
  };

  if (pRe < tRe) return { decision: 'silent', text: null, confidences };
  if (target.choice === 'source_repository' && targetConf >= 0.6) return { decision: 'silent', text: null, confidences };

  const header = `[rea-jev System 1 route · ${ctx.model} · ${Math.round(ctx.latencyMs)} ms]`;
  const wf = a.workflow ?? {};
  const wfP = probabilityOf(wf, wf.choice);
  const scopeLevel = modeLevel(a.scope);
  // One quantity drives both the printed scope and the fan-out rule: the
  // expected level (`score`), shown with the modal level's label.
  const scopeValue = typeof a.scope?.score === 'number' ? a.scope.score : scopeLevel;
  const needsRuntime = num(a.needs_runtime?.noul, 0);
  const wantsBuild = num(a.wants_build?.noul, 0);
  const workflowLine =
    `workflow: ${wf.choice ?? 'unknown'} (${fmt(wfP)}) · scope: ${scopeValue.toFixed(1)} "${SCOPE_SHORT[scopeLevel] ?? 'unknown'}"` +
    ` · runtime needed: ${fmt(needsRuntime)} · build after: ${fmt(wantsBuild)}`;
  const footer = 'Use the reverse-engineer skill. Keep observations, inferences, and unknowns separate; cite Evidence IDs.';

  if (targetConf < tMin || target.choice === 'unknown_or_missing' || !target.choice) {
    const top = topChoices(target, 2)
      .map((t) => `${t.option} ${fmt(t.p)}`)
      .join(', ');
    const lines = [
      header,
      `target: ambiguous (top: ${top || 'none'}) — ask the user which artifact to inspect before opening anything.`,
      workflowLine,
      ...ctx.sniff.hints.slice(0, MAX_HINT_LINES).map((h) => `hint: ${h}`),
      footer,
    ];
    return { decision: 'ambiguous', text: lines.join('\n'), confidences };
  }

  const lines = [
    header,
    `target: ${target.choice} (${fmt(probabilityOf(target, target.choice))}) → first tool: ${describeFirstTool(target.choice)}`,
    workflowLine,
    ...ctx.sniff.hints.slice(0, MAX_HINT_LINES).map((h) => `hint: ${h}`),
  ];
  if (scopeValue >= 2.5) lines.push('Consider fanning out `rea-investigator` subagents, one per independent question.');
  if (needsRuntime >= 0.7) {
    lines.push('Static evidence will not suffice; plan a declared capture (`capture_process_scenario` / browser / Electron) and keep it inside the declared target.');
  }
  lines.push(footer);
  return { decision: 'route', text: lines.slice(0, 12).join('\n'), confidences };
}

async function main() {
  const safety = setTimeout(() => exitSilently(0), SAFETY_MS);
  safety.unref?.();

  const input = await readStdinJson();
  if (!input) return exitSilently(0);
  const m = mode();
  if (m === 'off') return exitSilently(0);

  const prompt = typeof input.prompt === 'string' ? input.prompt : '';
  if (!prompt.trim()) return exitSilently(0);
  const cwd = typeof input.cwd === 'string' && input.cwd ? input.cwd : process.cwd();
  const sessionId = String(input.session_id ?? 'unknown');

  const sniff = sniffPrompt(prompt, cwd);
  const summary = summarize(readEvents(sessionId));
  if (!prefilterHolds(sniff, summary)) {
    debug('route: pre-filter did not hold; silent');
    return exitSilently(0);
  }

  // Every field is redacted: the prompt through excerpt(), hints and the
  // active target by the sniffer (URL credentials and query strings stripped).
  const state = {
    prompt: excerpt(prompt, PROMPT_MAX),
    sniff_hints: sniff.hints.slice(0, 8).map((h) => excerpt(h, 300)),
    active_target: summary.declaredTarget ? excerpt(summary.declaredTarget, 300) : null,
  };
  const result = await askJev({ state, questions: routeQuestions(), timeoutMs: Math.min(resolveTimeoutMs(), JEV_MAX_MS) });

  // Carry the previous declared target through non-RE prompts; adopt a new one for RE prompts
  // and when Jev could not say (the sniffed target is deterministic and the gate needs it).
  const isRe = !result.ok || num(result.answers.is_re_task?.noul, 0) >= threshold('ROUTE_RE', 0.35);
  const declaredTarget = isRe ? sniff.declaredTarget ?? summary.declaredTarget : summary.declaredTarget;

  if (!result.ok) {
    debug(`route: jev ${result.reason}; silent`);
    appendEvent(sessionId, {
      kind: 'route',
      prompt_excerpt: excerpt(prompt, 200),
      prompt_for_jev: excerpt(prompt, PROMPT_FOR_JEV_MAX),
      answers: null,
      target_hint: sniff.hints[0] ?? null,
      declared_target: declaredTarget,
      jev_failure: result.reason,
    });
    logDecision({ hook: 'route', session_id: sessionId, decision: 'silent', source: 'jev', reason: result.reason, latency_ms: result.latencyMs });
    return exitSilently(0);
  }

  const verdict = decideRoute(result.answers, { sniff, model: result.model, latencyMs: result.latencyMs });
  appendEvent(sessionId, {
    kind: 'route',
    prompt_excerpt: excerpt(prompt, 200),
    prompt_for_jev: excerpt(prompt, PROMPT_FOR_JEV_MAX),
    answers: result.answers,
    target_hint: result.answers.target_kind?.choice ?? null,
    declared_target: declaredTarget,
    decision: verdict.decision,
  });
  logDecision({
    hook: 'route',
    session_id: sessionId,
    decision: m === 'shadow' ? `shadow_${verdict.decision}` : verdict.decision,
    source: 'jev',
    latency_ms: result.latencyMs,
    usage: result.usage,
    confidences: verdict.confidences,
  });
  debug(`route: ${verdict.decision} in ${result.latencyMs} ms`);

  if (m === 'shadow' || verdict.decision === 'silent' || !verdict.text) return exitSilently(0);
  return emitAndExit({ hookSpecificOutput: { hookEventName: 'UserPromptSubmit', additionalContext: verdict.text } });
}

function num(v, fallback) {
  return typeof v === 'number' && Number.isFinite(v) ? v : fallback;
}

function fmt(p) {
  return num(p, 0).toFixed(2);
}

function probabilityOf(answer, option) {
  const p = answer?.probabilities?.[option];
  return num(p, 0);
}

function modeLevel(answer) {
  const probs = answer?.probabilities;
  if (probs && typeof probs === 'object') {
    let best = 0;
    let bestP = -1;
    for (const [k, v] of Object.entries(probs)) {
      const i = Number(k);
      const p = num(v, 0);
      if (Number.isInteger(i) && p > bestP) {
        best = i;
        bestP = p;
      }
    }
    if (bestP >= 0) return best;
  }
  const s = num(answer?.score, 0);
  return Math.max(0, Math.min(SCOPE_SHORT.length - 1, Math.round(s)));
}

main().catch((err) => {
  debug(`route hook failed open: ${err?.name ?? 'Error'}`);
  exitSilently(0);
});
