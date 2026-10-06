#!/usr/bin/env node
/**
 * rea-jev CLI: System 2 asks System 1.
 *
 *   jev ask --state <file|-|json> --questions <json|file>
 *   jev rank "<query>" --items <file|-> [--top 15] [--id-field id --text-field text]
 *   jev classify --items <file|-> --labels a,b,c[,other] --instructions "<q>"
 *   jev verify (--claim "<text>" | --claim-file <file|->) --evidence <file|->
 *   jev doctor [--offline]
 *   jev stats [--days 7]
 *
 * `--json` for machine output. Exit 0 on answers (also partial answers when
 * some rank/classify chunks failed; see `partial`), 1 on usage error, 2 on
 * provider failure. Secrets are redacted before anything is sent; item files
 * larger than 2 MB are refused unless `--force`. Chunked commands send at
 * most `MAX_CONCURRENCY` requests at a time.
 *
 * @module jev-cli
 */

import { parseArgs } from 'node:util';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  askJev,
  resolveProvider,
  confidenceOf,
  band,
  noul,
  choice,
  estimateCost,
  estimateTokens,
  topChoices,
  REQUEST_TOKEN_BUDGET,
} from './lib/jev.mjs';
import { redact, redactObject, truncate } from './lib/redact.mjs';
import { mode } from './lib/hookio.mjs';
import { ledgerDir, decisionsPath, readDecisions, logDecision, ensureDir } from './lib/ledger.mjs';
import { reaPin, loadCatalog, CATALOG_PATH } from './lib/rea.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');

/** Exit codes. */
export const EXIT = Object.freeze({ OK: 0, USAGE: 1, PROVIDER: 2 });
/** `rank`: items per request. */
export const RANK_CHUNK = 200;
/** `classify`: items per request. */
export const CLASSIFY_BATCH = 40;
/** `verify`: evidence characters sent. */
export const VERIFY_MAX_CHARS = 20000;
/** Items files above this size need `--force`. */
export const ITEMS_MAX_BYTES = 2 * 1024 * 1024;
/**
 * `verify`: verdict thresholds on the four Nouls. The deciding Nouls sit at
 * 0.75 (confidence 0.5, the `confirm` band): a verdict is never categorical
 * on a near-coin-flip, and a deciding answer in the `escalate` band downgrades
 * the verdict to `insufficient`. `overstated` is a veto on `supported`.
 */
export const VERIFY_THRESHOLDS = Object.freeze({ contradicted: 0.75, supported: 0.75, needs_runtime: 0.75, overstated: 0.6 });
/** Chunked commands (`rank`, `classify`): requests in flight at once. */
export const MAX_CONCURRENCY = 4;
/** `classify`: label added when the set has no "none of these" option. */
export const OTHER_LABEL = 'other';
const OTHER_LIKE_RE = /^(?:other|others|none|none_of_these|neither|unknown|n\/a)$/i;

const ITEM_TEXT_MAX = 400;
const PREVIEW_MAX = 72;
const CLI_DEFAULT_TIMEOUT_MS = 20000;
const VERSION = readVersion();

const USAGE = `rea-jev ${VERSION} — ask Jev (TypeSafe System One) from the shell

Usage:
  jev ask --state <file|-|json> --questions <json|file>
  jev rank "<query>" --items <file|-> [--top 15] [--id-field id] [--text-field text]
  jev classify --items <file|-> --labels a,b,c[,other] --instructions "<question>"
  jev verify (--claim "<text>" | --claim-file <file|->) --evidence <file|->
  jev doctor [--offline]
  jev stats [--days 7]

Options:
  --json            machine-readable output
  --timeout <ms>    per-request budget (default REA_JEV_TIMEOUT_MS or ${CLI_DEFAULT_TIMEOUT_MS})
  --force           accept an items file larger than 2 MB
  -h, --help        this help
  -v, --version     print the version

Items may be a JSON array, JSON lines, or plain lines. Objects use --id-field /
--text-field (defaults: id, text; falls back to common REA field names).
Prefer --claim-file when the claim quotes strings from the analyzed program, so
nothing from a tool result is interpolated into a shell command line.
Exit codes: 0 answers (partial when some chunks failed; see "partial") · 1 usage error ·
2 provider failure (no key, timeout, HTTP error).
Keys: TYPESAFE_API_KEY (preferred) or OPENROUTER_API_KEY; JEV_BASE_URL to override the endpoint.
`;

const OPTIONS = {
  json: { type: 'boolean' },
  help: { type: 'boolean', short: 'h' },
  version: { type: 'boolean', short: 'v' },
  force: { type: 'boolean' },
  offline: { type: 'boolean' },
  timeout: { type: 'string' },
  state: { type: 'string' },
  questions: { type: 'string' },
  items: { type: 'string' },
  top: { type: 'string' },
  'id-field': { type: 'string' },
  'text-field': { type: 'string' },
  labels: { type: 'string' },
  instructions: { type: 'string' },
  claim: { type: 'string' },
  'claim-file': { type: 'string' },
  evidence: { type: 'string' },
  days: { type: 'string' },
};

class UsageError extends Error {}

class ProviderError extends Error {
  constructor(result) {
    super(describeFailure(result));
    this.result = result;
  }
}

/**
 * Run the CLI without touching process.exit. Returns what to print and the exit code.
 *
 * @param {string[]} [argv]
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {Promise<{code: number, stdout: string, stderr: string}>}
 */
export async function main(argv = process.argv.slice(2), env = process.env) {
  let parsed;
  try {
    parsed = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true, strict: true });
  } catch (err) {
    return { code: EXIT.USAGE, stdout: '', stderr: `rea-jev: ${err.message}\n\n${USAGE}` };
  }
  const { values: opts, positionals } = parsed;
  if (opts.version) return { code: EXIT.OK, stdout: `${VERSION}\n`, stderr: '' };
  const command = positionals[0];
  if (opts.help) return { code: EXIT.OK, stdout: USAGE, stderr: '' };
  if (!command) return { code: EXIT.USAGE, stdout: '', stderr: USAGE };

  const ctx = { opts, positionals: positionals.slice(1), env, json: Boolean(opts.json), timeoutMs: resolveCliTimeout(opts, env), command };
  try {
    let payload;
    switch (command) {
      case 'ask':
        payload = await cmdAsk(ctx);
        break;
      case 'rank':
        payload = await cmdRank(ctx);
        break;
      case 'classify':
        payload = await cmdClassify(ctx);
        break;
      case 'verify':
        payload = await cmdVerify(ctx);
        break;
      case 'doctor':
        payload = await cmdDoctor(ctx);
        break;
      case 'stats':
        payload = await cmdStats(ctx);
        break;
      default:
        throw new UsageError(`unknown command "${command}"`);
    }
    const code = payload.exit_code ?? EXIT.OK;
    const human = payload.human ?? '';
    const { human: _h, exit_code: _c, ...data } = payload;
    return { code, stdout: ctx.json ? `${JSON.stringify(data, null, 2)}\n` : human, stderr: '' };
  } catch (err) {
    if (err instanceof UsageError) {
      return { code: EXIT.USAGE, stdout: '', stderr: `rea-jev: ${err.message}\nRun \`jev --help\` for usage.\n` };
    }
    if (err instanceof ProviderError) {
      const data = { ok: false, command, ...failurePayload(err.result) };
      return {
        code: EXIT.PROVIDER,
        stdout: ctx.json ? `${JSON.stringify(data, null, 2)}\n` : '',
        stderr: `rea-jev: Jev request failed: ${err.message}\n`,
      };
    }
    return { code: EXIT.USAGE, stdout: '', stderr: `rea-jev: ${err?.message ?? String(err)}\n` };
  }
}

// ---------------------------------------------------------------- commands

async function cmdAsk(ctx) {
  const { opts } = ctx;
  if (opts.state == null) throw new UsageError('ask needs --state <file|-|json>');
  if (opts.questions == null) throw new UsageError('ask needs --questions <json|file>');
  const state = redactObject(readStateArg(opts.state));
  const questions = redactObject(readJsonArg(opts.questions, '--questions'));
  if (!isPlainObject(questions) || Object.keys(questions).length === 0) throw new UsageError('--questions must be a non-empty JSON object');

  const res = await askOrThrow(ctx, state, questions);
  const answers = decorateAnswers(res.answers);
  const payload = {
    ok: true,
    command: 'ask',
    provider: res.provider,
    model: res.model,
    latency_ms: res.latencyMs,
    usage: res.usage,
    cost_usd: round6(estimateCost(res.usage)),
    answers,
  };
  log(ctx, payload, { questions: Object.keys(questions).length });
  const lines = Object.entries(answers).map(([key, a]) => `${key.padEnd(24)} ${describeAnswer(a)}`);
  payload.human = `${lines.join('\n')}\n${footer(res, 1)}\n`;
  return payload;
}

async function cmdRank(ctx) {
  const { opts } = ctx;
  const query = ctx.positionals[0];
  if (!query || !String(query).trim()) throw new UsageError('rank needs a query: jev rank "<query>" --items <file|->');
  if (opts.items == null) throw new UsageError('rank needs --items <file|->');
  const top = parseIntOpt(opts.top, 15, '--top');
  const { items } = loadItems(opts.items, ctx);
  if (items.length === 0) throw new UsageError('no items found in --items');

  // Balanced chunks (sizes differ by at most one) keep `p_in_chunk` comparable
  // across chunks: a Choice spreads its mass over the chunk's own options, so
  // a small final chunk would otherwise inflate its items.
  const chunks = balancedChunks(items, RANK_CHUNK, 300 + estimateTokens(query), 2);
  const cleanQuery = redact(String(query));
  const requests = chunks.map((chunk) => {
    const criteria = Object.fromEntries(chunk.map((it) => [it.id, it.text]));
    if (chunk.length === 1) criteria.none_of_these = 'No listed item matches the query';
    return {
      state: { query: cleanQuery, items: Object.fromEntries(chunk.map((it) => [it.id, it.text])) },
      questions: {
        best: choice('Which option is the item in `items` that best matches `query`? Each option is an item id; its description is that item\'s text.', criteria),
        match_exists: noul('Does any item in `items` match `query`?', {
          true: 'At least one item is what `query` describes',
          false: 'No item matches; the candidates are unrelated or only superficially similar',
        }),
      },
    };
  });

  const started = Date.now();
  const { results, failed } = await askChunks(ctx, requests);
  const latency = Date.now() - started;

  const scored = [];
  let unranked = 0;
  let matchMax = 0;
  results.forEach((res, ci) => {
    if (!res) {
      unranked += chunks[ci].length;
      return;
    }
    const best = res.answers.best;
    const me = typeof res.answers.match_exists?.noul === 'number' ? res.answers.match_exists.noul : 1;
    matchMax = Math.max(matchMax, me);
    for (const it of chunks[ci]) {
      const p = Number(best?.probabilities?.[it.id]) || 0;
      scored.push({ id: it.id, text: it.text, chunk: ci, p_in_chunk: round6(p), match_exists: round6(me), p: round6(p * me) });
    }
  });
  scored.sort((a, b) => b.p - a.p || b.p_in_chunk - a.p_in_chunk || a.chunk - b.chunk);
  const ranked = scored.slice(0, top).map((s, i) => ({ rank: i + 1, ...s }));
  const okResults = results.filter(Boolean);
  const usage = sumUsage(okResults);

  const payload = {
    ok: true,
    command: 'rank',
    query: cleanQuery,
    items_total: items.length,
    chunks: chunks.length,
    requests: requests.length,
    match_exists: round6(matchMax),
    top,
    items: ranked,
    ...(failed.length && { partial: true, failed_chunks: failed.length, unranked_items: unranked, failures: failed.map((f) => failurePayload(f.result)) }),
    provider: okResults[0].provider,
    model: okResults[0].model,
    latency_ms: latency,
    usage,
    cost_usd: round6(estimateCost(usage)),
  };
  log(ctx, payload, { items: items.length });
  const rows = ranked.map((r) => `${String(r.rank).padStart(4)}  ${fmtP(r.p)}  ${r.id.slice(0, 24).padEnd(24)}  ${preview(r.text)}`);
  const partialNote = failed.length ? `\nPARTIAL: ${failed.length} of ${requests.length} request${requests.length === 1 ? '' : 's'} failed (${describeFailure(failed[0].result)}); ${unranked} item${unranked === 1 ? '' : 's'} unranked` : '';
  payload.human = `rank  p      ${'id'.padEnd(24)}  preview\n${rows.join('\n')}\nmatch_exists ${fmtP(matchMax)} (max over ${chunks.length} chunk${chunks.length === 1 ? '' : 's'}) · ${items.length} items in ${requests.length} request${requests.length === 1 ? '' : 's'} · ${footerParts(okResults[0], usage, latency)}${partialNote}\n`;
  return payload;
}

async function cmdClassify(ctx) {
  const { opts } = ctx;
  if (opts.items == null) throw new UsageError('classify needs --items <file|->');
  if (!opts.labels) throw new UsageError('classify needs --labels a,b,c[,other]');
  if (!opts.instructions || !String(opts.instructions).trim()) throw new UsageError('classify needs --instructions "<question>"');
  const labels = parseLabels(opts.labels);
  const { items } = loadItems(opts.items, ctx);
  if (items.length === 0) throw new UsageError('no items found in --items');

  // The judgment lives in the question, the content in the state: each Choice
  // carries the user's instructions and names the one item it is about. A
  // label set without a "none of these" option gets `other` so the model is
  // never forced to pick a wrong label.
  const instructions = redact(String(opts.instructions).trim());
  const addedOther = !Object.keys(labels).some((l) => OTHER_LIKE_RE.test(l));
  if (addedOther) labels[OTHER_LABEL] = 'None of the listed labels fits';
  const indexed = items.map((it, gi) => ({ ...it, key: `item_${gi}` }));
  const perQuestion = estimateTokens(instructions) + estimateTokens(labels) + 12;
  const batches = chunkItems(indexed, CLASSIFY_BATCH, 300, 1, perQuestion);
  const requests = batches.map((batch) => ({
    state: { items: Object.fromEntries(batch.map((it) => [it.key, it.text])) },
    questions: Object.fromEntries(batch.map((it) => [it.key, choice(`${instructions} Judge \`items.${it.key}\` only; which label fits best?`, labels)])),
  }));

  const started = Date.now();
  const { results, failed } = await askChunks(ctx, requests);
  const latency = Date.now() - started;

  const out = [];
  batches.forEach((batch, bi) => {
    for (const it of batch) {
      const a = results[bi]?.answers[it.key];
      const label = typeof a?.choice === 'string' ? a.choice : null;
      const p = label ? Number(a.probabilities?.[label]) || 0 : 0;
      const conf = confidenceOf(a);
      out.push({ id: it.id, text: it.text, label, p: round6(p), confidence: round6(conf), band: band(conf), probabilities: a?.probabilities ?? {} });
    }
  });
  const okResults = results.filter(Boolean);
  const usage = sumUsage(okResults);
  const counts = {};
  for (const o of out) counts[o.label ?? 'null'] = (counts[o.label ?? 'null'] ?? 0) + 1;

  const payload = {
    ok: true,
    command: 'classify',
    labels: Object.keys(labels),
    ...(addedOther && { added_label: OTHER_LABEL }),
    items_total: items.length,
    batches: batches.length,
    requests: requests.length,
    counts,
    items: out,
    ...(failed.length && { partial: true, failed_batches: failed.length, unlabeled_items: out.filter((o) => o.label === null).length, failures: failed.map((f) => failurePayload(f.result)) }),
    provider: okResults[0].provider,
    model: okResults[0].model,
    latency_ms: latency,
    usage,
    cost_usd: round6(estimateCost(usage)),
  };
  log(ctx, payload, { items: items.length });
  const rows = out.map((o) => `${o.id.slice(0, 20).padEnd(20)}  ${String(o.label).padEnd(14)}  ${fmtP(o.p)}  ${fmtP(o.confidence)}  ${o.band.padEnd(8)}  ${preview(o.text, 48)}`);
  const notes = [];
  if (addedOther) notes.push(`note: added label "${OTHER_LABEL}" (None of the listed labels fits) so the model can decline every listed label`);
  if (failed.length) notes.push(`PARTIAL: ${failed.length} of ${requests.length} request${requests.length === 1 ? '' : 's'} failed (${describeFailure(failed[0].result)}); unlabeled items have label null`);
  payload.human = `${'id'.padEnd(20)}  ${'label'.padEnd(14)}  p      conf   band      preview\n${rows.join('\n')}\n${Object.entries(counts).map(([k, v]) => `${k}: ${v}`).join(' · ')} · ${items.length} items in ${requests.length} request${requests.length === 1 ? '' : 's'} · ${footerParts(okResults[0], usage, latency)}${notes.length ? `\n${notes.join('\n')}` : ''}\n`;
  return payload;
}

async function cmdVerify(ctx) {
  const { opts } = ctx;
  const claimFile = opts['claim-file'];
  if (claimFile != null && opts.claim != null) throw new UsageError('verify takes --claim or --claim-file, not both');
  if (claimFile === '-' && opts.evidence === '-') throw new UsageError('only one of --claim-file and --evidence can read stdin');
  let rawClaim;
  if (claimFile != null) {
    rawClaim = readSource(claimFile);
    if (rawClaim == null) throw new UsageError(`claim file not found: ${claimFile}`);
  } else {
    rawClaim = opts.claim;
  }
  if (!rawClaim || !String(rawClaim).trim()) throw new UsageError('verify needs --claim "<text>" or --claim-file <file|->');
  if (opts.evidence == null) throw new UsageError('verify needs --evidence <file|->');
  const claim = redact(String(rawClaim).trim());
  const rawEvidence = readSource(opts.evidence) ?? String(opts.evidence);
  const redacted = redact(rawEvidence);
  const evidenceTruncated = redacted.length > VERIFY_MAX_CHARS;
  const evidence = evidenceTruncated ? truncate(redacted, VERIFY_MAX_CHARS, { head: Math.round(VERIFY_MAX_CHARS * 0.75) }) : redacted;

  const questions = {
    supported: noul('Does `evidence` directly support `claim`?', {
      true: 'The evidence states or shows what the claim asserts',
      false: 'The evidence does not establish the claim',
    }),
    contradicted: noul('Does `evidence` contradict `claim`?', {
      true: 'The evidence shows something incompatible with the claim',
      false: 'Nothing in the evidence conflicts with the claim',
    }),
    needs_runtime: noul('Can `claim` only be established by observing the program while it runs, rather than from the static facts in `evidence`?'),
    overstated: noul('Does `claim` assert more than `evidence` shows, such as certainty, completeness, causation, or scope the evidence does not establish?'),
  };
  const res = await askOrThrow(ctx, { claim, evidence }, questions);
  const answers = decorateAnswers(res.answers);
  const v = verdictOf(res.answers);
  const verdict = v.verdict;
  const payload = {
    ok: true,
    command: 'verify',
    verdict,
    verdict_confidence: round6(v.confidence),
    verdict_band: v.band,
    decided_by: v.decidedBy,
    ...(v.downgradedFrom && { downgraded_from: v.downgradedFrom }),
    claim,
    evidence_chars: evidence.length,
    evidence_truncated: evidenceTruncated,
    answers,
    thresholds: VERIFY_THRESHOLDS,
    provider: res.provider,
    model: res.model,
    latency_ms: res.latencyMs,
    usage: res.usage,
    cost_usd: round6(estimateCost(res.usage)),
  };
  log(ctx, payload, { verdict });
  const p = (k) => fmtP(res.answers[k]?.noul ?? 0);
  const headline = v.downgradedFrom
    ? `verdict: ${verdict} (${v.downgradedFrom} at p ${p(v.downgradedFrom)} has confidence ${fmtP(v.confidence)}, band ${v.band}; treat as unknown)`
    : `verdict: ${verdict} (decided by ${v.decidedBy} at p ${p(v.decidedBy)}, confidence ${fmtP(v.confidence)}, band ${v.band})`;
  payload.human = `${headline}\n  supported ${p('supported')} · contradicted ${p('contradicted')} · needs_runtime ${p('needs_runtime')} · overstated ${p('overstated')}\n  ${verdictRationale(verdict, v.band)}${evidenceTruncated ? `\n  note: evidence truncated to ${VERIFY_MAX_CHARS} chars` : ''}\n${footer(res, 1)}\n`;
  return payload;
}

async function cmdDoctor(ctx) {
  const { env, opts } = ctx;
  const problems = [];
  const prov = resolveProvider(env);
  const catalog = loadCatalog();
  const pin = reaPin();
  const report = {
    ok: false,
    command: 'doctor',
    version: VERSION,
    mode: mode(env),
    provider: prov ? { id: prov.id, model: prov.model, url: prov.url, key_source: keySource(env), endpoint_override: Boolean(env.JEV_BASE_URL) } : null,
    round_trip: null,
    rea: { pin, catalog_path: CATALOG_PATH, catalog_tools: catalog.toolCount, npx: null, global_cli: null },
    ledger: ledgerStatus(env),
    hooks: hooksStatus(env),
    problems,
  };

  if (!prov) {
    report.round_trip = { ok: false, reason: 'no_key' };
    problems.push('no Jev API key: set TYPESAFE_API_KEY (preferred) or OPENROUTER_API_KEY, or the plugin option typesafe_api_key');
  } else {
    const res = await askJev({ state: { probe: 'pong' }, questions: { probe: noul('Is `probe` exactly the word "pong"?') }, timeoutMs: ctx.timeoutMs, env });
    report.round_trip = res.ok
      ? { ok: true, latency_ms: res.latencyMs, model: res.model, attempts: res.attempts, probe: round6(res.answers.probe?.noul ?? -1) }
      : { ok: false, ...failurePayload(res) };
    if (!res.ok) problems.push(`Jev round trip failed: ${describeFailure(res)}`);
  }

  if (!pin) problems.push('data/rea-tool-catalog.json is missing or unreadable; run `npm run catalog`');
  if (opts.offline) {
    report.rea.npx = { status: 'skipped', reason: '--offline' };
  } else if (pin) {
    report.rea.npx = probeCommand('npx', ['-y', `rea-agents@${pin}`, '--version'], 45_000);
    if (report.rea.npx.status !== 'ok') problems.push(`npx -y rea-agents@${pin} --version did not resolve (${report.rea.npx.detail ?? report.rea.npx.status})`);
  }
  report.rea.global_cli = probeCommand('rea', ['--version'], 10_000);
  if (!report.ledger.writable) problems.push(`ledger dir ${report.ledger.dir} is not writable`);
  if (!report.hooks.hooks_json) problems.push('hooks/hooks.json not found next to scripts/; hooks will not register');

  report.ok = Boolean(report.round_trip?.ok) && problems.length === 0;
  const exitCode = report.round_trip?.ok ? EXIT.OK : EXIT.PROVIDER;
  logDecision({ hook: 'cli', command: 'doctor', ok: report.ok, provider: prov?.id ?? null, latency_ms: report.round_trip?.latency_ms ?? null }, env);

  const mark = (ok) => (ok ? 'ok ' : '!! ');
  const lines = [
    `rea-jev ${VERSION} doctor`,
    `  ${mark(true)}mode            ${report.mode}`,
    `  ${mark(Boolean(prov))}provider        ${prov ? `${prov.id} · model ${prov.model} · key from ${report.provider.key_source} · ${prov.url}` : 'none (no key)'}`,
    `  ${mark(Boolean(report.round_trip?.ok))}round trip      ${report.round_trip?.ok ? `${report.round_trip.latency_ms} ms · model ${report.round_trip.model}` : describeFailure(report.round_trip)}`,
    `  ${mark(Boolean(pin))}REA pin         ${pin ?? 'unknown'} · ${catalog.toolCount} tools in ${path.relative(ROOT, CATALOG_PATH)}`,
    `  ${mark(report.rea.npx?.status !== 'failed')}npx rea-agents  ${describeProbe(report.rea.npx)}`,
    `  ${mark(true)}global rea      ${describeProbe(report.rea.global_cli)}`,
    `  ${mark(report.ledger.writable)}ledger          ${report.ledger.dir} (${report.ledger.exists ? 'exists' : 'will be created'}, ${report.ledger.writable ? 'writable' : 'NOT writable'})`,
    `  ${mark(report.hooks.hooks_json)}hooks           ${report.hooks.hooks_json ? `hooks/hooks.json registers ${report.hooks.events.join(', ')}` : 'hooks/hooks.json missing'}${report.hooks.plugin_root ? ` · CLAUDE_PLUGIN_ROOT=${report.hooks.plugin_root}` : ' · CLAUDE_PLUGIN_ROOT unset (run inside Claude Code, or `claude plugin list`, to confirm registration)'}`,
  ];
  if (problems.length) lines.push('problems:', ...problems.map((p) => `  - ${p}`));
  report.human = `${lines.join('\n')}\n`;
  report.exit_code = exitCode;
  return report;
}

async function cmdStats(ctx) {
  const { env, opts } = ctx;
  const days = parseIntOpt(opts.days, 7, '--days');
  const file = decisionsPath(env);
  const records = readDecisions({ days, env });
  const byHook = countBy(records, (r) => r.hook ?? r.kind ?? 'unknown');
  const byDecision = countBy(records.filter((r) => r.decision != null), (r) => r.decision);
  const latencies = records.map((r) => Number(r.latency_ms)).filter((n) => Number.isFinite(n) && n >= 0).sort((a, b) => a - b);
  const inputTokens = records.reduce((sum, r) => sum + (Number(r.usage?.input_tokens) || 0), 0);
  const bands = { act: 0, confirm: 0, escalate: 0 };
  for (const r of records) {
    if (isPlainObject(r.bands)) {
      for (const b of Object.values(r.bands)) if (b in bands) bands[b] += 1;
    } else if (isPlainObject(r.confidences)) {
      for (const c of Object.values(r.confidences)) bands[band(Number(c))] += 1;
    } else if (typeof r.band === 'string' && r.band in bands) {
      bands[r.band] += 1;
    }
  }
  const payload = {
    ok: true,
    command: 'stats',
    file,
    days,
    total: records.length,
    jev_calls: records.filter((r) => Number.isFinite(Number(r.latency_ms))).length,
    by_hook: byHook,
    by_decision: byDecision,
    latency_ms: latencies.length ? { p50: pct(latencies, 0.5), p90: pct(latencies, 0.9), p99: pct(latencies, 0.99), max: latencies[latencies.length - 1] } : null,
    input_tokens: inputTokens,
    cost_usd: round6(estimateCost({ input_tokens: inputTokens })),
    bands,
  };
  if (records.length === 0) {
    payload.human = `no decisions in the last ${days} day${days === 1 ? '' : 's'} at ${file}\n(set REA_JEV_LOG=1 to record every hook and CLI decision)\n`;
    return payload;
  }
  const lines = [
    `rea-jev stats · last ${days} day${days === 1 ? '' : 's'} · ${records.length} decisions · ${file}`,
    `  by hook      ${fmtCounts(byHook)}`,
    `  by decision  ${fmtCounts(byDecision) || '-'}`,
    `  latency ms   ${payload.latency_ms ? `p50 ${payload.latency_ms.p50} · p90 ${payload.latency_ms.p90} · p99 ${payload.latency_ms.p99} · max ${payload.latency_ms.max}` : '-'}`,
    `  tokens       ${inputTokens.toLocaleString('en-US')} input · est. $${payload.cost_usd.toFixed(6)}`,
    `  bands        act ${bands.act} · confirm ${bands.confirm} · escalate ${bands.escalate}`,
  ];
  payload.human = `${lines.join('\n')}\n`;
  return payload;
}

// ---------------------------------------------------------------- helpers: Jev

async function askOrThrow(ctx, state, questions) {
  const res = await askJev({ state, questions, timeoutMs: ctx.timeoutMs, env: ctx.env });
  if (!res.ok) throw new ProviderError(res);
  return res;
}

/**
 * Send chunked requests, at most `MAX_CONCURRENCY` in flight. A chunk that
 * fails (after the client's own retry) yields `null` in `results` and an
 * entry in `failed`; the command degrades to a partial answer. When every
 * chunk failed the first failure is thrown as a ProviderError (exit 2).
 *
 * @param {object} ctx
 * @param {Array<{state: unknown, questions: object}>} requests
 * @returns {Promise<{results: Array<object|null>, failed: Array<{index: number, result: object}>}>}
 */
async function askChunks(ctx, requests) {
  const results = new Array(requests.length).fill(null);
  const failed = [];
  await mapLimit(requests, MAX_CONCURRENCY, async (r, i) => {
    const res = await askJev({ state: r.state, questions: r.questions, timeoutMs: ctx.timeoutMs, env: ctx.env });
    if (res.ok) results[i] = res;
    else failed.push({ index: i, result: res });
  });
  failed.sort((a, b) => a.index - b.index);
  if (failed.length === requests.length) throw new ProviderError(failed[0].result);
  return { results, failed };
}

async function mapLimit(list, limit, fn) {
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, list.length) }, async () => {
    for (;;) {
      const i = next;
      next += 1;
      if (i >= list.length) return;
      await fn(list[i], i);
    }
  });
  await Promise.all(workers);
}

function decorateAnswers(answers) {
  const out = {};
  for (const [key, a] of Object.entries(answers ?? {})) {
    const conf = confidenceOf(a);
    out[key] = { ...a, confidence: round6(conf), band: band(conf) };
  }
  return out;
}

function describeAnswer(a) {
  const tail = `conf=${fmtP(a.confidence)} band=${a.band}`;
  if (a.type === 'noul') return `noul   p=${fmtP(a.noul)}  ${tail}`;
  if (a.type === 'choice') {
    const alts = topChoices(a, 3)
      .slice(1)
      .map((c) => `${c.option} ${fmtP(c.p)}`)
      .join(', ');
    return `choice ${a.choice} (${fmtP(a.probabilities?.[a.choice] ?? 0)})  ${tail}${alts ? `  [${alts}]` : ''}`;
  }
  if (a.type === 'score') {
    const level = Math.round(Number(a.score));
    const legend = a.legend?.[String(level)];
    return `score  ${Number(a.score).toFixed(2)}${legend ? ` "${truncate(legend, 48)}"` : ''}  ${tail}`;
  }
  return `${a.type ?? '?'}  ${tail}`;
}

/**
 * Map the four Nouls to a verdict. The deciding Noul's confidence and band are
 * returned with it; a deciding answer in the `escalate` band downgrades the
 * verdict to `insufficient` (`downgradedFrom` names what it would have been).
 *
 * @param {Record<string, any>} answers
 * @returns {{verdict: string, decidedBy: string, confidence: number, band: string, downgradedFrom?: string}}
 */
export function verdictOf(answers) {
  const p = (k) => (typeof answers[k]?.noul === 'number' ? answers[k].noul : 0);
  const t = VERIFY_THRESHOLDS;
  let verdict = 'insufficient';
  let decidedBy = 'supported';
  if (p('contradicted') >= t.contradicted) [verdict, decidedBy] = ['contradicted', 'contradicted'];
  else if (p('needs_runtime') >= t.needs_runtime && p('supported') < t.supported) [verdict, decidedBy] = ['needs_runtime', 'needs_runtime'];
  else if (p('supported') >= t.supported && p('overstated') < t.overstated) [verdict, decidedBy] = ['supported', 'supported'];
  const confidence = confidenceOf(answers[decidedBy]);
  const b = band(confidence);
  if (verdict !== 'insufficient' && b === 'escalate') return { verdict: 'insufficient', decidedBy, confidence, band: b, downgradedFrom: verdict };
  return { verdict, decidedBy, confidence, band: b };
}

function verdictRationale(v, b) {
  switch (v) {
    case 'contradicted':
      return 'the evidence conflicts with the claim; revise or drop it.';
    case 'needs_runtime':
      return 'static evidence cannot establish this; phrase it as an inference or capture runtime evidence.';
    case 'supported':
      return b === 'act'
        ? 'the evidence establishes the claim as stated; write it as an inference and cite the Evidence IDs behind it.'
        : 'the evidence supports the claim but only in the confirm band; write it as a hypothesis and name the probe that would settle it.';
    default:
      return 'the evidence does not establish the claim (or the claim overstates it); narrow the claim or gather more evidence.';
  }
}

function failurePayload(res) {
  if (!res) return { reason: 'unknown' };
  const out = { reason: res.reason, latency_ms: res.latencyMs, provider: res.provider ?? null, attempts: res.attempts ?? 0 };
  if (res.status != null) out.status = res.status;
  if (res.detail) out.detail = res.detail;
  return out;
}

function describeFailure(res) {
  if (!res) return 'unknown';
  const parts = [res.reason];
  if (res.status != null) parts.push(`HTTP ${res.status}`);
  if (res.detail) parts.push(res.detail);
  if (res.reason === 'no_key') parts.push('set TYPESAFE_API_KEY or OPENROUTER_API_KEY');
  if (res.reason === 'timeout') parts.push(`after ${res.latencyMs} ms`);
  return parts.join(' · ');
}

function footer(res, requests) {
  return footerParts(res, res.usage, res.latencyMs, requests);
}

function footerParts(res, usage, latency, requests = 1) {
  const cost = estimateCost(usage);
  return `${res.provider} ${res.model} · ${latency} ms · ${Number(usage.input_tokens).toLocaleString('en-US')} input tokens · $${cost.toFixed(6)}${requests > 1 ? ` · ${requests} requests` : ''}`;
}

function sumUsage(results) {
  const usage = { input_tokens: 0, output_tokens: 0 };
  let cost = 0;
  let hasCost = false;
  for (const r of results) {
    usage.input_tokens += Number(r.usage?.input_tokens) || 0;
    usage.output_tokens += Number(r.usage?.output_tokens) || 0;
    if (typeof r.usage?.cost === 'number') {
      hasCost = true;
      cost += r.usage.cost;
    }
  }
  if (hasCost) usage.cost = cost;
  return usage;
}

function log(ctx, payload, extra = {}) {
  logDecision(
    {
      hook: 'cli',
      command: payload.command,
      provider: payload.provider ?? null,
      model: payload.model ?? null,
      latency_ms: payload.latency_ms ?? null,
      usage: payload.usage ?? null,
      requests: payload.requests ?? 1,
      ...extra,
    },
    ctx.env,
  );
}

// ---------------------------------------------------------------- helpers: items

function loadItems(spec, ctx) {
  const { opts } = ctx;
  let text;
  let source;
  if (spec === '-') {
    text = readStdin();
    source = 'stdin';
    if (Buffer.byteLength(text, 'utf8') > ITEMS_MAX_BYTES && !opts.force) {
      throw new UsageError(`items on stdin exceed 2 MB (${Buffer.byteLength(text, 'utf8')} bytes); pass --force to send anyway`);
    }
  } else {
    const st = statSafe(spec);
    if (!st || !st.isFile()) throw new UsageError(`items file not found: ${spec}`);
    if (st.size > ITEMS_MAX_BYTES && !opts.force) throw new UsageError(`items file is ${st.size} bytes (> 2 MB); pass --force to send anyway`);
    text = fs.readFileSync(spec, 'utf8');
    source = spec;
  }
  const raw = parseItems(text);
  const items = normalizeItems(raw, opts['id-field'] ?? 'id', opts['text-field'] ?? 'text');
  return { items, source };
}

/**
 * Parse items text: a JSON array, an object holding an array (first array
 * found, depth ≤ 3; covers REA `{result:{...}}` envelopes), JSON lines, or
 * plain lines.
 *
 * @param {string} text
 * @returns {unknown[]}
 */
export function parseItems(text) {
  const trimmed = String(text ?? '').trim();
  if (!trimmed) return [];
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
    try {
      const whole = JSON.parse(trimmed);
      if (Array.isArray(whole)) return whole;
      const arr = firstArrayIn(whole, 0);
      if (arr) return arr;
    } catch {
      /* fall through to line formats */
    }
  }
  const lines = trimmed.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const parsed = [];
  for (const line of lines) {
    if (!/^[{["]/.test(line)) return lines;
    try {
      parsed.push(JSON.parse(line));
    } catch {
      return lines;
    }
  }
  return parsed;
}

function firstArrayIn(value, depth) {
  if (depth > 3 || !isPlainObject(value)) return null;
  for (const v of Object.values(value)) if (Array.isArray(v) && v.length) return v;
  for (const v of Object.values(value)) {
    const found = firstArrayIn(v, depth + 1);
    if (found) return found;
  }
  return null;
}

const ID_FALLBACKS = ['id', 'evidence_id', 'address', 'name', 'key', 'path', 'symbol'];
const TEXT_FALLBACKS = ['text', 'value', 'string', 'name', 'description', 'summary', 'title', 'label'];

/**
 * Normalise raw items to `{id, text}` with unique ids and redacted,
 * length-capped text.
 *
 * @param {unknown[]} raw
 * @param {string} idField
 * @param {string} textField
 * @returns {Array<{id: string, text: string}>}
 */
export function normalizeItems(raw, idField = 'id', textField = 'text') {
  const seen = new Map();
  const out = [];
  raw.forEach((item, i) => {
    if (item == null) return;
    let id;
    let text;
    if (typeof item !== 'object') {
      id = String(i + 1);
      text = String(item);
    } else {
      const idv = firstDefined(item, [idField, ...ID_FALLBACKS]);
      const tv = firstDefined(item, [textField, ...TEXT_FALLBACKS]);
      id = idv != null ? String(idv) : String(i + 1);
      text = tv == null ? safeJson(item) : typeof tv === 'string' ? tv : safeJson(tv);
    }
    id = id.trim() || String(i + 1);
    const n = seen.get(id) ?? 0;
    seen.set(id, n + 1);
    if (n > 0) id = `${id}#${n + 1}`;
    out.push({ id, text: truncate(redact(text), ITEM_TEXT_MAX) });
  });
  return out;
}

/**
 * Split items into chunks of (nearly) equal size, each within `maxCount` and
 * the request token budget. Starts from the greedy chunk count and adds
 * chunks until every one fits. Exported for tests.
 *
 * @param {Array<{id: string, text: string}>} items
 * @param {number} maxCount
 * @param {number} overheadTokens
 * @param {number} textFactor
 * @param {number} [perItemTokens]
 * @returns {Array<Array<{id: string, text: string}>>}
 */
export function balancedChunks(items, maxCount, overheadTokens, textFactor, perItemTokens = 4) {
  const tokensOf = (chunk) => overheadTokens + chunk.reduce((sum, it) => sum + estimateTokens(it.id + it.text) * textFactor + perItemTokens, 0);
  const greedy = chunkItems(items, maxCount, overheadTokens, textFactor, perItemTokens);
  for (let k = greedy.length; k <= items.length; k += 1) {
    const base = Math.floor(items.length / k);
    const extra = items.length % k;
    const chunks = [];
    for (let i = 0, pos = 0; i < k; i += 1) {
      const size = base + (i < extra ? 1 : 0);
      chunks.push(items.slice(pos, pos + size));
      pos += size;
    }
    if (chunks.every((c) => c.length <= maxCount && tokensOf(c) <= REQUEST_TOKEN_BUDGET)) return chunks;
  }
  return greedy;
}

function chunkItems(items, maxCount, overheadTokens, textFactor, perItemTokens = 4) {
  const chunks = [];
  let cur = [];
  let tokens = overheadTokens;
  for (const it of items) {
    const t = estimateTokens(it.id + it.text) * textFactor + perItemTokens;
    if (cur.length && (cur.length >= maxCount || tokens + t > REQUEST_TOKEN_BUDGET)) {
      chunks.push(cur);
      cur = [];
      tokens = overheadTokens;
    }
    cur.push(it);
    tokens += t;
  }
  if (cur.length) chunks.push(cur);
  return chunks;
}

function parseLabels(spec) {
  const labels = {};
  for (const part of String(spec).split(',')) {
    const s = part.trim();
    if (!s) continue;
    const eq = s.indexOf('=');
    if (eq > 0) labels[s.slice(0, eq).trim()] = s.slice(eq + 1).trim() || null;
    else labels[s] = null;
  }
  if (Object.keys(labels).length < 2) throw new UsageError('--labels needs at least two comma-separated labels');
  return labels;
}

// ---------------------------------------------------------------- helpers: input

function readStateArg(spec) {
  const src = readSource(spec);
  const text = src ?? String(spec);
  const trimmed = text.trim();
  if (/^[[{"]/.test(trimmed) || /^(?:true|false|null|-?\d)/.test(trimmed)) {
    try {
      return JSON.parse(trimmed);
    } catch {
      /* plain string */
    }
  }
  return text;
}

function readJsonArg(spec, label) {
  const src = readSource(spec);
  const text = src ?? String(spec);
  try {
    return JSON.parse(text);
  } catch {
    throw new UsageError(`${label} must be JSON or a path to a JSON file`);
  }
}

function readSource(spec) {
  if (spec === '-') return readStdin();
  const st = statSafe(spec);
  if (st && st.isFile()) return fs.readFileSync(spec, 'utf8');
  return null;
}

function readStdin() {
  try {
    return fs.readFileSync(0, 'utf8');
  } catch {
    return '';
  }
}

function statSafe(p) {
  try {
    if (typeof p !== 'string' || !p || p.length > 4096) return null;
    return fs.statSync(p, { throwIfNoEntry: false }) ?? null;
  } catch {
    return null;
  }
}

function parseIntOpt(raw, fallback, label) {
  if (raw == null) return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n <= 0) throw new UsageError(`${label} must be a positive integer`);
  return n;
}

function resolveCliTimeout(opts, env) {
  const fromFlag = Number.parseInt(opts.timeout ?? '', 10);
  if (Number.isFinite(fromFlag) && fromFlag > 0) return fromFlag;
  const fromEnv = Number.parseInt(env.REA_JEV_TIMEOUT_MS ?? '', 10);
  if (Number.isFinite(fromEnv) && fromEnv > 0) return fromEnv;
  return CLI_DEFAULT_TIMEOUT_MS;
}

// ---------------------------------------------------------------- helpers: doctor

function keySource(env) {
  if (env.CLAUDE_PLUGIN_OPTION_TYPESAFE_API_KEY) return 'plugin option typesafe_api_key';
  if (env.TYPESAFE_API_KEY) return 'TYPESAFE_API_KEY';
  if (env.OPENROUTER_API_KEY) return 'OPENROUTER_API_KEY';
  return 'none';
}

function ledgerStatus(env) {
  const dir = ledgerDir(env);
  let exists = false;
  let writable = false;
  try {
    exists = fs.statSync(dir, { throwIfNoEntry: false })?.isDirectory() ?? false;
    ensureDir(dir);
    fs.accessSync(dir, fs.constants.W_OK);
    writable = true;
  } catch {
    writable = false;
  }
  return { dir, exists, writable, decisions_log: env.REA_JEV_LOG === '1' };
}

function hooksStatus(env) {
  const file = path.join(ROOT, 'hooks', 'hooks.json');
  let events = [];
  let present = false;
  try {
    const json = JSON.parse(fs.readFileSync(file, 'utf8'));
    present = true;
    events = Object.keys(json.hooks ?? {});
  } catch {
    present = false;
  }
  return { hooks_json: present, events, plugin_root: env.CLAUDE_PLUGIN_ROOT ?? null };
}

function probeCommand(cmd, args, timeout) {
  try {
    const r = spawnSync(cmd, args, { encoding: 'utf8', timeout, stdio: ['ignore', 'pipe', 'pipe'] });
    if (r.error) return { status: r.error.code === 'ENOENT' ? 'missing' : 'failed', detail: r.error.code ?? r.error.message, command: [cmd, ...args].join(' ') };
    if (r.status !== 0) return { status: 'failed', detail: `exit ${r.status}: ${(r.stderr || r.stdout || '').trim().slice(0, 200)}`, command: [cmd, ...args].join(' ') };
    return { status: 'ok', version: (r.stdout || '').trim().split('\n').pop().slice(0, 80), command: [cmd, ...args].join(' ') };
  } catch (err) {
    return { status: 'failed', detail: err?.message ?? String(err), command: [cmd, ...args].join(' ') };
  }
}

function describeProbe(p) {
  if (!p) return 'not checked';
  if (p.status === 'ok') return `${p.version} (${p.command})`;
  if (p.status === 'skipped') return `skipped (${p.reason})`;
  if (p.status === 'missing') return `not installed (${p.command})`;
  return `failed: ${p.detail} (${p.command})`;
}

// ---------------------------------------------------------------- helpers: misc

function countBy(list, fn) {
  const out = {};
  for (const x of list) {
    const k = String(fn(x));
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

function fmtCounts(obj) {
  return Object.entries(obj)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => `${k} ${v}`)
    .join(' · ');
}

function pct(sorted, q) {
  if (!sorted.length) return null;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil(q * sorted.length) - 1));
  return sorted[idx];
}

function preview(text, max = PREVIEW_MAX) {
  const s = String(text ?? '').replace(/\s+/g, ' ').trim();
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function fmtP(x) {
  return Number(x ?? 0).toFixed(3);
}

function round6(x) {
  return Math.round((Number(x) || 0) * 1e6) / 1e6;
}

function firstDefined(obj, keys) {
  for (const k of keys) if (obj[k] != null) return obj[k];
  return undefined;
}

function isPlainObject(v) {
  return v != null && typeof v === 'object' && !Array.isArray(v);
}

function safeJson(v) {
  try {
    return JSON.stringify(v) ?? String(v);
  } catch {
    return String(v);
  }
}

function readVersion() {
  try {
    return String(JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version ?? '0.0.0');
  } catch {
    return '0.0.0';
  }
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  main().then(
    ({ code, stdout, stderr }) => {
      if (stderr) process.stderr.write(stderr);
      process.exitCode = code;
      process.stdout.write(stdout ?? '', () => process.exit(code));
    },
    (err) => {
      process.stderr.write(`rea-jev: ${err?.message ?? err}\n`);
      process.exit(EXIT.USAGE);
    },
  );
}
