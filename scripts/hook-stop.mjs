#!/usr/bin/env node
/**
 * Stop hook (DESIGN.md §5.4): check the closing message against the ledger
 * before the turn ends, and in enforce mode block an unverified "done".
 *
 * 1. `stop_hook_active` or mode off → exit 0.
 * 2. No REA activity this session → exit 0 (free).
 * 3. Caps: at most 1 block per stop, 2 per session, none within 60 s of the
 *    previous block → otherwise exit 0.
 * 4. Final message from `last_assistant_message`, else the last assistant text
 *    in `transcript_path` (JSONL). Unreadable → exit 0.
 * 5. Local facts from the ledger; one Jev call with five questions.
 * 6. enforce → `{"decision":"block","reason"}`; advise/shadow → `systemMessage`.
 *
 * Fails open: any error, timeout, or Jev failure → exit 0, empty stdout.
 *
 * @module hook-stop
 */

import fs from 'node:fs';
import { readStdinJson, emitAndExit, exitSilently, mode, threshold, debug } from './lib/hookio.mjs';
import { askJev, confidenceOf, noul, choice, resolveTimeoutMs } from './lib/jev.mjs';
import { excerpt } from './lib/redact.mjs';
import { readEvents, summarize, appendEvent, logDecision } from './lib/ledger.mjs';
import { EVIDENCE_ID_RE } from './lib/rea.mjs';

/** Hard ceiling for the whole hook, under the 25 s hooks.json timeout. */
const SAFETY_MS = 24000;
const MAX_BLOCKS_PER_SESSION = 2;
const BLOCK_COOLDOWN_MS = 60_000;
const USER_REQUEST_MAX = 1200;
const FINAL_MESSAGE_MAX = 4000;
/** Bytes read from the tail of a transcript. */
const TRANSCRIPT_TAIL_BYTES = 4 * 1024 * 1024;

/**
 * The five completeness questions, exactly as DESIGN.md §5.4 specifies.
 *
 * @returns {Record<string, object>}
 */
function stopQuestions() {
  return {
    claims_complete: noul("Does `final_message` present the investigation as finished or the user's question as answered?"),
    separates_epistemics: noul('Does `final_message` distinguish what was directly observed from what was inferred and from what remains unknown?'),
    cites_evidence: noul('Does `final_message` tie its main conclusions to specific Evidence IDs, addresses, file paths, function names, or named tool results?'),
    unaddressed_question: noul('Does `user_request` contain a question or deliverable that `final_message` neither answers nor explicitly marks as unresolved?'),
    outcome: choice('What does `final_message` report as the state of the work?', {
      complete: 'Finished with conclusions',
      partial_with_open_questions: 'Some conclusions, with explicitly listed open questions',
      blocked: 'Stopped because of a missing tool, permission, artifact, or user decision',
      not_an_investigation: 'The message is about something else',
    }),
  };
}

async function main() {
  const safety = setTimeout(() => exitSilently(0), SAFETY_MS);
  safety.unref?.();

  const input = await readStdinJson();
  if (!input) return exitSilently(0);
  if (input.stop_hook_active === true) return exitSilently(0);
  const m = mode();
  if (m === 'off') return exitSilently(0);

  const sessionId = String(input.session_id ?? 'unknown');
  const summary = summarize(readEvents(sessionId));
  if (!summary.hasReaActivity) {
    debug('stop: no REA activity; exit');
    return exitSilently(0);
  }
  if (summary.stopBlocksThisSession >= MAX_BLOCKS_PER_SESSION) {
    debug('stop: session block cap reached; exit');
    return exitSilently(0);
  }
  if (summary.lastStopBlockAt !== null && Date.now() - summary.lastStopBlockAt < BLOCK_COOLDOWN_MS) {
    debug('stop: within cooldown of the previous block; exit');
    return exitSilently(0);
  }

  const finalMessage = resolveFinalMessage(input);
  if (!finalMessage) {
    debug('stop: no final message available; exit');
    return exitSilently(0);
  }

  const seen = new Set(summary.evidenceIds);
  const cited = new Set((finalMessage.match(EVIDENCE_ID_RE) ?? []).filter((id) => seen.size === 0 || seen.has(id)));
  const facts = {
    open_session_not_closed: summary.openBinaryWithoutClose,
    evidence_ids_seen: seen.size,
    evidence_ids_cited: cited.size,
    limitations_flagged: summary.limitationsFlagged.length,
    unknowns_recorded: summary.unknownsRecorded,
    tool_calls: summary.toolCalls,
  };
  const state = {
    user_request: excerpt(summary.lastRoute?.prompt_excerpt ?? '', USER_REQUEST_MAX),
    final_message: excerpt(finalMessage, FINAL_MESSAGE_MAX),
    facts,
  };
  const result = await askJev({ state, questions: stopQuestions(), timeoutMs: resolveTimeoutMs() });
  if (!result.ok) {
    debug(`stop: jev ${result.reason}; exit`);
    logDecision({ hook: 'stop', session_id: sessionId, decision: 'allow', source: 'jev', reason: result.reason, latency_ms: result.latencyMs });
    return exitSilently(0);
  }

  const verdict = decideStop(result.answers, facts);
  const decision = !verdict.block ? 'allow' : m === 'enforce' ? 'block' : 'shadow_block';
  appendEvent(sessionId, { kind: 'stop', decision, answers: result.answers, reason: verdict.reason ? excerpt(verdict.reason, 400) : null, facts });
  logDecision({
    hook: 'stop',
    session_id: sessionId,
    decision,
    source: 'jev',
    latency_ms: result.latencyMs,
    usage: result.usage,
    confidences: verdict.confidences,
    reason: verdict.reason ? excerpt(verdict.reason, 200) : undefined,
  });
  debug(`stop: ${decision} in ${result.latencyMs} ms`);

  if (!verdict.block) return exitSilently(0);
  if (m === 'enforce') return emitAndExit({ decision: 'block', reason: verdict.reason });
  return emitAndExit({ systemMessage: `rea-jev would have asked for: ${verdict.reason}` });
}

/**
 * Apply the §5.4 policy.
 *
 * @param {Record<string, any>} answers
 * @param {{open_session_not_closed: boolean, evidence_ids_seen: number}} facts
 * @returns {{block: boolean, reason: string|null, confidences: Record<string, number>}}
 */
function decideStop(answers, facts) {
  const a = answers ?? {};
  const pDone = num(a.claims_complete?.noul);
  const pEpist = num(a.separates_epistemics?.noul);
  const pCites = num(a.cites_evidence?.noul);
  const pUnaddressed = num(a.unaddressed_question?.noul);
  const outcome = a.outcome?.choice ?? null;
  const confidences = {
    claims_complete: confidenceOf(a.claims_complete),
    separates_epistemics: confidenceOf(a.separates_epistemics),
    cites_evidence: confidenceOf(a.cites_evidence),
    unaddressed_question: confidenceOf(a.unaddressed_question),
    outcome: confidenceOf(a.outcome),
  };
  const tDone = threshold('STOP_DONE', 0.7);
  const tEpist = threshold('STOP_EPISTEMICS', 0.3);
  const tCites = threshold('STOP_CITES', 0.3);
  const tUnaddressed = threshold('STOP_UNADDRESSED', 0.7);

  if (outcome === 'blocked' || outcome === 'not_an_investigation') return { block: false, reason: null, confidences };
  if (pDone === null || pDone < tDone) return { block: false, reason: null, confidences };

  const problems = [];
  const asks = [];
  if (pCites !== null && pCites <= tCites && facts.evidence_ids_seen > 0) {
    problems.push(`conclusions do not cite Evidence IDs although ${facts.evidence_ids_seen} ${facts.evidence_ids_seen === 1 ? 'was' : 'were'} returned`);
    asks.push('Cite the Evidence IDs behind each conclusion');
  }
  if (pEpist !== null && pEpist <= tEpist) {
    problems.push('observations, inferences, and unknowns are not told apart');
    asks.push('state what is inferred vs observed vs unknown');
  }
  if (pUnaddressed !== null && pUnaddressed >= tUnaddressed) {
    problems.push('part of the request is neither answered nor marked unresolved');
    asks.push('answer each part of the request or mark it as an open question');
  }
  if (facts.open_session_not_closed) {
    problems.push('the native session is still open');
    asks.push('call close_binary');
  }
  if (problems.length === 0) return { block: false, reason: null, confidences };

  const reason =
    `rea-jev: the investigation reports completion (${pDone.toFixed(2)}) but: ${problems.join('; ')}. ` +
    `${joinAsks(asks)}. If something cannot be established, say so plainly instead of presenting it as done.`;
  return { block: true, reason, confidences };
}

/**
 * The closing message: `last_assistant_message` when present, else the last
 * assistant text in the transcript. Empty string when neither is available.
 *
 * @param {Record<string, unknown>} input hook stdin
 * @returns {string}
 */
function resolveFinalMessage(input) {
  if (typeof input.last_assistant_message === 'string' && input.last_assistant_message.trim()) return input.last_assistant_message;
  if (typeof input.transcript_path === 'string' && input.transcript_path) return lastAssistantText(input.transcript_path);
  return '';
}

/**
 * Last assistant text in a Claude Code transcript (JSONL, one entry per line;
 * an assistant message may span several lines sharing `message.id`). Sidechain
 * (subagent) entries are ignored. Returns '' on any error.
 *
 * @param {string} file
 * @returns {string}
 */
function lastAssistantText(file) {
  try {
    const st = fs.statSync(file, { throwIfNoEntry: false });
    if (!st || !st.isFile()) return '';
    let text;
    if (st.size <= TRANSCRIPT_TAIL_BYTES) {
      text = fs.readFileSync(file, 'utf8');
    } else {
      const fd = fs.openSync(file, 'r');
      try {
        const buf = Buffer.alloc(TRANSCRIPT_TAIL_BYTES);
        const n = fs.readSync(fd, buf, 0, TRANSCRIPT_TAIL_BYTES, st.size - TRANSCRIPT_TAIL_BYTES);
        text = buf.subarray(0, n).toString('utf8');
        text = text.slice(text.indexOf('\n') + 1);
      } finally {
        fs.closeSync(fd);
      }
    }
    const entries = [];
    for (const line of text.split('\n')) {
      const s = line.trim();
      if (!s) continue;
      try {
        const e = JSON.parse(s);
        if (e && typeof e === 'object' && !e.isSidechain) entries.push(e);
      } catch {
        /* skip malformed line */
      }
    }
    let lastId = null;
    let lastIdx = -1;
    for (let i = entries.length - 1; i >= 0; i -= 1) {
      if (!isAssistant(entries[i])) continue;
      if (textOf(entries[i])) {
        lastIdx = i;
        lastId = entries[i].message?.id ?? null;
        break;
      }
    }
    if (lastIdx < 0) return '';
    const parts = [];
    for (let i = 0; i < entries.length; i += 1) {
      const e = entries[i];
      if (i !== lastIdx && !(lastId && isAssistant(e) && e.message?.id === lastId)) continue;
      const t = textOf(e);
      if (t) parts.push(t);
    }
    return parts.join('\n').trim();
  } catch (err) {
    debug(`stop: transcript unreadable: ${err?.code ?? err?.name ?? 'error'}`);
    return '';
  }
}

function isAssistant(e) {
  return e.type === 'assistant' || e.role === 'assistant' || e.message?.role === 'assistant';
}

function textOf(e) {
  const msg = e.message && typeof e.message === 'object' ? e.message : e;
  const content = msg.content;
  if (typeof content === 'string') return content.trim();
  if (Array.isArray(content)) {
    return content
      .filter((c) => c && c.type === 'text' && typeof c.text === 'string')
      .map((c) => c.text)
      .join('\n')
      .trim();
  }
  return '';
}

function joinAsks(asks) {
  if (asks.length <= 1) return asks[0] ?? '';
  return `${asks.slice(0, -1).join(', ')}, and ${asks[asks.length - 1]}`;
}

function num(v) {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

main().catch((err) => {
  debug(`stop hook failed open: ${err?.name ?? 'Error'}`);
  exitSilently(0);
});
