/**
 * Secret redaction and bounded truncation.
 *
 * Everything that leaves the machine (Jev request state) or lands in the
 * ledger passes through here first. Pure functions, no I/O, no dependencies.
 * Redaction is best-effort pattern matching: it masks the common shapes
 * (API keys, GitHub/GitLab/AWS/Slack/Google/Stripe tokens, JWTs, Bearer
 * headers, `password=`/`token=`/`cookie=` pairs, private key blocks, URL
 * userinfo). It is not a guarantee.
 *
 * Every pattern is linear in the input: no alternative starts with an
 * unanchored `[\w-]*` run, so a 1 MB identifier costs milliseconds, not
 * minutes (the hooks run under hard time budgets and a synchronous regex
 * cannot be interrupted by them).
 *
 * @module redact
 */

/**
 * Ordered secret patterns. Each entry has a `kind` label (shown in the mask),
 * a global `re` used for replacement, and a `replace` template. Order matters:
 * whole-block patterns run first so their inner tokens are not half-masked.
 *
 * @type {ReadonlyArray<{kind: string, re: RegExp, test: RegExp, replace: string}>}
 */
export const SECRET_PATTERNS = Object.freeze(
  [
    {
      kind: 'private_key',
      re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
      replace: '[REDACTED:private_key]',
    },
    {
      kind: 'jwt',
      re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
      replace: '[REDACTED:jwt]',
    },
    {
      kind: 'bearer',
      re: /\b(Bearer)\s+[A-Za-z0-9._~+/=-]{8,}/gi,
      replace: '$1 [REDACTED:bearer]',
    },
    {
      // OpenAI / TypeSafe / OpenRouter style keys: sk-..., sk-or-v1-...
      kind: 'sk',
      re: /\bsk-[A-Za-z0-9_-]{8,}\b/g,
      replace: '[REDACTED:sk]',
    },
    {
      // GitHub tokens: ghp_, gho_, ghu_, ghs_, ghr_, github_pat_
      kind: 'github',
      re: /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g,
      replace: '[REDACTED:github]',
    },
    {
      kind: 'aws',
      re: /\bAKIA[0-9A-Z]{16}\b/g,
      replace: '[REDACTED:aws]',
    },
    {
      // Stripe secret keys: sk_live_..., sk_test_... (the sk- form is above)
      kind: 'stripe',
      re: /\bsk_(?:live|test)_[A-Za-z0-9]{10,}\b/g,
      replace: '[REDACTED:stripe]',
    },
    {
      // Slack tokens: xoxb-, xoxp-, xoxa-, xoxr-, xoxs-
      kind: 'slack',
      re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g,
      replace: '[REDACTED:slack]',
    },
    {
      // Google API keys
      kind: 'google',
      re: /\bAIza[0-9A-Za-z_-]{30,}\b/g,
      replace: '[REDACTED:google]',
    },
    {
      // GitLab personal access tokens
      kind: 'gitlab',
      re: /\bglpat-[A-Za-z0-9_-]{16,}\b/g,
      replace: '[REDACTED:gitlab]',
    },
    {
      // key=value / "key": "value" pairs whose key ends in a credential word.
      // The key is kept so the reader still knows a credential was there. The
      // credential word is matched directly (no `[\w-]*` prefix: that made the
      // pattern quadratic on long identifier runs). `pwd` is accepted as a
      // credential key (`db_pwd=`, SQL Server `Pwd=`) unless its value is a
      // filesystem path, which is the shell's `PWD`/`OLDPWD` variable.
      kind: 'kv',
      re: /((?:password|passwd|secret|token|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|sessionid|session|cookie|auth)(?:["']?\s*[=:]\s*["']?)|pwd(?:["']?\s*[=:]\s*["']?)(?![/~]))(?!\[REDACTED:)([^\s"'&,;}\])]{3,})/gi,
      replace: '$1[REDACTED:kv]',
    },
    {
      // URL userinfo: scheme://user:pass@host → scheme://[REDACTED:userinfo]@host
      kind: 'url_userinfo',
      re: /\b([a-z][a-z0-9+.-]*:\/\/)([^\s/@:]+)(?::[^\s/@]*)?@/gi,
      replace: '$1[REDACTED:userinfo]@',
    },
  ].map((p) => Object.freeze({ ...p, test: new RegExp(p.re.source, p.re.flags.replace('g', '')) })),
);

/**
 * Mask secrets in a string. Non-string input is stringified first
 * (objects via JSON), `null`/`undefined` become ''.
 *
 * @param {unknown} text
 * @returns {string} the text with every recognised secret replaced by `[REDACTED:<kind>]`
 */
export function redact(text) {
  let s = toText(text);
  if (!s) return '';
  for (const p of SECRET_PATTERNS) s = s.replace(p.re, p.replace);
  return s;
}

/** Object keys whose value is a credential regardless of the value's shape (`"token": 12345`). */
export const CREDENTIAL_KEY_RE = /(?:^|[_.-])(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|sessionid|session|cookie|auth)$/i;

const REDACT_OBJECT_MAX_DEPTH = 32;

/**
 * Redact a parsed JSON value structurally: string leaves go through
 * `redact()`, and any leaf (string, number, boolean) under a credential-named
 * key becomes `[REDACTED:kv]`, so a numeric token never survives and the value
 * stays an object (serialising, redacting and re-parsing would turn
 * `"token": 12345` into invalid JSON). `pwd`/`PWD` with a path value is the
 * shell variable and is left alone. Depth is bounded; deeper values are
 * stringified and redacted as text.
 *
 * @template T
 * @param {T} value
 * @param {number} [depth]
 * @returns {T|string}
 */
export function redactObject(value, depth = 0) {
  if (typeof value === 'string') return redact(value);
  if (value == null || typeof value !== 'object') return value;
  if (depth > REDACT_OBJECT_MAX_DEPTH) return redact(toText(value));
  if (Array.isArray(value)) return value.map((v) => redactObject(v, depth + 1));
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (isCredentialKey(k, v) && (v === null || typeof v !== 'object')) out[k] = '[REDACTED:kv]';
    else out[k] = redactObject(v, depth + 1);
  }
  return out;
}

/**
 * True when `key` names a credential (`GITHUB_TOKEN`, `api_key`, `password`…).
 * `pwd`-style keys do not count when the value is a filesystem path.
 *
 * @param {string} key
 * @param {unknown} [value]
 * @returns {boolean}
 */
export function isCredentialKey(key, value) {
  const k = String(key ?? '');
  if (!CREDENTIAL_KEY_RE.test(k)) return false;
  if (/pwd$/i.test(k) && typeof value === 'string' && /^[/~]/.test(value)) return false;
  return true;
}

/**
 * True when the text contains at least one recognised secret shape.
 * Used by the gate hook to flag credentials inside scenario environments.
 *
 * @param {unknown} text
 * @returns {boolean}
 */
export function hasSecret(text) {
  const s = toText(text);
  if (!s) return false;
  return SECRET_PATTERNS.some((p) => p.test.test(s));
}

/**
 * Keep the head and tail of a long string with an omission marker between.
 *
 * With only `maxChars`, 75% goes to the head and 25% to the tail. When `head`
 * and/or `tail` are given they are used as-is (the missing one is derived from
 * `maxChars`). The marker `…[n chars omitted]…` is added on top of head+tail,
 * so the result can exceed `maxChars` by the marker length.
 *
 * @param {unknown} text
 * @param {number} maxChars
 * @param {{head?: number, tail?: number}} [opts]
 * @returns {string}
 */
export function truncate(text, maxChars, opts = {}) {
  const s = toText(text);
  const max = Math.max(0, Math.floor(Number(maxChars) || 0));
  if (s.length <= max) return s;
  let { head, tail } = opts;
  if (head == null && tail == null) {
    head = Math.round(max * 0.75);
    tail = max - head;
  } else if (head == null) {
    tail = clampInt(tail, 0, max);
    head = max - tail;
  } else if (tail == null) {
    head = clampInt(head, 0, max);
    tail = max - head;
  } else {
    head = clampInt(head, 0, s.length);
    tail = clampInt(tail, 0, s.length);
  }
  const omitted = s.length - head - tail;
  if (omitted <= 0) return s;
  const marker = `…[${omitted} chars omitted]…`;
  return s.slice(0, head) + marker + (tail > 0 ? s.slice(s.length - tail) : '');
}

/**
 * Redact then truncate: the shape every ledger excerpt and every Jev state
 * field should take. Defaults to 200 chars, the ledger excerpt limit.
 *
 * @param {unknown} text
 * @param {number} [maxChars=200]
 * @param {{head?: number, tail?: number}} [opts]
 * @returns {string}
 */
export function excerpt(text, maxChars = 200, opts = {}) {
  return truncate(redact(text), maxChars, opts);
}

function toText(value) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'object') {
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }
  return String(value);
}

function clampInt(n, lo, hi) {
  const v = Math.floor(Number(n) || 0);
  return Math.min(hi, Math.max(lo, v));
}
