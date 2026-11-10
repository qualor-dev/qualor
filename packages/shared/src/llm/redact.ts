/*!
 * @license Qualor's secret redaction adapts patterns from Gitleaks' default rules
 * (github.com/gitleaks/gitleaks, config/gitleaks.toml), under Gitleaks' licence:
 *
 *   MIT License
 *
 *   Copyright (c) 2019 Zachary Rice
 *
 *   Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 *   and associated documentation files (the "Software"), to deal in the Software without
 *   restriction, including without limitation the rights to use, copy, modify, merge, publish,
 *   distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
 *   Software is furnished to do so, subject to the following conditions:
 *
 *   The above copyright notice and this permission notice shall be included in all copies or
 *   substantial portions of the Software.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 *   BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 *   DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
/**
 * llm.md §5.2: the server's own secret redaction before a prompt leaves, on top of what the CLI
 * already replaced (report-format.md §7). The token patterns are adapted from Gitleaks' default
 * rules (MIT, notice above; `/*!` and `@license` keep it in the server bundle): a curated subset of
 * high-confidence shapes, not a replacement for running Gitleaks.
 *
 * Bounded work (no ReDoS): every quantifier of every pattern has an upper bound, no pattern nests
 * quantifiers, and a text over {@link REDACT_MAX_CHARS} is replaced as a whole instead of scanned.
 * Fail closed: a secret split over up to four lines or glued from pieces on one line, a key block
 * whose BEGIN or END line is outside the text, and a token cut by the CLI's `…` truncation are
 * redacted too, at the cost of whole lines.
 */
import { REDACTED } from '../sarif/normalize';
import type { LlmIssueInput } from './input';

export interface SecretPattern {
  id: string;
  pattern: RegExp;
  /** The capture group holding the secret; the whole match when absent. */
  group?: number;
  /**
   * A second look at a match the pattern cannot express: `secret` is the group (or the match),
   * `prefix` group 1 when the secret is a later group, `next` the character after the match.
   */
  accept?: (secret: string, prefix: string, next: string) => boolean;
  /** False for a pattern that must not look across two joined lines (its value runs to the end). */
  joinable?: boolean;
}

/** A text (or all the lines of a snippet together) longer than this is redacted as a whole. */
export const REDACT_MAX_CHARS = 65_536;

/** A name that says secret; `auth` but not `author`. */
const SECRET_NAME =
  '(?:password|passwd|passphrase|pwd|secret|token|api[_.-]?key|apikey|access[_.-]?key|account[_.-]?key|private[_.-]?key|client[_.-]?secret|credential|auth(?!or))';

/**
 * The rest of the name; a name that ends in one of these suffixes names something about a secret
 * (`tokenType`, `secretName`, `authUrl`, `apiKeyHeader`, `PASSWORD_HINT`, `tokenizer`), not one.
 */
const NAME_TAIL =
  '[A-Za-z0-9_.-]{0,64}(?<!type|name|url|uri|header|label|hint|izer|length|field|placeholder)';

const NAME = `${SECRET_NAME}${NAME_TAIL}`;

/** Prefixes of the token shapes below, for a token the CLI cut short with `…`. */
const TOKEN_PREFIX =
  '(?:gh[pousr]_|github_pat_|gl(?:pat|dt|rt|ptt|soat|cbt|oas|ft|imt|agent|ffct)-|GR1348941|xox[abposr]-|[sr]k_live_|AIza|sk-|eyJ|qlr_(?:pat|prj)_|npm_|hf_|SG\\.|whsec_|A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA|MII)';

/** A reference to the environment, not a value. */
const ENV_ACCESS = /^(?:process\.env|import\.meta\.env|os\.environ|Deno\.env|ENV\[)/;
/** An identifier or a member chain (`password`, `config.apiKey`), maybe ending a statement. */
const CODE_REF = /^[A-Za-z_$][\w$]{0,256}(?:\.[A-Za-z_$][\w$]{0,256}){0,16}[,;]?$/;
/** A placeholder, a literal or a type, not a value. */
const PLACEHOLDER =
  /^(?:null|undefined|none|nil|true|false|string|number|boolean|any|unknown|object|required|optional)[,;]?$/i;

/**
 * llm.md §5.2: an unquoted value is a secret when it has at least 8 non-space characters, does not
 * start with `$`, `{`, `(` or `%` (a variable, a template or a format), holds no `(` (a call), and
 * is not a code reference on a line written as code (`password = password;`, `apiKey: cfg.key,`).
 */
function unquotedSecret(secret: string, prefix: string, next: string): boolean {
  const v = secret.trimEnd();
  if (/^[$({%«=>|&*!#[<"'`]/.test(v) || v.includes('(')) return false;
  if (v.replace(/\s/g, '').length < 8) return false;
  if (ENV_ACCESS.test(v) || PLACEHOLDER.test(v) || FETCH_CREDENTIALS.test(v)) return false;
  const code = /\s$/.test(prefix) && CODE_REF.test(v) && (/[,;]$/.test(v) || /^[,;]/.test(next));
  return !code;
}

/**
 * A name whose quoted value is a secret even when it reads as words (a passphrase): the ruling of
 * fix round 3a. Only a weaker name (`auth`, `access_key`, `account_key`) keeps the prose exemption.
 */
const STRONG_NAME =
  /password|passphrase|passwd|pwd|secret|token|api[_.-]?key|apikey|private[_.-]?key|credential/i;

/** The values of the `credentials` option of fetch(), not a secret. */
const FETCH_CREDENTIALS = /^(?:same-origin|include|omit)[,;]?$/;

/** Three or more plain words: a message, a label or a hint, not a secret. */
const PROSE = /^[A-Za-z][A-Za-z',.!?-]{0,64}(?: [A-Za-z][A-Za-z',.!?-]{0,64}){2,64}$/;

/** An unquoted value's characters: no space, quote, call, list or markup delimiter. */
const VALUE = '[^\\s"\'`(;&<,)\\]}]';
/** What may not follow an unquoted value (it would have been part of it, or a call). */
const VALUE_END = '(?![^\\s"\'`;&<,)\\]}])';
/** A value that runs to the end of the line (YAML, properties, .env, Dockerfile). */
const LINE_VALUE = '([^\\s"\'`$({%«=>|&*!#[<][^\\n(]{7,4095})$';
/** The start of a line that assigns: indentation, a YAML list dash, `export`, and a name. */
const LINE_START = `^(\\s{0,64}(?:-\\s{1,8})?(?:export\\s{1,8})?["']?[A-Za-z0-9_.-]{0,64}${NAME}["']?`;

/** A dotted or dashed name (`app.settings.title`, `com.example.Foo2`, `user-settings-v2`). */
const DOTTED_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,64}(?:[.:-][A-Za-z0-9_]{1,64}){0,64}$/;

/**
 * A value that looks generated rather than named: 16 or more characters without a space that mix
 * at least three of lower case, upper case, digits and symbols, or 32 or more hex digits with
 * both digits and letters; never a dotted or dashed name, a placeholder or a reference.
 */
function looksRandom(value: string): boolean {
  if (PLACEHOLDER.test(value) || ENV_ACCESS.test(value) || /^[$({%]/.test(value)) return false;
  if (/^[0-9a-f]{32,4096}$/i.test(value)) return /[0-9]/.test(value) && /[a-f]/i.test(value);
  const mixed = (s: string) =>
    [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((c) => c.test(s)).length >= 3;
  // A name's separators are not a symbol: only a long random-looking part of it counts.
  if (DOTTED_NAME.test(value)) return value.split(/[.:-]/).some((p) => p.length >= 16 && mixed(p));
  return mixed(value);
}

export const SECRET_PATTERNS: readonly SecretPattern[] = [
  { id: 'aws-access-key-id', pattern: /(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}/g },
  {
    id: 'github-token',
    pattern: /(?:gh[pousr]_[A-Za-z0-9]{36,4096}|github_pat_[A-Za-z0-9_]{22,4096})/g,
  },
  {
    id: 'gitlab-token',
    pattern: /gl(?:pat|dt|rt|ptt|soat|cbt|oas|ft|imt|agent|ffct)-[A-Za-z0-9_-]{20,4096}/g,
  },
  { id: 'gitlab-runner-registration-token', pattern: /GR1348941[A-Za-z0-9_-]{20,4096}/g },
  { id: 'slack-token', pattern: /xox[abposr]-[A-Za-z0-9-]{10,4096}/g },
  {
    id: 'slack-webhook',
    pattern: /https:\/\/hooks\.slack\.com\/(?:services|workflows)\/[A-Za-z0-9+/]{20,4096}/g,
  },
  { id: 'stripe-live-key', pattern: /(?:sk|rk)_live_[A-Za-z0-9]{20,4096}/g },
  { id: 'stripe-webhook-secret', pattern: /whsec_[A-Za-z0-9+/=]{24,4096}/g },
  { id: 'google-api-key', pattern: /AIza[0-9A-Za-z_-]{35}/g },
  {
    // Not inside a word (`task-…`), and random: a digit or both cases, unlike `sk-learn-more`.
    id: 'openai-or-anthropic-key',
    pattern: /(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,4096}/g,
    accept: (s) => /[0-9]/.test(s) || (/[A-Z]/.test(s) && /[a-z]/.test(s)),
  },
  { id: 'npm-token', pattern: /npm_[A-Za-z0-9]{36,4096}/g },
  { id: 'huggingface-token', pattern: /(?<![A-Za-z0-9])hf_[A-Za-z0-9]{30,4096}/g },
  {
    id: 'sendgrid-key',
    pattern: /(?<![A-Za-z0-9])SG\.[A-Za-z0-9_-]{16,64}\.[A-Za-z0-9_-]{16,128}/g,
  },
  {
    // The header is JSON (`eyJ`); the payload need not be.
    id: 'jwt',
    pattern: /eyJ[A-Za-z0-9_-]{10,4096}\.[A-Za-z0-9_-]{10,4096}\.[A-Za-z0-9_-]{10,4096}/g,
  },
  { id: 'qualor-token', pattern: /qlr_(?:pat|prj)_[0-9A-Za-z]{32}/g },
  /** A DER private key (or certificate) in base64 without its PEM lines. */
  { id: 'private-key-der', pattern: /\bMII[A-Za-z0-9+/]{60,4096}={0,2}/g },
  {
    // The password runs to the last `@` of the URL (it may hold `/` or `@`); `host:8080/…@` is a
    // port and a path, not a password.
    id: 'url-password',
    pattern: /([a-z][a-z0-9+.-]{0,30}:\/\/[^\s:/@"'`]{0,256}:)([^\s"'`]{1,1024})(@|…$)/gi,
    group: 2,
    accept: (s) => !/^[0-9]{1,5}(?:\/|$)/.test(s),
  },
  {
    // The closing quote is optional: a value cut by the CLI's truncation, or continued on the next
    // line, is still redacted. An escaped quote is part of the value.
    id: 'secret-assignment',
    pattern: new RegExp(
      `(${NAME}["']?\\s{0,32}(?::|=|:=|=>)\\s{0,32}["'\`])((?:\\\\.|[^"'\`\\\\\\n]){8,4096})(["'\`]?)`,
      'gi',
    ),
    group: 2,
    accept: (s, prefix) =>
      !FETCH_CREDENTIALS.test(s) && (STRONG_NAME.test(prefix) || !PROSE.test(s)),
  },
  {
    id: 'authorization-header',
    pattern:
      /(Authorization["']?\s{0,32}[:=,]\s{0,32}["'`]?\s{0,8}(?:Basic|Bearer|Token|Digest)\s{1,8})([A-Za-z0-9+/=._~-]{8,4096})/gi,
    group: 2,
  },
  {
    // YAML, properties, .env and shell lines: `password: my secret`, `db.password = x`.
    id: 'unquoted-line-assignment',
    pattern: new RegExp(`${LINE_START}\\s{0,32}(?::|=(?![=>~]))\\s{0,32})${LINE_VALUE}`, 'i'),
    group: 2,
    accept: unquotedSecret,
    joinable: false,
  },
  {
    id: 'dockerfile-env',
    pattern: new RegExp(
      `^(\\s{0,64}(?:ENV|ARG)\\s{1,8}[A-Za-z0-9_.-]{0,64}${NAME}\\s{1,32})${LINE_VALUE}`,
      'i',
    ),
    group: 2,
    accept: unquotedSecret,
    joinable: false,
  },
  {
    // Anywhere on a line: connection strings (`;Password=…;`, `Pwd=`, `AccountKey=`,
    // `SharedAccessKey=`), query strings (`?password=…&`), `export`/`ENV` with `=`.
    id: 'unquoted-assignment',
    pattern: new RegExp(
      `(${NAME}\\s{0,32}=(?![=>~])\\s{0,32})(${VALUE}{8,4096})${VALUE_END}`,
      'gi',
    ),
    group: 2,
    accept: unquotedSecret,
    joinable: false,
  },
  {
    id: 'xml-element',
    pattern: new RegExp(
      `(<[A-Za-z0-9_:.-]{0,64}${NAME}>\\s{0,32})([^<\\s]{8,4096})(?=\\s{0,32}<)`,
      'gi',
    ),
    group: 2,
    accept: unquotedSecret,
    joinable: false,
  },
  {
    // .NET appSettings: `<add key="StripeApiKey" value="…" />`. The name is in an attribute, so
    // the assignment patterns never see it next to its value.
    id: 'dotnet-app-setting',
    pattern: new RegExp(
      `(<add\\s{1,32}key\\s{0,8}=\\s{0,8}["'][A-Za-z0-9_.:-]{0,64}(?:${SECRET_NAME}|key)${NAME_TAIL}["']\\s{1,32}value\\s{0,8}=\\s{0,8}["'])([^"'\\n]{8,4096})(?=["'])`,
      'gi',
    ),
    group: 2,
    accept: (s) => !/^[$({%]/.test(s) && !ENV_ACCESS.test(s) && !PLACEHOLDER.test(s),
    joinable: false,
  },
  {
    // The MySQL clients take the password glued to `-p` (`mysql -uroot -pS3cret db`); `-P` is the
    // port, and `-p` alone asks for it.
    id: 'mysql-password-option',
    pattern:
      /(\bmysql(?:dump|admin|import|check|sh|pump)?(?:\.exe)?\s[^\n]{0,512}?(?<=\s)-p["']?)([^\s"'`$]{1,4096})/g,
    group: 2,
  },
  {
    // The short names `pass` and `key` say secret too often to ignore and name other things too
    // often to trust (`key: "user-settings"`, `pass: true`): their value is redacted only when it
    // looks random (see looksRandom).
    id: 'short-name-assignment',
    pattern:
      /((?<![A-Za-z0-9_.$-])(?:pass|key)["']?\s{0,32}(?::|=|:=|=>)\s{0,32}["'`]?)([A-Za-z0-9+/=_.~!@#%^&*:-]{16,4096})(?![A-Za-z0-9+/=_.~!@#%^&*:(-])/gi,
    group: 2,
    accept: (s) => looksRandom(s),
    joinable: false,
  },
  {
    id: 'truncated-token',
    pattern: new RegExp(`${TOKEN_PREFIX}[A-Za-z0-9_.+/=-]{4,512}…$`, 'g'),
  },
];

const KEY_BEGIN = /-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----|^PuTTY-User-Key-File-/i;
const KEY_END = /-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----|^Private-MAC:/i;

/** One line of base64, possibly quoted and glued to the next line (`"…" +`, `"…\n",`). */
const BASE64_LINE =
  /^\s{0,64}\+?\s{0,64}["'`]?([A-Za-z0-9+/]{1,256}={0,2})(?:\\n)?["'`]?\s{0,64}[,;+\\]?\s{0,64}$/;

/** A line's end and the next line's start that glue a string over two lines. */
const GLUE_END = /(?:["'`]\s{0,16}(?:\+|\.{1,2}|&|,)?|\\)\s{0,64}$/;
const GLUE_START = /^\s{0,64}(?:\+|\.{1,2}|&)?\s{0,16}[A-Za-z@$]{0,2}["'`]/;
/** Two string literals glued on one line: `"a" + "b"`, `"a", "b"` (a joined array), `"a" "b"`. */
const INLINE_GLUE = /["'`]\s{0,16}(?:\+|\.{1,2}|&|,)?\s{0,16}["'`]/g;
/** At most this many lines are joined to find a secret split over them. */
const MAX_JOINED_LINES = 4;

/** The patterns with match indices (`d`), to tell which joined line a secret touches. */
const SPLIT_PATTERNS = SECRET_PATTERNS.filter((p) => p.joinable !== false).map((p) => ({
  ...p,
  pattern: new RegExp(p.pattern.source, `${p.pattern.flags}d`),
}));

/** Whether a match is a secret: its group is not already a marker, and `accept` agrees. */
function accepted(
  { group, accept }: SecretPattern,
  groups: readonly (string | undefined)[],
  match: string,
  next: string,
): boolean {
  const secret = group === undefined ? match : (groups[group - 1] ?? '');
  if (secret === REDACTED) return false;
  return accept === undefined || accept(secret, group === undefined ? '' : (groups[0] ?? ''), next);
}

/** Every match of {@link SECRET_PATTERNS} in one line replaced by `«redacted»` (a marker is kept). */
function redactLine(text: string): { text: string; count: number } {
  let count = 0;
  let out = text;
  for (const p of SECRET_PATTERNS) {
    out = out.replace(p.pattern, (...args: unknown[]) => {
      const match = args[0] as string;
      const hasNamed = typeof args.at(-1) === 'object';
      const input = args.at(hasNamed ? -2 : -1) as string;
      const offset = args.at(hasNamed ? -3 : -2) as number;
      const groups = args.slice(1, hasNamed ? -3 : -2) as (string | undefined)[];
      if (!accepted(p, groups, match, input.charAt(offset + match.length))) return match;
      count += 1;
      const { group } = p;
      if (group === undefined) return REDACTED;
      return groups.map((g, i) => (i === group - 1 ? REDACTED : (g ?? ''))).join('');
    });
  }
  return { text: out, count };
}

/** How many secrets the one-line patterns find in a text. */
function countSecrets(text: string): number {
  let n = 0;
  for (const p of SPLIT_PATTERNS) {
    for (const m of text.matchAll(p.pattern)) {
      if (accepted(p, m.slice(1), m[0], text.charAt(m.index + m[0].length))) n += 1;
    }
  }
  return n;
}

/** A line whose string literals, glued together, hold a secret that none of them holds alone. */
function hasGluedSecret(line: string): boolean {
  const glued = line.replace(INLINE_GLUE, '');
  return glued !== line && countSecrets(glued) > countSecrets(line);
}

/**
 * A private key block from its BEGIN line to its END line, or to the last line when the END is
 * not in view; an END line without its BEGIN in view closes a block that began above the first
 * line, so every line since the previous block is part of it. A PuTTY key file counts from its
 * first line to its `Private-MAC:` line.
 */
function markKeyBlocks(lines: readonly string[], whole: boolean[]): void {
  let inKey = false;
  let from = 0;
  lines.forEach((line, i) => {
    if (!inKey && KEY_BEGIN.test(line)) inKey = true;
    if (inKey) {
      whole[i] = true;
      if (KEY_END.test(line)) {
        inKey = false;
        from = i + 1;
      }
      return;
    }
    if (KEY_END.test(line)) {
      for (let k = from; k <= i; k++) whole[k] = true;
      from = i + 1;
    }
  });
}

/**
 * Characters code puts before the text of a key body's line: indentation, a comment mark (`#`,
 * `*`, `;`, `--`, and `//` below), a patch's `+` or `-`, a quote. `/` alone is base64.
 */
const BODY_LEADING = new Set([' ', '\t', '#', '*', ';', '+', '-', '"', "'", '`']);
/**
 * ... and after it: a quote, a comma, a string glued by `+`, a continued line, the `;` that ends
 * the string's statement, a CR (and the escape `\n` below). The same marks the windows' rule for
 * base64 lines (`BASE64_LINE`) takes off, so that a line it would take is a body line here too.
 */
const BODY_TRAILING = new Set([' ', '\t', '\r', '"', "'", '`', ',', ';', '+', '\\']);
/** A body line longer than this, decoration off, is no PEM line (they are 64 or 76 characters). */
const BODY_LINE_MAX_CHARS = 4_096;
/** Room for the decoration around the longest body line, so that a longer line is not scanned. */
const BODY_LINE_DECORATION_CHARS = 256;
/** A line of base64: the body of a PEM key. 16 characters or more, so a short word is not one. */
const BODY_BASE64 = /^[A-Za-z0-9+/=]{16,4096}$/;
/** The header fields of an encrypted PEM key. */
const BODY_FIELD = /^(?:Proc-Type|DEK-Info):/i;
/** The short last line of a key: 1 to 15 characters of base64, and its padding. */
const BODY_LAST_LINE = /^[A-Za-z0-9+/]{1,15}={0,2}$/;

/**
 * `line` without what code puts around a key body's text: the marks of a comment, a string or a
 * patch (`BODY_LEADING`, `//`, `BODY_TRAILING`, the escape `\n` that ends a string's line). Linear
 * in the line.
 */
function undecorated(line: string): string {
  let start = 0;
  let end = line.length;
  while (start < end) {
    if (BODY_LEADING.has(line.charAt(start))) start += 1;
    else if (line.startsWith('//', start)) start += 2;
    else break;
  }
  while (end > start) {
    if (end - 2 >= start && line.startsWith('\\n', end - 2)) end -= 2;
    else if (BODY_TRAILING.has(line.charAt(end - 1))) end -= 1;
    else break;
  }
  return line.slice(start, end);
}

/** What a line of a key body can be: a header field, the blank line that ends the fields, base64. */
function bodyLineKind(line: string): 'field' | 'blank' | 'base64' | null {
  if (line.length > BODY_LINE_MAX_CHARS + BODY_LINE_DECORATION_CHARS) return null;
  const text = undecorated(line);
  if (text === '') return 'blank';
  if (BODY_FIELD.test(text)) return 'field';
  // The line as it stands too: base64 may start with `+` or `//`, which are decoration as well.
  return BODY_BASE64.test(text) || BODY_BASE64.test(line.trim()) ? 'base64' : null;
}

/**
 * Whether `line` can be the last line of a key: 1 to 15 characters of base64, decoration off. A PEM
 * line is 64 characters and the last is 4 to 64, a multiple of 4, so it is under 16 for 3 of its 16
 * possible lengths.
 */
function isShortLastLine(line: string): boolean {
  return line.length <= BODY_LINE_DECORATION_CHARS + 17 && BODY_LAST_LINE.test(undecorated(line));
}

/**
 * Marks the lines that follow each BEGIN line from `from` on (no END line comes after any of them)
 * while they are PEM body lines, decoration off: the header fields (`Proc-Type`, `DEK-Info`), one
 * blank line to end the fields, base64 of 16 characters or more. The first other line ends the
 * body, and the BEGIN line itself is left unmarked: it is the caller's. The one line that ends the
 * body is marked too when it is a short base64 line (`isShortLastLine`) and a base64 line came
 * before it: the last line of the key. The windows used to extend a run of long base64 lines to a
 * short one beside it, and no run is left for them once these lines are masked.
 */
function markLoneBodies(lines: readonly string[], from: number, marked: boolean[]): void {
  /** `header`: right after a BEGIN line, where fields and the blank line may come; `body`: base64 only. */
  let state: 'header' | 'body' | null = null;
  /** A base64 line of the key has been marked: a short line after it can be its last. */
  let sawBase64 = false;
  for (let i = from; i < lines.length; i++) {
    const line = lines[i] ?? '';
    if (KEY_BEGIN.test(line)) {
      state = 'header';
      sawBase64 = false;
      continue;
    }
    if (state === null) continue;
    const kind = bodyLineKind(line);
    if (kind === 'base64' || (state === 'header' && kind !== null)) {
      marked[i] = true;
      sawBase64 ||= kind === 'base64';
      state = kind === 'field' ? 'header' : 'body';
      continue;
    }
    if (sawBase64 && isShortLastLine(line)) marked[i] = true;
    state = null;
  }
}

/**
 * The lines of every private key block that is whole in `lines`: from a line with a BEGIN marker
 * to the next line with an END marker after it, both included, however the lines are decorated
 * (a comment's `# `, a string literal, a patch's `-`). An END line with no BEGIN line before it is
 * no whole block, and a BEGIN line with no END line after it is none either: what they mean is the
 * caller's (the redaction above masks up to such an END line, and from such a BEGIN line on, as far
 * as it sees). But the body that follows a BEGIN line like that is marked, while its lines are PEM
 * body lines once their decoration is off, and the short last line of the key (`markLoneBodies`): a
 * key whose END line is missing or mistyped is masked over a cut too, and ordinary code after a
 * BEGIN line named in code is not. For a caller that cuts a long text into pieces, so that a block
 * over a cut is still masked whole.
 */
export function keyBlockLines(lines: readonly string[]): boolean[] {
  const marked = lines.map(() => false);
  let begin: number | null = null;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    if (begin === null && KEY_BEGIN.test(line)) begin = i;
    if (begin !== null && KEY_END.test(line)) {
      for (let k = begin; k <= i; k++) marked[k] = true;
      begin = null;
    }
  }
  if (begin !== null) markLoneBodies(lines, begin, marked);
  return marked;
}

function isStrongBase64(line: string): boolean {
  const m = BASE64_LINE.exec(line);
  const value = m?.[1] ?? '';
  return value.length >= 40 && /[0-9]/.test(value) && /[A-Z]/.test(value) && /[a-z]/.test(value);
}

function isWeakBase64(line: string): boolean {
  const value = BASE64_LINE.exec(line)?.[1];
  if (value === undefined) return false;
  return value.length >= 16 || value.endsWith('=') || /[0-9]/.test(value);
}

/**
 * The body of a key block whose BEGIN and END lines are both outside the view: two or more lines
 * of long random base64 (or one next to a key block), and the short base64 lines around them.
 */
function markBase64Runs(lines: readonly string[], whole: boolean[]): void {
  let i = 0;
  while (i < lines.length) {
    if (!isStrongBase64(lines[i] ?? '')) {
      i += 1;
      continue;
    }
    let end = i;
    while (end + 1 < lines.length && isStrongBase64(lines[end + 1] ?? '')) end += 1;
    const nearKey = whole[i - 1] === true || whole[end + 1] === true;
    if (end > i || nearKey) i = markRun(lines, whole, i, end) + 1;
    else i = end + 1;
  }
}

/** Marks the strong base64 lines `i..end` and the weak ones right around them; returns the last. */
function markRun(lines: readonly string[], whole: boolean[], i: number, end: number): number {
  let lo = i;
  let hi = end;
  while (lo - 1 >= 0 && !whole[lo - 1] && isWeakBase64(lines[lo - 1] ?? '')) lo -= 1;
  while (hi + 1 < lines.length && !whole[hi + 1] && isWeakBase64(lines[hi + 1] ?? '')) hi += 1;
  for (let k = lo; k <= hi; k++) whole[k] = true;
  return hi;
}

/** The piece a position is in (a position in a separator counts for the piece before it). */
function pieceAt(starts: readonly number[], pos: number): number {
  let k = 0;
  while (k + 1 < starts.length && (starts[k + 1] ?? Infinity) <= pos) k += 1;
  return k;
}

/**
 * Pieces of consecutive lines (from line `first`) joined with `sep`: a match that spans two or more
 * pieces marks every line its secret touches.
 */
function markJoined(pieces: readonly string[], sep: string, first: number, whole: boolean[]): void {
  const joined = pieces.join(sep);
  const starts: number[] = [];
  let at = 0;
  for (const piece of pieces) {
    starts.push(at);
    at += piece.length + sep.length;
  }
  for (const p of SPLIT_PATTERNS) {
    for (const m of joined.matchAll(p.pattern)) {
      const end = m.index + m[0].length;
      if (pieceAt(starts, m.index) === pieceAt(starts, Math.max(m.index, end - 1))) continue;
      if (!accepted(p, m.slice(1), m[0], joined.charAt(end))) continue;
      const span = (p.group === undefined ? m.indices?.[0] : m.indices?.[p.group]) ?? [
        m.index,
        m.index,
      ];
      markSpan(span, pieces, starts, first, whole);
    }
  }
}

/** Marks the lines (pieces from line `first`) that a secret's span in the joined text touches. */
function markSpan(
  span: readonly [number, number],
  pieces: readonly string[],
  starts: readonly number[],
  first: number,
  whole: boolean[],
): void {
  let lo = pieceAt(starts, span[0]);
  // A secret that starts in a separator does not touch the piece before it.
  if (span[0] >= (starts[lo] ?? 0) + (pieces[lo] ?? '').length) lo += 1;
  const hi = pieceAt(starts, Math.max(span[0], span[1] - 1));
  for (let k = lo; k <= hi; k++) whole[first + k] = true;
}

/**
 * A secret split over lines (string concatenation, a joined array, a shell line continuation, a
 * wrapped literal, an assignment whose value is on the next line): each pair of lines is joined
 * three ways, and runs of up to {@link MAX_JOINED_LINES} lines glued at every line end are joined
 * with their glue removed; a match that needs more than one line marks the lines its secret touches.
 */
function markSplitSecrets(lines: readonly string[], whole: boolean[]): void {
  for (let i = 0; i + 1 < lines.length; i++) {
    const a = lines[i] ?? '';
    const b = lines[i + 1] ?? '';
    // No pattern matches fewer than 7 characters (`x://:p@`), so a shorter pair holds no secret.
    if (a.trim().length + b.trim().length >= 7) {
      markJoined([a.replace(GLUE_END, ''), b.replace(GLUE_START, '')], '', i, whole);
      markJoined([a.trimEnd(), b.trimStart()], '', i, whole);
      markJoined([a.trimEnd(), b.trimStart()], ' ', i, whole);
    }
    for (let k = 3; k <= MAX_JOINED_LINES && i + k <= lines.length; k++) {
      const window = lines.slice(i, i + k);
      if (!GLUE_END.test(window[k - 2] ?? '')) break;
      if (k === 3 && !GLUE_END.test(a)) break;
      const pieces = window.map((line, n) => {
        const start = n > 0 ? line.replace(GLUE_START, '') : line;
        return n < k - 1 ? start.replace(GLUE_END, '') : start;
      });
      markJoined(pieces, '', i, whole);
    }
  }
}

/** Lines of one text or snippet: key blocks, base64 runs and split secrets whole, the rest by pattern. */
function redactLines(lines: readonly string[]): { lines: string[]; count: number } {
  const size = lines.reduce((n, line) => n + line.length + 1, 0);
  if (size > REDACT_MAX_CHARS) {
    return { lines: lines.map(() => REDACTED), count: lines.length };
  }
  const whole = lines.map(() => false);
  markKeyBlocks(lines, whole);
  markBase64Runs(lines, whole);
  markSplitSecrets(lines, whole);
  lines.forEach((line, i) => {
    if (!whole[i] && hasGluedSecret(line)) whole[i] = true;
  });
  let count = 0;
  const out = lines.map((line, i) => {
    if (whole[i]) {
      if (line !== REDACTED) count += 1;
      return REDACTED;
    }
    const r = redactLine(line);
    count += r.count;
    return r.text;
  });
  return { lines: out, count };
}

/**
 * Every secret of {@link SECRET_PATTERNS} in the text replaced by `«redacted»` (an existing marker
 * is kept), private key blocks and secrets split over lines as whole lines; a text over
 * {@link REDACT_MAX_CHARS} becomes one marker. `count` is the number of replacements.
 */
export function redactText(text: string): { text: string; count: number } {
  if (text.length > REDACT_MAX_CHARS) return { text: REDACTED, count: 1 };
  const r = redactLines(text.split('\n'));
  return { text: r.lines.join('\n'), count: r.count };
}

/** llm.md §5.2: every string of the prompt's data redacted; `redactions` counts the replacements. */
export function redactInput(input: LlmIssueInput): { input: LlmIssueInput; redactions: number } {
  let redactions = 0;
  const t = (value: string): string => {
    const r = redactText(value);
    redactions += r.count;
    return r.text;
  };
  const snippet = input.snippet ? redactLines(input.snippet.lines) : null;
  redactions += snippet?.count ?? 0;
  return {
    input: {
      ...input,
      rule: {
        ...input.rule,
        key: t(input.rule.key),
        name: t(input.rule.name),
        description: t(input.rule.description),
      },
      message: t(input.message),
      path: input.path === null ? null : t(input.path),
      snippet:
        input.snippet && snippet
          ? { startLine: input.snippet.startLine, lines: snippet.lines }
          : null,
    },
    redactions,
  };
}
