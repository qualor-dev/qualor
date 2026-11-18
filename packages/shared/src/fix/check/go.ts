/**
 * B1 for Go modules (spec §12, R24). `go.mod` may raise existing `require` versions and add or
 * drop `// indirect` requires (MVS needs them), never change any other directive (`module`, `go`,
 * `toolchain`, `replace`, `exclude`, `retract`, `tool`, `godebug`, …). `go.sum` has no hosts; every
 * new line needs an `h1:` hash, and it has no dependency graph and no targets (Ruling F14).
 */
import { compareVersions, versionParses } from '../versions';
import { belowTarget, checkLockEntries } from './lock-entries';
import {
  FIX_CHECK_OK,
  fixRefused,
  type FixCheckContext,
  type FixCheckResult,
  type FixFileChange,
  type FixRule,
  type LockEntry,
} from './types';
import { stripBom } from './values';

/** A `go.mod` read: its module path, every other directive, and its requires. */
export interface GoModFile {
  module: string | null;
  /**
   * Every directive but `require`, one per line of a block, `module` included; `text` is its
   * arguments, unquoted, joined by one space (an argument that holds a space or a quote, or is
   * empty, written as a JSON string).
   */
  directives: { verb: string; text: string }[];
  requires: { path: string; version: string; indirect: boolean }[];
}

interface GoToken {
  kind: 'word' | '(' | ')';
  text: string;
  quoted: boolean;
}

interface GoLine {
  tokens: GoToken[];
  /** The text after `//`, or null. */
  comment: string | null;
}

/**
 * What a Go module file lexer skips between tokens. Any other white space, a control or format
 * character, `{` and `}` end the read, as `golang.org/x/mod/modfile` refuses them; `[`, `]` and
 * `,` are tokens of their own (a `retract` interval).
 */
const SKIPPED = new Set([' ', '\t', '\r']);
const PUNCTUATION = new Set(['[', ']', ',']);
const NOT_IDENT = /[\s()[\]{},\p{C}\p{Z}]/u;
/** A control or format character other than tab. */
const CONTROL = /[^\P{C}\t]/u;

function goError(message: string): never {
  throw new Error(`go.mod: ${message}`);
}

/** A quoted string at `start`: no newline (lines are split already) and no escape. */
function quotedAt(line: string, start: number): { token: GoToken; end: number } {
  const quote = line.charAt(start);
  const close = line.indexOf(quote, start + 1);
  if (close < 0) goError('unterminated string');
  const text = line.slice(start + 1, close);
  if (quote === '"' && text.includes('\\')) goError('an escape in a string');
  if (CONTROL.test(text)) goError('a control character in a string');
  return { token: { kind: 'word', text, quoted: true }, end: close + 1 };
}

/** An identifier at `start`: up to white space, punctuation or `//`. */
function identAt(line: string, start: number): { token: GoToken; end: number } {
  let end = start;
  while (end < line.length && !NOT_IDENT.test(line.charAt(end))) {
    if (line.startsWith('//', end)) break;
    if (line.startsWith('/*', end)) goError('a /* comment');
    end++;
  }
  if (end === start) goError(`unexpected character U+${line.charCodeAt(start).toString(16)}`);
  return { token: { kind: 'word', text: line.slice(start, end), quoted: false }, end };
}

/** The tokens and the trailing comment of one line. */
function lexGoLine(line: string): GoLine {
  const tokens: GoToken[] = [];
  let i = 0;
  while (i < line.length) {
    const c = line.charAt(i);
    if (SKIPPED.has(c)) {
      i++;
      continue;
    }
    if (line.startsWith('//', i)) return { tokens, comment: line.slice(i + 2) };
    if (line.startsWith('/*', i)) goError('a /* comment');
    if (c === '(' || c === ')') {
      tokens.push({ kind: c, text: c, quoted: false });
      i++;
      continue;
    }
    if (PUNCTUATION.has(c)) {
      tokens.push({ kind: 'word', text: c, quoted: false });
      i++;
      continue;
    }
    const { token, end } = c === '"' || c === '`' ? quotedAt(line, i) : identAt(line, i);
    tokens.push(token);
    i = end;
  }
  return { tokens, comment: null };
}

/** `// indirect` or `// indirect; …`, as `modfile` reads it. */
function isIndirect(comment: string | null): boolean {
  if (comment === null) return false;
  const fields = comment.trim().split(/\s+/);
  return (fields.length === 1 && fields[0] === 'indirect') || fields[0] === 'indirect;';
}

function argumentText(arg: string): string {
  return arg === '' || /[\s"`]/.test(arg) ? JSON.stringify(arg) : arg;
}

function addStatement(file: GoModFile, verb: string, args: string[], comment: string | null) {
  if (verb === 'require') {
    const [path, version] = args;
    if (args.length !== 2 || path === undefined || version === undefined) {
      goError('usage: require module/path v1.2.3');
    }
    file.requires.push({ path, version, indirect: isIndirect(comment) });
    return;
  }
  if (verb === 'module') {
    if (file.module !== null) goError('repeated module statement');
    if (args.length !== 1 || args[0] === undefined) goError('usage: module module/path');
    file.module = args[0];
  }
  file.directives.push({ verb, text: args.map(argumentText).join(' ') });
}

function words(tokens: readonly GoToken[]): string[] {
  if (tokens.some((token) => token.kind !== 'word')) goError('unexpected parenthesis');
  return tokens.map((token) => token.text);
}

/** A line outside a block: a statement, or `verb (` opening a block (its verb returned). */
function topLevelLine(file: GoModFile, { tokens, comment }: GoLine): string | null {
  const [verb, ...rest] = tokens;
  if (verb === undefined) return null;
  if (verb.kind !== 'word' || verb.quoted) goError('a directive must start with a keyword');
  if (rest.length === 1 && rest[0]?.kind === '(') return verb.text;
  addStatement(file, verb.text, words(rest), comment);
  return null;
}

/**
 * `go.mod` as `golang.org/x/mod/modfile` reads it: lines of tokens (identifiers, quoted strings,
 * `(` and `)`), `//` comments, and `verb ( … )` blocks whose lines are each one directive. It
 * throws where `modfile` reports an error or could read the file differently: escapes in strings,
 * stray parentheses, brackets, control characters, white space other than space, tab and CR.
 */
export function readGoMod(text: string): GoModFile {
  const file: GoModFile = { module: null, directives: [], requires: [] };
  let block: string | null = null;
  for (const raw of stripBom(text).split('\n')) {
    const line = lexGoLine(raw);
    if (line.tokens.length === 0) continue;
    if (block === null) {
      block = topLevelLine(file, line);
    } else if (line.tokens.length === 1 && line.tokens[0]?.kind === ')') {
      block = null;
    } else {
      addStatement(file, block, words(line.tokens), line.comment);
    }
  }
  if (block !== null) goError(`unterminated ${block} block`);
  return file;
}

/** A go.sum hash: `h1:` and a base64 SHA-256. */
const H1 = /^h1:[A-Za-z\d+/]{43}=$/;

/**
 * `go.sum`: one {@link LockEntry} per line, `/go.mod` lines included (their version keeps the
 * `/go.mod` suffix), kind `registry`, no source, the `h1:` hash as integrity (null for any other
 * third field or none). A line of one field, or of more than three, throws, as `go` refuses it.
 */
export function readGoSum(text: string): LockEntry[] {
  const entries: LockEntry[] = [];
  for (const line of stripBom(text).split('\n')) {
    const fields = line.trim().split(/\s+/);
    const [name, version, hash] = fields;
    if (name === undefined || name === '') continue;
    if (version === undefined || fields.length > 3) {
      throw new Error(`go.sum: a line of ${fields.length} fields`);
    }
    const integrity = hash !== undefined && H1.test(hash) ? hash : null;
    entries.push({
      name,
      version,
      source: null,
      kind: 'registry',
      integrity,
      dependencies: [],
      dependents: [],
    });
  }
  return entries;
}

function readBothGoMods(change: FixFileChange): [GoModFile, GoModFile] | null {
  try {
    return [readGoMod(change.base), readGoMod(change.next)];
  } catch {
    return null;
  }
}

function directiveKeys(file: GoModFile): string[] {
  return file.directives
    .map(({ verb, text }) => `${verb} ${text}`)
    .sort((a, b) => (a < b ? -1 : 1));
}

/** Whether both files have the same directives other than `require`, in any order. */
function sameDirectives(base: GoModFile, next: GoModFile): boolean {
  const a = directiveKeys(base);
  const b = directiveKeys(next);
  return a.length === b.length && a.every((key, i) => key === b[i]);
}

type Require = GoModFile['requires'][number];

function requiresByPath(file: GoModFile): Map<string, Require[]> {
  const byPath = new Map<string, Require[]>();
  for (const require of file.requires) {
    const list = byPath.get(require.path);
    if (list === undefined) byPath.set(require.path, [require]);
    else list.push(require);
  }
  return byPath;
}

/** A module required more than once: allowed only exactly as the base has it. */
function sameRequires(base: readonly Require[], next: readonly Require[]): boolean {
  return (
    base.length === next.length &&
    base.every((r, i) => r.version === next[i]?.version && r.indirect === next[i]?.indirect)
  );
}

/** One module in `next`: raised or kept (`other_change` when lowered), or added `// indirect`. */
function requireRule(
  base: Require | undefined,
  next: Require,
  packageName: string,
): FixRule | null {
  if (base?.version === next.version) return null;
  if (!versionParses('go', next.version)) return 'bad_spec';
  if (base === undefined) {
    return next.indirect || next.path === packageName ? null : 'new_dependency';
  }
  const raised = compareVersions('go', next.version, base.version);
  return raised === null || raised < 0 ? 'other_change' : null;
}

/** R24 for the requires: raised, `// indirect` added or dropped, nothing lowered or dropped. */
function requiresRule(base: GoModFile, next: GoModFile, packageName: string): FixRule | null {
  const before = requiresByPath(base);
  const after = requiresByPath(next);
  for (const [path, list] of after) {
    const old = before.get(path) ?? [];
    if (list.length > 1 || old.length > 1) {
      if (!sameRequires(old, list)) return 'other_change';
      continue;
    }
    const [only] = list;
    const rule = only === undefined ? null : requireRule(old[0], only, packageName);
    if (rule !== null) return rule;
  }
  for (const [path, list] of before) {
    if (!after.has(path) && list.some((require) => !require.indirect)) return 'other_change';
  }
  return null;
}

/** The package's require versions against the targets of this `go.mod` (Ruling F14). */
function goModBelowTarget(
  base: GoModFile,
  next: GoModFile,
  ctx: FixCheckContext,
  path: string,
): boolean {
  const targets = ctx.targets.filter((t) => t.lockfile === path);
  if (targets.length === 0) return false;
  const versions = (file: GoModFile) =>
    file.requires.filter((r) => r.path === ctx.packageName).map((r) => r.version);
  return belowTarget(versions(next), targets, 'go', versions(base));
}

/**
 * B1 and R24 for `go.mod`: every directive but `require` unchanged (`go_directive`); requires
 * only raised (`other_change` when lowered, a direct one dropped, or a module required twice
 * differently), added only `// indirect` or for the package (`new_dependency`), each new version a
 * Go module version (`bad_spec`); then the package's require at least its target
 * (`below_target`).
 */
export function checkGoMod(change: FixFileChange, ctx: FixCheckContext): FixCheckResult {
  const both = readBothGoMods(change);
  if (both === null) return fixRefused('unparsable', change.path);
  const [base, next] = both;
  if (!sameDirectives(base, next)) return fixRefused('go_directive', change.path);
  const rule = requiresRule(base, next, ctx.packageName);
  if (rule !== null) return fixRefused(rule, change.path);
  if (goModBelowTarget(base, next, ctx, change.path)) {
    return fixRefused('below_target', change.path);
  }
  return FIX_CHECK_OK;
}

/**
 * B1 and R24 for `go.sum`: every new line has an `h1:` hash (`missing_integrity`). There are no
 * hosts, no graph to follow (no reachability, as Ruling F14 skips the targets), and old lines may
 * stay.
 */
export function checkGoSum(change: FixFileChange, ctx: FixCheckContext): FixCheckResult {
  let base: LockEntry[];
  let next: LockEntry[];
  try {
    base = readGoSum(change.base);
    next = readGoSum(change.next);
  } catch {
    return fixRefused('unparsable', change.path);
  }
  return checkLockEntries(base, next, {
    ...ctx,
    lockfile: change.path,
    publicHosts: [],
    integrityRequired: true,
    reachableOnly: false,
  });
}
