import { cutAtGrapheme } from '@qualor/shared';
import { lineCountOf, MaskedText, type MaskBudget, type MaskedFiles } from './masked-files';
import type { Masker } from './masker';
import type { ListCaps } from './prompts';
import {
  patchFacts,
  removedLines,
  WHY,
  type Mask,
  type NoteReason,
  type Removal,
  type RemovedLine,
} from './patch';
import type { AnalyzerFinding, PriorFinding } from './findings-query';
import type { SnapshotChange, SnapshotFile, SnapshotMeta } from './snapshot-reader';

export {
  parsePatch,
  type ParsedPatch,
  type PatchHunk,
  type PatchRow,
  type RemovedLine,
} from './patch';
export {
  analyzerFindings,
  priorAiFindings,
  type AnalyzerFinding,
  type PriorFinding,
} from './findings-query';

/*
 * What a review is shown of a merge request: which of its changes are reviewed, the diff slices
 * printed with the real new-side line numbers (so that the model copies a number instead of
 * counting lines), the findings the analyzers already made and the ones an earlier review made,
 * and the merge request's own words and instructions files.
 *
 * Every text of the repository that reaches a prompt through here is masked as a whole text (llm.md
 * §5.2) before any of it is cut: a file through the review's MaskedFiles, the same instance the
 * tools read, so that it is masked once and the lines the slices print are the lines read_file
 * shows; the patches, the instructions, the title, the description and the findings through the
 * review's Masker, off the thread that serves requests. A text the Masker gives up on (it took too
 * long, or the review has spent its time or its bytes for masking) is left out with a fixed note;
 * nothing is ever masked a slice at a time.
 *
 * Masking costs time, and bytes of the review's budget, so only what is going to be shown is
 * masked, in the order the slices are cut. The merge request's words and the findings come first;
 * then each change in turn, its file and its patch, until the slices are full; how full they may
 * be, and the instructions files, the review says from the shape of the change (`limits`). What is
 * needed to choose is read from the texts as the snapshot stores them, which costs a read and no
 * masking: of each file only a yes or a no (generated, minified), a number of lines, the lines
 * after its removed runs and the number of characters its slices would take leave the reading. A
 * change does not hold its patch: a prompt is built from the context, and nothing in it can send a
 * removed line nobody masked.
 */

// ─── What is read, and how much of it ────────────────────────────────────────

/** Lines of context kept on each side of a change. */
const CONTEXT_LINES = 40;
/** The files `classify` reads in one query. */
export const CLASSIFY_BATCH = 25;
/**
 * The most a context shows, whatever the review's budget: characters of slices in all, and of each
 * instructions file. The review's limits (`ContextOptions.limits`) are at most these.
 */
export const CONTEXT_MAXIMA: Readonly<Omit<ContextLimits, 'lists'>> = Object.freeze({
  sliceChars: 120_000,
  instructionsChars: 32_000,
});
/** A line is cut here, with `…`. */
const MAX_LINE_CHARS = 400;
const TITLE_CHARS = 255;
const DESCRIPTION_CHARS = 4_000;
/** The lines at the head of a file that say it is generated, and the ones that say it is minified. */
const GENERATED_HEAD_LINES = 5;
const MINIFIED_HEAD_LINES = 50;
const MINIFIED_AVERAGE_CHARS = 300;
const MINIFIED_LONG_LINE_CHARS = 1_000;

/** `word` as a pattern that matches it in any case: `sso` is `[sS][sS][oO]`. */
const anyCase = (word: string): string =>
  word.replace(/[a-z]/g, (letter) => `[${letter}${letter.toUpperCase()}]`);

/**
 * Words that mark security-sensitive code wherever they stand in a path, inside another word too:
 * `basicauth`, `bcrypt`, `.htpasswd`, `adminlogin`.
 */
const SENSITIVE_WORDS = [
  'auth',
  'authn',
  'authz',
  'oauth',
  'saml',
  'secret',
  'passw',
  'credential',
  'crypt',
  'cipher',
  'permission',
  'session',
  'login',
  'sanitis',
  'sanitiz',
  'escap',
];
/**
 * Short words, which are also inside ordinary ones (`sso` in `processor`, `acl` in `oracle`, `token`
 * in `tokenizer`): one counts where no lower case letter follows it or its plural `s`, as in
 * `csrftoken`, `APIToken` and `acls`.
 */
const SHORT_SENSITIVE_WORDS = ['sso', 'acl', 'jwt', 'csrf', 'rbac', 'token'];

/**
 * A path that looks like security-sensitive code, in any case: one of the words above anywhere in
 * it, or one of the short words where no lower case letter follows. Deliberately loose (`author` has
 * `auth` in it, and `lasso` ends in `sso`): a hit only adds a reviewer, and a miss costs more. It has
 * no `i` flag, for a capital after a short word ends it as any other character does, and no global
 * flag, so it keeps no state between paths.
 */
export const SENSITIVE_PATH = new RegExp(
  `${SENSITIVE_WORDS.map(anyCase).join('|')}|(?:${SHORT_SENSITIVE_WORDS.map(anyCase).join('|')})[sS]?(?![a-z])`,
);

const LOCK_FILES: ReadonlySet<string> = new Set([
  'package-lock.json',
  'npm-shrinkwrap.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'bun.lockb',
  'Cargo.lock',
  'Gemfile.lock',
  'composer.lock',
  'poetry.lock',
  'Pipfile.lock',
  'uv.lock',
  'go.sum',
  'packages.lock.json',
  'gradle.lockfile',
  'flake.lock',
  'mix.lock',
  'pubspec.lock',
  'Podfile.lock',
]);
const MINIFIED_NAME = /\.(?:min\.js|min\.css|bundle\.js)$/i;

// ─── Types ───────────────────────────────────────────────────────────────────

/** Why a change is not reviewed. A change with no patch and no text is read as `binary`. */
export type SkipReason = 'lock' | 'generated' | 'minified' | 'binary';
export interface SkippedChange {
  path: string;
  why: SkipReason;
}

/**
 * Why the slices of a reviewed change are not cut: the change deleted the file (no slices by
 * design), the snapshot has no text of the file, the patch does not parse or does not fit the
 * file, or the file could not be masked (it took too long, or the review has no time or bytes left
 * for it).
 */
export type Unshown = 'deleted' | 'no_text' | 'unreadable' | 'timeout' | 'budget';

/**
 * A change that is reviewed. The snapshot's patch is not on it, for a prompt is built from the
 * context: `hasPatch` says that there was one, and `removed` holds the lines the patch removed as
 * the masking of the patch left them. The digest of the diff is made from the reader's changes.
 */
export interface ReviewableChange extends Omit<SnapshotChange, 'patch'> {
  /** The snapshot has a patch for the change; it is missing when it was too large to send. */
  hasPatch: boolean;
  /**
   * The patch says which lines the change touched: false when there is none (too large to send,
   * or a diff the scanner could not make) or it cannot be read against the file.
   */
  patchUsable: boolean;
  /** The lines the head file has, as the snapshot stores it; null when there is no text of it. */
  lines: number | null;
  /**
   * The head file masked as a whole, the text read_file shows. Set only for a change whose slices
   * are in the prompt, and only while MaskedFiles keeps that text (its cache is bounded); null for
   * every other change.
   */
  text: MaskedText | null;
  /** The new-side lines the change adds. */
  added: ReadonlySet<number>;
  /**
   * The new-side line after each run of lines the change removed (the last line, for a run at the
   * end of the file), in order, each once: where a problem in removed code is put. None for a
   * deleted file, which has no lines.
   */
  removalPoints: readonly number[];
  /** Lines added plus lines removed; the file's length when the patch says nothing. */
  changedLines: number;
  sensitive: boolean;
  /**
   * The lines the change removed, in the order of the patch, as the masking of the patch left
   * them. Set when the change has its turn to be masked; empty for the others.
   */
  removed: readonly RemovedLine[];
  /** Why there are no slices of it, or null. */
  unshown: Unshown | null;
}

export interface ContextOptions {
  /**
   * The administrator's "never send these paths" (llm.md §3.2), as the tools apply it. A change,
   * a finding or an instructions file on one is left out of what the model is shown, and its
   * file is not read. Not optional: a context built without it would send what the administrator
   * keeps out.
   */
  excluded: (path: string) => boolean;
  /**
   * What is left of the review's budget of bytes to mask, which the tools spend from too (the
   * policy's `budget.maskedBytes`). Every text the context has masked is charged to it. Not
   * optional: a context built without it would mask for free.
   */
  budget: MaskBudget;
  /**
   * How much of the slices and of the instructions the review's tokens leave room for, given the
   * shape of the change (the pipeline's `reviewLimits`). Asked once, before anything is masked or
   * cut; what it answers is held to CONTEXT_MAXIMA. Not optional: a context built without it would
   * show more than the review can read.
   */
  limits: (shape: ContextShape) => ContextLimits;
}

/** How much of the merge request a context shows. */
export interface ContextLimits {
  /** Characters of slices in all. */
  sliceChars: number;
  /** Characters of each instructions file; a longer one is cut, with a label. 0: no file is shown. */
  instructionsChars: number;
  /** The files longer than `instructionsChars` are left out, with no label; the others are whole. */
  instructionsDropLonger?: boolean;
  /**
   * The files are shown shorter than they otherwise are, because the window has no room. With
   * `instructionsChars` 0, none is shown.
   */
  instructionsShortened?: boolean;
  /** How much of each list the first message holds (R47); the context lists the changes with no slices up to `lists.notInSlices`. */
  lists: ListCaps;
}

/**
 * What a context knows of the change when it asks for its limits: nothing is masked or cut yet,
 * and of the texts only their sizes are given.
 */
export interface ContextShape {
  /** The changes that are reviewed; none has its text or its removed lines yet. */
  reviewed: readonly ReviewableChange[];
  skipped: readonly SkippedChange[];
  /** For each finding of the analyzers on the reviewed paths: the characters of its path, rule and message. */
  analyzerChars: readonly number[];
  /** The characters the title and the description take once they are cut. */
  wordsChars: number;
  /** The characters of each instructions file the model may be shown, as the snapshot holds it. */
  instructionChars: readonly number[];
}

export interface ReviewFindings {
  /**
   * The analyzers' findings on these paths, which are the paths of the changes that are reviewed
   * (the query that answers keeps a bounded number, so it is asked for these and no others).
   * Findings on other paths are not believed.
   */
  analyzer: (paths: readonly string[]) => Promise<AnalyzerFinding[]>;
  /** The earlier review's findings. */
  prior: PriorFinding[];
}

export interface ReviewContext {
  /**
   * The snapshot's meta with what the prompt may show of it: `mrTitle`, `mrDescription` and
   * `instructions` are masked, cut and labelled (the raw texts are in the reader only).
   */
  meta: SnapshotMeta;
  /** In the path order of the snapshot. */
  reviewed: ReviewableChange[];
  skipped: SkippedChange[];
  /** The slices of the reviewed changes that fit, the most important first. */
  slices: string;
  /** The changes with no slices in `slices`, each with what to do about it: the first `listCaps.notInSlices`. */
  omittedFromSlices: string[];
  /** How many more changes have no slices than `omittedFromSlices` lists. */
  unlistedFromSlices: number;
  /** The caps of the lists the review's data holds (the limits' `lists`). */
  listCaps: ListCaps;
  /** The instructions files were cut or left out to fit the model's context window. */
  instructionsShortened?: boolean;
  analyzer: AnalyzerFinding[];
  prior: PriorFinding[];
  /**
   * Secrets replaced in what the prompt shows. Only for the record of the spend: it depends on what
   * the tools masked, and is never shown to a person.
   */
  redactions: number;
}

const notShown = (why: NoteReason): string => `[not shown: ${WHY[why]}]`;
const plural = (count: number, noun: string): string => `${count} ${noun}${count === 1 ? '' : 's'}`;

/** The lines of a text, which is all that is needed of it to cut slices and to tell what a file is. */
interface TextLines {
  readonly lineCount: number;
  line(index: number): string;
  lineLength(index: number): number;
}

// ─── Which changes are reviewed ──────────────────────────────────────────────

const baseName = (path: string): string => path.slice(path.lastIndexOf('/') + 1);

/** A change skipped for its name alone: its file is not read at all. */
function skippedByName(path: string): SkipReason | null {
  if (LOCK_FILES.has(baseName(path))) return 'lock';
  if (MINIFIED_NAME.test(path)) return 'minified';
  return null;
}

/** The first lines of the file say a tool wrote it. */
function isGenerated(text: TextLines): boolean {
  const head: string[] = [];
  for (let i = 0; i < Math.min(GENERATED_HEAD_LINES, text.lineCount); i += 1)
    head.push(text.line(i));
  const joined = head.join('\n');
  return (
    joined.includes('@generated') ||
    (joined.includes('Code generated') && joined.includes('DO NOT EDIT'))
  );
}

/** The first lines of the file are long on average, and one of them is very long. */
function isMinified(text: TextLines): boolean {
  const lines = Math.min(MINIFIED_HEAD_LINES, text.lineCount);
  if (lines === 0) return false;
  let total = 0;
  let longest = 0;
  for (let i = 0; i < lines; i += 1) {
    const length = text.lineLength(i);
    total += length;
    if (length > longest) longest = length;
  }
  return total / lines > MINIFIED_AVERAGE_CHARS && longest > MINIFIED_LONG_LINE_CHARS;
}

/** The ranges of lines changed since the last review, cut to the lines the file has. */
function clipSince(
  since: readonly [number, number][] | null,
  lines: number,
): [number, number][] | null {
  if (since === null) return null;
  const clipped: [number, number][] = [];
  for (const [start, end] of since) {
    const last = Math.min(end, lines);
    if (start <= last) clipped.push([start, last]);
  }
  return clipped;
}

const isExcluded = (change: SnapshotChange, options: ContextOptions): boolean =>
  options.excluded(change.path) || (change.oldPath !== null && options.excluded(change.oldPath));

/**
 * The change as the review reads it. Only a rename has an old path, and an upload is not made to
 * keep to that: any other change has none here, so an old path it claims is not excluded by, not
 * followed by a finding and not shown to a model. A rename that does not say what it was renamed
 * from is an added file.
 */
function readChange(given: SnapshotChange): SnapshotChange {
  if (given.status === 'renamed') {
    return given.oldPath === null ? { ...given, status: 'added' } : given;
  }
  return given.oldPath === null ? given : { ...given, oldPath: null };
}

/** A change that is reviewed, and what the cutting of the slices needs of it besides. */
interface Candidate {
  change: ReviewableChange;
  /** The snapshot's patch, to mask when the change has its turn; it is not kept on `change`. */
  patch: string | null;
  /**
   * The characters its slices take, counted on the stored text and patch with nothing masked; 0
   * when there is nothing to print. Masking replaces secrets, so the slices are about this long:
   * enough to know that they do not fit, and a limit to check them against once they are cut.
   */
  size: number;
}

/** The paths to read, in the order of the changes and each once: the files of the changes that are reviewed. */
function pathsToRead(changes: readonly SnapshotChange[], options: ContextOptions): string[] {
  return [
    ...new Set(
      changes.flatMap((given) => {
        const change = readChange(given);
        return isExcluded(change, options) ||
          skippedByName(change.path) !== null ||
          change.status === 'deleted'
          ? []
          : [change.path];
      }),
    ),
  ];
}

/** The reader of the files of `toRead`, CLASSIFY_BATCH at a time; the paths are asked for in that order. */
function fileReader(
  toRead: readonly string[],
  files: MaskedFiles,
): (path: string) => Promise<SnapshotFile> {
  let read = new Map<string, SnapshotFile>();
  let fetched = 0;
  return async (path) => {
    const held = read.get(path);
    if (held !== undefined) return held;
    // A path asked for twice (a snapshot holds a path once) whose batch has gone is read alone.
    if (toRead.indexOf(path) < fetched) return files.reader.file(path);
    // Reached in order, so this path opens the next batch.
    const batch = toRead.slice(fetched, fetched + CLASSIFY_BATCH);
    fetched += batch.length;
    read = await files.reader.files(batch);
    return read.get(path) ?? { kind: 'absent' };
  };
}

/** What a change's file says of it: why it is not reviewed, or its stored text and why that is not shown. */
type FileJudgement = { skip: SkipReason } | { stored: TextLines | null; unshown: Unshown | null };

function judgeFile(change: SnapshotChange, file: SnapshotFile): FileJudgement {
  switch (file.kind) {
    case 'text': {
      // The text as stored, only to read its lines: it is not masked and never shown.
      const text = MaskedText.of(file.text, lineCountOf(file.text));
      if (isGenerated(text)) return { skip: 'generated' };
      if (isMinified(text)) return { skip: 'minified' };
      return { stored: text, unshown: null };
    }
    case 'omitted':
      if (file.reason === 'binary') return { skip: 'binary' };
      return { stored: null, unshown: 'no_text' };
    case 'absent':
      return { stored: null, unshown: change.status === 'deleted' ? 'deleted' : 'no_text' };
  }
}

/** The candidate of a change that is reviewed, from its stored text (if it has one) and why that is not shown. */
function candidateOf(
  change: SnapshotChange,
  stored: TextLines | null,
  shown: Unshown | null,
): Candidate {
  let unshown = shown;
  const lines = stored === null ? null : stored.lineCount;
  const facts = patchFacts(change, lines);
  if (unshown === null && !facts.readable) unshown = 'unreadable';
  return {
    change: {
      path: change.path,
      oldPath: change.oldPath,
      status: change.status,
      since: lines === null ? change.since : clipSince(change.since, lines),
      hasPatch: change.patch !== null,
      patchUsable: change.patch !== null && facts.readable,
      lines,
      text: null,
      added: facts.added,
      removalPoints: change.status === 'deleted' ? [] : removalPointsOf(facts.removals, lines),
      changedLines: facts.changedLines,
      sensitive: SENSITIVE_PATH.test(change.path),
      removed: [],
      unshown,
    },
    patch: change.patch,
    size:
      stored === null || unshown !== null
        ? 0
        : sliceChars(
            { path: change.path, added: facts.added, removed: facts.removals },
            stored,
            CONTEXT_MAXIMA.sliceChars,
          ),
  };
}

/**
 * The changes of a merge request that are reviewed, and the ones that are not, with why. Reviewed
 * is everything but the lock files, the generated and the minified files, and the changes with
 * neither a patch nor a text; migrations and deleted files are kept (a deleted file has no
 * slices). A path the administrator keeps from the model is in neither list, and its file is not
 * read. The files are read as the snapshot stores them, to tell what they are: nothing is masked
 * here, and the texts do not leave this function.
 *
 * Defensive reading: a `renamed` change that does not say what it was renamed from is `added`, and
 * a change that is not a rename has no old path, whatever the upload says; the ranges changed since
 * the last review are cut to the file; a patch that does not parse, or has a row past the end of
 * the file, drops that file's slices and nothing else.
 */
async function classify(
  changes: readonly SnapshotChange[],
  files: MaskedFiles,
  options: ContextOptions,
): Promise<{ candidates: Candidate[]; skipped: SkippedChange[] }> {
  const candidates: Candidate[] = [];
  const skipped: SkippedChange[] = [];
  const fileOf = fileReader(pathsToRead(changes, options), files);
  for (const given of changes) {
    const change = readChange(given);
    if (isExcluded(change, options)) continue;
    const byName = skippedByName(change.path);
    if (byName !== null) {
      skipped.push({ path: change.path, why: byName });
      continue;
    }
    const file: SnapshotFile =
      change.status === 'deleted' ? { kind: 'absent' } : await fileOf(change.path);
    const judged = judgeFile(change, file);
    if ('skip' in judged) {
      skipped.push({ path: change.path, why: judged.skip });
      continue;
    }
    if (change.patch === null && file.kind !== 'text') {
      skipped.push({ path: change.path, why: 'binary' });
      continue;
    }
    candidates.push(candidateOf(change, judged.stored, judged.unshown));
  }
  return { candidates, skipped };
}

/**
 * The line after each run of removed rows, held to the file's last line (a run at the end has none
 * after it), in order and each once. A file of no lines has none.
 */
function removalPointsOf(removals: readonly Removal[], lines: number | null): number[] {
  const points = new Set<number>();
  for (const { after } of removals) {
    const point = lines === null ? after + 1 : Math.min(after + 1, lines);
    if (point >= 1) points.add(point);
  }
  return [...points].sort((a, b) => a - b);
}

// ─── Where findings belong ───────────────────────────────────────────────────

/**
 * How far from its lines a finding may be and still be a finding on them: a problem is often a
 * line or two from the line that causes it.
 */
export const SCOPE_MARGIN = 3;

/**
 * The lines a review may raise new findings on, as sorted ranges apart from one another: on a
 * re-review (a change with `since`), the lines changed since the last reviewed commit (D6); on a
 * first review, the lines the change adds and the line after each run it removed, so that a removed
 * check can be reported where it was, and the whole file when its patch says nothing of its lines.
 * Prior findings are re-checked wherever they are.
 */
export function scopeRanges(
  change: Pick<ReviewableChange, 'since' | 'added' | 'removalPoints' | 'patchUsable' | 'lines'>,
): [number, number][] {
  if (change.since === null && !change.patchUsable) {
    return change.lines !== null && change.lines > 0 ? [[1, change.lines]] : [];
  }
  const ranges: [number, number][] =
    change.since !== null
      ? change.since.map(([from, to]): [number, number] => [from, to])
      : [...change.added, ...change.removalPoints].map((line): [number, number] => [line, line]);
  ranges.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  const merged: [number, number][] = [];
  for (const [from, to] of ranges) {
    const last = merged[merged.length - 1];
    if (last !== undefined && from <= last[1] + 1) last[1] = Math.max(last[1], to);
    else merged.push([from, to]);
  }
  return merged;
}

// ─── Slices ──────────────────────────────────────────────────────────────────

/** What the printing of slices needs of a change. */
interface SliceInput {
  path: string;
  added: ReadonlySet<number>;
  removed: readonly RemovedLine[];
}

/** A line as the model sees it: without its carriage return, and cut with `…`. */
function cutLine(line: string): string {
  const text = line.endsWith('\r') ? line.slice(0, -1) : line;
  if (text.length <= MAX_LINE_CHARS) return text;
  // Enough for the cut to land on the right character, and a minified line is not taken apart.
  return cutAtGrapheme(text.slice(0, 2 * MAX_LINE_CHARS + 2), MAX_LINE_CHARS);
}

/**
 * The windows of lines to print: `context` lines around every added line and every place lines
 * were removed from (the lines before it and the lines after), cut to the file, and merged when
 * they overlap or touch. A file the change emptied has the window 0 to 0, to show what it removed.
 */
function windowsOf(change: SliceInput, total: number, context: number): [number, number][] {
  if (total === 0) return change.removed.some((line) => line.after === 0) ? [[0, 0]] : [];
  const spans: [number, number][] = [];
  for (const line of change.added) spans.push([line - context, line + context]);
  for (const after of new Set(change.removed.map((line) => line.after))) {
    spans.push([after - context + 1, after + context]);
  }
  const windows: [number, number][] = [];
  for (const [from, to] of spans.sort((a, b) => a[0] - b[0])) {
    const lo = Math.max(1, from);
    const hi = Math.min(total, to);
    if (lo > hi) continue;
    const last = windows[windows.length - 1];
    if (last !== undefined && lo <= last[1] + 1) last[1] = Math.max(last[1], hi);
    else windows.push([lo, hi]);
  }
  return windows;
}

/**
 * The rows of the slices of one change, printed with the real new-side line numbers: a header
 * `@@ <path> lines a–b of T @@` for each window, then its rows. A row is the line number
 * right-aligned, then `+` for an added line or a space for an unchanged one, then the text; a row
 * for a removed line has no number and a `-`.
 */
function* sliceRows(change: SliceInput, text: TextLines, contextLines: number): Generator<string> {
  const total = text.lineCount;
  const windows = windowsOf(change, total, Math.max(1, Math.floor(contextLines)));
  const removedAfter = new Map<number, RemovedLine[]>();
  for (const line of change.removed) {
    const same = removedAfter.get(line.after);
    if (same === undefined) removedAfter.set(line.after, [line]);
    else same.push(line);
  }
  const width = String(total).length;
  const blank = ' '.repeat(width);
  function* removedRows(after: number): Generator<string> {
    for (const line of removedAfter.get(after) ?? []) yield `${blank}-${cutLine(line.text)}`;
  }
  for (const [lo, hi] of windows) {
    yield `@@ ${change.path} lines ${lo}–${hi} of ${total} @@`;
    if (lo <= 1) yield* removedRows(0);
    for (let n = Math.max(lo, 1); n <= hi; n += 1) {
      const mark = change.added.has(n) ? '+' : ' ';
      yield `${String(n).padStart(width)}${mark}${cutLine(text.line(n - 1))}`;
      yield* removedRows(n);
    }
  }
}

/**
 * The slices of one change: its rows, one to a line. The text of the rows is the masked head file's
 * (the lines read_file shows) and the removed lines' (masked with the patch). Empty when there is
 * nothing to print.
 */
export function slicesOf(change: ReviewableChange, contextLines: number = CONTEXT_LINES): string {
  const { text } = change;
  if (text === null || change.unshown !== null) return '';
  return [...sliceRows(change, text, contextLines)].join('\n');
}

/**
 * How many characters the slices of a change come to, counted row by row and not made: a count
 * that stops once it is past `limit`, as it cannot fit then.
 */
function sliceChars(change: SliceInput, text: TextLines, limit: number): number {
  let size = 0;
  for (const row of sliceRows(change, text, CONTEXT_LINES)) {
    // A row and the line end that follows it; the last has none.
    size += row.length + 1;
    if (size - 1 > limit) break;
  }
  return Math.max(0, size - 1);
}

/** Sensitive files first, then the most changed lines, then by path. */
function bySlicePriority(a: ReviewableChange, b: ReviewableChange): number {
  if (a.sensitive !== b.sensitive) return a.sensitive ? -1 : 1;
  if (a.changedLines !== b.changedLines) return b.changedLines - a.changedLines;
  if (a.path === b.path) return 0;
  return a.path < b.path ? -1 : 1;
}

/** Where to read a change whose slices the model does not get: its file, when the snapshot has one. */
function toRead(change: ReviewableChange): string {
  return change.lines === null ? notInSnapshot(change) : fileToRead(change, change.lines);
}

const notInSnapshot = (change: ReviewableChange): string =>
  `${change.path}: changed, its text is not in the snapshot`;
const fileToRead = (change: ReviewableChange, lines: number): string =>
  `${change.path} (${plural(lines, 'line')}): changed, read it with read_file`;

/**
 * A change whose slices would not fit in the room that is left of them: nothing of it is shown.
 * The line names the file's length, which is what the model reads (not the lines that changed).
 */
const noRoom = (change: ReviewableChange): string => toRead(change);

/** The secrets replaced so far in the texts the prompt shows. */
interface Tally {
  redactions: number;
}

/**
 * The slices that fit in `sliceChars`, in order of importance, and what is left out. This is
 * where the review's masking goes: a change is masked, its file and then its patch, only when its
 * slices fit in the room that is left, known from the stored texts before anything is masked, so a
 * merge request of thousands of files costs the masking of those that are shown. A change that does
 * not fit is left out whole, and the changes after it that do fit are still shown. Every change
 * that has no slices is listed, with the reason, except a deleted file: the first `maxListed`
 * (the caps' `notInSlices`) in order of importance, then the number of the others.
 */
async function cutSlices(input: CutInput): Promise<{
  slices: string;
  omitted: string[];
  unlisted: number;
}> {
  const cut: Cut = { parts: [], omitted: [], used: 0 };
  const order = [...input.candidates].sort((a, b) => bySlicePriority(a.change, b.change));
  for (const candidate of order) await cutOne(cut, candidate, input);
  const listed = cut.omitted.slice(0, input.maxListed);
  return {
    slices: cut.parts.join('\n'),
    omitted: listed,
    unlisted: cut.omitted.length - listed.length,
  };
}

/** What the cutting of the slices needs: the candidates, how the texts are read and masked, and the room. */
interface CutInput {
  candidates: readonly Candidate[];
  files: MaskedFiles;
  masker: Masker;
  mask: Mask;
  options: ContextOptions;
  tally: Tally;
  sliceChars: number;
  maxListed: number;
}

/** The slices cut so far, the changes left out, and the characters the slices take. */
interface Cut {
  parts: string[];
  omitted: string[];
  used: number;
}

function leaveOut(cut: Cut, change: ReviewableChange, why: 'timeout' | 'budget'): void {
  change.unshown = why;
  cut.omitted.push(`${change.path}: not shown: ${WHY[why]}`);
}

/** Whether the change is settled before its file is read: it is listed, or left out, or has nothing to show. */
function settledUnread(cut: Cut, { change, size }: Candidate, input: CutInput): boolean {
  if (change.unshown === 'deleted') return true;
  if (change.unshown !== null) {
    cut.omitted.push(toRead(change));
    return true;
  }
  if (size === 0) {
    // A patch too large to send says nothing of what changed: a file to read. One with no line
    // in it (a rename, a mode) has nothing to show.
    if (!change.hasPatch) cut.omitted.push(toRead(change));
    return true;
  }
  // Before the room: once the time for masking is spent, what the model is told is that the
  // change could not be masked, whether or not it would have fitted.
  if (input.masker.exhausted) {
    leaveOut(cut, change, 'budget');
    return true;
  }
  if (cut.used + joinerOf(cut) + size > input.sliceChars) {
    cut.omitted.push(noRoom(change));
    return true;
  }
  return false;
}

const joinerOf = (cut: Cut): number => (cut.parts.length === 0 ? 0 : 1);

async function cutOne(cut: Cut, candidate: Candidate, input: CutInput): Promise<void> {
  if (settledUnread(cut, candidate, input)) return;
  const { change, patch } = candidate;
  const { files, mask, tally } = input;
  const joiner = joinerOf(cut);
  const file = await files.file(change.path, input.options.budget);
  if (file.kind === 'budget' || file.kind === 'timeout') {
    leaveOut(cut, change, file.kind);
    return;
  }
  if (file.kind !== 'text') {
    // The snapshot no longer has the text it had when it was read to tell what the file is.
    change.unshown = 'no_text';
    cut.omitted.push(notInSnapshot(change));
    return;
  }
  let redactions = file.redactions;
  if (patch !== null) {
    const facts = patchFacts({ status: change.status, patch }, change.lines);
    const shown = await removedLines(patch, facts, mask);
    change.removed = shown.removed;
    redactions += shown.redactions;
  }
  const slice = [...sliceRows(change, file.text, CONTEXT_LINES)].join('\n');
  if (cut.used + joiner + slice.length > input.sliceChars) {
    // What the masking put in the place of a secret is longer than the secret was. Nothing of
    // the change is shown, so it keeps none of its removed rows and counts none of its
    // replacements; those of its file are the next request's to report.
    change.removed = [];
    files.giveBack(change.path);
    cut.omitted.push(noRoom(change));
    return;
  }
  tally.redactions += redactions;
  cut.parts.push(slice);
  cut.used += joiner + slice.length;
  change.text = files.keptText(change.path);
}

// ─── The review's context ────────────────────────────────────────────────────

/**
 * The masking of the texts of the review's context: the review's masker, and the review's budget of
 * bytes, which the tools spend from too. A text that does not fit what is left is not masked
 * (`budget`); one the masker did not mask is not charged.
 */
function chargedMask(masker: Masker, budget: MaskBudget): Mask {
  return async (text) => {
    const bytes = Buffer.byteLength(text, 'utf8');
    if (bytes > budget.maskedBytes) return { kind: 'budget' };
    budget.maskedBytes -= bytes;
    try {
      const result = await masker.mask(text);
      // The review had no time left: nothing was masked, and the bytes are not spent.
      if (result.kind === 'budget') budget.maskedBytes += bytes;
      return result;
    } catch (error) {
      budget.maskedBytes += bytes;
      throw error;
    }
  };
}

/** A text masked as a whole by the review's masker, or the fixed note for one it gave up on. */
async function shownText(mask: Mask, text: string, tally: Tally): Promise<string> {
  if (text === '') return text;
  const result = await mask(text);
  switch (result.kind) {
    case 'masked':
      tally.redactions += result.count;
      return result.text;
    case 'timeout':
    case 'budget':
      return notShown(result.kind);
  }
}

/** `text` cut to `max` characters, with a label that says it was and how long it is. */
function cutWithLabel(text: string, max: number): string {
  const chars = [...text];
  if (chars.length <= max) return text;
  return `${chars.slice(0, max).join('')}${cutLabel(chars.length, max)}`;
}

/** The label of a text of `total` characters cut to `max`. */
const cutLabel = (total: number, max: number): string =>
  `\n[cut: the text has ${total} characters, only the first ${max} are shown]`;

/** The characters a text takes once cut to `max`: all of it, or `max` and, cut with a label, the label. */
function shownChars(text: string | null, max: number, labelled: boolean): number {
  if (text === null) return 0;
  const total = [...text].length;
  if (total <= max) return total;
  return labelled ? max + cutLabel(total, max).length : max;
}

/** A limit the review gave, held to whole characters from 0 to `max`; one that is no number is 0. */
const heldTo = (limit: number, max: number): number =>
  Number.isNaN(limit) ? 0 : Math.min(max, Math.max(0, Math.floor(limit)));

/**
 * The meta of the snapshot with the texts the prompt may show: masked, cut (each instructions file
 * at `instructionsChars`), and labelled.
 */
async function shownMeta(
  meta: SnapshotMeta,
  mask: Mask,
  tally: Tally,
  options: ContextOptions,
  instructionsChars: number,
  dropOver: number,
): Promise<SnapshotMeta> {
  const instructions: { name: string; text: string }[] = [];
  for (const file of shownInstructions(meta, options)) {
    if (file.text.length > dropOver) continue;
    instructions.push({
      name: file.name,
      text: cutWithLabel(await shownText(mask, file.text, tally), instructionsChars),
    });
  }
  const mrTitle =
    meta.mrTitle === null
      ? null
      : cutAtGrapheme(await shownText(mask, meta.mrTitle, tally), TITLE_CHARS);
  const mrDescription =
    meta.mrDescription === null
      ? null
      : cutWithLabel(await shownText(mask, meta.mrDescription, tally), DESCRIPTION_CHARS);
  return { ...meta, mrTitle, mrDescription, instructions };
}

/** The instructions files the model may be shown: not one on a path the administrator keeps out. */
const shownInstructions = (meta: SnapshotMeta, options: ContextOptions) =>
  meta.instructions.filter((file) => !options.excluded(file.name));

/**
 * The analyzers' findings, as stored: asked for on the paths of the reviewed changes (so not for a
 * lock file, nor for a path the administrator keeps out), and only those are kept.
 */
async function analyzerOnReviewed(
  findings: ReviewFindings,
  reviewed: readonly ReviewableChange[],
): Promise<AnalyzerFinding[]> {
  const reviewedPaths = new Set(reviewed.map((change) => change.path));
  const found = await findings.analyzer([...reviewedPaths]);
  return found.filter((finding) => reviewedPaths.has(finding.path));
}

/**
 * The findings with their texts masked: the analyzers' on the reviewed paths, and an earlier
 * review's on any path but the ones the administrator keeps out.
 */
async function shownFindings(
  analyzerFound: readonly AnalyzerFinding[],
  priorFound: readonly PriorFinding[],
  mask: Mask,
  tally: Tally,
  options: ContextOptions,
): Promise<{ analyzer: AnalyzerFinding[]; prior: PriorFinding[] }> {
  const analyzer: AnalyzerFinding[] = [];
  for (const finding of analyzerFound) {
    analyzer.push({ ...finding, message: await shownText(mask, finding.message, tally) });
  }
  const prior: PriorFinding[] = [];
  for (const finding of priorFound) {
    if (options.excluded(finding.path)) continue;
    prior.push({
      ...finding,
      title: await shownText(mask, finding.title, tally),
      body: await shownText(mask, finding.body, tally),
    });
  }
  return { analyzer, prior };
}

/**
 * What a review is given, read from the snapshot `files` is of: the reviewed changes and their
 * slices, and the snapshot's words, masked, cut and labelled. The job passes the findings
 * `analyzerFindings` (bound to the analysis) and `priorAiFindings` read; the evaluation passes
 * none. `masker` is the review's, which `files` and the tools use too, and its caller closes: it
 * rejects here once it is closed or its signal has aborted. The administrator's excluded paths, the
 * review's budget of bytes for masking and the limits of what it shows are `options`.
 *
 * What is read to choose comes first and costs no masking: the changes, what each of them is, and
 * the analyzers' findings on them, with which the review's limits are asked. Then the masking: the
 * words first, then the findings, then the files; what the slices take of the masking that is
 * left, they take last.
 */
export async function buildReviewContext(
  files: MaskedFiles,
  masker: Masker,
  findings: ReviewFindings,
  options: ContextOptions,
): Promise<ReviewContext> {
  const { reader } = files;
  const mask = chargedMask(masker, options.budget);
  const tally: Tally = { redactions: 0 };
  const { candidates, skipped } = await classify(await reader.changes(), files, options);
  const reviewed = candidates.map((candidate) => candidate.change);
  const found = await analyzerOnReviewed(findings, reviewed);
  const { meta: stored } = reader;
  const limits = options.limits({
    reviewed,
    skipped,
    analyzerChars: found.map((f) => f.path.length + f.ruleKey.length + f.message.length),
    wordsChars:
      shownChars(stored.mrTitle, TITLE_CHARS, false) +
      shownChars(stored.mrDescription, DESCRIPTION_CHARS, true),
    instructionChars: shownInstructions(stored, options).map((file) => file.text.length),
  });
  const instructionsChars = heldTo(limits.instructionsChars, CONTEXT_MAXIMA.instructionsChars);
  // The window has no room to cut a long file to: it is left out, not even a label.
  const dropOver = limits.instructionsDropLonger === true ? instructionsChars : Infinity;
  const meta = await shownMeta(reader.meta, mask, tally, options, instructionsChars, dropOver);
  const { analyzer, prior } = await shownFindings(found, findings.prior, mask, tally, options);
  const { slices, omitted, unlisted } = await cutSlices({
    candidates,
    files,
    masker,
    mask,
    options,
    tally,
    sliceChars: heldTo(limits.sliceChars, CONTEXT_MAXIMA.sliceChars),
    maxListed: limits.lists.notInSlices,
  });
  return {
    meta,
    reviewed,
    skipped,
    slices,
    omittedFromSlices: omitted,
    unlistedFromSlices: unlisted,
    listCaps: limits.lists,
    ...(limits.instructionsShortened === true ? { instructionsShortened: true } : {}),
    analyzer,
    prior,
    redactions: tally.redactions,
  };
}
