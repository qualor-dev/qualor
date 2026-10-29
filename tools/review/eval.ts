import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { MAX_SNAPSHOT_PATCH_BYTES } from '@qualor/shared';
import { diffHeaderLine, DiffSplitter } from '../../cli/src/git/diff';
import { AI_CATEGORIES, type AiCategory } from '../../server/src/db/schema';
import { costOf } from '../../server/src/llm/job';
import type { PricePair } from '../../server/src/llm/settings';
import type { WrapUpReason } from '../../server/src/review/conversation';
import { buildReviewContext, SCOPE_MARGIN } from '../../server/src/review/context';
import { planFindings, type PlannedFinding } from '../../server/src/review/findings';
import { renderFinding } from '../../server/src/review/findings-render';
import { MaskedFiles } from '../../server/src/review/masked-files';
import { Masker } from '../../server/src/review/masker';
import type { ModelTier } from '../../server/src/review/model-tiers';
import { parsePatch } from '../../server/src/review/patch';
import {
  reviewFits,
  reviewLimits,
  runReviewPipeline,
  type PipelineDeps,
} from '../../server/src/review/pipeline';
import type { ReviewRole } from '../../server/src/review/prompts';
import { DEFAULT_REVIEW_BUDGETS } from '../../server/src/review/schema';
import {
  linesOf,
  memorySnapshotReader,
  type SnapshotChange,
  type SnapshotReader,
} from '../../server/src/review/snapshot-reader';
import { maskedHead, type ReviewPrepareDeps } from '../../server/src/review/store';
import {
  DEFAULT_CONTEXT_WINDOW_TOKENS,
  newToolPolicy,
} from '../../server/src/review/tool-conversation';
import { TOOL_LIMITS, type ToolPolicy } from '../../server/src/review/tools';

/*
 * Plan 6I-3 Task 14 (spec §12): the evaluation set of the AI review, and the harness that scores
 * a reviewer on it. A case is a small merge request written for this set: the files of the merge
 * base (`base/`) and of the head (`head/`), the patch between them (`patch.diff`, made from the two
 * by make-case.mjs), and `case.json`: what the merge request is called and says, whether it is
 * clean, and the problems it seeds.
 *
 * A review of a case is the server's own, minus the database: the case becomes a snapshot in memory,
 * the context is built from it (masked as the job masks it), the pipeline runs with the reviewer
 * the caller supplies (a script in the tests; the provider through pnpm review:live), and the
 * findings are placed and made as the job stores and posts them (planFindings, renderFinding). The
 * scores are counts, never texts: a report holds no line of a fixture and nothing a model said.
 */

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

/** The evaluation set, as it is committed. */
export const EVAL_DIR = path.join(root, 'fixtures', 'review-eval');

/**
 * How far from the lines of a seeded problem a finding, or the thread of a finding, may be and
 * still be on it: the margin the review itself allows a finding around the lines it may raise
 * findings on.
 */
const TOLERANCE = 3;

/** The tokens one review may use: the default ceiling of a review in the AI review settings. */
const REVIEW_TOKENS = DEFAULT_REVIEW_BUDGETS.maxTokensPerReview;

// ─── The cases ───────────────────────────────────────────────────────────────

/** A problem a case seeds: its category, and the lines (inclusive, of the head file) it is on. */
export interface ExpectedProblem {
  category: AiCategory;
  path: string;
  lines: [number, number];
}

export interface EvalCase {
  /** The name of the case's directory. */
  id: string;
  language: string;
  /** What the merge request is called and says. */
  title: string;
  description: string;
  /** Nothing is wrong with it: any finding on it is a false one. */
  clean: boolean;
  expected: ExpectedProblem[];
  /** The head tree: the text of each file, by path. */
  files: Readonly<Record<string, string>>;
  /** What the merge request changed, one change for each file that differs, with its patch. */
  changes: SnapshotChange[];
}

type Fail = (message: string) => never;

/** The order of two texts by their UTF-16 code units, as `<` compares them. */
export const compareText = (a: string, b: string): number => {
  if (a === b) return 0;
  return a < b ? -1 : 1;
};

interface CaseFile {
  language: string;
  title: string;
  description: string;
  clean: boolean;
  expected: ExpectedProblem[];
}

const CASE_KEYS: readonly string[] = ['language', 'title', 'description', 'clean', 'expected'];
const PROBLEM_KEYS: readonly string[] = ['category', 'path', 'lines'];

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const isCategory = (value: unknown): value is AiCategory =>
  AI_CATEGORIES.some((category) => category === value);

function textOf(raw: Record<string, unknown>, key: string, where: string, fail: Fail): string {
  const value = raw[key];
  if (typeof value !== 'string' || value.trim() === '') {
    return fail(`case.json: ${where}${key} must be a non-empty string`);
  }
  return value;
}

function problemOf(raw: unknown, index: number, fail: Fail): ExpectedProblem {
  const where = `expected[${index}]`;
  if (!isRecord(raw)) return fail(`case.json: ${where} must be an object`);
  for (const key of Object.keys(raw)) {
    if (!PROBLEM_KEYS.includes(key)) fail(`case.json: ${where}.${key} is not a key of a problem`);
  }
  const { category, lines } = raw;
  if (!isCategory(category)) {
    return fail(`case.json: ${where}.category must be one of ${AI_CATEGORIES.join(', ')}`);
  }
  const wholeLine = (n: unknown): n is number =>
    typeof n === 'number' && Number.isSafeInteger(n) && n >= 1;
  const [from, to] = Array.isArray(lines) && lines.length === 2 ? (lines as unknown[]) : [];
  if (!wholeLine(from) || !wholeLine(to) || to < from) {
    return fail(
      `case.json: ${where}.lines must be two line numbers from 1, the second not before the first`,
    );
  }
  return { category, path: textOf(raw, 'path', `${where}.`, fail), lines: [from, to] };
}

function parseCaseFile(text: string, fail: Fail): CaseFile {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return fail('case.json is not JSON');
  }
  if (!isRecord(raw)) return fail('case.json must be an object');
  for (const key of Object.keys(raw)) {
    if (!CASE_KEYS.includes(key)) fail(`case.json: ${key} is not a key of a case`);
  }
  const { description, clean, expected } = raw;
  if (typeof description !== 'string') return fail('case.json: description must be a string');
  if (typeof clean !== 'boolean') return fail('case.json: clean must be true or false');
  if (!Array.isArray(expected)) return fail('case.json: expected must be a list');
  const problems = expected.map((item, index) => problemOf(item, index, fail));
  if (clean !== (problems.length === 0)) {
    return fail(
      'case.json: clean must be true for a case that expects nothing, false for any other',
    );
  }
  return {
    language: textOf(raw, 'language', '', fail),
    title: textOf(raw, 'title', '', fail),
    description,
    clean,
    expected: problems,
  };
}

/** The text files under `dir`, by path with `/`; none when there is no such directory. */
function readTree(dir: string): Map<string, string> {
  const tree = new Map<string, string>();
  if (!existsSync(dir)) return tree;
  const files = readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => path.join(entry.parentPath, entry.name))
    .sort();
  for (const file of files) {
    const relative = path.relative(dir, file).split(path.sep).join('/');
    tree.set(relative, readFileSync(file, 'utf8').replaceAll('\r\n', '\n'));
  }
  return tree;
}

/** A file that differs between base/ and head/, or is in only one of them. */
interface Changed {
  path: string;
  status: 'added' | 'deleted' | 'modified';
}

function changedFiles(base: ReadonlyMap<string, string>, head: ReadonlyMap<string, string>) {
  const paths = [...new Set([...base.keys(), ...head.keys()])].sort();
  return paths.flatMap((p): Changed[] => {
    const before = base.get(p);
    const after = head.get(p);
    if (before === undefined) return [{ path: p, status: 'added' }];
    if (after === undefined) return [{ path: p, status: 'deleted' }];
    return before === after ? [] : [{ path: p, status: 'modified' }];
  });
}

/** patch.diff cut into the piece of each file, by its `diff --git` line. */
function piecesOf(patch: string, fail: Fail): Map<string, string> {
  const pieces = new Map<string, string>();
  const splitter = new DiffSplitter(MAX_SNAPSHOT_PATCH_BYTES, (header, bytes) => {
    if (bytes === null) fail(`patch.diff: the piece for ${header} is over the snapshot's limit`);
    if (pieces.has(header)) fail(`patch.diff has two pieces for ${header}`);
    pieces.set(header, bytes.toString('utf8'));
  });
  splitter.push(Buffer.from(patch.replaceAll('\r\n', '\n'), 'utf8'));
  splitter.end();
  return pieces;
}

type Hunks = NonNullable<ReturnType<typeof parsePatch>>['hunks'];

/** The lines the hunks of `p` make from its base/ `before`; a hunk that does not fit fails. */
function applyHunks(p: string, hunks: Hunks, before: readonly string[], fail: Fail): string[] {
  const made: string[] = [];
  let at = 0;
  for (const hunk of hunks) {
    // A hunk with no old line (`-5,0`) goes after the line its start names; any other starts at it.
    const oldRows = hunk.rows.filter((row) => row.kind !== '+').length;
    const copyTo = oldRows === 0 ? hunk.oldStart : hunk.oldStart - 1;
    if (copyTo < at || copyTo > before.length) {
      return fail(`the hunks of ${p} do not follow its lines in base/`);
    }
    for (const line of before.slice(at, copyTo)) made.push(line);
    at = applyRows(p, hunk.rows, before, copyTo, made, fail);
  }
  for (const line of before.slice(at)) made.push(line);
  return made;
}

/** The rows of one hunk, applied from line `from` of `before` onto `made`: where it ends. */
function applyRows(
  p: string,
  rows: Hunks[number]['rows'],
  before: readonly string[],
  from: number,
  made: string[],
  fail: Fail,
): number {
  let at = from;
  for (const row of rows) {
    if (row.kind === 'removed-marker') {
      return fail(`the patch of ${p} holds a removed-line marker`);
    }
    if (row.kind !== '+') {
      if (before[at] !== row.text) {
        return fail(`line ${at + 1} of ${p} in patch.diff differs from base/`);
      }
      at += 1;
    }
    if (row.kind !== '-') made.push(row.text);
  }
  return at;
}

/**
 * Applies the patch of one file to its base/ lines, and compares what it makes with the head/ file
 * (null: no such file, as when the patch deletes it). The server's parser reads the patch.
 */
function checkPatchOf(
  p: string,
  piece: string,
  base: readonly string[] | null,
  head: readonly string[] | null,
  fail: Fail,
): void {
  const parsed = parsePatch(piece);
  if (parsed === null) return fail(`the patch of ${p} is not a unified diff`);
  const made = applyHunks(p, parsed.hunks, base ?? [], fail);
  if (head === null) {
    if (made.length > 0) {
      fail(`the patch of ${p} has lines of the new side, but head/ has no such file`);
    }
    return;
  }
  for (let i = 0; i < Math.max(made.length, head.length); i += 1) {
    if (made[i] !== head[i]) return fail(`line ${i + 1} of ${p} differs from head/`);
  }
}

/** Fails when a seeded problem is outside `head/`: in a file it does not have, or past its end. */
function checkExpected(
  expected: readonly ExpectedProblem[],
  head: ReadonlyMap<string, string>,
  fail: Fail,
): void {
  for (const problem of expected) {
    const text = head.get(problem.path);
    if (text === undefined) return fail(`expected path ${problem.path} is not in head/`);
    const count = linesOf(text).length;
    if (problem.lines[1] > count) {
      return fail(
        `expected lines ${problem.lines[0]}-${problem.lines[1]} of ${problem.path} are outside the file (${count} lines)`,
      );
    }
  }
}

function readCase(dir: string, id: string): EvalCase {
  const fail: Fail = (message) => {
    throw new Error(`${id}: ${message}`);
  };
  const caseFile = path.join(dir, 'case.json');
  if (!existsSync(caseFile)) return fail('case.json is missing');
  const file = parseCaseFile(readFileSync(caseFile, 'utf8'), fail);

  const head = readTree(path.join(dir, 'head'));
  if (head.size === 0) return fail('head/ has no files');
  checkExpected(file.expected, head, fail);

  const patchFile = path.join(dir, 'patch.diff');
  if (!existsSync(patchFile)) return fail('patch.diff is missing');
  const base = readTree(path.join(dir, 'base'));
  const changed = changedFiles(base, head);
  const byHeader = new Map(changed.map((c) => [diffHeaderLine(c.path, c.path), c]));
  const changes = new Map<string, SnapshotChange>();
  for (const [header, piece] of piecesOf(readFileSync(patchFile, 'utf8'), fail)) {
    const c = byHeader.get(header);
    if (c === undefined) {
      const named = /^diff --git a\/(.+) b\/.+$/.exec(header)?.[1] ?? header;
      return fail(`patch.diff changes ${named}, which neither base/ nor head/ has changed`);
    }
    const before = base.get(c.path);
    const after = head.get(c.path);
    checkPatchOf(
      c.path,
      piece,
      before === undefined ? null : linesOf(before),
      after === undefined ? null : linesOf(after),
      fail,
    );
    changes.set(c.path, {
      path: c.path,
      oldPath: null,
      status: c.status,
      patch: piece,
      since: null,
    });
  }
  for (const c of changed) {
    if (!changes.has(c.path)) {
      return fail(`patch.diff has no change for ${c.path}, which differs between base/ and head/`);
    }
  }
  return {
    id,
    language: file.language,
    title: file.title,
    description: file.description,
    clean: file.clean,
    expected: file.expected,
    files: Object.fromEntries(head),
    changes: [...changes.values()].sort((a, b) => compareText(a.path, b.path)),
  };
}

/**
 * The cases under `dir`, one for each directory, in the order of their names. A case that is wrong
 * fails the load, with its name: a `case.json` the schema does not accept, an
 * expected problem outside `head/`, a patch that does not make `head/` from `base/` (a hunk whose
 * lines differ from either, a changed file with no change in the patch, a patched file that
 * neither tree has changed), or no patch. A file the patch deletes needs no file in `head/`.
 */
export function loadCases(dir: string): EvalCase[] {
  return readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort()
    .map((id) => readCase(path.join(dir, id), id));
}

// ─── Reviewing a case ────────────────────────────────────────────────────────

/** One call to the model, as the reviewer measured it: how long it took, and what it used. */
export interface CallRecord {
  role: ReviewRole;
  /** Milliseconds from sending the call to its answer. */
  ms: number;
  /** Every prompt token of the call, the cached ones among them. */
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
}

/** What a reviewer of one case is given besides the data of its conversations. */
export interface CaseRun {
  readonly evalCase: EvalCase;
  /** The case as a snapshot: what the review's tools read. */
  readonly reader: SnapshotReader;
  /** The tools' policy and budget, shared by every conversation of the review. */
  readonly policy: ToolPolicy;
  /** Told of each call to the model, for the report's call lines; a reviewer that skips it has none. */
  readonly recordCall: (call: CallRecord) => void;
}

/** The prices of the calls that go to the model of a tier; null: that model has none. */
export type PricesOf = (tier: ModelTier) => PricePair | null;

export interface EvalDeps {
  /**
   * The pipeline's dependencies for one case: `converse` is one conversation of a role, on the
   * model of the tier it is asked for. The evaluation counts the tokens of every conversation it
   * returns, and costs them at the prices of that tier's model.
   */
  pipelineFor(run: CaseRun): PipelineDeps;
  /** Times each case is reviewed; 1 when left out. */
  runs?: number;
  /**
   * USD for a million tokens: one pair for every call, or the pair of the model of each tier when
   * the tiers have models of their own. The report has a cost only when every call has prices. A
   * conversation costs what the server records for its calls (`costOf`): cached reads and writes
   * at their prices.
   */
  prices?: PricePair | PricesOf | null;
  /**
   * USD: before each review, the evaluation stops once the cost so far has reached it (the review
   * that would start past it does not start; one running finishes). Null, left out, or no cost
   * known (no prices): no cap.
   */
  maxCostUsd?: number | null;
  /**
   * The model's context window, in tokens, which the first messages are sized within as the job
   * sizes them (`reviewLimits`); null or left out: DEFAULT_CONTEXT_WINDOW_TOKENS. `pipelineFor`'s
   * conversations keep each call within it themselves (`ConversationIo.contextWindowTokens`).
   */
  contextWindowTokens?: number | null;
  /** The clock, in milliseconds. */
  now?: () => number;
  /** Told after each review: how many are done, of how many, and the tokens spent so far. */
  progress?: (done: number, total: number, tokens: { input: number; output: number }) => void;
}

/** A finding the review would store, as the evaluation reads it. */
interface Found {
  category: AiCategory;
  path: string;
  line: number;
  endLine: number;
  /**
   * The line its thread sits on, as the job stores it: the first line of the suggestion it keeps,
   * else the added line nearest; null when none is near.
   */
  anchorLine: number | null;
  /** The model wrote a suggestion for it. */
  suggested: boolean;
  /**
   * The job keeps that suggestion, and posts it: it is within SCOPE_MARGIN lines of the finding and
   * passes the review's checks against the masked head file.
   */
  applies: boolean;
}

/** What the conversations of one review spent; the cost is null without prices for every call. */
interface Spent {
  input: number;
  output: number;
  costUsd: number | null;
}

type Review =
  ({ kind: 'reviewed'; found: Found[] } & Spent) | ({ kind: 'failed'; reason: string } & Spent);

/** The tier's prices of every call, or null when there are none: no call has a cost then. */
function pricesOf(prices: EvalDeps['prices']): PricesOf | null {
  if (prices === undefined || prices === null) return null;
  return typeof prices === 'function' ? prices : () => prices;
}

/** The cost so far with one more conversation, as the server prices it; unknown without prices. */
function withCall(
  costUsd: number | null,
  prices: PricePair | null,
  usage: {
    inputTokens: number;
    outputTokens: number;
    cacheReadTokens: number;
    cacheWriteTokens: number;
  },
): number | null {
  const micro = costOf(prices, usage);
  return costUsd === null || micro === null ? null : costUsd + micro / 1_000_000;
}

/** The stages the tokens are counted by: the specialists, the judge, and the verification. */
type Stage = 'specialists' | 'judge' | 'verification';
const STAGES: readonly Stage[] = ['specialists', 'judge', 'verification'];
const stageOf = (role: ReviewRole): Stage => {
  if (role === 'judge') return 'judge';
  return role === 'verify' ? 'verification' : 'specialists';
};

/** The wrap-ups counted: the evaluation gives a review no time limit, so none wraps up for it. */
type Counted = Exclude<WrapUpReason, 'time'>;

/** What the reviews measure besides their findings, summed over every review of the evaluation. */
interface Measures {
  /** Milliseconds of each call the reviewer recorded. */
  callMs: number[];
  maxCallInputTokens: number;
  verification: { run: number; starved: number; confirmed: number; needsValidation: number };
  wrapUps: Record<Counted, number> & {
    byRole: Partial<Record<ReviewRole, Record<Counted, number>>>;
  };
  stageTokens: Record<Stage, number>;
  cache: { read: number; write: number; byStage: Record<Stage, { read: number; write: number }> };
  listsShortened: number;
}

const newMeasures = (): Measures => ({
  callMs: [],
  maxCallInputTokens: 0,
  verification: { run: 0, starved: 0, confirmed: 0, needsValidation: 0 },
  wrapUps: { budget: 0, turns: 0, window: 0, byRole: {} },
  stageTokens: { specialists: 0, judge: 0, verification: 0 },
  cache: {
    read: 0,
    write: 0,
    byStage: {
      specialists: { read: 0, write: 0 },
      judge: { read: 0, write: 0 },
      verification: { read: 0, write: 0 },
    },
  },
  listsShortened: 0,
});

/** The merge request's meta: the case's words, and no earlier review. */
const metaOf = (c: EvalCase) => ({
  snapshotId: null,
  headSha: 'a'.repeat(40),
  baseSha: 'b'.repeat(40),
  sinceSha: null,
  targetBranch: 'main',
  mrTitle: c.title,
  mrDescription: c.description === '' ? null : c.description,
  instructions: [],
  partial: false,
});

/**
 * What the job stores of a planned finding, and so posts: the values `renderFinding` makes of it
 * with the masked head file, read as the store reads it (`maskedHead`: a file that cannot be masked
 * is no text, never a failed review). Its anchor and its suggestion are those values'.
 */
async function foundOf(planned: PlannedFinding, deps: ReviewPrepareDeps): Promise<Found> {
  const { finding, change } = planned;
  const head = await maskedHead(finding.path, change, deps);
  const stored = renderFinding(planned, finding.category, head);
  return {
    category: finding.category,
    path: finding.path,
    line: finding.line,
    endLine: finding.endLine,
    anchorLine: stored.anchorLine,
    suggested: finding.suggestion !== null,
    applies: stored.suggestion !== null,
  };
}

const NO_FINDINGS = { analyzer: () => Promise.resolve([]), prior: [] };

/**
 * A case the review would not run on, as the job skips a merge request (job-context.ts):
 * `too_large` for Tokens per review, `window_too_small` for the model's context window alone.
 */
class CaseSkipped extends Error {
  constructor(readonly detail: 'too_large' | 'window_too_small') {
    super(detail);
    this.name = 'CaseSkipped';
  }
}

/**
 * One review of a case, as the job makes one without a database: the snapshot in memory, its files
 * masked by a masker of the review's own, the context, the pipeline, and the findings it would
 * store (planFindings), as it would store them (`foundOf`). A case the job would skip for its size
 * is not reviewed: it fails with the detail the job gives it (`too_large`, `window_too_small`), and
 * no call is made. A review the window failed fails as `window_full`.
 */
async function reviewCase(
  c: EvalCase,
  deps: EvalDeps,
  priceOf: PricesOf | null,
  measures: Measures,
): Promise<Review> {
  const reader = memorySnapshotReader({
    meta: metaOf(c),
    changes: c.changes,
    files: Object.fromEntries(
      Object.entries(c.files).map(([p, text]) => [p, { kind: 'text' as const, text }]),
    ),
  });
  const masker = new Masker();
  const window = deps.contextWindowTokens ?? DEFAULT_CONTEXT_WINDOW_TOKENS;
  const spent: Spent = { input: 0, output: 0, costUsd: priceOf === null ? null : 0 };
  try {
    const files = new MaskedFiles(reader, { masker });
    const policy = newToolPolicy({ excludePaths: [], masked: files, masker });
    let context;
    try {
      context = await buildReviewContext(files, masker, NO_FINDINGS, {
        excluded: () => false,
        budget: policy.budget,
        limits: (shape) => {
          if (shape.reviewed.length === 0) {
            throw new Error(`${c.id}: nothing in the patch is reviewed`);
          }
          if (!reviewFits(shape, REVIEW_TOKENS, window)) {
            throw new CaseSkipped(
              reviewFits(shape, REVIEW_TOKENS, Number.POSITIVE_INFINITY)
                ? 'window_too_small'
                : 'too_large',
            );
          }
          return reviewLimits(shape, REVIEW_TOKENS, window);
        },
      });
    } catch (err) {
      if (!(err instanceof CaseSkipped)) throw err;
      return { kind: 'failed', reason: err.detail, ...spent };
    }
    // The verifications of this review: they count once it ends scored (a failed review's
    // findings are not, so its verifications would only inflate "rejected or unread").
    const verified = { run: 0, starved: 0 };
    const pipeline = deps.pipelineFor({
      evalCase: c,
      reader,
      policy,
      recordCall: (call) => {
        measures.callMs.push(call.ms);
        measures.maxCallInputTokens = Math.max(measures.maxCallInputTokens, call.inputTokens);
      },
    });
    const outcome = await runReviewPipeline(
      context,
      REVIEW_TOKENS,
      {
        providerKey: pipeline.providerKey,
        converse: async (role, user, nonce, tokenBudget, accept, modelTier, deadline) => {
          const stage = stageOf(role);
          if (role === 'verify') {
            verified.run += 1;
            if (policy.budget.calls === 0) verified.starved += 1;
          }
          const result = await pipeline.converse(
            role,
            user,
            nonce,
            tokenBudget,
            accept,
            modelTier,
            deadline,
          );
          spent.input += result.inputTokens;
          spent.output += result.outputTokens;
          spent.costUsd = withCall(spent.costUsd, priceOf?.(modelTier) ?? null, result);
          measures.stageTokens[stage] += result.inputTokens + result.outputTokens;
          measures.cache.read += result.cacheReadTokens;
          measures.cache.write += result.cacheWriteTokens;
          measures.cache.byStage[stage].read += result.cacheReadTokens;
          measures.cache.byStage[stage].write += result.cacheWriteTokens;
          if (
            result.kind === 'answer' &&
            result.wrappedUp !== null &&
            result.wrappedUp !== 'time'
          ) {
            const { wrapUps } = measures;
            wrapUps[result.wrappedUp] += 1;
            const own = (wrapUps.byRole[role] ??= { budget: 0, turns: 0, window: 0 });
            own[result.wrappedUp] += 1;
          }
          return result;
        },
      },
      () => Promise.resolve(),
      window,
    );
    if (outcome.kind !== 'reviewed') {
      const reason = outcome.kind === 'failed' ? (outcome.detail ?? outcome.reason) : outcome.kind;
      return { kind: 'failed', reason, ...spent };
    }
    measures.verification.run += verified.run;
    measures.verification.starved += verified.starved;
    if (outcome.notes.includes('lists_shortened')) measures.listsShortened += 1;
    for (const finding of outcome.findings) {
      if (finding.verification === 'confirmed') measures.verification.confirmed += 1;
      if (finding.verification === 'needs_validation') measures.verification.needsValidation += 1;
    }
    const found: Found[] = [];
    for (const planned of planFindings(context, outcome).creates) {
      found.push(await foundOf(planned, { files, masker, budget: policy.budget }));
    }
    return { kind: 'reviewed', found, ...spent };
  } finally {
    await masker.close();
  }
}

// ─── Scoring ─────────────────────────────────────────────────────────────────

/**
 * The counts a score is made of, for the reviews of some cases. Each metric is a ratio of two of
 * them, `x/y`.
 */
export interface Tally {
  /** Seeded problems, in all the reviews. */
  problems: number;
  /** ...with a finding on their lines (widened by 3) in the review of their case. */
  found: number;
  /** ...of those found, with a finding of their category. */
  rightCategory: number;
  /** ...of those found, with a finding whose thread sits on their lines (widened by 3). */
  anchored: number;
  /** Suggestions the model made, in findings the review would store. */
  suggestions: number;
  /**
   * ...of them, the ones the review keeps and posts: within SCOPE_MARGIN lines of their finding,
   * and passing its checks.
   */
  applying: number;
  /** Reviews of clean cases. */
  cleanReviews: number;
  /** ...of them, the ones that raised a finding. */
  flagged: number;
  /** The findings raised on clean cases. */
  falseFindings: number;
}

const emptyTally = (): Tally => ({
  problems: 0,
  found: 0,
  rightCategory: 0,
  anchored: 0,
  suggestions: 0,
  applying: 0,
  cleanReviews: 0,
  flagged: 0,
  falseFindings: 0,
});

function addTally(into: Tally, from: Tally): void {
  for (const key of Object.keys(into) as (keyof Tally)[]) into[key] += from[key];
}

/** A finding is on a problem when it is in its file and its lines meet the problem's, widened. */
const onProblem = (f: Found, p: ExpectedProblem): boolean =>
  f.path === p.path && f.line <= p.lines[1] + TOLERANCE && f.endLine >= p.lines[0] - TOLERANCE;

const nearProblem = (line: number, p: ExpectedProblem): boolean =>
  line >= p.lines[0] - TOLERANCE && line <= p.lines[1] + TOLERANCE;

/** What one review of `c` scores, given the findings it would store. */
function scoreReview(c: EvalCase, found: readonly Found[]): Tally {
  const tally = emptyTally();
  for (const problem of c.expected) {
    tally.problems += 1;
    const hits = found.filter((f) => onProblem(f, problem));
    if (hits.length === 0) continue;
    tally.found += 1;
    if (hits.some((f) => f.category === problem.category)) tally.rightCategory += 1;
    if (hits.some((f) => f.anchorLine !== null && nearProblem(f.anchorLine, problem))) {
      tally.anchored += 1;
    }
  }
  if (c.clean) {
    tally.cleanReviews = 1;
    tally.flagged = found.length > 0 ? 1 : 0;
    tally.falseFindings = found.length;
  }
  for (const f of found) {
    if (!f.suggested) continue;
    tally.suggestions += 1;
    if (f.applies) tally.applying += 1;
  }
  return tally;
}

export interface EvalReport {
  cases: number;
  clean: number;
  /** Times each case was reviewed. */
  runs: number;
  /** Reviews made: cases times runs. */
  reviews: number;
  /** Reviews that failed and so found nothing, by the reason the pipeline gave. */
  failed: Record<string, number>;
  total: Tally;
  /** The same counts for the cases of each language. */
  languages: Record<string, Tally>;
  tokens: { input: number; output: number };
  /** USD; null without prices. */
  costUsd: number | null;
  /** Milliseconds a review took; null without reviews. */
  latencyMs: { min: number; median: number; max: number } | null;
  /** Calls to the model the reviewer recorded. */
  calls: number;
  /** Milliseconds a call took, p95 by nearest rank; null without calls. */
  callLatencyMs: { median: number; p95: number; max: number } | null;
  /** The most input tokens one call sent. */
  maxCallInputTokens: number;
  /**
   * The verifications (one conversation each): how many ran, how they ended among the findings the
   * reviews kept, and how many found the review's tool calls used up (the floor,
   * `TOOL_LIMITS.verifyCallsFloor`, gave them calls of their own).
   */
  verification: {
    run: number;
    confirmed: number;
    needsValidation: number;
    rejectedOrUnread: number;
    starved: number;
  };
  /** Conversations that wrapped up, by why and by role. */
  wrapUps: {
    budget: number;
    turns: number;
    window: number;
    byRole: Partial<Record<ReviewRole, { budget: number; turns: number; window: number }>>;
  };
  /** Input and output tokens of the conversations of each stage. */
  stageTokens: { specialists: number; judge: number; verification: number };
  /** Prompt-cache reads and writes, in all and by stage; hitRate = read / every input token. */
  cache: {
    read: number;
    write: number;
    hitRate: number | null;
    byStage: Record<Stage, { read: number; write: number }>;
  };
  /** Reviews that shortened the lists of the first message (the note `lists_shortened`). */
  listsShortened: number;
  /** The evaluation stopped before its last review: the cost had reached the cap. */
  stoppedAtCostCap: boolean;
  /**
   * The evaluation stopped before its last review because a cost cap was set and a review's cost
   * was unknown (a call had no prices), so the cap could not be kept.
   */
  stoppedAtUnknownCost: boolean;
}

/** The median of sorted values: the mean of the middle two when their count is even. */
function medianOf(sorted: readonly number[]): number {
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1
    ? (sorted[mid] ?? 0)
    : ((sorted[mid - 1] ?? 0) + (sorted[mid] ?? 0)) / 2;
}

function spread(values: readonly number[]): EvalReport['latencyMs'] {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return { min: sorted[0] ?? 0, median: medianOf(sorted), max: sorted[sorted.length - 1] ?? 0 };
}

/** Median, p95 (nearest rank: the value at ceil(0.95 n)) and max of the latencies of the calls. */
function callSpread(values: readonly number[]): EvalReport['callLatencyMs'] {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return {
    median: medianOf(sorted),
    p95: sorted[Math.ceil(0.95 * sorted.length) - 1] ?? 0,
    max: sorted[sorted.length - 1] ?? 0,
  };
}

/** Why no further review starts, or null: the cost cap is reached, or a cost came back unknown. */
function stopBeforeReview(
  cap: number | null,
  done: number,
  costUsd: number | null,
): 'unknown_cost' | 'cost_cap' | null {
  if (cap === null) return null;
  // A review's cost came back unknown: the cap cannot be kept, so no quiet uncapped run.
  if (done > 0 && costUsd === null) return 'unknown_cost';
  return costUsd !== null && costUsd >= cap ? 'cost_cap' : null;
}

/**
 * Reviews every case `deps.runs` times, one after the other, and scores the reviews: how many
 * seeded problems have a finding on them, with their category and with their thread on their lines;
 * how many suggestions pass the checks; how many clean cases got a finding; and what the reviews
 * spent. A review that fails finds nothing, and is counted as failed with the reason.
 */
export async function runEval(cases: readonly EvalCase[], deps: EvalDeps): Promise<EvalReport> {
  const runs = deps.runs ?? 1;
  const now = deps.now ?? (() => performance.now());
  const priceOf = pricesOf(deps.prices);
  const report: EvalReport = {
    cases: cases.length,
    clean: cases.filter((c) => c.clean).length,
    runs,
    reviews: cases.length * runs,
    failed: {},
    total: emptyTally(),
    languages: {},
    tokens: { input: 0, output: 0 },
    costUsd: null,
    latencyMs: null,
    calls: 0,
    callLatencyMs: null,
    maxCallInputTokens: 0,
    verification: { run: 0, confirmed: 0, needsValidation: 0, rejectedOrUnread: 0, starved: 0 },
    wrapUps: { budget: 0, turns: 0, window: 0, byRole: {} },
    stageTokens: { specialists: 0, judge: 0, verification: 0 },
    cache: { read: 0, write: 0, hitRate: null, byStage: newMeasures().cache.byStage },
    listsShortened: 0,
    stoppedAtCostCap: false,
    stoppedAtUnknownCost: false,
  };
  const measures = newMeasures();
  const planned = report.reviews;
  const latencies: number[] = [];
  let costUsd: number | null = priceOf === null ? null : 0;
  let done = 0;
  const cap = deps.maxCostUsd ?? null;
  // Every case, once for each run, one run after the other.
  for (const c of Array.from({ length: runs }, () => cases).flat()) {
    // The cap is checked before a review starts: the one running finishes.
    const stop = stopBeforeReview(cap, done, costUsd);
    report.stoppedAtUnknownCost = stop === 'unknown_cost';
    report.stoppedAtCostCap = stop === 'cost_cap';
    if (stop !== null) break;
    const started = now();
    const review = await reviewCase(c, deps, priceOf, measures);
    latencies.push(now() - started);
    report.tokens.input += review.input;
    report.tokens.output += review.output;
    costUsd = costUsd === null || review.costUsd === null ? null : costUsd + review.costUsd;
    if (review.kind === 'failed') {
      report.failed[review.reason] = (report.failed[review.reason] ?? 0) + 1;
    }
    const score = scoreReview(c, review.kind === 'reviewed' ? review.found : []);
    addTally(report.total, score);
    const tally = report.languages[c.language] ?? emptyTally();
    report.languages[c.language] = tally;
    addTally(tally, score);
    done += 1;
    deps.progress?.(done, planned, { ...report.tokens });
  }
  // Reviews made: fewer than cases times runs when the cost cap stopped the evaluation.
  report.reviews = done;
  report.latencyMs = spread(latencies);
  report.costUsd = costUsd;
  report.calls = measures.callMs.length;
  report.callLatencyMs = callSpread(measures.callMs);
  report.maxCallInputTokens = measures.maxCallInputTokens;
  const { run: verified, confirmed, needsValidation, starved } = measures.verification;
  report.verification = {
    run: verified,
    confirmed,
    needsValidation,
    rejectedOrUnread: verified - confirmed - needsValidation,
    starved,
  };
  report.wrapUps = measures.wrapUps;
  report.stageTokens = measures.stageTokens;
  report.cache = {
    ...measures.cache,
    hitRate: report.tokens.input === 0 ? null : measures.cache.read / report.tokens.input,
  };
  report.listsShortened = measures.listsShortened;
  return report;
}

// ─── Printing ────────────────────────────────────────────────────────────────

/** `x/y (p%)`; `(-)` without a y. */
const ratio = (x: number, y: number): string => {
  const percent = y === 0 ? '-' : `${Math.round((100 * x) / y)}%`;
  return `${x}/${y} (${percent})`;
};

const COLUMNS = ['recall', 'category', 'anchors', 'suggestions', 'false findings'];

const cellsOf = (t: Tally): string[] => [
  ratio(t.found, t.problems),
  ratio(t.rightCategory, t.found),
  ratio(t.anchored, t.found),
  ratio(t.applying, t.suggestions),
  ratio(t.flagged, t.cleanReviews),
];

const seconds = (ms: number): string => `${(ms / 1000).toFixed(1)} s`;
const count = (n: number): string => n.toLocaleString('en-US');

/**
 * The report as text, aggregates only: the scores by language and in total, the tokens, the cost
 * when there are prices, and the time of a review. It holds no line of a fixture, no path of a
 * seeded problem and nothing a model said; the report it is made from holds none either.
 */
export function formatReport(report: EvalReport): string {
  const rows: string[][] = [
    ['', ...COLUMNS],
    ...Object.keys(report.languages)
      .sort()
      .map((language) => [language, ...cellsOf(report.languages[language] ?? emptyTally())]),
    ['total', ...cellsOf(report.total)],
  ];
  const widths = (rows[0] ?? []).map((_, i) => Math.max(...rows.map((row) => row[i]?.length ?? 0)));
  const table = rows.map((row) =>
    row
      .map((cell, i) => cell.padEnd(widths[i] ?? 0))
      .join('  ')
      .trimEnd(),
  );
  const failed = Object.entries(report.failed).sort(([a], [b]) => compareText(a, b));
  const failedCount = failed.reduce((sum, [, n]) => sum + n, 0);
  const failedWhy = failed.map(([reason, n]) => `${reason} ${n}`).join(', ');
  const latency = report.latencyMs;
  const callLatency = report.callLatencyMs;
  const { verification, wrapUps, stageTokens, cache } = report;
  const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? '' : 's'}`;
  const byRole = Object.entries(wrapUps.byRole)
    .map(([role, n]) => [role, (n?.budget ?? 0) + (n?.turns ?? 0) + (n?.window ?? 0)] as const)
    .sort(([a], [b]) => compareText(a, b))
    .map(([role, n]) => `${role} ${n}`)
    .join(', ');
  const stage = (name: Stage): string =>
    `${name} ${count(cache.byStage[name].read)}/${count(cache.byStage[name].write)}`;
  const roles = byRole === '' ? '' : ` (${byRole})`;
  const lines = [
    'AI review evaluation',
    `${plural(report.cases, 'case')} (${report.clean} clean), ${plural(report.runs, 'run')} each, ${plural(report.reviews, 'review')}`,
    ...(report.stoppedAtCostCap
      ? [`stopped at the cost cap after ${report.reviews} of ${report.cases * report.runs} reviews`]
      : []),
    ...(report.stoppedAtUnknownCost
      ? [
          `stopped after ${report.reviews} of ${report.cases * report.runs} reviews: the cost of a review was unknown, so the cost cap could not be kept`,
        ]
      : []),
    ...(failedCount === 0 ? [] : [`failed reviews: ${failedCount} (${failedWhy})`]),
    '',
    ...table,
    '',
    `findings on clean cases: ${report.total.falseFindings}`,
    `tokens: ${count(report.tokens.input)} in, ${count(report.tokens.output)} out`,
    ...(report.costUsd === null ? [] : [`cost: $${report.costUsd.toFixed(4)}`]),
    ...(latency === null
      ? []
      : [
          `latency per review: min ${seconds(latency.min)}, median ${seconds(latency.median)}, max ${seconds(latency.max)}`,
        ]),
    ...(callLatency === null
      ? []
      : [
          `model calls: ${report.calls}; per call: median ${seconds(callLatency.median)}, p95 ${seconds(callLatency.p95)}, max ${seconds(callLatency.max)}; largest input ${count(report.maxCallInputTokens)} tokens`,
        ]),
    `verification: ${verification.run} run (${verification.confirmed} confirmed, ${verification.needsValidation} needs validation, ${verification.rejectedOrUnread} rejected or unread), ${verification.starved} found the review's tool calls used up (the floor gave them ${TOOL_LIMITS.verifyCallsFloor})`,
    `wrap-ups: ${wrapUps.budget} at the token budget, ${wrapUps.turns} at the turn limit, ${wrapUps.window} at the context window${roles}`,
    `tokens by stage: specialists ${count(stageTokens.specialists)}, judge ${count(stageTokens.judge)}, verification ${count(stageTokens.verification)}`,
    `cache: ${count(cache.read)} read, ${count(cache.write)} written (hit rate ${cache.hitRate === null ? '-' : (100 * cache.hitRate).toFixed(1)} % of input); ${STAGES.map(stage).join(', ')}`,
    `reviews with shortened lists: ${report.listsShortened}`,
    '',
    `recall: seeded problems with a finding on their lines, or within ${TOLERANCE} lines of them`,
    'category: of those, the problems with a finding of their category',
    `anchors: of those, the problems with a finding whose thread sits on their lines, or within ${TOLERANCE} lines`,
    `suggestions: suggestions the review posts (within ${SCOPE_MARGIN} lines of their finding, passing its checks), of all those made`,
    'false findings: reviews of a clean case that raised a finding',
  ];
  return lines.join('\n');
}
