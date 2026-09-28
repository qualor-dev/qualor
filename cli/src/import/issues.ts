import {
  importCommentHeader,
  SONAR_LINE_HASH,
  SONAR_MAPPING,
  STATUS_IMPORT_MAX_ITEMS,
  type ImportCommentLabel,
  type ImportStatus,
  type SonarIssue,
  type SonarMapping,
  type StatusCompetitorItem,
  type StatusImportItem,
  type StatusImportRequestItem,
  type StatusImportResult,
} from '@qualor/shared';
import { CliError, EXIT } from '../errors';
import { MAX_JSON_BODY_BYTES, UnreachableError } from '../server/http';
import type { QualorApi } from './qualor-api';
import type { SonarClient, SonarConnection } from './sonarqube/client';
import {
  fetchOpenIssues,
  type IssueProbe,
  type ReadBounds,
  reprobeResolvedIssues,
  type UnreadResolved,
} from './sonarqube/fetch';

/** Spec §11.2: the bounds of one item, as the endpoint checks them. */
const MAX_COMMENT = 2000;
const MAX_MESSAGE = 4000;
const MAX_TARGETS = 8;
const MAX_PATH_BYTES = 1024;
const MAX_LINE = 10_000_000;
const MAX_RULE_KEY = 553;
/**
 * Ruling S14: the most SonarQube rules one mapping component may have and still be read for open
 * competitors (the table's largest has 15). A larger one is not read: its items are marked.
 */
export const MAX_COMPONENT_RULES = 100;
const REF = /^[A-Za-z0-9_.:-]{1,100}$/;
/** report-format.md §7.1: `<engine>:<rule id>`, as the endpoint checks it. */
const RULE_KEY = /^[a-z0-9][a-z0-9-]{0,39}:[\s\S]{1,512}$/;
/** Spec §10.2: only the day of `updateDate` goes into the comment, and only in this form. */
const DAY = /^(\d{4}-\d{2}-\d{2})(?:T|$)/;
/** Every control character but the tab and the line feed (the server's cleaning, §11.2). */
const CONTROL = /[^\P{Cc}\t\n]/gu;
/** Any control character: a path takes none. */
const ANY_CONTROL = /\p{Cc}/u;
const ITEM_FIELDS = new Set([
  'ref',
  'ruleKeys',
  'path',
  'line',
  'sonarLineHash',
  'message',
  'status',
  'comment',
  'competitorsUnknown',
]);

/** `text` cut to `max` UTF-16 units (as the endpoint counts), the last one `…`, pairs kept whole. */
function cut(text: string, max: number): string {
  if (text.length <= max) return text;
  let end = max - 1;
  const last = text.charCodeAt(end - 1);
  if (last >= 0xd800 && last <= 0xdbff) end -= 1;
  return `${text.slice(0, end)}…`;
}

/** Spec §11.2: a comment as the server stores it (CR and CRLF to LF, controls removed, trimmed). */
function clean(text: string): string {
  return text.replace(/\r\n?/g, '\n').replace(CONTROL, '').trim();
}

/** Spec §10.1: the Qualor status a person gave the issue in SonarQube, or `null`. */
export function sonarStatus(i: SonarIssue): ImportStatus | null {
  if (i.issueStatus === 'FALSE_POSITIVE') return 'false_positive';
  if (i.issueStatus === 'ACCEPTED') return 'wont_fix';
  if (i.issueStatus !== undefined && i.issueStatus !== '') return null;
  if (i.resolution === 'FALSE-POSITIVE') return 'false_positive';
  if (i.resolution === 'WONTFIX') return 'wont_fix';
  return null;
}

/**
 * Spec §10.2, rulings S8c and 9c, the header of `importCommentHeader` (the key, the status
 * label and the `YYYY-MM-DD` day of `updateDate`, nothing else in its place), then `: ` and the
 * latest non-blank SonarQube comment's text, cleaned as the server stores it and cut to 2 000
 * UTF-16 units with `…`. No login, author or other field of SonarQube's comment is copied.
 */
export function importComment(i: SonarIssue, status: ImportStatus): string {
  const label: ImportCommentLabel =
    status === 'false_positive'
      ? 'False positive'
      : i.issueStatus === 'ACCEPTED'
        ? 'Accepted'
        : "Won't fix";
  const date = DAY.exec(i.updateDate ?? '')?.[1] ?? null;
  const head = importCommentHeader({ key: i.key, label, date });
  const latest = [...(i.comments ?? [])]
    .reverse()
    .map((c) => clean(c.markdown ?? ''))
    .find((text) => text !== '');
  return cut(latest === undefined ? head : `${head}: ${latest}`, MAX_COMMENT);
}

/**
 * Spec §10.2, §11.2: relative, with `/`, no empty, `.` or `..` segment, no control character
 * (NUL included), ≤ 1 024 bytes.
 */
function validPath(p: string): boolean {
  return (
    p.length > 0 &&
    Buffer.byteLength(p, 'utf8') <= MAX_PATH_BYTES &&
    !p.startsWith('/') &&
    !p.includes('\\') &&
    !ANY_CONTROL.test(p) &&
    p.split('/').every((s) => s !== '' && s !== '.' && s !== '..')
  );
}

/**
 * Spec §10.2: the repository path of a component, `--path-prefix` in front; `null` for the
 * project itself (file-less); `'invalid'` when the resulting path is not one the endpoint takes.
 */
export function sonarPath(
  projectKey: string,
  component: string,
  prefix: string | null,
): string | null | 'invalid' {
  if (component === projectKey) return null;
  if (!component.startsWith(`${projectKey}:`)) return 'invalid';
  const rel = component.slice(projectKey.length + 1);
  const dir = (prefix ?? '').replace(/\/+$/, '');
  const full = dir === '' ? rel : `${dir}/${rel}`;
  return validPath(full) ? full : 'invalid';
}

const validRuleKey = (k: string) =>
  k.length <= MAX_RULE_KEY && RULE_KEY.test(k) && !k.includes('\u0000');

/**
 * Spec §11.2: the first field of `item` the endpoint would refuse (422), or `null`. Unknown
 * fields count too: the endpoint's items are strict.
 */
export function requestItemProblem(item: StatusImportRequestItem): string | null {
  const extra = Object.keys(item).find((k) => !ITEM_FIELDS.has(k));
  if (extra !== undefined) return extra;
  if (!REF.test(item.ref)) return 'ref';
  if (
    item.ruleKeys.length < 1 ||
    item.ruleKeys.length > MAX_TARGETS ||
    !item.ruleKeys.every(validRuleKey)
  ) {
    return 'ruleKeys';
  }
  if (item.path !== null && !validPath(item.path)) return 'path';
  if (
    item.line !== null &&
    !(Number.isInteger(item.line) && item.line >= 1 && item.line <= MAX_LINE)
  ) {
    return 'line';
  }
  if (item.sonarLineHash !== null && !SONAR_LINE_HASH.test(item.sonarLineHash)) {
    return 'sonarLineHash';
  }
  if (
    item.message !== null &&
    (item.message.length > MAX_MESSAGE || item.message.includes('\u0000'))
  ) {
    return 'message';
  }
  if (item.status === 'open') {
    if ('competitorsUnknown' in item) return 'competitorsUnknown';
    if (item.comment === undefined) return null;
  }
  const comment = item.comment;
  if (
    comment === undefined ||
    comment.length < 1 ||
    comment.length > MAX_COMMENT ||
    comment.includes('\u0000') ||
    clean(comment) === ''
  ) {
    return 'comment';
  }
  return null;
}

export interface ItemBuild {
  /** The resolved issues, as items (`competitorsUnknown: true` when competitors may be missing). */
  items: StatusImportItem[];
  /** Spec §10.1: the open issues on a resolved item's path, as competitors (never applied). */
  competitors: StatusCompetitorItem[];
  /**
   * The SonarQube rules not all read, not sendable or whose resolved count changed, in the
   * mapping component of a resolved item they made `competitorsUnknown` (ruling S14). A component
   * marked as a whole (`unreadComponents`) names none.
   */
  competitorsUnknownRules: string[];
  /**
   * Ruling S11: resolved issues that the open read found open again (reopened between the two
   * reads). Never sent as resolved, never applied; reported `changed`. Each is sent as an open
   * competitor instead, like any open issue.
   */
  changed: StatusImportItem[];
  /** Resolved item ref (`changed` ones included) → its SonarQube rule key, for the report. */
  rules: Map<string, string>;
  unmappedRules: Map<string, number>;
  /** Resolved issues whose path (with `--path-prefix`) the endpoint would refuse: not sent. */
  pathInvalid: number;
  /** Resolved issues the endpoint would refuse for another field (not expected): not sent. */
  invalid: number;
  /**
   * Issues read that no person resolved as false positive or accepted. Ruling S14 (d): each one
   * with a target marks the resolved items of its path, like `invalid`.
   */
  ignored: number;
}

/** Every valid Qualor rule key an issue of `rule` may be (spec §10.2: every relation). */
function targetsOf(mapping: SonarMapping, rule: string): string[] {
  return [...new Set(mapping.targets(rule).map((t) => t.key))].filter(validRuleKey);
}

/** What an issue says about where it is, shared by resolved items and competitors. */
function evidence(i: SonarIssue, ruleKeys: string[], path: string | null) {
  return {
    ref: i.key,
    ruleKeys,
    path,
    line: i.line ?? i.textRange?.startLine ?? null,
    sonarLineHash: i.hash !== undefined && SONAR_LINE_HASH.test(i.hash) ? i.hash : null,
    message: i.message === undefined ? null : cut(i.message.replaceAll('\u0000', ''), MAX_MESSAGE),
  };
}

const pathKey = (p: string | null) => p ?? '\u0000';

/**
 * Spec §10.1-§10.3: the resolved issues as import items and, from `open` (the open issues of the
 * rules of the resolved items' mapping components, `SonarMapping.componentRules`), the
 * competitors on their paths. A resolved item is `competitorsUnknown` (ruling S14) when its
 * rule's mapping component holds a rule of `unreadRules` (open or resolved issues not all read,
 * or whose count changed) or is one of `unreadComponents`, when its rule has more targets than an
 * item can carry, or when a resolved issue of its path was dropped as invalid or ignored (it
 * competes for the path's Qualor issues unseen). A competitor that cannot be sent whole makes its
 * rule count as unread. A resolved issue that `open` lists too (reopened
 * between the reads) is `changed`, never sent as resolved. Unmapped and path-invalid open issues
 * are dropped uncounted; so are those on no resolved item's path.
 */
export function buildStatusItems(
  projectKey: string,
  issues: readonly SonarIssue[],
  o: {
    pathPrefix: string | null;
    mapping?: SonarMapping;
    open?: readonly SonarIssue[];
    unreadRules?: readonly string[];
    unreadComponents?: readonly string[];
  },
): ItemBuild {
  const mapping = o.mapping ?? SONAR_MAPPING;
  const out: ItemBuild = {
    items: [],
    competitors: [],
    competitorsUnknownRules: [],
    changed: [],
    rules: new Map(),
    unmappedRules: new Map(),
    pathInvalid: 0,
    invalid: 0,
    ignored: 0,
  };
  const targetsByRef = new Map<string, string[]>();
  /** Paths of resolved issues dropped as invalid or ignored: their items are unsure. */
  const unsurePaths = new Set<string>();
  /**
   * Fix 12c: rules that make their whole mapping component unsure, found while building: a
   * resolved item with more targets than it can carry (the candidates of the others are missing
   * for every rule of the component, not only for it), and a resolved issue reopened between the
   * reads (its own resolved count may hide another change of that rule).
   */
  const unread = new Set(o.unreadRules ?? []);
  for (const i of issues) {
    if (targetsByRef.has(i.key)) continue;
    const status = sonarStatus(i);
    if (status === null) {
      out.ignored += 1;
      // Ruling S14 (d): its status is not known, so it may compete for its path's Qualor issues.
      const path = sonarPath(projectKey, i.component, o.pathPrefix);
      if (path !== 'invalid' && targetsOf(mapping, i.rule).length > 0) {
        unsurePaths.add(pathKey(path));
      }
      continue;
    }
    const targets = targetsOf(mapping, i.rule);
    if (targets.length === 0) {
      out.unmappedRules.set(i.rule, (out.unmappedRules.get(i.rule) ?? 0) + 1);
      continue;
    }
    const path = sonarPath(projectKey, i.component, o.pathPrefix);
    if (path === 'invalid') {
      out.pathInvalid += 1;
      continue;
    }
    const item: StatusImportItem = {
      ...evidence(i, targets.slice(0, MAX_TARGETS), path),
      status,
      comment: importComment(i, status),
    };
    // Never truncated silently: the candidates of the targets left out would be missing.
    if (targets.length > MAX_TARGETS) {
      item.competitorsUnknown = true;
      unread.add(i.rule);
    }
    const problem = requestItemProblem(item);
    if (problem !== null) {
      if (problem === 'path') out.pathInvalid += 1;
      else {
        out.invalid += 1;
        unsurePaths.add(pathKey(item.path));
      }
      continue;
    }
    targetsByRef.set(i.key, targets);
    out.rules.set(i.key, i.rule);
    out.items.push(item);
  }

  // Ruling S11: resolved when read, open when the open issues were read: it changed in between.
  const reopened = new Set((o.open ?? []).map((i) => i.key).filter((k) => targetsByRef.has(k)));
  if (reopened.size > 0) {
    out.changed = out.items.filter((i) => reopened.has(i.ref));
    out.items = out.items.filter((i) => !reopened.has(i.ref));
    // Fix 12c: a reopen and a resolve of one rule between the reads leave its counts unchanged,
    // so the reopened issue's rule counts as not read in full.
    for (const i of out.changed) unread.add(out.rules.get(i.ref) ?? '');
  }
  for (const item of out.items) {
    if (unsurePaths.has(pathKey(item.path))) item.competitorsUnknown = true;
  }

  const paths = new Set(out.items.map((i) => pathKey(i.path)));
  const refs = new Set(out.items.map((i) => i.ref));
  for (const i of o.open ?? []) {
    if (refs.has(i.key)) continue;
    const targets = targetsOf(mapping, i.rule);
    if (targets.length === 0) continue;
    const path = sonarPath(projectKey, i.component, o.pathPrefix);
    if (path === 'invalid' || !paths.has(pathKey(path))) continue;
    const competitor: StatusCompetitorItem = {
      ...evidence(i, targets.slice(0, MAX_TARGETS), path),
      status: 'open',
    };
    if (targets.length > MAX_TARGETS || requestItemProblem(competitor) !== null) {
      unread.add(i.rule);
      continue;
    }
    refs.add(i.key);
    out.competitors.push(competitor);
  }

  // Ruling S14 (b): closure, not hops. A rule of a mapping component not all read makes every
  // resolved item of that component unsure, however many shared targets lie between them.
  const unreadByComponent = new Map<string, string[]>();
  for (const rule of unread) {
    const k = mapping.component(rule);
    if (k !== null) unreadByComponent.set(k, [...(unreadByComponent.get(k) ?? []), rule]);
  }
  const wholesale = new Set(o.unreadComponents ?? []);
  const culprits = new Set<string>();
  for (const item of out.items) {
    const k = mapping.component(out.rules.get(item.ref) ?? '');
    if (k === null) continue;
    const rules = unreadByComponent.get(k);
    if (rules === undefined && !wholesale.has(k)) continue;
    item.competitorsUnknown = true;
    for (const r of rules ?? []) culprits.add(r);
  }
  out.competitorsUnknownRules = [...culprits].sort();
  return out;
}

/**
 * Spec §10.1 (rulings S3, S7, S11 and S14): builds the resolved issues' items, then reads the
 * open issues of every SonarQube rule of their rules' mapping components
 * (`SonarMapping.componentRules`, `GET` only, at most `maxIssues`). A component of more than
 * `MAX_COMPONENT_RULES` rules is not read, and its items are marked. It then probes the resolved
 * query again (`probe`, from `fetchResolvedIssues`) and builds again with those competitors and
 * the rules not all read: those of the open read, those of the resolved read (`unreadResolved`),
 * and those whose resolved count changed between the two probes (every component, when the
 * total changed). When the resolved read cannot name its unread rules (`all_but`), every rule of
 * the items' components is unread but those proven complete.
 */
export async function buildWithCompetitors(
  c: SonarClient,
  conn: SonarConnection,
  projectKey: string,
  resolved: readonly SonarIssue[],
  o: {
    pathPrefix: string | null;
    maxIssues: number;
    unreadResolved?: UnreadResolved;
    /** The resolved read's first probe (`fetchResolvedIssues`); without it, no re-probe. */
    probe?: IssueProbe;
    bounds?: ReadBounds;
    mapping?: SonarMapping;
  },
): Promise<ItemBuild> {
  const mapping = o.mapping ?? SONAR_MAPPING;
  const first = buildStatusItems(projectKey, resolved, { pathPrefix: o.pathPrefix, mapping });
  const components = mapping.componentsOf(first.rules.values());
  if (components.length === 0) return first;
  const rulesOf = new Map(components.map((k) => [k, mapping.componentRules(k)]));
  const tooLarge = components.filter((k) => (rulesOf.get(k) ?? []).length > MAX_COMPONENT_RULES);
  const readable = components.filter((k) => !tooLarge.includes(k));
  const readRules = readable.flatMap((k) => rulesOf.get(k) ?? []);
  const u = o.unreadResolved ?? { kind: 'rules', rules: [] };
  const complete = new Set(u.kind === 'all_but' ? u.complete : []);
  // `all_but`: the unread rules cannot be named, so any rule of an item's component may be one.
  const unreadResolved = u.kind === 'rules' ? u.rules : readRules.filter((r) => !complete.has(r));
  const open = await fetchOpenIssues(c, conn, projectKey, readRules, o.maxIssues, o.bounds);
  // Ruling S14 (c): an issue resolved or reopened during the reads may have been seen by neither;
  // its rule's resolved count (or the total) tells.
  const changed =
    o.probe === undefined
      ? { total: false, rules: [], listed: null }
      : await reprobeResolvedIssues(c, conn, projectKey, o.probe);
  // Fix 12c: a probe's facet that did not cover its total hides the counts of the rules it did not
  // list; a component with such a rule may have changed unseen, so it is marked whole.
  const listed = changed.listed === null ? null : new Set(changed.listed);
  const unseen =
    listed === null
      ? []
      : readable.filter((k) => (rulesOf.get(k) ?? []).some((r) => !listed.has(r)));
  if (changed.total || changed.rules.length > 0 || unseen.length > 0) {
    c.warn(
      'SONARQUBE_ISSUE_WINDOW',
      unseen.length > 0 && !changed.total && changed.rules.length === 0
        ? "resolved issues of a project may have changed while they were read (SonarQube's rules facet did not list every rule); the resolved issues they may compete with are not applied"
        : 'resolved issues of a project changed while they were read; the resolved issues they may compete with are not applied',
    );
  }
  return buildStatusItems(projectKey, resolved, {
    pathPrefix: o.pathPrefix,
    mapping,
    open: open.issues,
    unreadRules: [...new Set([...unreadResolved, ...open.unreadRules, ...changed.rules])].sort(),
    unreadComponents: changed.total ? components : [...tooLarge, ...unseen],
  });
}

const isResolved = (i: StatusImportRequestItem): i is StatusImportItem => i.status !== 'open';
/** `{"dryRun":false,"items":[]}`: the body around the items (`false` is the longer flag). */
const ENVELOPE_BYTES = Buffer.byteLength(JSON.stringify({ dryRun: false, items: [] }), 'utf8');
const itemBytes = (i: StatusImportRequestItem) => Buffer.byteLength(JSON.stringify(i), 'utf8');

/**
 * Spec §10.1, §11.2 (carry to Task 12): requests of whole paths, each path's resolved items with
 * all of its competitors, at most `maxCount` items and `maxBytes` of body. A path is never split
 * across requests (a competitor in another request competes with nothing): when it does not fit
 * with its competitors, its resolved items go alone, marked `competitorsUnknown`; when even they
 * do not fit, they are `unsent`. Paths with no resolved item are never sent.
 */
export function chunkItems(
  items: readonly StatusImportRequestItem[],
  maxCount: number = STATUS_IMPORT_MAX_ITEMS,
  maxBytes: number = MAX_JSON_BODY_BYTES,
): { chunks: StatusImportRequestItem[][]; unsent: StatusImportItem[] } {
  const byPath = new Map<string, { resolved: StatusImportItem[]; open: StatusCompetitorItem[] }>();
  for (const i of items) {
    const k = pathKey(i.path);
    const group = byPath.get(k) ?? { resolved: [], open: [] };
    if (isResolved(i)) group.resolved.push(i);
    else group.open.push(i);
    byPath.set(k, group);
  }
  /** The bytes of a list of items inside the array: each item, and a comma between two. */
  const listBytes = (list: readonly StatusImportRequestItem[]) =>
    list.reduce((n, i) => n + itemBytes(i), Math.max(0, list.length - 1));
  const fits = (count: number, bytes: number) =>
    count <= maxCount && ENVELOPE_BYTES + bytes <= maxBytes;

  const chunks: StatusImportRequestItem[][] = [];
  const unsent: StatusImportItem[] = [];
  let current: StatusImportRequestItem[] = [];
  let bytes = 0;
  for (const k of [...byPath.keys()].sort()) {
    const { resolved, open } = byPath.get(k) ?? { resolved: [], open: [] };
    if (resolved.length === 0) continue;
    let unit: StatusImportRequestItem[] = [...resolved, ...open];
    let size = listBytes(unit);
    if (!fits(unit.length, size)) {
      unit = resolved.map((i) => ({ ...i, competitorsUnknown: true }));
      size = listBytes(unit);
      if (!fits(unit.length, size)) {
        unsent.push(...resolved);
        continue;
      }
    }
    if (current.length > 0 && !fits(current.length + unit.length, bytes + 1 + size)) {
      chunks.push(current);
      current = [];
      bytes = 0;
    }
    bytes = current.length === 0 ? size : bytes + 1 + size;
    current.push(...unit);
  }
  if (current.length > 0) chunks.push(current);
  return { chunks, unsent };
}

/**
 * A resolved item's result: the server's (spec §10.5), or `not_sent` for an item of a path too
 * large to send whole with its competitors (spec §12.2), which the server never saw. `not_sent` is
 * the CLI's own marker, kept apart from the server's `competitors_unknown` (final review M-4).
 */
export type SendItemResult =
  StatusImportResult | { ref: string; outcome: 'not_sent'; issueId: null; status: null };

export type SendResult =
  | { kind: 'not_analysed' }
  | {
      kind: 'done';
      /** One per resolved item the server answered for, and `not_sent` for each of `unsent`. */
      results: SendItemResult[];
      /** The refs of `chunkItems`' `unsent` (a path too large to send whole): never sent. */
      unsent: string[];
      /** Resolved items with no answer: a request refused (413 down to one path, 4xx, 5xx). */
      failedRefs: string[];
      /** Why, one line per refused request (bounded). */
      failures: string[];
      /** The `open` competitors the server counted. */
      competitors: number;
    };

const fatal = (err: unknown) =>
  !(err instanceof CliError) || err instanceof UnreachableError || err.exitCode === EXIT.AUTH;

/**
 * Spec §11.2: sends the items one request at a time with the endpoint's `dryRun` flag, and
 * returns what the server answered. A 413 splits the request by path, down to one path, whose
 * resolved items are then `failed`; any other refusal fails that request's resolved items and the
 * rest goes on. Authentication failures and an unreachable Qualor stop the whole import.
 * `not_analysed` on the first request is the whole answer; later (the project lost its analysis
 * mid-run), the results already answered are kept and the resolved items not yet answered fail.
 */
export async function sendStatuses(
  api: QualorApi,
  projectId: string,
  items: readonly StatusImportRequestItem[],
  dryRun: boolean,
  bounds: { maxCount?: number; maxBytes?: number } = {},
): Promise<SendResult> {
  const { chunks, unsent } = chunkItems(items, bounds.maxCount, bounds.maxBytes);
  const results: SendItemResult[] = unsent.map((i) => ({
    ref: i.ref,
    outcome: 'not_sent',
    issueId: null,
    status: null,
  }));
  const failedRefs: string[] = [];
  const failures: string[] = [];
  let competitors = 0;
  let answered = 0;
  const fail = (chunk: readonly StatusImportRequestItem[], why: string) => {
    failedRefs.push(...chunk.filter(isResolved).map((i) => i.ref));
    if (failures.length < 100) failures.push(why.slice(0, 500));
  };
  const queue = [...chunks];
  for (let chunk = queue.shift(); chunk !== undefined; chunk = queue.shift()) {
    let answer: Awaited<ReturnType<QualorApi['importStatuses']>>;
    try {
      answer = await api.importStatuses(projectId, chunk, dryRun);
    } catch (err) {
      if (fatal(err)) throw err;
      fail(chunk, (err as Error).message);
      continue;
    }
    if (answer.kind === 'not_analysed') {
      if (answered === 0) return { kind: 'not_analysed' };
      fail(
        [chunk, ...queue].flat(),
        'Qualor answered that the project has no analysis any more (409 PROJECT_NOT_ANALYSED)',
      );
      break;
    }
    if (answer.kind === 'too_large') {
      const paths = [...new Set(chunk.map((i) => pathKey(i.path)))].sort();
      if (paths.length > 1) {
        const half = new Set(paths.slice(0, Math.ceil(paths.length / 2)));
        queue.unshift(
          chunk.filter((i) => half.has(pathKey(i.path))),
          chunk.filter((i) => !half.has(pathKey(i.path))),
        );
      } else {
        fail(chunk, 'the items of one path select too many Qualor issues (413), even alone');
      }
      continue;
    }
    const byRef = new Map(answer.results.map((r) => [r.ref, r]));
    const missing: StatusImportItem[] = [];
    for (const i of chunk.filter(isResolved)) {
      const r = byRef.get(i.ref);
      if (r === undefined) missing.push(i);
      else results.push(r);
    }
    if (missing.length > 0) {
      fail(missing, `Qualor answered no result for ${String(missing.length)} items of a request`);
    }
    competitors += answer.competitors;
    answered += 1;
  }
  return {
    kind: 'done',
    results,
    unsent: unsent.map((i) => i.ref),
    failedRefs,
    failures,
    competitors,
  };
}
