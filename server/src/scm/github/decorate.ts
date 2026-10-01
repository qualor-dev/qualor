import { SEVERITIES, type Quality, type Severity } from '@qualor/shared';
import type { DecorationDeps, DecorationOutcome } from '../decorate';
import {
  branchUrl,
  comparable,
  desiredInlineIssues,
  issueUrl,
  recordMergeRequest,
  summaryData,
  type DesiredInlineIssue,
  type Loaded,
} from '../decoration-data';
import { addedLines } from '../inline';
import { markerOf } from '../markdown';
import { ScmError } from '../provider';
import type { DecorationPayload } from '../queue';
import { statusName, summaryBody, type SummaryInput } from '../render';
import {
  GITHUB_PR_NUMBER,
  GITHUB_TEXT,
  type CheckRunUpdate,
  type GitHubAnnotation,
  type GitHubClient,
  type GitHubPullRequest,
} from './client';
import { githubClientFor } from './connections';
import {
  annotationFor,
  annotationsDigest,
  checkRunExternalId,
  checkRunSummary,
  checkRunVerdict,
  MAX_ANNOTATIONS,
  parseCheckRunExternalId,
} from './render';
import { githubWebBase, parseRepoRef } from './url';

/** github.md §5.3: pages of pull request files and of issue comments one job reads. */
export const MAX_FILE_PAGES = 30;
export const MAX_COMMENT_PAGES = 50;
export const REPOSITORY_MISMATCH =
  "The workflow's GitHub repository is not the repository Qualor is mapped to";

type Inline = SummaryInput['inline'];

const severityRank = (severity: string) => {
  const i = (SEVERITIES as readonly string[]).indexOf(severity);
  return i === -1 ? SEVERITIES.length : i;
};
/** Code-unit order: the same on every machine and locale (no `localeCompare`). */
const byText = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * github.md §6.4: the desired issues that fall on added lines of the pull request's files, as
 * annotations, and how many do not. The annotations are in a total order (severity descending,
 * then path, line, rule key and issue id), whatever order the issues come in: the check run's
 * digest depends on it, and a rerun must find the same digest to change nothing. An issue without
 * a positive line, or on a file without a patch (binary, generated, too large), is not placed.
 */
export function annotationsOnDiff(
  desired: readonly DesiredInlineIssue[],
  added: ReadonlyMap<string, ReadonlySet<number>>,
  url: (issueId: string) => string | null,
): { annotations: GitHubAnnotation[]; unplaced: number } {
  const placed: (DesiredInlineIssue & { path: string; line: number })[] = [];
  let unplaced = 0;
  for (const issue of desired) {
    const { path, line } = issue;
    if (
      path === null ||
      line === null ||
      !Number.isSafeInteger(line) ||
      line <= 0 ||
      !added.get(path)?.has(line)
    ) {
      unplaced += 1;
      continue;
    }
    placed.push({ ...issue, path, line });
  }
  placed.sort(
    (a, b) =>
      severityRank(a.severity) - severityRank(b.severity) ||
      byText(a.path, b.path) ||
      a.line - b.line ||
      byText(a.ruleKey, b.ruleKey) ||
      byText(a.id, b.id),
  );
  return {
    annotations: placed.map((issue) =>
      annotationFor({
        path: issue.path,
        line: issue.line,
        severity: issue.severity as Severity,
        quality: issue.quality as Quality,
        ruleKey: issue.ruleKey,
        message: issue.message,
        url: url(issue.id),
      }),
    ),
    unplaced,
  };
}

/** github.md §6.4: the desired issues placed on added lines of the pull request's files. */
async function placeAnnotations(
  deps: DecorationDeps,
  client: GitHubClient,
  loaded: Loaded,
  number: string,
): Promise<{ annotations: GitHubAnnotation[]; unplaced: number }> {
  const desired = await desiredInlineIssues(deps.db, loaded.branch.id, MAX_ANNOTATIONS);
  if (desired.length === 0) return { annotations: [], unplaced: 0 };
  const files = await client.pullRequestFiles(number, MAX_FILE_PAGES);
  const added = new Map<string, Set<number>>();
  for (const f of files.items) {
    if (f.status !== 'removed' && f.patch !== undefined) added.set(f.filename, addedLines(f.patch));
  }
  return annotationsOnDiff(desired, added, (id) => issueUrl(deps.publicUrl, loaded.project.id, id));
}

/**
 * What the check run's summary says about its annotations: those placed this time, a refusal of
 * them by GitHub, or (the annotations kept, `annotations: null`) the count the check run holds.
 */
type AnnotationState = 'placed' | 'rejected' | { kept: number };

/**
 * github.md §6.1: Qualor's check run of this name on the revision, read before written. The same
 * annotations (by digest) and output → nothing; the same annotations, other output → PATCH; other
 * annotations or none of Qualor's → a new check run. `annotations: null` keeps the current ones
 * (the pull request part failed, or the analysis is not the branch's latest), and the summary
 * then counts the ones kept. When GitHub refuses the annotations, the check run is created without
 * them but with the digest of those it tried (§6.4, ruling C2): a rerun of the same analysis then
 * finds that digest and sends nothing, rather than a refused POST and a new fallback each time.
 * Returns whether the check run is such a fallback.
 */
async function reconcileCheckRun(
  client: GitHubClient,
  a: {
    name: string;
    revision: string;
    analysisId: string;
    verdict: { conclusion: 'success' | 'failure'; title: string };
    detailsUrl: string | null;
    annotations: GitHubAnnotation[] | null;
    summary: (state: AnnotationState) => string;
  },
): Promise<{ rejected: boolean }> {
  const current =
    (await client.checkRuns(a.revision, a.name))
      .map((run) => ({ run, ids: parseCheckRunExternalId(run.external_id) }))
      .filter((c) => c.ids !== null)
      .sort((x, y) => y.run.id - x.run.id)[0] ?? null;
  const digest =
    a.annotations === null
      ? (current?.ids?.digest ?? annotationsDigest([]))
      : annotationsDigest(a.annotations);
  const matches = current !== null && current.ids?.digest === digest;
  // The fallback of an earlier refusal: the digest of annotations it does not hold.
  const refusedBefore =
    matches &&
    a.annotations !== null &&
    a.annotations.length > 0 &&
    current.run.output.annotations_count === 0;
  const state: AnnotationState =
    a.annotations === null
      ? { kept: current?.run.output.annotations_count ?? 0 }
      : refusedBefore
        ? 'rejected'
        : 'placed';
  const update = (summary: string): CheckRunUpdate => ({
    conclusion: a.verdict.conclusion,
    title: a.verdict.title,
    summary,
    detailsUrl: a.detailsUrl,
    externalId: checkRunExternalId(a.analysisId, digest),
  });
  const desired = update(a.summary(state));
  if (matches) {
    const r = current.run;
    const same =
      r.conclusion === desired.conclusion &&
      (r.output.title ?? '') === desired.title &&
      comparable(r.output.summary ?? '') === comparable(desired.summary) &&
      // GitHub fills in a details URL of its own when none is sent: compare only one Qualor sent.
      (desired.detailsUrl === null || r.details_url === desired.detailsUrl) &&
      r.external_id === desired.externalId;
    if (!same) await client.updateCheckRun(r.id, desired);
    return { rejected: refusedBefore };
  }
  const created = await client.createCheckRun({
    ...desired,
    name: a.name,
    headSha: a.revision,
    annotations: a.annotations ?? [],
  });
  if (created !== 'annotations_rejected') return { rejected: false };
  await client.createCheckRun({
    ...update(a.summary('rejected')),
    name: a.name,
    headSha: a.revision,
    annotations: [],
  });
  return { rejected: true };
}

/** github.md §6.2–§6.3: the summary comment, recognised by the App's bot login and the marker. */
async function reconcileComment(
  deps: DecorationDeps,
  client: GitHubClient,
  loaded: Loaded,
  number: string,
  body: string,
  slug: string,
): Promise<void> {
  const listed = await client.issueComments(number, MAX_COMMENT_PAGES);
  const login = `${slug}[bot]`;
  const own = listed.items.find((c) => {
    if (c.user?.type !== 'Bot' || c.user.login !== login || c.body === null) return false;
    const marker = markerOf(c.body);
    return marker?.kind === 'summary' && marker.projectId === loaded.project.id;
  });
  if (own) {
    if (comparable(own.body ?? '') !== comparable(body)) await client.updateComment(own.id, body);
  } else if (listed.complete) {
    await client.createComment(number, body);
  } else {
    // Beyond the page bound the summary may exist unseen: never post a second one.
    deps.logger?.warn(
      { analysisId: loaded.analysis.id, connectionId: loaded.connection.id },
      'GitHub pull request has too many comments to find the Qualor summary; not posting one',
    );
  }
}

const retryable = (e: ScmError) => e.kind === 'transient' || e.kind === 'rate_limited';
/** More requests now would only be refused too (the retry waits for GitHub's Retry-After). */
const stopsTheJob = (e: ScmError) => e.kind === 'budget' || e.kind === 'rate_limited';

/**
 * One GitHub decoration (github.md §5.2): the App, the installation and the repository; for the
 * branch's latest analysis of an open pull request, its annotations; the check run of the
 * revision; then the summary comment. A failed pull request part does not stop the check run
 * (which then keeps its annotations), unless GitHub rate-limited it or the budget ran out. Only a
 * transient failure or a rate limit is retried (by the caller, through `failed`); any other error
 * stops the job.
 */
export async function decorateGitHub(
  deps: DecorationDeps,
  payload: DecorationPayload,
  loaded: Loaded,
  failed: (error: ScmError) => DecorationOutcome,
): Promise<DecorationOutcome> {
  const { connection, branch, project, analysis } = loaded;
  // The key is decrypted and the base URL checked against the current rules (scm.md §2.1,
  // github.md §2.2) before any request; the worker's token cache and pacer are shared.
  const found = githubClientFor(connection, deps.scm, deps.runtime);
  if ('problem' in found) return failed(new ScmError('refused', found.problem));
  const ref = parseRepoRef(project.scmProjectRef ?? '');
  if (ref === null) {
    return failed(new ScmError('refused', GITHUB_TEXT.notFound, { reason: 'invalid_input' }));
  }
  const client = found.client;
  const errors: ScmError[] = [];
  try {
    const app = await client.app();
    const repo = await client.useRepository(ref);
    const expected = payload.github?.repositoryId;
    if (expected !== undefined && String(repo.id) !== expected) {
      return failed(new ScmError('refused', REPOSITORY_MISMATCH));
    }
    let pull: GitHubPullRequest | null = null;
    // An analysis that is no longer the branch's latest keeps the annotations the check run has.
    let annotations: GitHubAnnotation[] | null = branch.lastAnalysisId === analysis.id ? [] : null;
    let inline: Inline = { commented: 0, unplaced: 0, skipped: null };
    const latestPullRequest =
      branch.kind === 'merge_request' &&
      GITHUB_PR_NUMBER.test(branch.name) &&
      branch.lastAnalysisId === analysis.id;
    if (latestPullRequest) {
      try {
        pull = await client.pullRequest(branch.name);
        await recordMergeRequest(
          deps.db,
          loaded,
          { title: pull.title, url: pull.html_url },
          githubWebBase(connection.baseUrl),
        );
        if (pull.state === 'open') {
          const skipped: Inline['skipped'] =
            payload.github?.checkout !== 'head'
              ? 'checkout_other'
              : pull.head.sha !== loaded.revision
                ? 'stale'
                : null;
          if (skipped === null) {
            const placed = await placeAnnotations(deps, client, loaded, branch.name);
            annotations = placed.annotations;
            inline = {
              commented: placed.annotations.length,
              unplaced: placed.unplaced,
              skipped: null,
            };
          } else {
            inline = { commented: 0, unplaced: 0, skipped };
          }
        }
      } catch (err) {
        if (!(err instanceof ScmError)) throw err;
        if (stopsTheJob(err)) return failed(err);
        errors.push(err);
        pull = null;
        annotations = null;
      }
    }
    const data = await summaryData(deps.db, loaded, deps.publicUrl);
    const head = pull !== null && pull.head.sha !== loaded.revision ? pull.head.sha : null;
    const render = (i: Inline) =>
      summaryBody({
        projectId: project.id,
        revision: loaded.revision,
        gate: loaded.gate,
        newIssues: data.newIssues,
        topIssues: data.top,
        topIssuesTotal: data.total,
        inline: i,
        branchUrl: branchUrl(deps.publicUrl, loaded),
        mergeRequestHead: head,
        vocabulary: 'github',
        smallChangesetLines: data.smallChangesetLines,
      });
    const rejectedInline: Inline = {
      commented: 0,
      unplaced: inline.commented + inline.unplaced,
      skipped: null,
    };
    let body = render(inline);
    try {
      const { rejected } = await reconcileCheckRun(client, {
        name: statusName(project.key),
        revision: loaded.revision,
        analysisId: analysis.id,
        verdict: checkRunVerdict(loaded.gate),
        detailsUrl: branchUrl(deps.publicUrl, loaded),
        annotations,
        summary: (state) =>
          checkRunSummary(
            state === 'placed'
              ? body
              : state === 'rejected'
                ? render(rejectedInline)
                : render({ commented: state.kept, unplaced: 0, skipped: null }),
          ),
      });
      if (rejected) body = render(rejectedInline);
    } catch (err) {
      if (!(err instanceof ScmError)) throw err;
      if (stopsTheJob(err)) return failed(err);
      errors.push(err);
    }
    if (pull !== null && pull.state === 'open') {
      try {
        await reconcileComment(deps, client, loaded, branch.name, body, app.slug);
      } catch (err) {
        if (!(err instanceof ScmError)) throw err;
        errors.push(err);
      }
    }
    const error =
      errors.find((e) => e.kind === 'budget') ?? errors.find(retryable) ?? errors[0] ?? null;
    return error === null ? { kind: 'done', connectionId: connection.id } : failed(error);
  } catch (err) {
    if (err instanceof ScmError) return failed(err);
    throw err;
  }
}
