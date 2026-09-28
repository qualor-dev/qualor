import path from 'node:path';
import { planGate, planProfile, type ImportReport, type SonarProjectData } from '@qualor/shared';
import type { ImportFlags } from '../args';
import { CliError, EXIT, type ExitCode } from '../errors';
import {
  applyGates,
  applyProfiles,
  applyProjects,
  type ApplyOptions,
  type GateResult,
  type ProfileResult,
  type ProjectResult,
} from '../import/apply';
import { buildWithCompetitors, type SendItemResult, sendStatuses } from '../import/issues';
import { resolveImportSetup } from '../import/options';
import { httpQualorApi, type QualorApi } from '../import/qualor-api';
import {
  buildReport,
  checkReportPath,
  printSummary,
  writeReport,
  type Issues,
} from '../import/report';
import { connectSonar, type Transport } from '../import/sonarqube/client';
import {
  countReviewedHotspots,
  fetchGates,
  fetchProfiles,
  fetchProjectSettings,
  fetchResolvedIssues,
  listProjects,
} from '../import/sonarqube/fetch';
import type { CliIO } from '../io';
import type { Logger } from '../log';
import { clean, UnreachableError } from '../server/http';

type Warning = ImportReport['warnings'][number];
type ItemOutcome = Issues['items'][number]['outcome'];

export interface ImportDeps {
  qualor?: QualorApi;
  transport?: Transport;
  sleep?: (ms: number) => Promise<void>;
  now?: () => Date;
}

/** Spec §12.2: at most this many items listed per project (the counts are always complete). */
const MAX_ITEMS_IN_REPORT = 10_000;
const MAX_UNMAPPED_RULES = 1000;
/** Review focus 2: at least 10 statuses sent and at least 90 % unmatched hint at --path-prefix. */
const HINT_MIN_ITEMS = 10;
const HINT_UNMATCHED_SHARE = 0.9;
const MAX_WARNING = 2000;

/**
 * Spec §4.3 step 4: the Qualor organisation, from `--qualor-organization` or the token user's
 * only admin membership. A user who is not an admin of it (nor an instance admin) is exit 5.
 * The key is only compared with the keys Qualor sends, never put into a request.
 */
export async function resolveQualorOrganization(
  api: QualorApi,
  key: string | undefined,
): Promise<{ id: string; key: string }> {
  const me = await api.me();
  const notAdmin = (k: string) =>
    new CliError(EXIT.AUTH, `the Qualor token's user is not an admin of the organisation ${k}`);
  if (key !== undefined) {
    const m = me.memberships.find((x) => x.organizationKey === key);
    if (m !== undefined) {
      if (m.role !== 'admin' && !me.isInstanceAdmin) throw notAdmin(key);
      return { id: m.organizationId, key };
    }
    if (me.isInstanceAdmin) {
      const org = (await api.organizations()).find((o) => o.key === key);
      if (org !== undefined) return org;
    }
    throw new CliError(EXIT.USAGE, `no Qualor organisation ${key} is visible to the Qualor token`);
  }
  const admin = me.memberships.filter((m) => m.role === 'admin' || me.isInstanceAdmin);
  const [only] = admin;
  if (admin.length === 1 && only !== undefined) {
    return { id: only.organizationId, key: only.organizationKey };
  }
  if (admin.length === 0 && me.isInstanceAdmin) {
    const orgs = await api.organizations();
    const [one] = orgs;
    if (orgs.length === 1 && one !== undefined) return one;
  }
  if (admin.length === 0 && !me.isInstanceAdmin) {
    throw new CliError(EXIT.AUTH, "the Qualor token's user is not an admin of any organisation");
  }
  throw new CliError(
    EXIT.USAGE,
    'the Qualor token can reach several organisations; pass --qualor-organization',
  );
}

function emptyIssues(outcome: Issues['outcome']): Issues {
  return {
    outcome,
    read: 0,
    applied: 0,
    wouldApply: 0,
    alreadySet: 0,
    conflict: 0,
    unmatched: 0,
    ambiguous: 0,
    competitorsUnknown: 0,
    notSent: 0,
    changed: 0,
    failed: 0,
    unmappedRule: 0,
    pathInvalid: 0,
    invalid: 0,
    notRead: 0,
    // Unknown until counted: a step that never reached the count does not claim 0.
    hotspotsNotImported: null,
    unmappedRules: [],
    items: [],
  };
}

/**
 * Failures no later step can escape end the run instead (spec §13): authentication, an
 * unreachable server, and anything that is not a `CliError` (a defect, reported by `main` as an
 * internal error).
 */
function isFatal(err: unknown): boolean {
  return (
    !(err instanceof CliError) || err instanceof UnreachableError || err.exitCode === EXIT.AUTH
  );
}

/** A step's failure as a bounded reason; a fatal one is thrown on. */
function stepFailure(err: unknown): string {
  if (isFatal(err)) throw err;
  return (err as CliError).message.slice(0, 500);
}

/**
 * Objects of a step not run (`--only`) serve assignments only when Qualor has them as planned;
 * one Qualor failed to look up stays `failed`, so its assignments fail (exit 4).
 */
function lookedUp<T extends ProfileResult | GateResult>(r: T): T {
  return r.outcome === 'unchanged' || r.outcome === 'skipped' || r.outcome === 'failed'
    ? r
    : { ...r, outcome: 'skipped', reason: 'not imported in this run (--only)' };
}

/** Why a run stopped, for the report: a `CliError`'s message names no token (spec §14). */
function fatalReason(err: unknown): string {
  if (err instanceof CliError) return err.message;
  return `internal error: ${err instanceof Error ? err.message : String(err)}`;
}

/** The worse of two exit codes (5 over 4 over 2 over 0). */
const worse = (a: ExitCode, b: ExitCode): ExitCode => (b > a ? b : a);

const count = (outcome: ItemOutcome, i: Issues) => {
  switch (outcome) {
    case 'applied':
      i.applied += 1;
      break;
    case 'would_apply':
      i.wouldApply += 1;
      break;
    case 'already_set':
      i.alreadySet += 1;
      break;
    case 'conflict':
      i.conflict += 1;
      break;
    case 'unmatched':
      i.unmatched += 1;
      break;
    case 'ambiguous':
      i.ambiguous += 1;
      break;
    case 'competitors_unknown':
      i.competitorsUnknown += 1;
      break;
    case 'not_sent':
      i.notSent += 1;
      break;
    case 'changed':
      i.changed += 1;
      break;
    case 'failed':
      i.failed += 1;
      break;
  }
};

/**
 * `qualor import sonarqube` (import-sonarqube.md §3, §12): checks both connections (Qualor
 * first, so a user who cannot import never reaches SonarQube), reads SonarQube with `GET` only,
 * plans, writes profiles, gates, projects and issue statuses (each only as a dry run under
 * `--dry-run`), prints the summary and writes `--output`. A `CliError` that ends the run
 * propagates to `main`. Exit 0 when the import finished, whatever it could not map or match
 * (`unmatched`, `ambiguous`, `competitors_unknown`, `not_sent`, `changed` and conflicts are outcomes it
 * reports); 4 when a step failed (the others ran, the report names it).
 */
export async function runImportSonarqube(
  flags: ImportFlags,
  io: CliIO,
  log: Logger,
  deps: ImportDeps = {},
): Promise<ExitCode> {
  const now = deps.now ?? (() => new Date());
  const startedAt = now();
  // Logs its own warnings once; no token is in any of them.
  const setup = resolveImportSetup(flags, io.env, io.cwd, log);
  const output = flags.output === undefined ? null : path.resolve(io.cwd, flags.output);
  if (output !== null) checkReportPath(output);
  const warnings: Warning[] = [...setup.warnings];
  /** Records a warning for the report and logs it, once, here. */
  const warn = (code: Warning['code'], message: string) => {
    const text = message.slice(0, MAX_WARNING);
    warnings.push({ code, message: text });
    log.warn(clean(text));
  };

  const qualor = deps.qualor ?? httpQualorApi(setup.qualor, deps.sleep);
  const organization = await resolveQualorOrganization(qualor, flags.qualorOrganization);
  const conn = await connectSonar({
    ...setup.sonar,
    log,
    transport: deps.transport,
    sleep: deps.sleep,
  });
  const steps = new Set(flags.only);
  const o: ApplyOptions = {
    dryRun: flags.dryRun,
    overwrite: flags.overwrite,
    setDefaults: flags.setDefaults,
    createProjects: flags.createProjects,
  };
  const lookup: ApplyOptions = { ...o, dryRun: true, overwrite: false, setDefaults: false };

  // Read (GET only) and plan: everything but the issues, before any write (ruling S13).
  const readsProfiles = steps.has('profiles') || steps.has('projects');
  const readsGates = steps.has('gates') || steps.has('projects');
  const plannedProfiles = readsProfiles
    ? (await fetchProfiles(conn.client)).map((p) => planProfile(p))
    : [];
  const plannedGates = readsGates ? (await fetchGates(conn.client)).map((g) => planGate(g)) : [];
  const listed =
    steps.has('projects') || steps.has('issues')
      ? await listProjects(conn.client, flags.projects)
      : { projects: [], missing: [] };
  const bare = (p: { key: string; name: string }): SonarProjectData => ({
    ...p,
    mainBranch: 'main',
    profiles: [],
    gate: null,
  });
  const settings: SonarProjectData[] = [];
  /** Projects no Qualor step can take: settings not read, or not in SonarQube (spec §5.1). */
  const unread: ProjectResult[] = [];
  for (const p of listed.projects) {
    if (!steps.has('projects')) {
      settings.push(bare(p));
      continue;
    }
    try {
      settings.push(await fetchProjectSettings(conn.client, p));
    } catch (err) {
      unread.push({
        sonar: bare(p),
        outcome: 'failed',
        reason: stepFailure(err),
        qualorProjectId: null,
        profiles: [],
        gate: null,
      });
    }
  }
  for (const key of listed.missing) {
    unread.push({
      sonar: bare({ key, name: key }),
      outcome: 'missing',
      reason: 'SonarQube has no project of this key visible to this token',
      qualorProjectId: null,
      profiles: [],
      gate: null,
    });
  }

  // Write, in order: profiles, gates, projects and assignments, then each project's issues,
  // read and sent one project at a time. What is done is kept for a partial report.
  const profiles: ProfileResult[] = [];
  const gates: GateResult[] = [];
  const projects: ProjectResult[] = [];
  const issuesOf = new Map<ProjectResult, Issues>();

  /** Spec §10, §11.2: one project's resolved issues, sent with their open competitors. */
  async function importIssues(key: string, projectId: string, issues: Issues): Promise<void> {
    try {
      const fetched = await fetchResolvedIssues(conn.client, conn, key, flags.maxIssues);
      issues.read = fetched.issues.length;
      issues.notRead = fetched.notRead;
      // Never fails the project's issues: an unanswered count is null, with a warning.
      issues.hotspotsNotImported = await countReviewedHotspots(conn.client, conn, key);
      const built = await buildWithCompetitors(conn.client, conn, key, fetched.issues, {
        pathPrefix: flags.pathPrefix ?? null,
        maxIssues: flags.maxIssues,
        unreadResolved: fetched.unread,
        probe: fetched.probe,
      });
      issues.unmappedRule = [...built.unmappedRules.values()].reduce((a, b) => a + b, 0);
      issues.pathInvalid = built.pathInvalid;
      // Read as resolved but in no status the import takes: not expected either; never sent.
      issues.invalid = built.invalid + built.ignored;
      issues.unmappedRules = [...built.unmappedRules]
        .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))
        .slice(0, MAX_UNMAPPED_RULES)
        .map(([rule, n]) => ({ key: rule, issues: n }));
      const record = (
        item: (typeof built.items)[number],
        outcome: ItemOutcome,
        id: string | null,
      ) => {
        count(outcome, issues);
        if (issues.items.length < MAX_ITEMS_IN_REPORT) {
          issues.items.push({
            sonarKey: item.ref,
            rule: built.rules.get(item.ref) ?? '',
            path: item.path,
            line: item.line,
            outcome,
            qualorIssueId: id,
          });
        }
      };
      // Ruling S11: reopened between the two reads; never sent as resolved, never applied.
      for (const item of built.changed) record(item, 'changed', null);
      if (built.items.length === 0) return;
      const sent = await sendStatuses(
        qualor,
        projectId,
        [...built.items, ...built.competitors],
        flags.dryRun,
      );
      if (sent.kind === 'not_analysed') {
        issues.outcome = 'not_analysed';
        warn(
          'ISSUES_NOT_READ',
          `project ${key} has no analysis in Qualor yet: scan it, then run the import again with --only issues`,
        );
        return;
      }
      const byRef = new Map<string, SendItemResult>(sent.results.map((x) => [x.ref, x]));
      const failed = new Set(sent.failedRefs);
      for (const item of built.items) {
        const r = byRef.get(item.ref);
        const outcome: ItemOutcome = failed.has(item.ref) || r === undefined ? 'failed' : r.outcome;
        record(item, outcome, r?.issueId ?? null);
      }
      if (issues.notSent > 0) {
        warn(
          'ISSUE_STATUSES_NOT_SENT',
          `project ${key}: ${issues.notSent} resolved issues were not sent, because their file has more resolved and open issues than one request holds; nothing was applied for them`,
        );
      }
      if (issues.failed > 0) {
        issues.outcome = 'failed';
        const [first = 'no answer'] = sent.failures;
        const more = sent.failures.length > 1 ? ` (and ${sent.failures.length - 1} more)` : '';
        warn(
          'ISSUE_STATUSES_FAILED',
          `project ${key}: ${issues.failed} statuses were not imported: ${first}${more}`,
        );
      }
      const answered = built.items.length - issues.notSent - issues.failed;
      if (answered >= HINT_MIN_ITEMS && issues.unmatched / answered >= HINT_UNMATCHED_SHARE) {
        warn(
          'PATH_PREFIX_HINT',
          `${issues.unmatched} of ${answered} statuses of project ${key} matched no Qualor issue; if SonarQube analysed a subdirectory of the repository (sonar.projectBaseDir), pass it as --path-prefix`,
        );
      }
    } catch (err) {
      issues.outcome = 'failed';
      warn('ISSUES_NOT_READ', `project ${key}: ${stepFailure(err)}`);
    }
  }

  let fatal: unknown = null;
  try {
    if (steps.has('profiles')) {
      await applyProfiles(qualor, organization.id, plannedProfiles, o, profiles);
    } else {
      const found = await applyProfiles(qualor, organization.id, plannedProfiles, lookup);
      profiles.push(...found.map(lookedUp));
    }
    if (steps.has('gates')) {
      await applyGates(qualor, organization.id, plannedGates, o, gates);
    } else {
      const found = await applyGates(qualor, organization.id, plannedGates, lookup);
      gates.push(...found.map(lookedUp));
    }
    if (steps.has('projects')) {
      await applyProjects(qualor, organization.id, settings, profiles, gates, o, projects);
    } else {
      const byKey = { ...lookup, createProjects: false };
      await applyProjects(qualor, organization.id, settings, [], [], byKey, projects);
    }
    projects.push(...unread);
    if (steps.has('issues')) {
      for (const result of projects) {
        const issues = emptyIssues(result.qualorProjectId === null ? 'skipped' : 'done');
        issuesOf.set(result, issues);
        if (result.qualorProjectId !== null) {
          await importIssues(result.sonar.key, result.qualorProjectId, issues);
        }
      }
    }
  } catch (err) {
    // Ruling S13: once writing has begun, a fatal failure still leaves the summary and the report.
    fatal = err;
    for (const r of unread) if (!projects.includes(r)) projects.push(r);
  }

  const origin = new URL(setup.sonar.url);
  const report = buildReport({
    source: {
      kind: 'sonarqube',
      edition: conn.kind,
      origin: `${origin.origin}${origin.pathname.replace(/\/+$/, '')}`,
      organization: setup.sonar.organization,
      version: conn.version?.text ?? null,
    },
    dryRun: flags.dryRun,
    startedAt,
    finishedAt: now(),
    organization,
    profiles: steps.has('profiles') ? profiles : [],
    gates: steps.has('gates') ? gates : [],
    projects: projects.map((result) => ({
      result,
      issues: steps.has('issues') ? (issuesOf.get(result) ?? emptyIssues('skipped')) : null,
    })),
    warnings: [...warnings, ...conn.client.warnings],
    aborted: fatal === null ? null : { reason: fatalReason(fatal) },
  });
  printSummary(report, log);
  let unwritten: CliError | null = null;
  if (output !== null) {
    try {
      writeReport(output, report);
    } catch (err) {
      if (!(err instanceof CliError)) throw err;
      unwritten = err;
    }
  }
  if (fatal !== null) {
    // The fatal failure goes on to `main`, unless the report's own failure is worse.
    if (unwritten !== null && fatal instanceof CliError && unwritten.exitCode > fatal.exitCode) {
      log.error(fatal.message);
      throw unwritten;
    }
    if (unwritten !== null) log.error(unwritten.message);
    throw fatal;
  }
  const failed =
    report.profiles.some((p) => p.outcome === 'failed') ||
    report.gates.some((g) => g.outcome === 'failed') ||
    report.projects.some(
      (p) =>
        p.outcome === 'failed' ||
        p.issues?.outcome === 'failed' ||
        p.profiles.some((a) => a.outcome === 'failed') ||
        p.gate?.outcome === 'failed',
    );
  const code: ExitCode = failed ? EXIT.SERVER : EXIT.OK;
  if (unwritten === null) return code;
  log.error(unwritten.message);
  return worse(code, unwritten.exitCode);
}
