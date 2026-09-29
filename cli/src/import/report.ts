import { randomBytes } from 'node:crypto';
import {
  closeSync,
  constants,
  fchmodSync,
  lstatSync,
  openSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { importReportSchema, type ImportReport } from '@qualor/shared';
import { CliError, EXIT } from '../errors';
import type { Logger } from '../log';
import { clean } from '../server/http';
import type { GateResult, ProfileResult, ProjectResult } from './apply';

type Warning = ImportReport['warnings'][number];
export type Issues = NonNullable<ImportReport['projects'][number]['issues']>;

/**
 * What the report is built from. Deliberately no flags, no setup and no endpoint: nothing that
 * holds a token can reach the report (spec §14); only the warnings are copied as they are.
 */
export interface ReportInput {
  source: ImportReport['source'];
  dryRun: boolean;
  startedAt: Date;
  finishedAt: Date;
  organization: { id: string; key: string };
  profiles: readonly ProfileResult[];
  gates: readonly GateResult[];
  projects: readonly { result: ProjectResult; issues: Issues | null }[];
  warnings: readonly Warning[];
  /** Ruling S13: why the run stopped before it finished, or `null`. */
  aborted: { reason: string } | null;
}

/** Spec §12.2: list bounds (the counts are always complete). */
const MAX_UNMAPPED = 2000;
const MAX_REASON = 2000;
const MAX_MESSAGE = 2000;

const reason = (r: string | null) => (r === null ? null : r.slice(0, MAX_REASON));

/** Spec §12.2: the `--output` report, checked against its schema before it is written. */
export function buildReport(r: ReportInput): ImportReport {
  return importReportSchema.parse({
    format: 'qualor-import-report',
    version: 1,
    source: r.source,
    dryRun: r.dryRun,
    startedAt: r.startedAt.toISOString(),
    finishedAt: r.finishedAt.toISOString(),
    organization: r.organization,
    profiles: r.profiles.map((p) => ({
      sonarKey: p.planned.sonarKey,
      name: p.planned.name,
      sonarLanguage: p.planned.sonarLanguage,
      language: p.planned.language,
      outcome: p.outcome,
      reason: reason(p.reason),
      qualorProfileId: p.qualorProfileId,
      defaultChange: p.defaultChange,
      rules: {
        active: p.planned.stats.active,
        mapped: p.planned.stats.mapped,
        deactivated: p.planned.stats.deactivated,
        severityOverrides: p.planned.stats.severityOverrides,
        pendingReview: p.planned.stats.pendingReview,
        statusOnly: p.planned.stats.statusOnly,
        unmapped: p.planned.stats.unmapped.slice(0, MAX_UNMAPPED),
        unmappedCount: p.planned.stats.unmapped.length,
        parametersNotImported: p.planned.stats.parametersNotImported,
        mappedNotRun: p.planned.stats.mappedNotRun,
      },
    })),
    gates: r.gates.map((g) => ({
      name: g.planned.name,
      outcome: g.outcome,
      reason: reason(g.reason),
      qualorGateId: g.qualorGateId,
      defaultChange: g.defaultChange,
      conditions: g.planned.conditions.map((c) => {
        const sonar = { metric: c.sonar.metric, op: c.sonar.op, error: c.sonar.error };
        const m = c.mapping;
        return m.ok
          ? {
              ...sonar,
              outcome: 'mapped',
              qualor: { metric: m.metric, operator: m.operator, threshold: m.threshold },
              approximate: m.approximate,
              reason: null,
            }
          : {
              ...sonar,
              outcome: 'unmapped',
              qualor: null,
              approximate: false,
              reason: m.reason,
              qualorMetric: 'qualorMetric' in m ? m.qualorMetric : null,
            };
      }),
    })),
    projects: r.projects.map(({ result, issues }) => ({
      key: result.sonar.key,
      outcome: result.outcome,
      reason: reason(result.reason),
      qualorProjectId: result.qualorProjectId,
      profiles: result.profiles.map((a) => ({
        language: a.language,
        profile: a.profile,
        outcome: a.outcome,
        reason: reason(a.reason),
      })),
      gate:
        result.gate === null
          ? null
          : {
              gate: result.gate.gate,
              outcome: result.gate.outcome,
              reason: reason(result.gate.reason),
            },
      issues,
    })),
    warnings: r.warnings.map((w) => ({ code: w.code, message: w.message.slice(0, MAX_MESSAGE) })),
    aborted: r.aborted === null ? null : { reason: r.aborted.reason.slice(0, MAX_REASON) },
  });
}

const errorCode = (err: unknown) =>
  err instanceof Error && 'code' in err && typeof err.code === 'string' ? err.code : 'unknown';

/**
 * Spec §3: `--output` must name a file in an existing directory. Checked before any request, so
 * a run is not lost to a typo at its end. The path is not echoed (it is the operator's own).
 */
export function checkReportPath(file: string): void {
  let dir;
  try {
    dir = statSync(path.dirname(file));
  } catch (err) {
    throw new CliError(
      EXIT.USAGE,
      `cannot write --output: its directory is missing (${errorCode(err)})`,
    );
  }
  if (!dir.isDirectory()) {
    throw new CliError(EXIT.USAGE, 'cannot write --output: its parent is not a directory');
  }
  try {
    if (lstatSync(file).isDirectory()) {
      throw new CliError(EXIT.USAGE, 'cannot write --output: it names a directory');
    }
  } catch (err) {
    if (err instanceof CliError) throw err;
  }
}

/**
 * Spec §3, §12.2: the report, created with mode 0600; a failure is exit 4. It is written to a new file next to the
 * target (`O_CREAT | O_EXCL`, so an existing file or symbolic link there is never opened) and
 * renamed over the target, which replaces a symbolic link at that name instead of following it.
 */
export function writeReport(file: string, report: ImportReport): void {
  const tmp = path.join(
    path.dirname(file),
    `.${path.basename(file)}.${randomBytes(6).toString('hex')}.tmp`,
  );
  let fd: number | undefined;
  try {
    fd = openSync(
      tmp,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    // The creation mode is filtered by the umask; the report is the operator's alone.
    fchmodSync(fd, 0o600);
    writeFileSync(fd, `${JSON.stringify(report, null, 2)}\n`);
    closeSync(fd);
    fd = undefined;
    renameSync(tmp, file);
  } catch (err) {
    if (fd !== undefined) closeSync(fd);
    try {
      unlinkSync(tmp);
    } catch {
      // Not created, or already renamed.
    }
    // An I/O failure at the end of a run, not a usage error (the path was checked first).
    throw new CliError(EXIT.SERVER, `cannot write --output: ${errorCode(err)}`);
  }
}

const n = (x: number) => x.toLocaleString('en-US');
const words = (outcome: string) => outcome.replaceAll('_', ' ');
const why = (r: string | null) => (r === null ? '' : ` (${clean(r)})`);
const defaultNote = (d: 'set' | 'would_set' | null) =>
  d === 'set' ? '; made the default' : d === 'would_set' ? '; would be made the default' : '';

/**
 * Spec §12.1: the summary on stderr at `info`. Warnings were logged when they were recorded;
 * here only their codes and counts are repeated.
 */
export function printSummary(report: ImportReport, log: Logger): void {
  for (const p of report.profiles) {
    const r = p.rules;
    log.info(
      `profile ${clean(p.name)} (${clean(p.sonarLanguage)}): ${words(p.outcome)}${why(p.reason)}${defaultNote(p.defaultChange)}; ` +
        `${n(r.active)} active, ${n(r.mapped)} mapped, ${n(r.deactivated)} turned off, ${n(r.unmappedCount)} unmapped, ` +
        `${n(r.pendingReview.length)} pending review, ${n(r.parametersNotImported.length)} with parameters not imported, ` +
        `${n(r.mappedNotRun.length)} mapped but not run by the bundled configuration`,
    );
  }
  for (const g of report.gates) {
    log.info(
      `gate ${clean(g.name)}: ${words(g.outcome)}${why(g.reason)}${defaultNote(g.defaultChange)}`,
    );
    for (const c of g.conditions) {
      const sonar = `${clean(c.metric)} ${clean(c.op)} ${clean(c.error)}`;
      log.info(
        c.outcome === 'unmapped'
          ? `  ${sonar}: unmapped (${c.reason}${c.qualorMetric === null ? '' : `: ${c.qualorMetric}`})`
          : `  ${sonar} -> ${c.qualor.metric} ${c.qualor.operator} ${c.qualor.threshold}${c.approximate ? ' (approximate)' : ''}`,
      );
    }
  }
  const unmapped = new Map<string, number>();
  for (const p of report.projects) {
    log.info(`project ${clean(p.key)}: ${words(p.outcome)}${why(p.reason)}`);
    for (const a of p.profiles) {
      log.info(`  ${a.language} profile ${clean(a.profile)}: ${words(a.outcome)}${why(a.reason)}`);
    }
    if (p.gate !== null) {
      log.info(`  gate ${clean(p.gate.gate)}: ${words(p.gate.outcome)}${why(p.gate.reason)}`);
    }
    const i = p.issues;
    if (i === null) continue;
    log.info(
      `  issues ${words(i.outcome)}: ${n(i.read)} read, ` +
        `${n(report.dryRun ? i.wouldApply : i.applied)} ${report.dryRun ? 'would apply' : 'applied'}, ` +
        `${n(i.alreadySet)} already set, ${n(i.conflict)} conflict, ${n(i.unmatched)} unmatched, ` +
        `${n(i.ambiguous)} ambiguous, ${n(i.competitorsUnknown)} competitors unknown, ${n(i.notSent)} not sent, ${n(i.changed)} changed in SonarQube, ` +
        `${n(i.failed)} failed, ${n(i.unmappedRule)} unmapped rule, ${n(i.pathInvalid)} path invalid, ${n(i.invalid)} invalid, ` +
        `${n(i.notRead)} not read, ` +
        (i.hotspotsNotImported === null
          ? 'reviewed hotspots not counted'
          : `${n(i.hotspotsNotImported)} reviewed hotspots not imported`),
    );
    for (const u of i.unmappedRules) unmapped.set(u.key, (unmapped.get(u.key) ?? 0) + u.issues);
  }
  const top = [...unmapped].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).slice(0, 20);
  if (top.length > 0) {
    log.info(
      `unmapped rules with the most resolved issues (the full list is in --output): ${top.map(([k, c]) => `${clean(k)} (${n(c)})`).join(', ')}`,
    );
  }
  if (report.warnings.length > 0) {
    const codes = new Map<string, number>();
    for (const w of report.warnings) codes.set(w.code, (codes.get(w.code) ?? 0) + 1);
    log.info(
      `warnings (shown above as they occurred): ${[...codes].map(([code, count]) => `${code} ${n(count)}`).join(', ')}`,
    );
  }
  if (report.dryRun) log.info('dry run: nothing was written to Qualor');
  if (report.aborted !== null) {
    log.info(
      `the import stopped before it finished (${clean(report.aborted.reason)}); what is listed above is what it did`,
    );
  }
}
