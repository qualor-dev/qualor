import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { importReportSchema, planGate } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { EXIT } from '../errors';
import { createLogger } from '../log';
import {
  buildReport,
  checkReportPath,
  printSummary,
  writeReport,
  type ReportInput,
} from './report';

const input = (over: Partial<ReportInput> = {}): ReportInput => ({
  source: {
    kind: 'sonarqube',
    edition: 'server',
    origin: 'https://sonar.test',
    organization: null,
    version: '10.7.0.96327',
  },
  dryRun: true,
  startedAt: new Date('2026-09-25T10:00:00Z'),
  finishedAt: new Date('2026-09-25T10:01:00Z'),
  organization: { id: '00000000-0000-7000-8000-000000000001', key: 'default' },
  profiles: [],
  gates: [],
  projects: [],
  warnings: [],
  aborted: null,
  ...over,
});

const summary = (r: ReturnType<typeof buildReport>) => {
  const lines: string[] = [];
  printSummary(
    r,
    createLogger('debug', (t) => lines.push(t)),
  );
  return lines.join('');
};

describe('the import report (import-sonarqube.md §12)', () => {
  it('builds an empty report that passes the schema, and a dry run says so', () => {
    const report = buildReport(input());
    expect(importReportSchema.safeParse(report).success).toBe(true);
    expect(summary(report)).toContain('dry run: nothing was written to Qualor');
    expect(summary(buildReport(input({ dryRun: false })))).not.toContain('dry run');
  });

  it('reports a condition that lost to another on one Qualor metric with that metric', () => {
    const planned = planGate({
      name: 'Mixed',
      isDefault: false,
      isBuiltIn: false,
      conditions: [
        { metric: 'coverage', op: 'LT', error: '80' },
        { metric: 'coverage', op: 'GT', error: '99' },
        { metric: 'violations', op: 'GT', error: '0' },
        { metric: 'open_issues', op: 'GT', error: '0' },
      ],
    });
    const report = buildReport(
      input({
        gates: [
          {
            planned,
            outcome: 'would_create',
            reason: null,
            qualorGateId: null,
            defaultChange: null,
          },
        ],
      }),
    );
    const [, conflict, , duplicate] = report.gates[0]?.conditions ?? [];
    expect(conflict).toMatchObject({ reason: 'operator_conflict', qualorMetric: 'coverage' });
    expect(duplicate).toMatchObject({ reason: 'duplicate_metric', qualorMetric: 'issues' });
    const text = summary(report);
    expect(text).toContain('coverage GT 99: unmapped (operator_conflict: coverage)');
    expect(text).toContain('open_issues GT 0: unmapped (duplicate_metric: issues)');
  });

  it('counts each outcome of spec §12.1 in the summary, changed and path invalid included (M-1)', () => {
    const issues = {
      outcome: 'done' as const,
      read: 9,
      applied: 1,
      wouldApply: 0,
      alreadySet: 0,
      conflict: 0,
      unmatched: 0,
      ambiguous: 0,
      competitorsUnknown: 0,
      notSent: 0,
      changed: 3,
      failed: 0,
      unmappedRule: 0,
      pathInvalid: 2,
      invalid: 1,
      notRead: 0,
      hotspotsNotImported: 0,
      unmappedRules: [],
      items: [],
    };
    const result = {
      sonar: {
        key: 'acme:shop',
        name: 'Shop',
        mainBranch: 'main',
        profiles: [],
        gate: null,
      },
      outcome: 'found' as const,
      reason: null,
      qualorProjectId: '00000000-0000-7000-8000-000000000002',
      profiles: [],
      gate: null,
    };
    const text = summary(buildReport(input({ dryRun: false, projects: [{ result, issues }] })));
    expect(text).toContain('3 changed in SonarQube');
    expect(text).toContain('2 path invalid, 1 invalid');
  });

  it('lists warnings by code and count only: their text was logged when they occurred', () => {
    const report = buildReport(
      input({
        warnings: [
          { code: 'SONARQUBE_ISSUE_WINDOW', message: 'first text' },
          { code: 'SONARQUBE_ISSUE_WINDOW', message: 'second text' },
          { code: 'PATH_PREFIX_HINT', message: 'third text' },
        ],
      }),
    );
    const text = summary(report);
    expect(text).toContain('SONARQUBE_ISSUE_WINDOW 2, PATH_PREFIX_HINT 1');
    expect(text).not.toMatch(/first text|second text|third text/);
    expect(text).not.toContain('warn: ');
  });

  it('marks a report the run could not finish as aborted, with the reason, and says so (ruling S13)', () => {
    expect(buildReport(input()).aborted).toBeNull();
    const report = buildReport(input({ aborted: { reason: 'SonarQube refused the token (401)' } }));
    expect(report.aborted).toEqual({ reason: 'SonarQube refused the token (401)' });
    expect(summary(report)).toContain(
      'the import stopped before it finished (SonarQube refused the token (401)); what is listed above is what it did',
    );
  });

  it('fails a report it cannot write with exit 4 (an I/O failure, not a usage error)', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-report-'));
    const file = path.join(dir, 'report.json');
    mkdirSync(file);
    expect(() => writeReport(file, buildReport(input()))).toThrow(
      expect.objectContaining({ exitCode: EXIT.SERVER }),
    );
  });

  it('checks the --output path before any request (exit 2)', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-report-'));
    expect(() => checkReportPath(path.join(dir, 'report.json'))).not.toThrow();
    expect(() => checkReportPath(path.join(dir, 'missing', 'report.json'))).toThrow(
      expect.objectContaining({ exitCode: EXIT.USAGE }),
    );
    mkdirSync(path.join(dir, 'sub'));
    expect(() => checkReportPath(path.join(dir, 'sub'))).toThrow(/directory/);
  });

  it('writes the report with mode 0600, replacing an older file', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-report-'));
    const file = path.join(dir, 'report.json');
    writeFileSync(file, 'old', { mode: 0o644 });
    const report = buildReport(input());
    writeReport(file, report);
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual(report);
    if (process.platform !== 'win32') expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(readdirSync(dir)).toEqual(['report.json']);
  });

  it('never follows a symbolic link at the --output path', (ctx) => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-report-'));
    const victim = path.join(dir, 'victim.txt');
    writeFileSync(victim, 'keep me');
    const file = path.join(dir, 'report.json');
    try {
      symlinkSync(victim, file, 'file');
    } catch {
      ctx.skip(); // Windows without the right to create symbolic links
    }
    writeReport(file, buildReport(input()));
    expect(readFileSync(victim, 'utf8')).toBe('keep me');
    expect(lstatSync(file).isSymbolicLink()).toBe(false);
    expect(existsSync(file)).toBe(true);
  });
});
