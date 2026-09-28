import { allMetricKeys } from '@qualor/shared';
import { and, asc, eq, sql } from 'drizzle-orm';
import { collectGarbage } from '../../test/perf';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { engine, file, finding, reportWith } from '../../test/reports';
import { branchFiles, branches, issues, measures } from '../db/schema';
import {
  MAX_ANALYSIS_DUPLICATION_BYTES,
  MAX_ANALYSIS_DUPLICATIONS,
  MAX_DUPLICATION_OTHERS,
  MAX_FILE_DUPLICATION_BYTES,
  MAX_FILE_DUPLICATIONS,
} from './store';

describe('measures stage (server step 10)', () => {
  let h: IngestHarness;
  const measuresOf = async (analysisId: string) => {
    const rows = await h.ctx.db.select().from(measures).where(eq(measures.analysisId, analysisId));
    return Object.fromEntries(
      rows.map((r) => [r.scope === 'new' ? `new_${r.metricKey}` : r.metricKey, r.value]),
    );
  };
  const filesOf = async (p: IngestProject) => {
    const [main] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, p.id), eq(branches.isMain, true)));
    return h.ctx.db
      .select()
      .from(branchFiles)
      .where(eq(branchFiles.branchId, main!.id))
      .orderBy(asc(branchFiles.path));
  };

  beforeAll(async () => {
    h = await createIngestHarness();
  });
  afterAll(async () => {
    await h.close();
  });

  it('stores one row per catalog metric and scope, from the report and the visible issues', async () => {
    const p = await h.project('measures/basic');
    const id = await p.ingestOk(
      reportWith({
        projectKey: p.key,
        engines: [
          engine('eslint', [{ id: 'no-console', quality: 'reliability', defaultSeverity: 'high' }]),
          engine('gitleaks'),
          engine('semgrep', [{ id: 'hardcoded-key', cwe: [798], quality: 'security' }]),
        ],
        files: [
          file('src/a.ts', {
            lines: 40,
            newLines: [[10, 12]],
            coverage: { covered: [[1, 8]], uncovered: [[9, 12]], branches: [] },
          }),
          file('src/a.test.ts', { kind: 'test', lines: 7 }),
        ],
        findings: [
          finding({ line: 10 }),
          finding({ line: 30, severity: 'low' }),
          finding({ engineId: 'gitleaks', ruleId: 'generic-api-key', line: 20 }),
          // Same line as the Gitleaks finding: a hidden duplicate, excluded from every count.
          finding({ engineId: 'semgrep', ruleId: 'hardcoded-key', line: 20, severity: 'high' }),
        ],
      }),
    );
    const m = await measuresOf(id);
    expect(Object.keys(m).sort()).toEqual(allMetricKeys().sort());
    expect(m).toMatchObject({
      files: 1,
      lines: 40,
      issues: 3,
      security_issues: 1,
      reliability_issues: 2,
      blocker_issues: 1,
      security_rating: 5,
      reliability_rating: 4,
      new_issues: 1,
      new_lines: 3,
      lines_to_cover: 12,
      coverage: 66.7,
      new_lines_to_cover: 3,
      new_coverage: 0,
    });
  });

  it('excludes wont_fix and false_positive issues from counts and reports them separately', async () => {
    const p = await h.project('measures/resolutions');
    const report = (date: string) =>
      reportWith({
        projectKey: p.key,
        analysisDate: date,
        files: [file('src/a.ts')],
        findings: [1, 2, 3].map((line) => finding({ line, ruleId: `r${line}` })),
      });
    await p.ingestOk(report('2026-09-22T10:00:00Z'));
    const rows = await h.ctx.db
      .select()
      .from(issues)
      .where(eq(issues.projectId, p.id))
      .orderBy(asc(issues.startLine));
    await h.ctx.db.update(issues).set({ status: 'wont_fix' }).where(eq(issues.id, rows[0]!.id));
    await h.ctx.db
      .update(issues)
      .set({ status: 'false_positive' })
      .where(eq(issues.id, rows[1]!.id));
    const id = await p.ingestOk(report('2026-09-22T11:00:00Z'));
    expect(await measuresOf(id)).toMatchObject({
      issues: 1,
      accepted_issues: 1,
      false_positive_issues: 1,
    });
  });

  it('replaces the branch file snapshot on every analysis', async () => {
    const p = await h.project('measures/files');
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        analysisDate: '2026-09-22T10:00:00Z',
        files: [file('src/gone.ts'), file('src/kept.ts')],
        findings: [],
      }),
    );
    const id = await p.ingestOk(
      reportWith({
        projectKey: p.key,
        analysisDate: '2026-09-22T11:00:00Z',
        files: [
          file('src/kept.ts', {
            lines: 30,
            newLines: 'all',
            metrics: {
              ncloc: 20,
              commentLines: 2,
              functions: 3,
              classes: 1,
              statements: 9,
              complexity: 4,
              cognitiveComplexity: 2,
            },
            coverage: { covered: [[1, 3]], uncovered: [[4, 4]], branches: [[2, 2, 1]] },
          }),
          file('src/twin.ts', { lines: 30 }),
        ],
        findings: [],
        duplications: [
          {
            blocks: [
              { path: 'src/kept.ts', startLine: 11, endLine: 20 },
              { path: 'src/twin.ts', startLine: 1, endLine: 10 },
            ],
          },
        ],
      }),
    );
    const files = await filesOf(p);
    expect(files.map((f) => f.path)).toEqual(['src/kept.ts', 'src/twin.ts']);
    expect(files[0]).toMatchObject({
      analysisId: id,
      language: 'typescript',
      kind: 'main',
      metrics: {
        lines: 30,
        ncloc: 20,
        newLines: 30,
        linesToCover: 4,
        uncoveredLines: 1,
        conditionsToCover: 2,
        uncoveredConditions: 1,
        duplicatedLines: 10,
        duplicatedBlocks: 1,
      },
      coverage: { covered: [[1, 3]], uncovered: [[4, 4]], branches: [[2, 2, 1]] },
      newLines: 'all',
      duplications: [
        {
          startLine: 11,
          endLine: 20,
          others: [{ path: 'src/twin.ts', startLine: 1, endLine: 10 }],
        },
      ],
    });
    expect(files[1]!.coverage).toBeNull();
  });

  it('bounds the partners stored per duplicated block', async () => {
    const p = await h.project('measures/partners');
    const blocks = Array.from({ length: 150 }, (_, i) => ({
      path: 'src/a.ts',
      startLine: i * 10 + 1,
      endLine: i * 10 + 5,
    }));
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        files: [file('src/a.ts', { lines: 2_000 })],
        findings: [],
        duplications: [{ blocks }],
      }),
    );
    const [row] = await filesOf(p);
    const stored = row!.duplications as { others: unknown[]; othersTotal: number }[];
    expect(stored).toHaveLength(150);
    expect(stored.every((d) => d.others.length === MAX_DUPLICATION_OTHERS)).toBe(true);
    expect(stored.every((d) => d.othersTotal === 149)).toBe(true);
    expect(row!.metrics).toMatchObject({ duplicatedBlocks: 150, duplicatedLines: 750 });
  });

  it('charges partner paths their JSON-escaped UTF-8 size against the byte budget (D-M4)', async () => {
    // Control characters are legal in a repo path and cost 6 bytes each once JSON-escaped
    // (a backslash, "u" and four hex digits), so counting UTF-16 code units under-charged such
    // paths about 6-fold.
    const p = await h.project('measures/escaped-paths');
    const partner = (i: number) => `x/${String.fromCharCode(1).repeat(1_000)}${i}`;
    const duplications = Array.from({ length: 100 }, (_, g) => ({
      blocks: [
        { path: 'src/a.ts', startLine: g * 10 + 1, endLine: g * 10 + 5 },
        ...Array.from({ length: MAX_DUPLICATION_OTHERS }, (_, i) => ({
          path: partner(i),
          startLine: g * 10 + 1,
          endLine: g * 10 + 5,
        })),
      ],
    }));
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        files: [file('src/a.ts', { lines: 2_000 })],
        findings: [],
        duplications,
      }),
    );
    const [row] = await filesOf(p);
    const stored = row!.duplications as unknown[];
    expect(stored.length).toBeGreaterThan(0);
    expect(stored.length).toBeLessThan(100);
    expect(Buffer.byteLength(JSON.stringify(stored), 'utf8')).toBeLessThanOrEqual(
      MAX_FILE_DUPLICATION_BYTES,
    );
    expect(row!.metrics).toMatchObject({ duplicatedBlocks: 100, duplicationEntries: 100 });
  });

  it('stores a bounded duplication detail for 200 000 blocks, in bounded memory', async () => {
    const p = await h.project('measures/many-blocks');
    const FILES = 100;
    const GROUPS = 200;
    const PER_GROUP = 1_000;
    const duplications = Array.from({ length: GROUPS }, (_, g) => ({
      blocks: Array.from({ length: PER_GROUP }, (_, b) => {
        const startLine = (g * (PER_GROUP / FILES) + Math.floor(b / FILES)) * 5 + 1;
        return { path: `src/f${b % FILES}.ts`, startLine, endLine: startLine + 3 };
      }),
    }));
    const files = Array.from({ length: FILES }, (_, i) => file(`src/f${i}.ts`, { lines: 20_000 }));
    let peak = 0;
    const sample = () => {
      peak = Math.max(peak, process.memoryUsage().heapUsed);
    };
    const report = reportWith({ projectKey: p.key, files, findings: [], duplications });
    // Measure from the live heap, not from whatever garbage earlier tests left behind, so the
    // growth below is the ingestion's own (it would otherwise vary with GC timing).
    collectGarbage();
    sample();
    const before = peak;
    const timer = setInterval(sample, 1);
    try {
      await p.ingestOk(report);
    } finally {
      clearInterval(timer);
    }
    sample();
    // The previous code grew by ~600 MB here (100k blocks); the report itself is ~15 MB of JSON.
    // Measured: ~160 MB, ~200 MB under v8 coverage.
    expect(peak - before).toBeLessThan(300 * 1024 * 1024);

    const [main] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, p.id), eq(branches.isMain, true)));
    const size = await h.ctx.db.execute<{ total: string; largest: number; entries: string }>(sql`
      SELECT sum(pg_column_size(duplications))::text AS total,
             max(pg_column_size(duplications))::int AS largest,
             sum(jsonb_array_length(duplications))::text AS entries
        FROM branch_files WHERE branch_id = ${main!.id}`);
    const { total, largest, entries } = size.rows[0]!;
    expect(Number(entries)).toBeLessThanOrEqual(MAX_ANALYSIS_DUPLICATIONS);
    expect(Number(total)).toBeLessThan(MAX_ANALYSIS_DUPLICATION_BYTES);
    expect(largest).toBeLessThan(MAX_FILE_DUPLICATION_BYTES);

    const rows = await filesOf(p);
    expect(rows).toHaveLength(FILES);
    for (const row of rows) {
      const stored = row.duplications as { others: unknown[]; othersTotal: number }[];
      expect(stored.length).toBeLessThanOrEqual(MAX_FILE_DUPLICATIONS);
      expect(stored.every((d) => d.others.length === MAX_DUPLICATION_OTHERS)).toBe(true);
      expect(stored.every((d) => d.othersTotal === PER_GROUP - 1)).toBe(true);
      // Counts still use every block of the report.
      expect(row.metrics).toMatchObject({
        duplicatedBlocks: GROUPS * (PER_GROUP / FILES),
        duplicationEntries: GROUPS * (PER_GROUP / FILES),
      });
    }
  }, 180_000);

  it('stores no new lines on a first analysis, like the measures', async () => {
    const p = await h.project('measures/first');
    const id = await p.ingestOk(
      reportWith({
        projectKey: p.key,
        baseline: { revision: null, kind: 'server_baseline', status: 'first_analysis' },
        files: [file('src/a.ts', { lines: 10, newLines: [[1, 3]] })],
        findings: [],
      }),
    );
    const [row] = await filesOf(p);
    expect(row!.newLines).toBeNull();
    expect(row!.metrics).not.toHaveProperty('newLines');
    expect(await measuresOf(id)).toMatchObject({ new_lines: 0 });
  });

  it('counts only issues, not hotspots, as accepted or false positive', async () => {
    const p = await h.project('measures/hotspots');
    const report = (date: string) =>
      reportWith({
        projectKey: p.key,
        analysisDate: date,
        engines: [
          engine('eslint'),
          engine('semgrep', [{ id: 'hs', kind: 'hotspot', quality: 'security' }]),
        ],
        files: [file('src/a.ts')],
        findings: [
          finding({ line: 1, ruleId: 'r1' }),
          finding({ line: 2, ruleId: 'r2' }),
          finding({ engineId: 'semgrep', ruleId: 'hs', line: 3 }),
          finding({ engineId: 'semgrep', ruleId: 'hs', line: 4 }),
        ],
      });
    await p.ingestOk(report('2026-09-22T10:00:00Z'));
    const rows = await h.ctx.db
      .select()
      .from(issues)
      .where(eq(issues.projectId, p.id))
      .orderBy(asc(issues.startLine));
    const status = ['wont_fix', 'false_positive', 'wont_fix', 'false_positive'] as const;
    for (const [i, row] of rows.entries()) {
      await h.ctx.db.update(issues).set({ status: status[i]! }).where(eq(issues.id, row.id));
    }
    expect(rows.map((r) => r.kind)).toEqual(['issue', 'issue', 'hotspot', 'hotspot']);
    const id = await p.ingestOk(report('2026-09-22T11:00:00Z'));
    expect(await measuresOf(id)).toMatchObject({ accepted_issues: 1, false_positive_issues: 1 });
  });
});
