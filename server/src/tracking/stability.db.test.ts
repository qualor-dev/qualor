import { splitSourceLines } from '@qualor/shared';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { file, reportWith } from '../../test/reports';
import {
  BASE_SOURCE,
  FLAGGED_LINE,
  sourceFinding,
  STABILITY_CASES,
} from '../../test/tracking-fixtures';
import { issues } from '../db/schema';

describe('tracking stability fixtures (brief §7, data-model.md §8.3)', () => {
  let h: IngestHarness;
  beforeAll(async () => {
    h = await createIngestHarness();
  });
  afterAll(async () => {
    await h.close();
  });

  STABILITY_CASES.forEach((c, n) => {
    it(`${c.keepsId ? 'keeps the issue id' : 'closes the issue'}: ${c.name}`, async () => {
      const p = await h.project(`stability/${n}`);
      const before = reportWith({
        projectKey: p.key,
        analysisDate: '2026-09-22T10:00:00Z',
        files: [file('src/refunds.ts', { lines: splitSourceLines(BASE_SOURCE).length })],
        findings: [sourceFinding('src/refunds.ts', BASE_SOURCE, FLAGGED_LINE)],
      });
      await p.ingestOk(before);
      const [original] = await h.ctx.db.select().from(issues).where(eq(issues.projectId, p.id));
      const after = reportWith({
        projectKey: p.key,
        analysisDate: '2026-09-22T11:00:00Z',
        files: [file(c.path, { lines: splitSourceLines(c.source).length })],
        findings: c.line === null ? [] : [sourceFinding(c.path, c.source, c.line)],
        renames: c.renames ?? [],
      });
      await p.ingestOk(after);
      const rows = await h.ctx.db.select().from(issues).where(eq(issues.projectId, p.id));
      if (c.keepsId) {
        expect(rows).toHaveLength(1);
        expect(rows[0]).toMatchObject({
          id: original!.id,
          status: 'open',
          path: c.path,
          startLine: c.line,
        });
      } else {
        expect(rows).toMatchObject([{ id: original!.id, status: 'closed' }]);
      }
    });
  });

  it('keeps 12 000 identical findings in one file as 12 000 issues after a shift (chunked writes)', async () => {
    const p = await h.project('stability/identical');
    const block = 'console.log(x);\n\n\n\n';
    const n = 12_000;
    const source = block.repeat(n);
    const findings = (text: string, offset: number) => {
      const split = splitSourceLines(text);
      return Array.from({ length: n }, (_, i) =>
        sourceFinding('src/noisy.ts', split, 1 + offset + i * 4),
      );
    };
    const lines = splitSourceLines(source).length;
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        analysisDate: '2026-09-22T10:00:00Z',
        files: [file('src/noisy.ts', { lines })],
        findings: findings(source, 0),
      }),
    );
    const ids = new Set(
      (await h.ctx.db.select({ id: issues.id }).from(issues).where(eq(issues.projectId, p.id))).map(
        (r) => r.id,
      ),
    );
    expect(ids.size).toBe(n);
    const shifted = `// header\n${source}`;
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        analysisDate: '2026-09-22T11:00:00Z',
        files: [file('src/noisy.ts', { lines: lines + 1 })],
        findings: findings(shifted, 1),
      }),
    );
    const after = await h.ctx.db
      .select({ id: issues.id, status: issues.status, fingerprint: issues.fingerprint })
      .from(issues)
      .where(eq(issues.projectId, p.id));
    expect(after).toHaveLength(n);
    expect(after.every((r) => r.status === 'open' && ids.has(r.id))).toBe(true);
    expect(new Set(after.map((r) => r.fingerprint)).size).toBe(n);
  });
});
