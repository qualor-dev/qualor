import { gunzipSync, gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { makeReport } from '../../test/make-report';
import { REPORT_BOUNDS, reportSchema, type Report } from './schema';

function issues(report: unknown): string[] {
  const r = reportSchema.safeParse(report);
  return r.success ? [] : r.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`);
}

/** Narrows away `null | undefined` without a non-null assertion (forbidden by lint). */
function must<T>(value: T | null | undefined, message = 'expected a value'): T {
  if (value === null || value === undefined) throw new Error(message);
  return value;
}

const base = makeReport();
const finding = must(base.findings[0]);
const file = must(base.files[0]);

describe('reportSchema', () => {
  it('accepts a valid report', () => {
    expect(issues(base)).toEqual([]);
  });

  it('round-trips through JSON + gzip unchanged', () => {
    const bytes = gzipSync(JSON.stringify(base));
    const parsed = reportSchema.parse(JSON.parse(gunzipSync(bytes).toString('utf8')));
    expect(parsed).toEqual(base);
  });

  it('strips unknown fields (forward compatibility)', () => {
    const parsed = reportSchema.parse({ ...base, futureField: 1 });
    expect(parsed).not.toHaveProperty('futureField');
  });

  it('rejects unsupported schema versions', () => {
    expect(issues({ ...base, schemaVersion: 2 })[0]).toMatch(/^schemaVersion/);
  });

  it.each(['../x.ts', '/abs.ts', 'src\\a.ts', './a.ts'])('rejects bad file path %j', (p) => {
    expect(issues({ ...base, files: [{ ...file, path: p }] }).join()).toMatch(/files\.0\.path/);
  });

  it('rejects duplicate file paths', () => {
    expect(issues({ ...base, files: [file, file] }).join()).toMatch(/duplicate file path/);
  });

  it('accepts a Python file (plan 8C)', () => {
    expect(issues({ ...base, files: [{ ...file, language: 'python' }] })).toEqual([]);
  });

  it('rejects a finding on a file that is not in files[]', () => {
    const f = { ...finding, location: { ...must(finding.location), path: 'src/missing.ts' } };
    expect(issues({ ...base, findings: [f] }).join()).toMatch(/findings\.0\.location\.path/);
  });

  it('accepts a file-less finding (location null)', () => {
    expect(issues({ ...base, findings: [{ ...finding, location: null }] })).toEqual([]);
  });

  it('rejects a finding whose engine is not listed', () => {
    expect(issues({ ...base, findings: [{ ...finding, engineId: 'pmd' }] }).join()).toMatch(
      /findings\.0\.engineId/,
    );
  });

  it('rejects an external engine claiming a reserved id', () => {
    const engines = [{ ...must(base.engines[0]), kind: 'external' as const }];
    expect(issues({ ...base, engines }).join()).toMatch(/reserved/);
  });

  it('rejects invalid engine ids', () => {
    const engines = [{ ...must(base.engines[0]), id: 'Bad_Id' }];
    expect(issues({ ...base, engines }).join()).toMatch(/engines\.0\.id/);
  });

  it('rejects over-long messages and too many secondary locations', () => {
    const long = { ...finding, message: 'x'.repeat(REPORT_BOUNDS.messageChars + 1) };
    expect(issues({ ...base, findings: [long] }).join()).toMatch(/findings\.0\.message/);
    const sec = Array.from({ length: REPORT_BOUNDS.secondaryLocations + 1 }, () => ({
      path: 'src/a.ts',
      startLine: 1,
    }));
    expect(issues({ ...base, findings: [{ ...finding, secondaryLocations: sec }] }).join()).toMatch(
      /secondaryLocations/,
    );
  });

  it('bounds scm.renames (report-format §9)', () => {
    const rename = { from: 'src/a.ts', to: 'src/b.ts' };
    const at = (n: number) => ({
      ...base,
      scm: { ...base.scm, renames: Array.from({ length: n }, () => rename) },
    });
    expect(issues(at(REPORT_BOUNDS.renames))).toEqual([]);
    expect(issues(at(REPORT_BOUNDS.renames + 1)).join()).toMatch(/scm\.renames/);
  });

  it('accepts the optional GitLab CI context and checks its values (scm.md §3)', () => {
    const at = (gitlab: unknown) => ({ ...base, scm: { ...base.scm, gitlab } });
    expect(
      issues(
        at({ projectId: '4711', pipelineId: '99001', mergeRequestEventType: 'merged_result' }),
      ),
    ).toEqual([]);
    expect(issues(at({}))).toEqual([]);
    expect(issues(at({ projectId: '47a' })).join()).toMatch(/scm\.gitlab\.projectId/);
    expect(issues(at({ pipelineId: 1 })).join()).toMatch(/scm\.gitlab\.pipelineId/);
    expect(issues(at({ mergeRequestEventType: 'push' })).join()).toMatch(
      /scm\.gitlab\.mergeRequestEventType/,
    );
    // Bounded: ids are 1-20 ASCII digits, nothing else.
    for (const bad of ['', '1'.repeat(21), ' 1', '1\n', '-1', '\u0661', '1e3']) {
      expect(issues(at({ projectId: bad })).join(), JSON.stringify(bad)).toMatch(
        /scm\.gitlab\.projectId/,
      );
    }
    expect(issues(at({ projectId: '1'.repeat(20) }))).toEqual([]);
    expect(issues(at(null)).join()).toMatch(/scm\.gitlab/);
  });

  it('keeps reports without scm.gitlab valid and drops unknown scm.gitlab keys (scm.md §3)', () => {
    // An older CLI's report has no scm.gitlab at all.
    expect(base.scm).not.toHaveProperty('gitlab');
    expect(issues(base)).toEqual([]);
    // Nothing but the three known fields survives parsing, so no stray value (a token) is kept.
    const parsed = reportSchema.parse({
      ...base,
      scm: { ...base.scm, gitlab: { projectId: '1', jobToken: 'glcbt-SECRET', password: 'x' } },
    });
    expect(parsed.scm.gitlab).toEqual({ projectId: '1' });
    expect(JSON.stringify(parsed)).not.toContain('SECRET');
  });

  it("accepts an engine's vulnerability database and checks it (plan 2B)", () => {
    const at = (database: unknown) => ({
      ...base,
      engines: base.engines.map((e) => ({ ...e, database })),
    });
    expect(issues(at({ name: 'trivy-db', updatedAt: '2026-09-25T06:36:11.019457553Z' }))).toEqual(
      [],
    );
    expect(issues(at(undefined))).toEqual([]);
    // report-format.md §9: at most 64 characters, however many fraction digits.
    const long = `2026-09-25T06:36:11.${'0'.repeat(50)}Z`;
    expect(issues(at({ name: 'trivy-db', updatedAt: long })).join()).toMatch(
      /engines.0.database.updatedAt/,
    );
    expect(issues(at({ name: 'trivy-db', updatedAt: 'yesterday' })).join()).toMatch(
      /engines\.0\.database\.updatedAt/,
    );
    expect(issues(at({ name: '', updatedAt: '2026-09-25T06:36:11Z' })).join()).toMatch(
      /engines\.0\.database\.name/,
    );
    expect(issues(at({ name: 'x'.repeat(65), updatedAt: '2026-09-25T06:36:11Z' }))).not.toEqual([]);
  });

  it('rejects inverted ranges', () => {
    const f = { ...finding, location: { ...must(finding.location), startLine: 5, endLine: 4 } };
    expect(issues({ ...base, findings: [f] }).join()).toMatch(/endLine/);
    expect(issues({ ...base, files: [{ ...file, newLines: [[4, 3]] }] }).join()).toMatch(
      /newLines/,
    );
  });

  it('requires a baseline revision when baseline status is ok', () => {
    const scm = {
      ...base.scm,
      baseline: { revision: null, kind: 'merge_base' as const, status: 'ok' as const },
    };
    expect(issues({ ...base, scm }).join()).toMatch(/scm\.baseline\.revision/);
  });

  it('forbids newLines when the baseline is unavailable', () => {
    const scm = {
      ...base.scm,
      baseline: { revision: null, kind: 'none' as const, status: 'unavailable' as const },
    };
    expect(issues({ ...base, scm }).join()).toMatch(/files\.0\.newLines/);
    const { newLines: _drop, ...noNewLines } = file;
    void _drop;
    expect(issues({ ...base, scm, files: [noNewLines] })).toEqual([]);
  });

  it('accepts newLines "all" for added files', () => {
    expect(issues({ ...base, files: [{ ...file, newLines: 'all' }] })).toEqual([]);
  });

  it('requires at least two blocks per duplication group', () => {
    const one = { blocks: [{ path: 'src/a.ts', startLine: 1, endLine: 2 }] };
    expect(issues({ ...base, duplications: [one] }).join()).toMatch(/duplications\.0\.blocks/);
  });

  it('limits properties to 4 KiB', () => {
    const big = { ...finding, properties: { blob: 'x'.repeat(5000) } };
    expect(issues({ ...base, findings: [big] }).join()).toMatch(/properties/);
  });

  it('bounds partialFingerprints to 16 keys of <= 128 chars with values <= 256 chars', () => {
    const pf = (partialFingerprints: Record<string, string>) =>
      issues({ ...base, findings: [{ ...finding, partialFingerprints }] });
    const sixteen = Object.fromEntries(Array.from({ length: 16 }, (_, i) => [`k${i}`, 'v']));
    expect(pf(sixteen)).toEqual([]);
    expect(pf({ ['k'.repeat(128)]: 'v'.repeat(256) })).toEqual([]);
    expect(pf({ ...sixteen, k16: 'v' }).join()).toMatch(/partialFingerprints/);
    expect(pf({ ['k'.repeat(129)]: 'v' }).join()).toMatch(/partialFingerprints/);
    expect(pf({ k: 'v'.repeat(257) }).join()).toMatch(/partialFingerprints/);
  });

  it('types line ranges as tuples', () => {
    const r: Report = base;
    const first = must(r.files[0]).newLines;
    expect(Array.isArray(first) && first[0]).toEqual([3, 4]);
  });
});

describe('scm.github (github.md §3)', () => {
  const withGithub = (github: unknown) => {
    const report = structuredClone(base);
    (report.scm as Record<string, unknown>).provider = 'github';
    (report.scm as Record<string, unknown>).github = github;
    return reportSchema.safeParse(report);
  };

  it('accepts the three fields and drops unknown keys', () => {
    const parsed = withGithub({ repositoryId: '123', runId: '456', checkout: 'head', token: 'x' });
    expect(parsed.success).toBe(true);
    expect(parsed.data?.scm.github).toEqual({
      repositoryId: '123',
      runId: '456',
      checkout: 'head',
    });
  });

  it('refuses a malformed id and an unknown checkout, naming the field', () => {
    for (const [github, path] of [
      [{ repositoryId: '12a' }, 'scm.github.repositoryId'],
      [{ runId: '1'.repeat(21) }, 'scm.github.runId'],
      [{ checkout: 'merge' }, 'scm.github.checkout'],
    ] as const) {
      const parsed = withGithub(github);
      expect(parsed.success).toBe(false);
      expect(parsed.error?.issues.map((i) => i.path.join('.'))).toContain(path);
    }
  });
});
