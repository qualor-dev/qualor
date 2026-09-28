import type { Report } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { sampleReport } from '../../test/reports';
import { INVALID_SCM_CONTEXT, readScmContext, scmContextOf } from './context';

describe('analyses.scm_context (scm.md §7)', () => {
  it('keeps the provider, the merge request id and the GitLab CI context', () => {
    const report = sampleReport();
    const gitlab = { projectId: '7', pipelineId: '99', mergeRequestEventType: 'detached' as const };
    const withCi: Report = {
      ...report,
      scm: {
        ...report.scm,
        mergeRequest: { id: '12', targetBranch: 'main', sourceBranch: 'feature/x' },
        gitlab,
      },
    };
    const context = scmContextOf(withCi);
    expect(context).toEqual({ provider: 'gitlab', mergeRequestId: '12', gitlab });
    expect(readScmContext(context)).toEqual({ kind: 'ok', context });
  });

  it('stores a context that does not fit as invalid, logging why, and reads it back as invalid', () => {
    const report = sampleReport();
    const bad = {
      ...report,
      scm: { ...report.scm, gitlab: { pipelineId: 'x; DROP TABLE' } },
    } as unknown as Report;
    const warnings: string[] = [];
    const stored = scmContextOf(bad, {
      warn: (_: unknown, message: string) => warnings.push(message),
    } as never);
    expect(stored).toEqual(INVALID_SCM_CONTEXT);
    expect(warnings).toEqual([expect.stringContaining('stored as invalid')]);
    expect(warnings[0]).not.toContain('ingested before');
    expect(readScmContext(stored)).toEqual({ kind: 'invalid' });
    expect(readScmContext(null)).toEqual({ kind: 'missing' });
    expect(
      readScmContext({ provider: 'gitlab', mergeRequestId: null, gitlab: null, x: 1 }),
    ).toEqual({
      kind: 'invalid',
    });
  });
});

describe('the GitHub context (github.md §3, D2)', () => {
  it('stores and reads back scm.github', () => {
    const report = sampleReport();
    report.scm.provider = 'github';
    report.scm.github = { repositoryId: '1', runId: '2', checkout: 'head' };
    const stored = scmContextOf(report);
    expect(stored).toEqual({
      provider: 'github',
      mergeRequestId: null,
      gitlab: null,
      github: { repositoryId: '1', runId: '2', checkout: 'head' },
    });
    expect(readScmContext(JSON.parse(JSON.stringify(stored)))).toEqual({
      kind: 'ok',
      context: stored,
    });
  });

  it('stores scm.github only for a GitHub report', () => {
    const report = sampleReport();
    report.scm.github = { repositoryId: '1', runId: '2', checkout: 'head' };
    for (const provider of ['gitlab', 'none'] as const) {
      report.scm.provider = provider;
      expect(scmContextOf(report)).not.toHaveProperty('github');
    }
  });

  it('reads a 2A row without the github key as github null', () => {
    const row = { provider: 'gitlab', mergeRequestId: '12', gitlab: { projectId: '7' } };
    const read = readScmContext(row);
    expect(read.kind).toBe('ok');
    expect(read.kind === 'ok' && (read.context.github ?? null)).toBeNull();
  });

  it('reads an unknown checkout as invalid', () => {
    const row = {
      provider: 'github',
      mergeRequestId: null,
      gitlab: null,
      github: { checkout: 'x' },
    };
    expect(readScmContext(row)).toEqual({ kind: 'invalid' });
  });
});
