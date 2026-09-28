import { describe, expect, it } from 'vitest';
import { ciMask, exitFourOnFailure, gateLines, portableLcov } from './scans';

describe('dogfood scan output', () => {
  it('keeps the gate verdict, failed conditions and skipped analyzers', () => {
    const stderr = [
      'info: scanning /src',
      'spotbugs: skipped (no compiled classes in target/classes)',
      'error: quality gate "Qualor way": failed',
      'error:   new_issues > 0: 1 (failed)',
      'info: uploaded',
    ].join('\n');
    expect(gateLines(stderr)).toEqual([
      '    spotbugs: skipped (no compiled classes in target/classes)',
      '    error: quality gate "Qualor way": failed',
      '    error:   new_issues > 0: 1 (failed)',
    ]);
  });

  it('turns Windows LCOV paths into repository paths', () => {
    expect(portableLcov('TN:\nSF:cli\\src\\args.ts\nDA:1,1\n')).toBe(
      'TN:\nSF:cli/src/args.ts\nDA:1,1\n',
    );
  });

  it('masks a secret in GitHub Actions logs, and prints nothing elsewhere', () => {
    expect(ciMask('0123abcd', { GITHUB_ACTIONS: 'true' })).toBe('::add-mask::0123abcd\n');
    expect(ciMask('0123abcd', { GITLAB_CI: 'true' })).toBe('');
    expect(ciMask('0123abcd', {})).toBe('');
  });
});

describe('dogfood exit codes', () => {
  it('passes a scan exit code through, and turns an infrastructure failure into 4', async () => {
    expect(await exitFourOnFailure(async () => 1)).toBe(1);
    expect(await exitFourOnFailure(async () => 0)).toBe(0);
    const failure = await exitFourOnFailure(async () => {
      throw new Error('docker compose up failed (exit 1)');
    });
    // Not 1: a broken stack, clone or install must not read as "the gate failed".
    expect(failure).toBe(4);
  });
});
