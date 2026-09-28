import { describe, expect, it } from 'vitest';
import { fakeContext } from '../../test/analyzers';
import { useTempDirs } from '../../test/tmp';
import { roslynAnalyzer } from './roslyn';
import type { DotnetRun } from './types';

const tmp = useTempDirs();
const prepare = (dotnet: DotnetRun | null) =>
  roslynAnalyzer.prepare({ ...fakeContext(tmp()), dotnet });

describe('roslyn prepare (ruling D7)', () => {
  it('is a C# engine whose rules are C# rules', () => {
    expect(roslynAnalyzer).toMatchObject({
      id: 'roslyn',
      languages: ['csharp'],
      ruleLanguages: ['csharp'],
    });
  });
  it('skips a plain qualor scan', async () => {
    expect(await prepare(null)).toEqual({
      skip: 'C# is analysed through qualor dotnet begin and end (see https://qualor.dev/docs/cli)',
    });
  });
  it('skips without a session and without a build', async () => {
    expect(await prepare({ kind: 'no-session' })).toEqual({
      skip: 'qualor dotnet begin was not run',
    });
    expect(await prepare({ kind: 'no-build' })).toEqual({
      skip: 'no C# project was built between qualor dotnet begin and end',
    });
  });
  it('is unavailable when projects were built but none compiled', async () => {
    expect(await prepare({ kind: 'not-compiled' })).toEqual({
      unavailable:
        'no C# project was compiled between qualor dotnet begin and end (build with --no-incremental)',
    });
  });
  it('is unavailable when begin could not install the hook, with the reason cleaned (final review R10)', async () => {
    expect(
      await prepare({ kind: 'hook-failed', reason: 'cannot install\u001b[31m it\nthere' }),
    ).toEqual({
      unavailable: 'the MSBuild hook could not be installed (cannot install it there)',
    });
    const long = await prepare({ kind: 'hook-failed', reason: 'x'.repeat(5_000) });
    expect('unavailable' in long && long.unavailable.length).toBeLessThan(1_000);
  });
  it('hands over the merged logs', async () => {
    const merged = {
      sarif: { version: '2.1.0', runs: [] },
      version: '5.9.0',
      results: 0,
      duplicates: 0,
    };
    expect(await prepare({ kind: 'collected', merged })).toEqual({
      collected: { sarif: merged.sarif, version: '5.9.0' },
    });
  });
});
