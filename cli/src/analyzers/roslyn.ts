import { clean } from '../server/http';
import type { Analyzer, Preparation } from './types';

/**
 * C# (plan 2D, config.md §6.1): the Roslyn analyzers already ran inside the project's own build
 * between `qualor dotnet begin` and `end`; this adapter only hands their merged logs over.
 */
export const roslynAnalyzer: Analyzer = {
  id: 'roslyn',
  languages: ['csharp'],
  ruleLanguages: ['csharp'],
  prepare(ctx): Promise<Preparation> {
    const run = ctx.dotnet;
    if (run === null) {
      return Promise.resolve({
        skip: 'C# is analysed through qualor dotnet begin and end (see https://qualor.dev/docs/cli)',
      });
    }
    switch (run.kind) {
      case 'no-session':
        return Promise.resolve({ skip: 'qualor dotnet begin was not run' });
      case 'no-build':
        return Promise.resolve({
          skip: 'no C# project was built between qualor dotnet begin and end',
        });
      case 'not-compiled':
        return Promise.resolve({
          unavailable:
            'no C# project was compiled between qualor dotnet begin and end (build with --no-incremental)',
        });
      case 'hook-failed':
        // Final review R10: begin failed under auto, so the build ran without the hook; its C#
        // findings are missing, not fixed (incomplete for scm.md §9's ruling G6).
        return Promise.resolve({
          unavailable: `the MSBuild hook could not be installed (${clean(run.reason)})`,
        });
      case 'collected':
        return Promise.resolve({
          collected: { sarif: run.merged.sarif, version: run.merged.version },
        });
    }
  },
};
