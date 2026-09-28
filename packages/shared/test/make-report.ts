import type { Report } from '../src/report/schema';

export function makeReport(overrides: Partial<Report> = {}): Report {
  return {
    schemaVersion: 1,
    scanner: { name: 'qualor-cli', version: '0.0.0', platform: 'linux-x64' },
    project: { key: 'acme/demo', name: 'Demo' },
    scm: {
      provider: 'gitlab',
      revision: 'a'.repeat(40),
      branch: 'main',
      mainBranch: 'main',
      mergeRequest: null,
      baseline: { revision: 'b'.repeat(40), kind: 'server_baseline', status: 'ok' },
      renames: [],
    },
    analysisDate: '2026-09-22T10:15:00Z',
    engines: [
      {
        id: 'eslint',
        kind: 'builtin',
        version: '9.0.0',
        status: 'ok',
        durationMs: 10,
        rules: [{ id: 'no-console', defaultSeverity: 'medium', quality: 'maintainability' }],
      },
    ],
    files: [
      {
        path: 'src/a.ts',
        language: 'typescript',
        kind: 'main',
        sha256: 'c'.repeat(64),
        lines: 10,
        metrics: {
          ncloc: 8,
          commentLines: 1,
          functions: 1,
          classes: 0,
          statements: 4,
          complexity: 2,
          cognitiveComplexity: 1,
        },
        newLines: [[3, 4]],
        coverage: { covered: [[1, 2]], uncovered: [[3, 3]], branches: [[3, 2, 1]] },
      },
    ],
    findings: [
      {
        engineId: 'eslint',
        ruleId: 'no-console',
        message: 'Unexpected console statement.',
        severity: 'medium',
        location: { path: 'src/a.ts', startLine: 3, startColumn: 1, endLine: 3, endColumn: 12 },
        lineHash: 'd'.repeat(32),
        contextHash: 'e'.repeat(32),
      },
    ],
    duplications: [],
    warnings: [],
    ...overrides,
  };
}
