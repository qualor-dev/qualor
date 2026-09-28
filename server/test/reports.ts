import { gzipSync } from 'node:zlib';
import { BUILTIN_ENGINES, hex32, type Report } from '@qualor/shared';
import type { TestContext } from './app';

export const REPORT_CONTENT_TYPE = 'application/vnd.qualor.report+json';

export interface ReportOverrides {
  projectKey?: string;
  branch?: string | null;
  mergeRequest?: Report['scm']['mergeRequest'];
  analysisDate?: string;
  revision?: string;
}

/** A small report that satisfies reportSchema (one file, one ESLint finding, one warning). */
export function sampleReport(overrides: ReportOverrides = {}): Report {
  return {
    schemaVersion: 1,
    scanner: { name: 'qualor-cli', version: '0.1.0', platform: 'linux-x64' },
    project: { key: overrides.projectKey ?? 'acme/api', name: 'API', version: '1.0.0' },
    scm: {
      provider: 'gitlab',
      revision: overrides.revision ?? 'a'.repeat(40),
      branch: overrides.branch === undefined ? 'main' : overrides.branch,
      mainBranch: 'main',
      mergeRequest: overrides.mergeRequest ?? null,
      baseline: { revision: 'b'.repeat(40), kind: 'server_baseline', status: 'ok' },
      renames: [],
    },
    analysisDate: overrides.analysisDate ?? '2026-09-22T10:15:00Z',
    engines: [
      {
        id: 'eslint',
        kind: 'builtin',
        version: '9.12.0',
        status: 'ok',
        durationMs: 1_200,
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
        newLines: [[3, 4]],
      },
    ],
    findings: [
      {
        engineId: 'eslint',
        ruleId: 'no-console',
        message: 'Unexpected console statement.',
        severity: 'medium',
        location: { path: 'src/a.ts', startLine: 3 },
        lineHash: 'd'.repeat(32),
        contextHash: 'e'.repeat(32),
      },
    ],
    duplications: [],
    warnings: [
      { code: 'COVERAGE_PATH_UNRESOLVED', message: '2 coverage paths did not resolve', count: 2 },
    ],
  };
}

export function gzipJson(value: unknown): Buffer {
  return gzipSync(Buffer.from(JSON.stringify(value), 'utf8'));
}

/**
 * Gzips a JSON array nested `depth` levels deep around a leaf string, built by string
 * concatenation rather than `JSON.stringify`/recursion — the point of this helper is testing code
 * that must reject pathological nesting without overflowing its own call stack, so building the
 * fixture must not risk overflowing this test's.
 */
export function gzipDeeplyNestedArray(depth: number): Buffer {
  const text = '['.repeat(depth) + '"leaf"' + ']'.repeat(depth);
  return gzipSync(Buffer.from(text, 'utf8'));
}

export async function uploadReport(
  ctx: TestContext,
  headers: Record<string, string>,
  projectKey: string,
  body: Buffer,
): Promise<string> {
  const res = await ctx.app.inject({
    method: 'POST',
    url: `/api/v0/analyses?projectKey=${encodeURIComponent(projectKey)}`,
    headers: { ...headers, 'content-type': REPORT_CONTENT_TYPE, 'content-encoding': 'gzip' },
    payload: body,
  });
  if (res.statusCode !== 202) throw new Error(`upload failed: ${res.statusCode} ${res.body}`);
  return (res.json() as { analysisId: string }).analysisId;
}

export interface ReportParts extends ReportOverrides {
  engines?: Report['engines'];
  files?: Report['files'];
  findings?: Report['findings'];
  duplications?: Report['duplications'];
  warnings?: Report['warnings'];
  baseline?: Report['scm']['baseline'];
  renames?: Report['scm']['renames'];
  version?: string;
}

/** {@link sampleReport} with whole sections replaced. */
export function reportWith(parts: ReportParts): Report {
  const base = sampleReport(parts);
  return {
    ...base,
    project:
      parts.version === undefined ? base.project : { ...base.project, version: parts.version },
    scm: {
      ...base.scm,
      baseline: parts.baseline ?? base.scm.baseline,
      renames: parts.renames ?? base.scm.renames,
    },
    engines: parts.engines ?? base.engines,
    files: parts.files ?? base.files,
    findings: parts.findings ?? base.findings,
    duplications: parts.duplications ?? base.duplications,
    warnings: parts.warnings ?? [],
  };
}

/** An engine entry with status ok and the given rule metadata. */
export function engine(
  id: string,
  rules: Report['engines'][number]['rules'] = [],
  status: Report['engines'][number]['status'] = 'ok',
): Report['engines'][number] {
  return {
    id,
    kind: (BUILTIN_ENGINES as readonly string[]).includes(id) ? 'builtin' : 'external',
    version: '1.0.0',
    status,
    durationMs: 1,
    rules,
  };
}

/** A main TypeScript file entry; `newLines` defaults to none changed. */
export function file(
  path: string,
  overrides: Partial<Report['files'][number]> = {},
): Report['files'][number] {
  return {
    path,
    language: 'typescript',
    kind: 'main',
    sha256: 'c'.repeat(64),
    lines: 100,
    newLines: [],
    ...overrides,
  };
}

/** A finding; hashes default to values derived from the rule and line, so they are distinct. */
export function finding(
  overrides: Partial<Report['findings'][number]> & { path?: string | null; line?: number },
): Report['findings'][number] {
  const { path = 'src/a.ts', line = 1, ...rest } = overrides;
  const engineId = rest.engineId ?? 'eslint';
  const ruleId = rest.ruleId ?? 'no-console';
  const seed = `${engineId}:${ruleId}:${path}:${line}`;
  return {
    engineId,
    ruleId,
    message: `Problem at ${seed}`,
    location: path === null ? null : { path, startLine: line },
    lineHash: hex32(`line:${seed}`),
    contextHash: hex32(`context:${seed}`),
    ...rest,
  };
}
