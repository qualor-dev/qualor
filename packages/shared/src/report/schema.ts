import { z } from 'zod';
import { validateRepoPath } from '../paths';
import {
  BUILTIN_ENGINES,
  ENGINE_ID_PATTERN,
  ISSUE_KINDS,
  LANGUAGES,
  QUALITIES,
  SEVERITIES,
} from './taxonomy';

export const REPORT_SCHEMA_VERSION = 1;

export const REPORT_BOUNDS = {
  files: 200_000,
  renames: 200_000,
  findings: 500_000,
  duplicationGroups: 100_000,
  rulesPerEngine: 20_000,
  messageChars: 4_000,
  secondaryLocations: 20,
  snippetLineChars: 400,
  propertiesBytes: 4_096,
  partialFingerprintKeys: 16,
  partialFingerprintKeyChars: 128,
  partialFingerprintValueChars: 256,
  ruleIdChars: 512,
  ruleNameChars: 512,
  ruleDescriptionChars: 4_000,
  helpUriChars: 2_048,
  ruleTagChars: 128,
  ruleTags: 64,
  ruleCwes: 64,
  engineVersionChars: 128,
} as const;

const repoPath = z.string().superRefine((p, ctx) => {
  const problem = validateRepoPath(p);
  if (problem !== null) ctx.addIssue({ code: 'custom', message: `invalid repo path: ${problem}` });
});
const line = z.number().int().min(1);
const column = z.number().int().min(1);
const gitRevision = z.string().regex(/^[0-9a-f]{40}([0-9a-f]{24})?$/);
const hash32 = z.string().regex(/^[0-9a-f]{32}$/);
const engineId = z.string().regex(ENGINE_ID_PATTERN);

const lineRange = z
  .tuple([line, line])
  .refine(([a, b]) => a <= b, { message: 'range start must be <= end' });
const lineRanges = z.array(lineRange);

const severity = z.enum(SEVERITIES);
const quality = z.enum(QUALITIES);

const location = z
  .object({
    path: repoPath,
    startLine: line,
    startColumn: column.optional(),
    endLine: line.optional(),
    endColumn: column.optional(),
  })
  .refine((l) => l.endLine === undefined || l.endLine >= l.startLine, {
    message: 'endLine must be >= startLine',
    path: ['endLine'],
  });

export const secondaryLocation = z.object({
  path: repoPath,
  startLine: line,
  startColumn: column.optional(),
  endLine: line.optional(),
  endColumn: column.optional(),
  message: z.string().max(REPORT_BOUNDS.messageChars).optional(),
});

const ruleMeta = z.object({
  id: z.string().min(1).max(REPORT_BOUNDS.ruleIdChars),
  name: z.string().max(REPORT_BOUNDS.ruleNameChars).optional(),
  shortDescription: z.string().max(REPORT_BOUNDS.ruleDescriptionChars).optional(),
  helpUri: z.string().max(REPORT_BOUNDS.helpUriChars).optional(),
  defaultSeverity: severity.optional(),
  quality: quality.optional(),
  kind: z.enum(ISSUE_KINDS).optional(),
  tags: z.array(z.string().max(REPORT_BOUNDS.ruleTagChars)).max(REPORT_BOUNDS.ruleTags).optional(),
  cwe: z.array(z.number().int().positive()).max(REPORT_BOUNDS.ruleCwes).optional(),
  languages: z.array(z.string().max(64)).max(32).optional(),
});

const engine = z.object({
  id: engineId,
  kind: z.enum(['builtin', 'external']),
  version: z.string().max(REPORT_BOUNDS.engineVersionChars).nullable().optional(),
  status: z.enum(['ok', 'failed', 'skipped', 'timeout']),
  reason: z.string().max(4_000).nullable().optional(),
  durationMs: z.number().int().min(0),
  rules: z.array(ruleMeta).max(REPORT_BOUNDS.rulesPerEngine),
  /**
   * The vulnerability database a dependency scanner used (Trivy, plan 2B): its name and when it
   * was built, so a stale database is visible in the analysis (report-format.md §5).
   */
  database: z
    .object({
      name: z.string().min(1).max(64),
      updatedAt: z.iso.datetime({ offset: true }).max(64),
    })
    .optional(),
});

const fileMetrics = z.object({
  ncloc: z.number().int().min(0),
  commentLines: z.number().int().min(0),
  functions: z.number().int().min(0),
  classes: z.number().int().min(0),
  statements: z.number().int().min(0),
  complexity: z.number().int().min(0),
  cognitiveComplexity: z.number().int().min(0),
});

const coverage = z.object({
  covered: lineRanges,
  uncovered: lineRanges,
  branches: z.array(
    z
      .tuple([line, z.number().int().min(0), z.number().int().min(0)])
      .refine(([, total, covered]) => covered <= total, {
        message: 'covered conditions must be <= total',
      }),
  ),
});

const file = z.object({
  path: repoPath,
  language: z.enum(LANGUAGES),
  kind: z.enum(['main', 'test']),
  sha256: z.string().regex(/^[0-9a-f]{64}$/),
  lines: z.number().int().min(0),
  metrics: fileMetrics.optional(),
  newLines: z.union([z.literal('all'), lineRanges]).optional(),
  coverage: coverage.optional(),
});

const finding = z.object({
  engineId,
  ruleId: z.string().min(1).max(REPORT_BOUNDS.ruleIdChars),
  message: z.string().min(1).max(REPORT_BOUNDS.messageChars),
  severity: severity.optional(),
  location: location.nullable(),
  secondaryLocations: z.array(secondaryLocation).max(REPORT_BOUNDS.secondaryLocations).optional(),
  lineHash: hash32,
  contextHash: hash32,
  snippet: z
    .object({
      startLine: line,
      lines: z.array(z.string().max(REPORT_BOUNDS.snippetLineChars)).max(50),
    })
    .optional(),
  partialFingerprints: z
    .record(
      z.string().max(REPORT_BOUNDS.partialFingerprintKeyChars),
      z.string().max(REPORT_BOUNDS.partialFingerprintValueChars),
    )
    .refine((p) => Object.keys(p).length <= REPORT_BOUNDS.partialFingerprintKeys, {
      message: `at most ${REPORT_BOUNDS.partialFingerprintKeys} partialFingerprints keys`,
    })
    .meta({ maxProperties: REPORT_BOUNDS.partialFingerprintKeys })
    .optional(),
  properties: z
    .record(z.string(), z.unknown())
    .refine((p) => Buffer.byteLength(JSON.stringify(p), 'utf8') <= REPORT_BOUNDS.propertiesBytes, {
      message: `properties must serialise to <= ${REPORT_BOUNDS.propertiesBytes} bytes`,
    })
    .optional(),
});

/** `CI_MERGE_REQUEST_EVENT_TYPE` values (scm.md §3). */
export const GITLAB_MR_EVENT_TYPES = ['detached', 'merged_result', 'merge_train'] as const;
export type GitLabMergeRequestEventType = (typeof GITLAB_MR_EVENT_TYPES)[number];

/** A GitLab numeric id (`CI_PROJECT_ID`, `CI_PIPELINE_ID`): 1-20 ASCII digits, as a string. */
export const GITLAB_ID = /^[0-9]{1,20}$/;

/** `scm.github.checkout` (github.md §3): whether the checked-out commit is the PR head. */
export const GITHUB_CHECKOUTS = ['head', 'other'] as const;
export type GitHubCheckout = (typeof GITHUB_CHECKOUTS)[number];

/** A GitHub numeric id (repository, workflow run), 1–20 digits (github.md §3). */
export const GITHUB_ID = /^[0-9]{1,20}$/;

const scm = z.object({
  provider: z.enum(['gitlab', 'github', 'none']),
  revision: gitRevision,
  branch: z.string().min(1).max(255).nullable(),
  mainBranch: z.string().min(1).max(255),
  mergeRequest: z
    .object({
      id: z.string().min(1).max(64),
      targetBranch: z.string().min(1).max(255),
      sourceBranch: z.string().min(1).max(255),
    })
    .nullable(),
  baseline: z
    .object({
      revision: gitRevision.nullable(),
      kind: z.enum(['merge_base', 'server_baseline', 'none']),
      status: z.enum(['ok', 'unavailable', 'first_analysis']),
    })
    .refine((b) => b.status !== 'ok' || b.revision !== null, {
      message: 'revision is required when status is ok',
      path: ['revision'],
    }),
  renames: z.array(z.object({ from: repoPath, to: repoPath })).max(REPORT_BOUNDS.renames),
  /**
   * scm.md §3: the GitLab CI context, only in GitLab CI; never trusted to choose a project. Unknown
   * keys are stripped, so nothing but these three non-secret values is ever kept. A malformed or
   * unknown value of a known key is refused, not dropped (scm.md §3, forward compatibility): an
   * event type the server cannot read must not be taken for a detached pipeline.
   */
  gitlab: z
    .object({
      projectId: z.string().regex(GITLAB_ID).optional(),
      pipelineId: z.string().regex(GITLAB_ID).optional(),
      mergeRequestEventType: z.enum(GITLAB_MR_EVENT_TYPES).optional(),
    })
    .optional(),
  /**
   * github.md §3: the GitHub Actions context, only in GitHub Actions; never trusted to choose a
   * repository. Unknown keys are stripped; a malformed or unknown value of a known key is refused
   * (the forward-compatibility rule of scm.md §3).
   */
  github: z
    .object({
      repositoryId: z.string().regex(GITHUB_ID).optional(),
      runId: z.string().regex(GITHUB_ID).optional(),
      checkout: z.enum(GITHUB_CHECKOUTS).optional(),
    })
    .optional(),
});

export const reportSchema = z
  .object({
    schemaVersion: z.literal(REPORT_SCHEMA_VERSION),
    scanner: z.object({
      name: z.string().min(1).max(64),
      version: z.string().min(1).max(64),
      platform: z.string().max(64).optional(),
    }),
    project: z.object({
      key: z.string().regex(/^[A-Za-z0-9._\-/:]{1,255}$/),
      name: z.string().min(1).max(255).optional(),
      version: z.string().max(100).optional(),
    }),
    scm,
    analysisDate: z.iso.datetime({ offset: true }),
    engines: z.array(engine).max(64),
    files: z.array(file).max(REPORT_BOUNDS.files),
    findings: z.array(finding).max(REPORT_BOUNDS.findings),
    duplications: z
      .array(
        z.object({
          blocks: z
            .array(z.object({ path: repoPath, startLine: line, endLine: line }))
            .min(2)
            .max(1_000),
        }),
      )
      .max(REPORT_BOUNDS.duplicationGroups),
    warnings: z
      .array(
        z.object({
          code: z.string().min(1).max(64),
          message: z.string().max(4_000),
          count: z.number().int().min(1).optional(),
        }),
      )
      .max(1_000),
  })
  .superRefine((r, ctx) => {
    const paths = new Set<string>();
    r.files.forEach((f, i) => {
      if (paths.has(f.path)) {
        ctx.addIssue({
          code: 'custom',
          message: 'duplicate file path',
          path: ['files', i, 'path'],
        });
      }
      paths.add(f.path);
      if (r.scm.baseline.status === 'unavailable' && f.newLines !== undefined) {
        ctx.addIssue({
          code: 'custom',
          message: 'newLines must be omitted when the baseline is unavailable',
          path: ['files', i, 'newLines'],
        });
      }
    });
    const engines = new Set<string>();
    r.engines.forEach((e, i) => {
      engines.add(e.id);
      if (e.kind === 'external' && (BUILTIN_ENGINES as readonly string[]).includes(e.id)) {
        ctx.addIssue({
          code: 'custom',
          message: `engine id "${e.id}" is reserved for built-in analyzers`,
          path: ['engines', i, 'id'],
        });
      }
    });
    r.findings.forEach((f, i) => {
      if (!engines.has(f.engineId)) {
        ctx.addIssue({
          code: 'custom',
          message: `engine "${f.engineId}" is not listed in engines[]`,
          path: ['findings', i, 'engineId'],
        });
      }
      if (f.location !== null && !paths.has(f.location.path)) {
        ctx.addIssue({
          code: 'custom',
          message: 'location.path is not listed in files[]',
          path: ['findings', i, 'location', 'path'],
        });
      }
    });
  });

export type Report = z.infer<typeof reportSchema>;
export type ReportFinding = Report['findings'][number];
export type ReportFile = Report['files'][number];
export type ReportEngine = Report['engines'][number];
export type RuleMeta = ReportEngine['rules'][number];
export type Location = NonNullable<ReportFinding['location']>;
export type LineRange = [number, number];
