import { z } from 'zod';
import { BUILTIN_ENGINES, ENGINE_ID_PATTERN } from '../report/taxonomy';
import { RUFF_SELECTOR, RUFF_VERSION, ruffSelectorKnown } from '../rules/ruff';

const SCANNABLE_LANGUAGES = ['typescript', 'javascript', 'java', 'csharp', 'python'] as const;

export const BUILTIN_EXCLUDES: readonly string[] = [
  '**/node_modules/**',
  '**/.git/**',
  '**/dist/**',
  '**/build/**',
  '**/target/**',
  '**/*.min.js',
  '**/vendor/**',
  // The scanner's own session files (config.md §6.1).
  '.qualor/**',
  // .NET build output and generated C# (a bare **/bin/** holds source in other ecosystems).
  '**/obj/**',
  '**/bin/Debug/**',
  '**/bin/Release/**',
  '**/*.g.cs',
  '**/*.g.i.cs',
  '**/*.Designer.cs',
  // Python virtual environments, caches and installed packages (the directories Ruff leaves out itself).
  '**/.venv/**',
  '**/venv/**',
  '**/.tox/**',
  '**/.nox/**',
  '**/__pycache__/**',
  '**/__pypackages__/**',
  '**/.eggs/**',
  '**/site-packages/**',
];

const enabled = z.union([z.literal('auto'), z.boolean()]).default('auto');
const timeout = (seconds: number) => z.number().int().positive().max(86_400).default(seconds);
/**
 * A Ruff selector (or a value `extra` allows): the shape first, then — so a typo is a config error
 * naming it, not a Ruff exit 2 — `ALL` or a prefix of a code Ruff RUFF_VERSION has.
 */
const ruffSelector = (extra: (s: string) => boolean, shape: string) =>
  z.string().superRefine((s, ctx) => {
    if (extra(s)) return;
    if (!RUFF_SELECTOR.test(s)) ctx.addIssue({ code: 'custom', message: shape });
    else if (!ruffSelectorKnown(s)) {
      ctx.addIssue({
        code: 'custom',
        message: `unknown Ruff rule selector "${s}": no rule of Ruff ${RUFF_VERSION} starts with it`,
      });
    }
  });
const globs = z.array(z.string().min(1)).default([]);

/**
 * Semgrep registry ids and URLs (`https://`, `git+https://`, …) fetch rules over the network
 * (config.md §6).
 */
function isRegistryConfig(c: string): boolean {
  return c === 'auto' || /^(p|r|s)\//.test(c) || isUrl(c);
}

/**
 * A URL scheme (`https://`, `jar:file:`, …), but not a Windows drive path (`C:\`): PMD would
 * download such a ruleset (config.md §6).
 */
export function isUrl(c: string): boolean {
  return /^[A-Za-z][A-Za-z0-9+.-]*:/.test(c) && !/^[A-Za-z]:[\\/]/.test(c);
}

const noToken = z.object({ token: z.never().optional() });

const languages = z
  .union([z.literal('auto'), z.array(z.enum(SCANNABLE_LANGUAGES))])
  .default('auto');

const analyzers = z
  .strictObject({
    eslint: z
      .strictObject({
        enabled,
        configFile: z.string().nullable().default(null),
        args: z.array(z.string()).default([]),
        timeoutSeconds: timeout(900),
      })
      .prefault({}),
    // SonarQube-compatible JS/TS rules (eslint-plugin-sonarjs 2.0.4, LGPL-3.0), a separate pass
    // from Qualor's own ESLint (§6).
    sonarjs: z
      .strictObject({ enabled, timeoutSeconds: timeout(900), typeChecking: enabled })
      .default({ enabled: 'auto', timeoutSeconds: 900, typeChecking: 'auto' }),
    // Python (plan 8C): Ruff with Qualor's own rule selection, never the project's Ruff
    // configuration (config.md §6).
    ruff: z
      .strictObject({
        enabled,
        select: z
          .array(
            ruffSelector(
              (s) => s === 'qualor-default',
              'a Ruff rule selector (F, B, S608, PLE, ALL…) or qualor-default',
            ),
          )
          .min(1, { message: 'list at least one rule selector, or set enabled: false' })
          .default(['qualor-default']),
        ignore: z
          .array(ruffSelector(() => false, 'a Ruff rule selector (F, B, S608, PLE…)'))
          .default([]),
        timeoutSeconds: timeout(600),
      })
      .prefault({}),
    pmd: z
      .strictObject({
        enabled,
        rulesets: z
          .array(
            z
              .string()
              .min(1)
              .refine((r) => !isUrl(r), {
                message:
                  'use a local ruleset file or a PMD classpath ruleset, not a URL (PMD would download it)',
              })
              .refine((r) => !r.includes(','), {
                message:
                  'a ruleset cannot contain a comma (PMD splits --rulesets on commas); list each ruleset as its own entry',
              }),
          )
          .default(['qualor-default']),
        timeoutSeconds: timeout(900),
      })
      .prefault({}),
    spotbugs: z
      .strictObject({
        enabled,
        classDirs: z
          .array(z.string().min(1))
          .default(['target/classes', 'build/classes/java/main']),
        auxClasspathFile: z.string().nullable().default(null),
        timeoutSeconds: timeout(1200),
      })
      .prefault({}),
    semgrep: z
      .strictObject({
        enabled,
        binary: z.enum(['auto', 'semgrep', 'opengrep']).default('auto'),
        configs: z
          .array(
            z
              .string()
              .min(1)
              .refine((c) => !isRegistryConfig(c), {
                message:
                  'registry configs download rules over the network; use local rule files (write a local directory named p/, r/ or s/ as ./p/…)',
              }),
          )
          .min(1, { message: 'list at least one config, or set enabled: false' })
          .default(['qualor-default']),
        timeoutSeconds: timeout(900),
      })
      .prefault({}),
    gitleaks: z
      .strictObject({
        enabled: z.union([z.literal('auto'), z.boolean()]).default(true),
        configFile: z.string().nullable().default(null),
        timeoutSeconds: timeout(300),
      })
      .prefault({}),
    // Dependency vulnerabilities (plan 2B). No config file: a repository `trivy.yaml` is never
    // read (config.md §6), so the only repository input is the lockfiles and `.trivyignore`.
    trivy: z
      .strictObject({
        enabled,
        timeoutSeconds: timeout(600),
      })
      .prefault({}),
    // C# (plan 2D): the Roslyn analyzers run inside the project's own build between
    // `qualor dotnet begin` and `end` (config.md §6.1). The CLI runs nothing, so no timeout.
    roslyn: z
      .strictObject({
        enabled,
        bundledAnalyzers: z.boolean().default(true),
        // Also add the bundled SonarAnalyzer.CSharp 9.32.0.97167 (only with bundledAnalyzers); a
        // project's own SonarAnalyzer wins (config.md §3).
        sonarAnalyzer: z.boolean().default(true),
      })
      .prefault({}),
  })
  .prefault({});

export const configSchema = z
  .strictObject({
    version: z.literal(1),
    project: z
      .strictObject({
        key: z
          .string()
          .regex(/^[A-Za-z0-9._\-/:]{1,255}$/)
          .optional(),
        name: z.string().min(1).max(255).optional(),
        version: z.string().max(100).optional(),
      })
      .prefault({}),
    server: z
      .strictObject({
        ...noToken.shape,
        url: z
          .url({ protocol: /^https?$/ })
          .meta({ pattern: '^[Hh][Tt][Tt][Pp][Ss]?://' })
          .optional(),
        timeoutSeconds: timeout(30),
        caFile: z.string().nullable().default(null),
      })
      .prefault({}),
    sources: z
      .strictObject({
        include: z.array(z.string().min(1)).default(['**/*']),
        exclude: globs,
        useGitignore: z.boolean().default(true),
      })
      .prefault({}),
    tests: z
      .strictObject({
        include: z
          .array(z.string().min(1))
          .default([
            '**/*.test.*',
            '**/*.spec.*',
            '**/__tests__/**',
            '**/src/test/**',
            '**/*Tests/**',
            '**/test_*.py',
            '**/*_test.py',
            '**/conftest.py',
          ]),
        exclude: globs,
      })
      .prefault({}),
    languages,
    analyzers,
    sarif: z
      .array(
        z.strictObject({
          path: z.string().min(1),
          engine: z
            .string()
            .regex(ENGINE_ID_PATTERN)
            .refine((e) => !(BUILTIN_ENGINES as readonly string[]).includes(e), {
              message: 'engine id is reserved for built-in analyzers',
            })
            .optional(),
        }),
      )
      .default([]),
    coverage: z
      .strictObject({
        reports: z
          .array(
            z.strictObject({
              path: z.string().min(1),
              format: z.enum(['auto', 'lcov', 'cobertura', 'jacoco']).default('auto'),
            }),
          )
          .default([]),
        pathPrefixes: z.array(z.string()).default([]),
      })
      .prefault({}),
    duplication: z
      .strictObject({
        enabled: z.boolean().default(true),
        minTokens: z.number().int().min(10).default(100),
        minLines: z.number().int().min(2).default(10),
        exclude: globs,
      })
      .prefault({}),
    newCode: z
      .strictObject({ referenceBranch: z.string().min(1).nullable().default(null) })
      .prefault({}),
    scm: z
      .strictObject({
        autoFetch: z.boolean().default(true),
        mainBranch: z.string().min(1).nullable().default(null),
      })
      .prefault({}),
    gate: z
      .strictObject({
        wait: z.boolean().default(true),
        timeoutSeconds: timeout(300),
        failOnError: z.boolean().default(true),
      })
      .prefault({}),
  })
  .extend(noToken.shape);

export type QualorConfigInput = z.input<typeof configSchema>;
export type QualorConfig = z.output<typeof configSchema>;

export class ConfigError extends Error {
  constructor(readonly issues: { path: string; message: string }[]) {
    super(`invalid qualor.yml:\n${issues.map((i) => `  ${i.path}: ${i.message}`).join('\n')}`);
    this.name = 'ConfigError';
  }
}

/**
 * A plain `z.union` reports a failure with `code: 'invalid_union'` at the union's own
 * path, bundling each branch's issues inside `errors` without folding their (relative)
 * paths back in — so `languages: ['cobol']` would otherwise surface `languages` rather
 * than `languages.0`. This walks into the branch whose issues reach the greatest path
 * depth (the "closest" structural match, e.g. the array branch over the `'auto'` literal
 * branch) and reports every issue from that branch — not just the deepest one — so
 * `languages: ['cobol', 'rust']` reports both `languages.0` and `languages.1`. When
 * every branch is equally shallow (a genuine type mismatch, e.g. `enabled: 5` failing
 * both `'auto'` and `boolean`), it falls back to a single issue at the union's own path.
 */
function resolveIssue(issue: z.core.$ZodIssue): { path: PropertyKey[]; message: string }[] {
  if (issue.code !== 'invalid_union') return [{ path: [...issue.path], message: issue.message }];
  let best: { path: PropertyKey[]; message: string }[] = [
    { path: [...issue.path], message: issue.message },
  ];
  let bestDepth = issue.path.length;
  for (const branch of issue.errors) {
    const resolved = branch.flatMap((sub) =>
      resolveIssue(sub).map((r) => ({ path: [...issue.path, ...r.path], message: r.message })),
    );
    const depth = resolved.reduce((max, r) => Math.max(max, r.path.length), 0);
    if (depth > bestDepth) {
      best = resolved;
      bestDepth = depth;
    }
  }
  return best;
}

export function parseConfig(raw: unknown): QualorConfig {
  const result = configSchema.safeParse(raw);
  if (result.success) return result.data;
  throw new ConfigError(
    result.error.issues.flatMap((i) => {
      if (i.code === 'unrecognized_keys' && i.path.length === 0) {
        return [{ path: i.keys.join(','), message: i.message }];
      }
      return resolveIssue(i).map((r) => ({ path: r.path.join('.'), message: r.message }));
    }),
  );
}

const VAR = /\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}/g;

export interface InterpolateOptions {
  /**
   * Names that must never be interpolated (e.g. secrets): a reference to one resolves to the
   * empty string, ignoring both its value and any `:-default`, and `onDenied` is called instead
   * of `warn`. Checked inside the single replacement pass, so no text produced by a replacement
   * is ever scanned again (`$${SECRET}{SECRET}` stays the literal `${SECRET}`).
   */
  deny?: (name: string) => boolean;
  onDenied?: (name: string) => void;
}

/**
 * Replaces `${VAR}` and `${VAR:-default}` in every string of `value`, recursively, in a single
 * pass per string: substituted values are never re-scanned.
 */
export function interpolateEnv(
  value: unknown,
  env: Record<string, string | undefined>,
  warn: (name: string) => void,
  options: InterpolateOptions = {},
): unknown {
  if (typeof value === 'string') {
    return value.replace(VAR, (_m, name: string, fallback: string | undefined) => {
      if (options.deny?.(name) === true) {
        options.onDenied?.(name);
        return '';
      }
      const v = env[name];
      if (v !== undefined) return v;
      if (fallback !== undefined) return fallback;
      warn(name);
      return '';
    });
  }
  if (Array.isArray(value)) return value.map((v) => interpolateEnv(v, env, warn, options));
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, interpolateEnv(v, env, warn, options)]),
    );
  }
  return value;
}
