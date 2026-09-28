import { existsSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import type { Logger } from '../log';
import { staysInside } from './binary';
import { shown } from './reason';
import type { Analyzer, AnalyzerContext, Preparation } from './types';

/** ESLint's flat config names (v9+), in its own lookup order. */
const FLAT_CONFIGS = [
  'eslint.config.js',
  'eslint.config.mjs',
  'eslint.config.cjs',
  'eslint.config.ts',
  'eslint.config.mts',
  'eslint.config.cts',
] as const;

/** Legacy eslintrc names (ESLint ≤ 8, or 9 with ESLINT_USE_FLAT_CONFIG=false; see `prepare`). */
const LEGACY_CONFIGS = [
  '.eslintrc.js',
  '.eslintrc.cjs',
  '.eslintrc.yaml',
  '.eslintrc.yml',
  '.eslintrc.json',
  '.eslintrc',
] as const;

/**
 * A regular file (symlinks followed, as ESLint follows them) whose path and real path both stay
 * inside the repository: a config that links out of the checkout is not the project's config.
 */
function isRepoFile(root: string, file: string): boolean {
  try {
    return statSync(file).isFile() && staysInside(root, file);
  } catch {
    return false;
  }
}

/** True when `package.json` at the root carries an `eslintConfig` key (legacy config). */
function packageJsonConfig(root: string): boolean {
  const file = path.join(root, 'package.json');
  if (!isRepoFile(root, file)) return false;
  try {
    const pkg = JSON.parse(readFileSync(file, 'utf8')) as unknown;
    return typeof pkg === 'object' && pkg !== null && 'eslintConfig' in pkg;
  } catch {
    return false;
  }
}

/** config.md §6: ESLint runs only with the project's own configuration (none is bundled). */
export function findEslintConfig(root: string): string | null {
  for (const name of [...FLAT_CONFIGS, ...LEGACY_CONFIGS]) {
    if (isRepoFile(root, path.join(root, name))) return name;
  }
  return packageJsonConfig(root) ? 'package.json' : null;
}

/** An eslintrc-style configuration (ESLint ≤ 8, or 9 in eslintrc mode; ESLint 10 removed it). */
function isLegacyConfig(name: string): boolean {
  const base = path.basename(name);
  return base === 'package.json' || base.startsWith('.eslintrc');
}

/** `x.y.z…` from a package.json or `eslint --version`, bounded; anything else is null. */
export function eslintVersion(text: string): string | null {
  return /^v?(\d+\.\d+\.\d+[0-9A-Za-z.+-]{0,64})$/.exec(text.trim())?.[1] ?? null;
}

function majorVersion(version: string | null): number | null {
  const m = version === null ? null : /^(\d+)\./.exec(version);
  return m?.[1] === undefined ? null : Number(m[1]);
}

const packageSchema = z.looseObject({
  version: z.string(),
  bin: z.union([z.string(), z.record(z.string(), z.string())]).optional(),
});

export interface LocalEslint {
  /** Absolute path of ESLint's CLI script inside the project's node_modules. */
  script: string;
  version: string | null;
}

/**
 * The project's own ESLint (`<root>/node_modules/eslint`), which is what resolves the config's
 * plugins. It is started as `node <bin script>`, never through the `.bin` shim (ruling C19).
 */
export function findLocalEslint(root: string): LocalEslint | null {
  const dir = path.join(root, 'node_modules', 'eslint');
  let pkg: z.infer<typeof packageSchema>;
  try {
    pkg = packageSchema.parse(JSON.parse(readFileSync(path.join(dir, 'package.json'), 'utf8')));
  } catch {
    return null;
  }
  const bin = typeof pkg.bin === 'string' ? pkg.bin : pkg.bin?.['eslint'];
  if (bin === undefined) return null;
  const script = path.resolve(dir, bin);
  // The bin must stay inside the package directory: a crafted package.json cannot point elsewhere.
  if (!script.startsWith(`${path.resolve(dir)}${path.sep}`) || !existsSync(script)) return null;
  return { script, version: eslintVersion(pkg.version) };
}

const eslintMessage = z.looseObject({
  ruleId: z.string().nullable().optional(),
  severity: z.number(),
  message: z.string(),
  line: z.number().int().optional(),
  column: z.number().int().optional(),
  endLine: z.number().int().optional(),
  endColumn: z.number().int().optional(),
});

const eslintOutput = z.looseObject({
  results: z.array(
    z.looseObject({
      filePath: z.string(),
      messages: z.array(eslintMessage),
    }),
  ),
  metadata: z
    .looseObject({
      rulesMeta: z
        .record(
          z.string(),
          z.looseObject({
            docs: z
              .looseObject({ description: z.string().optional(), url: z.string().optional() })
              .optional(),
          }),
        )
        .optional(),
    })
    .optional(),
});

/** A repo-relative, percent-encoded SARIF URI for an absolute path ESLint reported. */
function relativeUri(root: string, filePath: string): string {
  const rel = path.relative(root, filePath).split(path.sep).join('/');
  return rel.split('/').map(encodeURIComponent).join('/');
}

/**
 * ESLint's built-in `json-with-metadata` formatter output → SARIF 2.1.0. This replaces
 * `@microsoft/eslint-formatter-sarif`, which the project would have to install and which pins
 * ESLint 8 as a dependency. Messages without a rule id (fatal parse errors, which ESLint puts in
 * the JSON output like any other message) carry no rule to report and are dropped; their count
 * goes to the debug log. Rule metadata is copied as is: the shared normaliser bounds it.
 */
export function eslintJsonToSarif(
  output: unknown,
  root: string,
  version: string | null,
  log?: Logger,
): unknown {
  const parsed = eslintOutput.parse(output);
  const meta = parsed.metadata?.rulesMeta ?? {};
  const ruleIds = new Set<string>();
  const results: unknown[] = [];
  let dropped = 0;
  for (const file of parsed.results) {
    const uri = relativeUri(root, file.filePath);
    for (const m of file.messages) {
      if (m.ruleId === null || m.ruleId === undefined || m.ruleId === '') {
        dropped++;
        continue;
      }
      ruleIds.add(m.ruleId);
      const region: Record<string, number> = { startLine: m.line ?? 1 };
      if (m.column !== undefined) region['startColumn'] = m.column;
      if (m.endLine !== undefined) region['endLine'] = m.endLine;
      if (m.endColumn !== undefined) region['endColumn'] = m.endColumn;
      results.push({
        ruleId: m.ruleId,
        level: m.severity >= 2 ? 'error' : 'warning',
        message: { text: m.message },
        locations: [{ physicalLocation: { artifactLocation: { uri }, region } }],
      });
    }
  }
  if (dropped > 0) {
    log?.debug(`eslint: dropped ${dropped} message(s) without a rule id (fatal parse errors)`);
  }
  const rules = [...ruleIds].sort().map((id) => {
    const docs = meta[id]?.docs;
    return {
      id,
      ...(docs?.description !== undefined && { shortDescription: { text: docs.description } }),
      ...(docs?.url !== undefined && { helpUri: docs.url }),
    };
  });
  return {
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'ESLint',
            informationUri: 'https://eslint.org',
            ...(version !== null && { version }),
            rules,
          },
        },
        results,
      },
    ],
  };
}

/**
 * Whether this ESLint reads an eslintrc configuration: ESLint ≤ 8 always, ESLint 9 only with
 * `ESLINT_USE_FLAT_CONFIG=false`, ESLint 10 never (it removed eslintrc). Unknown version: assume
 * it does, and let ESLint itself report a mismatch.
 */
function readsEslintrc(major: number | null, env: AnalyzerContext['env']): boolean {
  if (major === null || major <= 8) return true;
  return major === 9 && env['ESLINT_USE_FLAT_CONFIG'] === 'false';
}

async function prepare(ctx: AnalyzerContext): Promise<Preparation> {
  const settings = ctx.config.analyzers.eslint;
  const configArgs: string[] = [];
  let configName: string;
  if (settings.configFile !== null) {
    const file = path.resolve(ctx.root, settings.configFile);
    // ESLint executes its config: one outside the checkout is not the project's to run.
    if (!staysInside(ctx.root, file)) {
      return { skip: `configFile ${shown(settings.configFile)} is outside the repository` };
    }
    if (!isRepoFile(ctx.root, file)) {
      return { skip: `configFile ${shown(settings.configFile)} does not exist` };
    }
    configArgs.push('--config', file);
    configName = settings.configFile;
  } else {
    const found = findEslintConfig(ctx.root);
    if (found === null) {
      return { skip: 'the repository has no ESLint configuration (none is bundled)' };
    }
    configName = found;
  }
  const outFile = path.join(ctx.workDir, 'eslint.json');
  const args = [
    '--format',
    'json-with-metadata',
    '--output-file',
    outFile,
    '--no-color',
    ...configArgs,
    ...settings.args,
    '.',
  ];
  let command: string;
  let version: string | null;
  // `node` and a fallback `eslint` come from PATH or the scanner image only, never from the
  // repository (its node_modules/.bin shim or a planted binary), ruling V3.
  const local = findLocalEslint(ctx.root);
  if (local !== null) {
    const node = ctx.resolveBinary('node');
    if (node === null) {
      return {
        unavailable:
          ctx.repoBinary('node') === null
            ? 'the project ESLint needs node on PATH'
            : 'the project ESLint needs node on PATH (a node inside the repository is not used)',
      };
    }
    command = node;
    args.unshift(local.script);
    version = local.version;
  } else {
    const global = ctx.resolveBinary('eslint');
    if (global === null) {
      return {
        unavailable:
          ctx.repoBinary('eslint') === null
            ? 'ESLint is not installed (node_modules/eslint or PATH)'
            : 'ESLint is not installed (node_modules/eslint or PATH; an eslint binary inside the repository is not used)',
      };
    }
    command = global;
    const probe = await ctx.exec(global, ['--version'], { timeoutMs: 30_000 });
    version = eslintVersion(probe.stdout);
  }
  const major = majorVersion(version);
  if (isLegacyConfig(configName) && !readsEslintrc(major, ctx.env)) {
    return {
      skip: `${shown(configName)} is a legacy eslintrc configuration, which ESLint ${major} does not read (migrate to eslint.config.js)`,
    };
  }
  return {
    run: {
      command,
      args,
      cwd: ctx.root,
      sarifPath: outFile,
      // 0: no errors, 1: lint errors found, 2: configuration or internal error.
      okExitCodes: [0, 1],
      version,
      transform: (output) => eslintJsonToSarif(output, ctx.root, version, ctx.log),
    },
  };
}

export const eslintAnalyzer: Analyzer = {
  id: 'eslint',
  languages: ['typescript', 'javascript'],
  ruleLanguages: ['typescript', 'javascript'],
  prepare,
};
