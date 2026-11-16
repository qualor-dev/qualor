import { mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import type { NormalizeWarning } from '@qualor/shared';
import { fileLines } from './normalize';
import { deadProxyEnv } from './offline';
import {
  cacheInRepository,
  checkTrivyConfig,
  exists,
  isTrivyVariable,
  regularFile,
  skipDirs,
} from './trivy';
import { trivyIacJsonToSarif } from './trivy-iac-output';
import type { Analyzer, AnalyzerContext, Preparation } from './types';

/** Where the `qualor/scanner` image keeps the filtered trivy-checks bundle (`policy/content`). */
export const DEFAULT_IAC_CHECKS_DIR = '/opt/qualor/share/trivy-iac';
/** The warning's text when Trivy falls back to the checks built into its binary. */
export const IAC_CHECKS_EMBEDDED_MESSAGE =
  "Trivy used its built-in checks (the scanner image's pinned checks were not found); findings can differ from the scanner image.";
/** The bundle's `version` file holds one short line (`2.3.0`). */
const MAX_VERSION_FILE_BYTES = 1024;

/** The misconfiguration scanners Qualor enables, in Trivy's flag syntax. */
const MISCONFIG_SCANNERS = [
  'azure-arm',
  'cloudformation',
  'dockerfile',
  'helm',
  'kubernetes',
  'terraform',
  'terraformplan-json',
  'terraformplan-snapshot',
].join(',');

const IAC_EXTENSIONS = new Set(['.tf', '.tfvars', '.json', '.yaml', '.yml']);
const DOCKERFILE_NAME = /^(?:dockerfile|containerfile|dockerfile\..*|.*\.dockerfile)$/i;

/** True for a file the pass can read as infrastructure code (a `.tf.json` ends in `.json`). */
export function isIacCandidate(repoPath: string): boolean {
  const name = repoPath.slice(repoPath.lastIndexOf('/') + 1);
  const dot = name.lastIndexOf('.');
  return (
    (dot > 0 && IAC_EXTENSIONS.has(name.slice(dot).toLowerCase())) || DOCKERFILE_NAME.test(name)
  );
}

/** `TF_TOKEN_*` hold Terraform registry credentials; Trivy gets no token (and `TRIVY_*` configure it). */
const isIacDroppedVariable = (name: string): boolean =>
  isTrivyVariable(name) || /^TF_TOKEN_/i.test(name);

/**
 * The directory holding `policy/content`: the one the CI names (`QUALOR_TRIVY_CHECKS_DIR`, only
 * when absolute and outside the checkout), else the image's. Null when it has no `policy/content`.
 */
function checksDir(ctx: AnalyzerContext, defaultDir: string): string | null {
  const named = ctx.env['QUALOR_TRIVY_CHECKS_DIR'];
  const usable =
    named !== undefined &&
    named !== '' &&
    path.isAbsolute(named) &&
    !cacheInRepository(ctx.root, named);
  const dir = usable ? named : defaultDir;
  try {
    return statSync(path.join(dir, 'policy', 'content')).isDirectory() ? dir : null;
  } catch {
    return null;
  }
}

/** `checks <v>` from the bundle's `version` file, or `checks unknown`. */
function checksVersion(dir: string): string {
  const file = path.join(dir, 'version');
  if (!regularFile(file, MAX_VERSION_FILE_BYTES)) return 'checks unknown';
  try {
    const first = readFileSync(file, 'utf8').split(/\r?\n/, 1)[0]?.trim() ?? '';
    return first === '' ? 'checks unknown' : `checks ${first}`;
  } catch {
    return 'checks unknown';
  }
}

/**
 * The second Trivy pass (0.16): `trivy fs --scanners misconfig` over the checkout, offline, with
 * the filtered trivy-checks bundle of the scanner image. Remote Terraform modules are never
 * fetched (dead proxy, `GIT_ALLOW_PROTOCOL=file`, downloaded modules excluded).
 */
export function createTrivyIacAnalyzer(defaultDir = DEFAULT_IAC_CHECKS_DIR): Analyzer {
  const prepare = (ctx: AnalyzerContext): Promise<Preparation> => {
    // `qualor scan` stops with exit 2 on this before any analyzer runs (checkConfig).
    const problem = checkTrivyConfig(ctx.root, ctx.config, ctx.env);
    if (problem !== null) return Promise.resolve({ skip: problem });
    if (!ctx.files.some((f) => isIacCandidate(f.path))) {
      return Promise.resolve({ skip: 'no infrastructure files in scope' });
    }
    const trivy = ctx.resolveBinary('trivy');
    if (trivy === null) {
      return Promise.resolve({
        unavailable: 'Trivy is not installed (trivy on PATH or in the scanner image)',
      });
    }
    // Never Trivy's default cache: without the pinned checks it reads an empty one and uses the
    // checks built into its binary.
    const pinned = checksDir(ctx, defaultDir);
    let dir = pinned;
    if (dir === null) {
      dir = path.join(ctx.workDir, 'iac-cache');
      mkdirSync(dir, { recursive: true });
    }
    const warnings: NormalizeWarning[] =
      pinned === null
        ? [{ code: 'IAC_CHECKS_EMBEDDED', message: IAC_CHECKS_EMBEDDED_MESSAGE, count: 1 }]
        : [];
    // `.trivyignore` is named explicitly, as for the vulnerability pass (config.md §6).
    let ignoreFile = path.join(ctx.root, '.trivyignore');
    if (!exists(ignoreFile)) {
      ignoreFile = path.join(ctx.workDir, 'trivyignore');
      writeFileSync(ignoreFile, '');
    }
    const out = path.join(ctx.workDir, 'trivy-iac.json');
    const inRepository = ctx.trivyCacheSkipDir ?? null;
    const timeout = ctx.config.analyzers['trivy-iac'].timeoutSeconds;
    return Promise.resolve({
      run: {
        command: trivy,
        args: [
          'fs',
          '--cache-dir',
          dir,
          '--cache-backend',
          'memory',
          '--skip-check-update',
          '--skip-version-check',
          '--disable-telemetry',
          '--scanners',
          'misconfig',
          '--misconfig-scanners',
          MISCONFIG_SCANNERS,
          '--tf-exclude-downloaded-modules',
          '--ignorefile',
          ignoreFile,
          ...[...skipDirs(), ...(inRepository === null ? [] : [inRepository])].flatMap((d) => [
            '--skip-dirs',
            d,
          ]),
          '--timeout',
          `${timeout}s`,
          '--format',
          'json',
          '--output',
          out,
          '--quiet',
          '.',
        ],
        cwd: ctx.root,
        env: { ...deadProxyEnv(), GIT_ALLOW_PROTOCOL: 'file' },
        dropEnv: isIacDroppedVariable,
        sarifPath: out,
        // Trivy exits 0 whatever it finds (`--exit-code` is not set).
        okExitCodes: [0],
        version: pinned === null ? 'embedded checks' : checksVersion(pinned),
        ...(warnings.length > 0 && { warnings }),
        transform: (output) => trivyIacJsonToSarif(output, fileLines(ctx.root)),
      },
    });
  };
  // Languages: [] — infrastructure files of any kind; without any in scope it is skipped.
  return { id: 'trivy-iac', languages: [], prepare, checkConfig: checkTrivyConfig };
}

export const trivyIacAnalyzer = createTrivyIacAnalyzer();
