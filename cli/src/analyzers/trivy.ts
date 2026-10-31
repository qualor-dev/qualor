import { lstatSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { BUILTIN_EXCLUDES, type QualorConfig } from '@qualor/shared';
import { isInside, real, staysInside, within } from './binary';
import { deadProxyEnv } from './offline';
import { shown } from './reason';
import { trivyJsonToSarif } from './trivy-output';
import type { Analyzer, AnalyzerContext, Preparation } from './types';

/** Where the `qualor/scanner` image keeps Trivy's cache directory, the database in `db/`. */
export const DEFAULT_TRIVY_CACHE_DIR = '/opt/qualor/share/trivy';
/** A `.trivyignore` larger than this is a configuration error (it lists vulnerability ids). */
export const MAX_TRIVYIGNORE_BYTES = 1024 * 1024;
/** Trivy's `db/metadata.json` is 143 bytes; anything much larger is not one. */
const MAX_METADATA_BYTES = 64 * 1024;
/** report-format.md §9: the longest `engines[].database.updatedAt`. */
const MAX_UPDATED_AT_CHARS = 64;
/** config.md §6: a database older than this, before the scan, draws `VULNERABILITY_DB_STALE`. */
export const STALE_DATABASE_DAYS = 14;
const DAY_MS = 24 * 60 * 60 * 1000;

type Env = Readonly<Record<string, string | undefined>>;

/**
 * The directory names of the built-in excludes (config.md §3.1), as Trivy `--skip-dirs` globs:
 * Trivy need not read what the scan leaves out anyway (the normaliser drops a finding on a file
 * outside the scope).
 */
export function skipDirs(): string[] {
  return BUILTIN_EXCLUDES.filter((g) => g.startsWith('**/') && g.endsWith('/**')).map((g) =>
    g.slice(0, -3),
  );
}

/** The files of a cache directory the scanner reads or writes (vuln plan 3, P4). */
const CACHE_ENTRIES = ['db.tar.gz', 'server.json', 'db', 'db/trivy.db', 'db/metadata.json'];

/**
 * Where the scanner keeps the server's database archive (P6): `QUALOR_TRIVY_CACHE_DIR` when it is
 * set and absolute, else `<home>/.cache/qualor/trivy`.
 */
export function vulnerabilityCacheDir(env: Env): string {
  const named = env['QUALOR_TRIVY_CACHE_DIR'];
  if (named !== undefined && named !== '' && path.isAbsolute(named)) return named;
  return path.join(os.homedir(), '.cache', 'qualor', 'trivy');
}

/**
 * True when the cache directory `dir`, or one of the files in it, is inside the checkout, as
 * written or after resolving symlinks: a merge request controls its content.
 */
export function cacheInRepository(root: string, dir: string): boolean {
  return isInside(root, dir) || CACHE_ENTRIES.some((e) => isInside(root, path.join(dir, e)));
}

/**
 * The cache directory as a `/`-separated path relative to the checkout, when it lies inside it
 * (it is left out of the report's files and Trivy's scan); null otherwise, or when it is the
 * checkout itself.
 */
export function cacheDirInRepository(root: string, env: Env): string | null {
  const dir = vulnerabilityCacheDir(env);
  for (const [r, d] of [
    [path.resolve(root), path.resolve(dir)],
    [real(root), real(dir)],
  ] as const) {
    if (!within(r, d)) continue;
    const rel = path.relative(r, d);
    return rel === '' ? null : rel.split(path.sep).join('/');
  }
  return null;
}

/**
 * The database directory when the scan chose none: the one the CI names
 * (`QUALOR_TRIVY_CACHE_DIR`), else the image's. A named directory inside the checkout is ignored
 * (P5: the scan's choice warns `VULNERABILITY_DB_CACHE_UNTRUSTED`).
 */
function cacheDir(root: string, env: Env, defaultDir: string): string {
  const named = env['QUALOR_TRIVY_CACHE_DIR'];
  if (named === undefined || named === '' || cacheInRepository(root, named)) return defaultDir;
  return named;
}

const regularFile = (file: string, max: number): boolean => {
  try {
    const s = statSync(file);
    return s.isFile() && s.size <= max;
  } catch {
    return false;
  }
};

const exists = (file: string): boolean => {
  try {
    lstatSync(file);
    return true;
  } catch {
    return false;
  }
};

/**
 * The Trivy configuration errors of config.md §6 (exit 2): a relative `QUALOR_TRIVY_CACHE_DIR`,
 * and a root `.trivyignore` that links out of the repository, is not a regular file or is over
 * 1 MiB. A `QUALOR_TRIVY_CACHE_DIR` inside the checkout is no error (vuln plan 3, P5): its archive
 * is used only once the server confirms its checksum, otherwise the image's database is.
 */
export function checkTrivyConfig(
  root: string,
  _config: QualorConfig,
  env: Env = {},
): string | null {
  const named = env['QUALOR_TRIVY_CACHE_DIR'];
  if (named !== undefined && named !== '' && !path.isAbsolute(named)) {
    return 'QUALOR_TRIVY_CACHE_DIR must be an absolute path';
  }
  const ignore = path.join(root, '.trivyignore');
  if (!exists(ignore)) return null;
  if (!staysInside(root, ignore)) return '.trivyignore is outside the repository';
  if (!regularFile(ignore, Number.POSITIVE_INFINITY)) return '.trivyignore is not a regular file';
  if (!regularFile(ignore, MAX_TRIVYIGNORE_BYTES)) {
    return `.trivyignore is larger than ${MAX_TRIVYIGNORE_BYTES / 1024 / 1024} MiB`;
  }
  return null;
}

/** `db/metadata.json`: when the database was built (`UpdatedAt`), for schema version 2. */
export function readDatabaseDate(dir: string): string | null {
  const file = path.join(dir, 'db', 'metadata.json');
  if (!regularFile(file, MAX_METADATA_BYTES)) return null;
  try {
    const meta = JSON.parse(readFileSync(file, 'utf8')) as {
      Version?: unknown;
      UpdatedAt?: unknown;
    };
    if (meta.Version !== 2 || typeof meta.UpdatedAt !== 'string') return null;
    // report-format.md §9 bounds it (64 characters); Trivy writes 30.
    if (meta.UpdatedAt.length > MAX_UPDATED_AT_CHARS) return null;
    const at = new Date(meta.UpdatedAt);
    // Trivy writes nanoseconds; the report keeps the text as written when it is a valid date.
    return Number.isNaN(at.getTime()) || !/^\d{4}-\d{2}-\d{2}T/.test(meta.UpdatedAt)
      ? null
      : meta.UpdatedAt;
  } catch {
    return null;
  }
}

/** `TRIVY_*` variables would configure Trivy behind the command line's back (config.md §6). */
export const isTrivyVariable = (name: string): boolean => /^TRIVY_/i.test(name);

export function createTrivyAnalyzer(
  defaultDir = DEFAULT_TRIVY_CACHE_DIR,
  now = () => new Date(),
): Analyzer {
  const prepare = (ctx: AnalyzerContext): Promise<Preparation> => {
    // `qualor scan` stops with exit 2 on these before any analyzer runs (checkConfig); this is
    // the same check for any other caller of the runner.
    const problem = checkTrivyConfig(ctx.root, ctx.config, ctx.env);
    if (problem !== null) return Promise.resolve({ skip: problem });
    // The scan's choice (a server-verified copy), else today's rule without a cache in the checkout.
    const dir = ctx.trivyDatabaseDir ?? cacheDir(ctx.root, ctx.env, defaultDir);
    if (!regularFile(path.join(dir, 'db', 'trivy.db'), Number.POSITIVE_INFINITY)) {
      return Promise.resolve({
        skip: `no Trivy vulnerability database in ${shown(dir)} (it comes with the qualor/scanner image; or set QUALOR_TRIVY_CACHE_DIR)`,
      });
    }
    const updatedAt = readDatabaseDate(dir);
    if (updatedAt === null) {
      return Promise.resolve({
        unavailable: `the Trivy vulnerability database in ${shown(dir)} cannot be read (db/metadata.json)`,
      });
    }
    const trivy = ctx.resolveBinary('trivy');
    if (trivy === null) {
      return Promise.resolve({
        unavailable: 'Trivy is not installed (trivy on PATH or in the scanner image)',
      });
    }
    // Trivy reads `trivy.yaml` from the working directory and `.trivyignore` next to it unless it
    // is told otherwise: both are named explicitly, the config empty (config.md §6).
    const emptyConfig = path.join(ctx.workDir, 'trivy.yaml');
    const modules = path.join(ctx.workDir, 'modules');
    writeFileSync(emptyConfig, '');
    mkdirSync(modules);
    let ignoreFile = path.join(ctx.root, '.trivyignore');
    if (!exists(ignoreFile)) {
      ignoreFile = path.join(ctx.workDir, 'trivyignore');
      writeFileSync(ignoreFile, '');
    }
    const out = path.join(ctx.workDir, 'trivy.json');
    // A cache directory inside the checkout holds the archive, not lockfiles of the project.
    const inRepository = cacheDirInRepository(ctx.root, ctx.env);
    const ageDays = (now().getTime() - new Date(updatedAt).getTime()) / DAY_MS;
    const timeout = ctx.config.analyzers.trivy.timeoutSeconds;
    return Promise.resolve({
      run: {
        command: trivy,
        args: [
          'fs',
          '--config',
          emptyConfig,
          '--cache-dir',
          dir,
          '--cache-backend',
          'memory',
          // Offline (brief §5.5): no database, Java database, VEX or checks bundle download, no Maven Central,
          // no version check, no telemetry.
          '--skip-db-update',
          '--skip-java-db-update',
          '--skip-vex-repo-update',
          '--skip-check-update',
          '--offline-scan',
          '--skip-version-check',
          '--disable-telemetry',
          // No WebAssembly module of the user's home directory runs.
          '--module-dir',
          modules,
          '--scanners',
          'vuln',
          '--pkg-types',
          'library',
          // The package list carries each package's position in its lockfile.
          '--list-all-pkgs',
          '--ignorefile',
          ignoreFile,
          ...[...skipDirs(), ...(inRepository === null ? [] : [inRepository])].flatMap((d) => [
            '--skip-dirs',
            d,
          ]),
          // Trivy's own default is 5 minutes; the runner kills it at the same deadline.
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
        env: deadProxyEnv(),
        dropEnv: isTrivyVariable,
        sarifPath: out,
        // Trivy exits 0 whatever it finds (`--exit-code` is not set).
        okExitCodes: [0],
        version: null,
        database: { name: 'trivy-db', updatedAt },
        ...(ageDays > STALE_DATABASE_DAYS && {
          warnings: [
            {
              code: 'VULNERABILITY_DB_STALE',
              message: `the Trivy vulnerability database is ${Math.floor(ageDays)} days old (built ${updatedAt.slice(0, 10)}); update the scanner image or set QUALOR_TRIVY_CACHE_DIR`,
              count: 1,
            },
          ],
        }),
        transform: (output) => trivyJsonToSarif(output, ctx.root),
      },
    });
  };
  // Languages: [] — lockfiles of any ecosystem; without a database it is skipped (config.md §6).
  return { id: 'trivy', languages: [], prepare, checkConfig: checkTrivyConfig };
}

export const trivyAnalyzer = createTrivyAnalyzer();
