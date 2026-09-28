import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { gunzipSync } from 'node:zlib';
import { generateSources } from '../test/generate';
import { CLI_DIR } from './targets';

/**
 * CLI step 14 (brief §2.1, plan 1D ruling K1): `qualor scan` on a generated ~300k-line TypeScript
 * repository must take less than 60 s with warm caches, excluding analyzer time. The analyzers
 * are disabled in the generated qualor.yml; one untimed warm-up scan fills the OS file cache, then
 * a second `--dry-run` scan is timed. The repository is generated from a fixed seed into a fresh
 * directory under the OS temp directory (removed afterwards unless `--keep`), and nothing touches
 * the network. `QUALOR_BIN` times a compiled binary (the nightly CI jobs), otherwise the
 * TypeScript sources run under tsx.
 */
const DEFAULT_BUDGET_SECONDS = 60;
/** 1 256 files of 239 lines each (`generateSources(n, 20)`): 300 184 lines. */
export const DEFAULT_FILES = 1_256;
/** The generator's seed: the benchmark always scans the same repository. */
export const BENCH_SEED = 1;
const FUNCTIONS_PER_FILE = 20;

export const BENCH_QUALOR_YML = [
  'version: 1',
  'analyzers:',
  ...['eslint', 'pmd', 'spotbugs', 'semgrep', 'gitleaks'].map((a) => `  ${a}:\n    enabled: false`),
  '',
].join('\n');

export interface BenchResult {
  files: number;
  lines: number;
  seconds: number;
  budgetSeconds: number;
  ok: boolean;
}

const CI_VARIABLE = /^(CI|CI_.*|GITHUB_.*|GITLAB_.*|QUALOR_.*)$/i;

function git(cwd: string, env: NodeJS.ProcessEnv, ...args: string[]): void {
  const r = spawnSync('git', ['-c', 'core.autocrlf=false', '-c', 'commit.gpgsign=false', ...args], {
    cwd,
    env,
    encoding: 'utf8',
  });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')} failed: ${r.stderr}`);
}

/** Writes the generated sources and qualor.yml under `root`; returns the number of source lines. */
export function generateRepo(root: string, files: number): number {
  let lines = 0;
  for (const f of generateSources(files, FUNCTIONS_PER_FILE, BENCH_SEED)) {
    const abs = path.join(root, ...f.path.split('/'));
    mkdirSync(path.dirname(abs), { recursive: true });
    writeFileSync(abs, f.text);
    lines += f.text.split('\n').length - (f.text.endsWith('\n') ? 1 : 0);
  }
  writeFileSync(path.join(root, 'qualor.yml'), BENCH_QUALOR_YML);
  return lines;
}

/** `generateSources` copies two functions into every file 20k+1: one duplication group each. */
function expectedDuplications(files: number): number {
  return Math.floor((files + 18) / 20);
}

function scanCommand(): [string, string[]] {
  const bin = process.env['QUALOR_BIN'];
  if (bin !== undefined && bin !== '') {
    // Relative to the repo root, like the fixture harness (pnpm runs this script in cli/).
    return [path.resolve(CLI_DIR, '..', bin), []];
  }
  const tsx = pathToFileURL(createRequire(import.meta.url).resolve('tsx')).href;
  return [process.execPath, ['--import', tsx, path.join(CLI_DIR, 'src', 'cli.ts')]];
}

/** A timed scan is killed after this many budgets. */
const SCAN_TIMEOUT_BUDGETS = 10;

export function runBench(o: { files: number; budgetSeconds: number; keep: boolean }): BenchResult {
  if (!Number.isInteger(o.files) || o.files < 1)
    throw new Error(`--files must be a positive integer`);
  if (!(o.budgetSeconds > 0)) throw new Error(`--budget must be a positive number of seconds`);
  const work = mkdtempSync(path.join(os.tmpdir(), 'qualor-bench-'));
  try {
    const repo = path.join(work, 'repo');
    mkdirSync(repo);
    const lines = generateRepo(repo, o.files);
    const gitConfig = path.join(work, 'empty.gitconfig');
    writeFileSync(gitConfig, '');
    const env: NodeJS.ProcessEnv = {
      // The scan must not see the runner's CI (it would try to diff against origin).
      ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !CI_VARIABLE.test(k))),
      GIT_CONFIG_GLOBAL: gitConfig,
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_AUTHOR_NAME: 'bench',
      GIT_AUTHOR_EMAIL: 'bench@qualor.invalid',
      GIT_COMMITTER_NAME: 'bench',
      GIT_COMMITTER_EMAIL: 'bench@qualor.invalid',
      QUALOR_LOG_LEVEL: 'warn',
    };
    git(repo, env, 'init', '-q', '-b', 'main');
    git(repo, env, 'add', '-A');
    git(repo, env, 'commit', '-q', '--no-verify', '-m', 'generated');
    const [command, pre] = scanCommand();
    const out = path.join(work, 'report.json.gz');
    // A scan far over its budget is killed, so a hang fails the job instead of holding it.
    const limitSeconds = o.budgetSeconds * SCAN_TIMEOUT_BUDGETS;
    const scan = (): number => {
      const started = performance.now();
      const r = spawnSync(
        command,
        [...pre, 'scan', '--dry-run', '--output', out, '--project-key', 'bench/generated'],
        {
          cwd: repo,
          env,
          encoding: 'utf8',
          maxBuffer: 64 * 1024 * 1024,
          timeout: limitSeconds * 1000,
        },
      );
      const seconds = (performance.now() - started) / 1000;
      if ((r.error as NodeJS.ErrnoException | undefined)?.code === 'ETIMEDOUT') {
        throw new Error(
          `qualor scan (${command}) did not finish within ${limitSeconds} s (${SCAN_TIMEOUT_BUDGETS} times the budget)`,
        );
      }
      if (r.status !== 0) {
        throw new Error(
          `qualor scan (${command}) exited ${r.status ?? r.signal}: ${r.error?.message ?? r.stderr}`,
        );
      }
      return seconds;
    };
    scan(); // warm-up: the OS file cache, and bun's/node's own start-up caches
    const seconds = scan();
    const report = JSON.parse(gunzipSync(readFileSync(out)).toString('utf8')) as {
      files: unknown[];
      duplications: unknown[];
    };
    // The timed scan did the whole job: the generated sources plus qualor.yml (language other),
    // and every planted duplication.
    if (report.files.length !== o.files + 1) {
      throw new Error(`the report has ${report.files.length} files, expected ${o.files + 1}`);
    }
    if (report.duplications.length !== expectedDuplications(o.files)) {
      throw new Error(
        `the report has ${report.duplications.length} duplications, expected ${expectedDuplications(o.files)}`,
      );
    }
    return {
      files: o.files,
      lines,
      seconds,
      budgetSeconds: o.budgetSeconds,
      ok: seconds < o.budgetSeconds,
    };
  } finally {
    if (o.keep) console.log(`kept ${work}`);
    else rmSync(work, { recursive: true, force: true, maxRetries: 5 });
  }
}

function main(): number {
  const { values } = parseArgs({
    options: {
      budget: { type: 'string', default: String(DEFAULT_BUDGET_SECONDS) },
      files: { type: 'string', default: String(DEFAULT_FILES) },
      keep: { type: 'boolean', default: false },
    },
  });
  const r = runBench({
    files: Number(values.files),
    budgetSeconds: Number(values.budget),
    keep: values.keep,
  });
  console.log(
    `${r.ok ? '✓' : '✗'} qualor scan (analyzers off, warm): ${r.lines} lines in ${r.files} files in ` +
      `${r.seconds.toFixed(1)} s (budget ${r.budgetSeconds} s)`,
  );
  return r.ok ? 0 : 1;
}

if (
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === path.resolve(CLI_DIR, 'scripts', 'bench.ts')
) {
  process.exitCode = main();
}
