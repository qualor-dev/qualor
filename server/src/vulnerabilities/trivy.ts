import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdir, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';

export interface VulnerabilityMatch {
  vulnerabilityId: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'unknown';
  title: string | null;
  fixedVersion: string | null;
  primaryUrl: string | null;
  publishedAt: string | null;
}

export type TrivyRun =
  | { ok: true; matches: Map<string, VulnerabilityMatch[]> }
  | {
      ok: false;
      code: 'NOT_INSTALLED' | 'TIMEOUT' | 'FAILED' | 'BAD_OUTPUT' | 'TOO_LARGE' | 'ABORTED';
      message: string;
    };

export interface TrivyRunner {
  /** `signal`: the server is stopping; Trivy is killed and the run answers ABORTED. */
  run(sbomJson: string, cacheDir: string, signal?: AbortSignal): Promise<TrivyRun>;
}

export interface TrivyRunnerOptions {
  /** Program and leading arguments: `[config.vulndb.trivyPath]` in production. */
  command: string[];
  /**
   * Where each run's `work-<12 hex>` directory goes (the SBOM, Trivy's output and its HOME and
   * TMPDIR): `config.vulndb.dir` in production, the cache volume, never a small `/tmp`.
   */
  workDir: string;
  timeoutMs: number;
  /** A run whose output file is larger answers TOO_LARGE, unread: the caller splits its SBOM. */
  maxOutputBytes: number;
}

/** A run's work directory below {@link TrivyRunnerOptions.workDir}. */
const WORK_DIRECTORY = /^work-[0-9a-f]{12}$/;

/**
 * Removes the work directories that runs left in `dir` (a run killed with its server cannot
 * remove its own). Only `work-<12 hex>` directories; every other entry stays. Never throws: a
 * directory that cannot be read or removed is left for the next time. Call it while no run uses
 * `dir`: the re-check does, inside the local copy's lock.
 */
export async function removeStaleWorkDirs(dir: string): Promise<void> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.isDirectory() && WORK_DIRECTORY.test(entry.name)) {
      await rm(path.join(dir, entry.name), { recursive: true, force: true }).catch(() => undefined);
    }
  }
}

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low']);

const text = (v: unknown): string | null => (typeof v === 'string' && v !== '' ? v : null);

/**
 * Reads `trivy sbom --format json` output into matches keyed by each package's BOMRef (the purl
 * our SBOM put there, unchanged), falling back to Trivy's PURL. Throws on bad JSON.
 */
export function parseTrivyOutput(json: string): Map<string, VulnerabilityMatch[]> {
  const doc: unknown = JSON.parse(json);
  const matches = new Map<string, VulnerabilityMatch[]>();
  const results = (doc as { Results?: unknown } | null)?.Results;
  if (!Array.isArray(results)) return matches;
  for (const result of results) {
    const vulns = (result as { Vulnerabilities?: unknown } | null)?.Vulnerabilities;
    if (!Array.isArray(vulns)) continue;
    for (const v of vulns as Record<string, unknown>[]) {
      // Trivy re-serialises the purl; the bom-ref is our own string, unchanged.
      const ident = v.PkgIdentifier as { PURL?: unknown; BOMRef?: unknown } | undefined;
      const purl = text(ident?.BOMRef) ?? text(ident?.PURL);
      const id = text(v.VulnerabilityID);
      if (purl === null || id === null) continue;
      const severity = typeof v.Severity === 'string' ? v.Severity.toLowerCase() : '';
      const match: VulnerabilityMatch = {
        vulnerabilityId: id,
        severity: SEVERITIES.has(severity)
          ? (severity as VulnerabilityMatch['severity'])
          : 'unknown',
        title: text(v.Title),
        fixedVersion: text(v.FixedVersion),
        primaryUrl: text(v.PrimaryURL),
        publishedAt: text(v.PublishedDate),
      };
      const list = matches.get(purl);
      if (list === undefined) matches.set(purl, [match]);
      else list.push(match);
    }
  }
  return matches;
}

function killTree(pid: number | undefined): void {
  if (pid === undefined) return;
  try {
    if (process.platform === 'win32') {
      spawnSync('taskkill', ['/pid', String(pid), '/t', '/f'], { stdio: 'ignore' });
    } else {
      process.kill(-pid, 'SIGKILL');
    }
  } catch {
    // already gone
  }
}

export function createTrivyRunner(options: TrivyRunnerOptions): TrivyRunner {
  const [program, ...lead] = options.command;
  return {
    async run(sbomJson, cacheDir, signal) {
      if (program === undefined) {
        return { ok: false, code: 'NOT_INSTALLED', message: 'no Trivy command configured' };
      }
      const aborted: TrivyRun = {
        ok: false,
        code: 'ABORTED',
        message: 'Trivy was stopped: the server is stopping',
      };
      if (signal?.aborted === true) return aborted;
      const work = path.join(options.workDir, `work-${randomBytes(6).toString('hex')}`);
      try {
        await mkdir(work, { recursive: true });
      } catch (e) {
        return {
          ok: false,
          code: 'FAILED',
          message: `cannot create Trivy's work directory in ${options.workDir}: ${(e as Error).message}`,
        };
      }
      try {
        const input = path.join(work, 'sbom.json');
        const output = path.join(work, 'out.json');
        await writeFile(input, sbomJson);
        const args = [
          ...lead,
          'sbom',
          '--format',
          'json',
          '--skip-db-update',
          '--skip-java-db-update',
          '--offline-scan',
          '--scanners',
          'vuln',
          '--disable-telemetry',
          '--skip-version-check',
          '--quiet',
          '--cache-dir',
          cacheDir,
          '-o',
          output,
          input,
        ];
        const env: NodeJS.ProcessEnv = { HOME: work, TMPDIR: work };
        if (process.env.PATH !== undefined) env.PATH = process.env.PATH;
        const exit = await new Promise<
          | { kind: 'exit'; code: number | null; stderr: string }
          | { kind: 'spawn-error'; error: NodeJS.ErrnoException }
          | { kind: 'timeout' }
          | { kind: 'aborted' }
        >((resolve) => {
          let stderr = '';
          let done = false;
          let onAbort: (() => void) | undefined;
          const finish = (r: Parameters<typeof resolve>[0]) => {
            if (done) return;
            done = true;
            clearTimeout(timer);
            if (onAbort !== undefined) signal?.removeEventListener('abort', onAbort);
            resolve(r);
          };
          const child = spawn(program, args, {
            env,
            cwd: work,
            stdio: ['ignore', 'ignore', 'pipe'],
            detached: process.platform !== 'win32',
            windowsHide: true,
          });
          const timer = setTimeout(() => {
            killTree(child.pid);
            finish({ kind: 'timeout' });
          }, options.timeoutMs);
          if (signal !== undefined) {
            onAbort = () => {
              killTree(child.pid);
              finish({ kind: 'aborted' });
            };
            signal.addEventListener('abort', onAbort, { once: true });
            // Aborted since the first look (while the work directory was made): no event will come.
            if (signal.aborted) onAbort();
          }
          child.stderr.on('data', (c: Buffer) => {
            if (stderr.length < 4000) stderr += c.toString('utf8');
          });
          child.on('error', (error: NodeJS.ErrnoException) =>
            finish({ kind: 'spawn-error', error }),
          );
          child.on('close', (code) => finish({ kind: 'exit', code, stderr }));
        });
        if (exit.kind === 'aborted') return aborted;
        if (exit.kind === 'timeout') {
          return {
            ok: false,
            code: 'TIMEOUT',
            message: `Trivy ran longer than ${options.timeoutMs} ms`,
          };
        }
        if (exit.kind === 'spawn-error') {
          const missing = exit.error.code === 'ENOENT' || exit.error.code === 'EACCES';
          return {
            ok: false,
            code: missing ? 'NOT_INSTALLED' : 'FAILED',
            message: `cannot start Trivy: ${exit.error.message}`,
          };
        }
        if (exit.code !== 0) {
          return {
            ok: false,
            code: 'FAILED',
            message: `Trivy exited with ${String(exit.code)}: ${exit.stderr.trim().slice(0, 500)}`,
          };
        }
        let size: number;
        try {
          size = (await stat(output)).size;
        } catch {
          return { ok: false, code: 'BAD_OUTPUT', message: 'Trivy wrote no output file' };
        }
        if (size > options.maxOutputBytes) {
          return {
            ok: false,
            code: 'TOO_LARGE',
            message: `Trivy output is ${size} bytes, over the ${options.maxOutputBytes} byte cap`,
          };
        }
        try {
          return { ok: true, matches: parseTrivyOutput(await readFile(output, 'utf8')) };
        } catch (e) {
          return {
            ok: false,
            code: 'BAD_OUTPUT',
            message: `unreadable Trivy output: ${(e as Error).message}`,
          };
        }
      } finally {
        // Retried: on Windows a killed Trivy holds its working directory for a moment.
        await rm(work, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }).catch(
          () => undefined,
        );
      }
    },
  };
}
