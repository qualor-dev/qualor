import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
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
  | { ok: false; code: 'NOT_INSTALLED' | 'TIMEOUT' | 'FAILED' | 'BAD_OUTPUT'; message: string };

export interface TrivyRunner {
  run(sbomJson: string, cacheDir: string): Promise<TrivyRun>;
}

export interface TrivyRunnerOptions {
  /** Program and leading arguments: `[config.vulndb.trivyPath]` in production. */
  command: string[];
  timeoutMs: number;
  maxOutputBytes: number;
}

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low']);

const text = (v: unknown): string | null => (typeof v === 'string' && v !== '' ? v : null);

/** Reads `trivy sbom --format json` output into matches keyed by the package purl. Throws on bad JSON. */
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
    async run(sbomJson, cacheDir) {
      if (program === undefined) {
        return { ok: false, code: 'NOT_INSTALLED', message: 'no Trivy command configured' };
      }
      const work = await mkdtemp(path.join(os.tmpdir(), 'qualor-trivy-'));
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
        >((resolve) => {
          let stderr = '';
          let done = false;
          const finish = (r: Parameters<typeof resolve>[0]) => {
            if (done) return;
            done = true;
            clearTimeout(timer);
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
          child.stderr.on('data', (c: Buffer) => {
            if (stderr.length < 4000) stderr += c.toString('utf8');
          });
          child.on('error', (error: NodeJS.ErrnoException) =>
            finish({ kind: 'spawn-error', error }),
          );
          child.on('close', (code) => finish({ kind: 'exit', code, stderr }));
        });
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
            code: 'BAD_OUTPUT',
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
        await rm(work, { recursive: true, force: true }).catch(() => undefined);
      }
    },
  };
}
