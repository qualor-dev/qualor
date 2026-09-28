import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import net, { type AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Throwaway Qualor stacks for the deploy scripts (plan 1G): `deploy/docker-compose.yml` under its
 * own compose project name, with freshly generated secrets in a private env file, on a free port.
 * Nothing here reads `deploy/.env`, so a developer's own stack is never touched.
 */
export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
export const COMPOSE_FILE = path.join(REPO_ROOT, 'deploy', 'docker-compose.yml');
export const SERVER_IMAGE = process.env['QUALOR_SERVER_IMAGE'] || 'qualor/server:dev';
export const SCANNER_IMAGE = process.env['QUALOR_SCANNER_IMAGE'] || 'qualor/scanner:dev';
/** Where the published port is reached: this host, or the Docker daemon's (GitLab `docker:dind`). */
const PUBLISHED_HOST = process.env['QUALOR_DEPLOY_HOST'] || '127.0.0.1';
/** The variables a stack's env file sets; the caller's own values of them never leak in. */
const STACK_VARIABLES = [
  'POSTGRES_PASSWORD',
  'QUALOR_SECRET_KEY',
  'QUALOR_BOOTSTRAP_ADMIN_USERNAME',
  'QUALOR_BOOTSTRAP_ADMIN_PASSWORD',
  'QUALOR_BIND_ADDRESS',
  'QUALOR_PORT',
  'QUALOR_SERVER_IMAGE',
  'QUALOR_TRUST_PROXY',
  'QUALOR_LOG_LEVEL',
] as const;

export interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

export interface RunOptions {
  input?: string | Buffer;
  env?: Record<string, string | undefined>;
  cwd?: string;
  /** Show the command's output live instead of capturing it (long builds). */
  inherit?: boolean;
}

/** Runs a program without a shell and captures its output. */
export function run(command: string, args: readonly string[], o: RunOptions = {}): RunResult {
  const r = spawnSync(command, args, {
    cwd: o.cwd ?? REPO_ROOT,
    env: { ...process.env, ...o.env },
    input: o.input,
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
    stdio: o.inherit ? ['pipe', 'inherit', 'inherit'] : 'pipe',
  });
  if (r.error) throw r.error;
  return { code: r.status ?? 1, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

export function must(result: RunResult, what: string): RunResult {
  if (result.code !== 0) {
    // Some tools (pnpm) report their errors on stdout, and docker push its progress (which layer
    // it was on) there; so the tail of both.
    const output = [result.stdout.slice(-3000), result.stderr.slice(-3000)]
      .filter((s) => s.trim() !== '')
      .join('\n');
    throw new Error(`${what} failed (exit ${result.code}):\n${output}`);
  }
  return result;
}

/** A random secret in hex, so it can go into a postgres:// URL unescaped. */
export function secret(bytes = 32): string {
  return randomBytes(bytes).toString('hex');
}

/** `KEY=value` lines for `docker compose --env-file`; a value may not span lines. */
export function envFileText(env: Record<string, string>): string {
  return Object.entries(env)
    .map(([key, value]) => {
      if (!/^[A-Z_][A-Z0-9_]*$/.test(key)) throw new Error(`invalid variable name ${key}`);
      if (/[\r\n]/.test(value)) throw new Error(`${key} must be a single line`);
      return `${key}=${value}\n`;
    })
    .join('');
}

export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      server.close(() => resolve(port));
    });
  });
}

export interface Stack {
  /** The compose project name; also the prefix of its network and volume. */
  name: string;
  dir: string;
  envFile: string;
  /** The server as this host reaches it. */
  url: string;
  /** The compose network a scanner container joins to reach `http://server:8080`. */
  network: string;
  admin: { username: string; password: string };
}

/** Stacks started and not yet stopped, by name: what a signal must tear down. */
const liveStacks = new Map<string, Pick<Stack, 'name' | 'envFile' | 'dir'>>();

/**
 * Tears down every stack started from now on, and not yet stopped, when the process gets SIGINT
 * (Ctrl+C) or SIGTERM (a CI timeout or cancel): `finally` blocks do not run on a signal. Call it
 * before `startStack`, so a signal during `compose up` is covered too; returns the undo.
 */
export function stopStacksOnSignal(): () => void {
  const onSignal = (signal: NodeJS.Signals): void => {
    for (const stack of [...liveStacks.values()]) stopStack(stack);
    process.exit(signal === 'SIGINT' ? 130 : 143);
  };
  process.once('SIGINT', onSignal);
  process.once('SIGTERM', onSignal);
  return () => {
    process.off('SIGINT', onSignal);
    process.off('SIGTERM', onSignal);
  };
}

/** The caller's environment without the stack's variables (they would override the env file). */
function composeEnv(): Record<string, string | undefined> {
  return Object.fromEntries(STACK_VARIABLES.map((name) => [name, undefined]));
}

export function compose(
  stack: Pick<Stack, 'name' | 'envFile'>,
  args: string[],
  o: RunOptions = {},
) {
  const base = ['compose', '-p', stack.name, '-f', COMPOSE_FILE, '--env-file', stack.envFile];
  return run('docker', [...base, ...args], { ...o, env: { ...composeEnv(), ...o.env } });
}

/** Resolves once `GET <url>/readyz` answers 200, or rejects after `timeoutMs`. */
export async function waitReady(url: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let last = 'no answer';
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${url}/readyz`, { signal: AbortSignal.timeout(5_000) });
      if (res.status === 200) return;
      last = `status ${res.status}`;
    } catch (err) {
      last = err instanceof Error ? err.message : String(err);
    }
    await new Promise((r) => setTimeout(r, 1_000));
  }
  throw new Error(`${url}/readyz not ready after ${timeoutMs / 1000} s (${last})`);
}

export interface StartOptions {
  /** Build the server image first (`up --build`); otherwise it must exist. */
  build?: boolean;
  port?: number;
}

/** Brings a fresh stack up and waits until it is healthy; `upMs` is how long that took. */
export async function startStack(
  name: string,
  o: StartOptions = {},
): Promise<Stack & { upMs: number }> {
  const port = o.port ?? (await freePort());
  const dir = mkdtempSync(path.join(os.tmpdir(), `${name}-`));
  const envFile = path.join(dir, 'stack.env');
  const admin = { username: 'admin', password: secret(16) };
  const env = {
    POSTGRES_PASSWORD: secret(),
    QUALOR_SECRET_KEY: secret(),
    QUALOR_BOOTSTRAP_ADMIN_USERNAME: admin.username,
    QUALOR_BOOTSTRAP_ADMIN_PASSWORD: admin.password,
    QUALOR_BIND_ADDRESS: process.env['QUALOR_BIND_ADDRESS'] || '127.0.0.1',
    QUALOR_PORT: String(port),
    QUALOR_SERVER_IMAGE: SERVER_IMAGE,
  };
  writeFileSync(envFile, envFileText(env), { mode: 0o600 });
  const stack: Stack = {
    name,
    dir,
    envFile,
    url: `http://${PUBLISHED_HOST}:${port}`,
    network: `${name}_default`,
    admin,
  };
  liveStacks.set(name, stack);
  const started = Date.now();
  const up = compose(
    stack,
    ['up', '-d', '--wait', '--wait-timeout', '300', ...(o.build ? ['--build'] : [])],
    {
      inherit: o.build === true,
    },
  );
  if (up.code !== 0) {
    const logs = compose(stack, ['logs', '--no-color', '--tail', '100']).stdout;
    stopStack(stack);
    throw new Error(
      `docker compose up failed (exit ${up.code}):\n${up.stderr.slice(-4000)}\n${logs}`,
    );
  }
  try {
    await waitReady(stack.url, 120_000);
  } catch (err) {
    // Healthy inside Docker but unreachable from here (a wrong QUALOR_DEPLOY_HOST): no leftovers.
    stopStack(stack);
    throw err;
  }
  return { ...stack, upMs: Date.now() - started };
}

/** Removes the stack's containers, network and volumes, and its env file. */
export function stopStack(stack: Pick<Stack, 'name' | 'envFile' | 'dir'>): void {
  liveStacks.delete(stack.name);
  const down = compose(stack, ['down', '--volumes', '--remove-orphans', '--timeout', '20']);
  if (down.code !== 0) {
    // Teardown runs in finally blocks: say what is left behind instead of hiding the first error.
    process.stderr.write(
      `docker compose down of ${stack.name} failed (exit ${down.code}); what is left carries ` +
        `the label com.docker.compose.project=${stack.name}:\n${down.stderr.slice(-2000)}\n`,
    );
  }
  rmSync(stack.dir, { recursive: true, force: true });
}

/** A signed-in browser-style session against the public API (cookie plus CSRF header). */
export class Api {
  private cookie = '';
  private csrf = '';

  /** Every request gives up after `timeoutMs`, so a hung server cannot hang the script. */
  constructor(
    readonly base: string,
    private readonly timeoutMs = 30_000,
  ) {}

  async login(username: string, password: string): Promise<void> {
    const res = await fetch(`${this.base}/api/v0/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username, password }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (res.status !== 204) throw new Error(`login as ${username}: status ${res.status}`);
    const session = /qualor_session=([^;]+)/.exec(res.headers.get('set-cookie') ?? '')?.[1];
    if (!session) throw new Error('the login set no session cookie');
    this.cookie = `qualor_session=${session}`;
    this.csrf = (await this.json<{ csrfToken: string }>('GET', '/api/v0/auth/me')).csrfToken;
  }

  async json<T>(method: string, apiPath: string, body?: unknown): Promise<T> {
    const res = await fetch(`${this.base}${apiPath}`, {
      method,
      headers: {
        cookie: this.cookie,
        ...(method === 'GET' ? {} : { 'x-qualor-csrf': this.csrf }),
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    const text = await res.text();
    if (!res.ok)
      throw new Error(`${method} ${apiPath}: status ${res.status} ${text.slice(0, 500)}`);
    return (text ? JSON.parse(text) : undefined) as T;
  }

  /**
   * Creates a project in the default organisation (its main branch `mainBranchName`, default
   * `main`) and returns an analysis token for it.
   */
  async createProject(
    key: string,
    name: string,
    mainBranchName = 'main',
  ): Promise<{ id: string; token: string }> {
    const orgs = await this.json<{ items: { id: string; key: string }[] }>(
      'GET',
      '/api/v0/organizations',
    );
    const org = orgs.items.find((o) => o.key === 'default') ?? orgs.items[0];
    if (!org) throw new Error('no organisation to create the project in');
    const project = await this.json<{ id: string }>('POST', '/api/v0/projects', {
      organizationId: org.id,
      key,
      name,
      mainBranchName,
    });
    const { token } = await this.json<{ token: string }>(
      'POST',
      `/api/v0/projects/${project.id}/tokens`,
      { name: 'ci' },
    );
    return { id: project.id, token };
  }
}
