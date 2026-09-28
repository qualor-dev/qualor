import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { must, REPO_ROOT, run, type RunResult } from '../deploy/stack';

/**
 * Runs Helm, cosign and Syft (release.md §9, ruling RE1) in the local image built from
 * tools/release/Dockerfile. Never pushed: the name has no registry and no namespace. A tool gets
 * no network unless it names one allowed for that tool (NETWORKS), a read-only root, no
 * capabilities, and the repository read-only at /work with only /work/.tmp writable.
 * `QUALOR_TOOLBOX=direct` runs the tools from PATH instead, for CI job containers built from the
 * same pins that cannot start containers themselves.
 */
export const TOOLBOX_IMAGE = 'qualor-release-tools:local';
export const DRY_RUN_NETWORK_PREFIX = 'qualor-release-dry-run-';
export const SMOKE_CONTAINER_PREFIX = 'qualor-helm-smoke-';
export type Tool = 'helm' | 'cosign' | 'syft';

export interface ToolboxOptions {
  /** 'none' (default), a dry-run network, or `container:<smoke cluster>`. */
  network?: string;
  /** Only release:publish, after its gate, may use the default bridge network. */
  allowPublishNetwork?: boolean;
  /** More bind mounts. The repository is always /work. */
  mounts?: { source: string; target: string; readOnly?: boolean }[];
  /** Passed by name only (`-e NAME`); the values reach docker through its environment. */
  env?: Record<string, string>;
  /**
   * Values that are not secret and belong to the container only (`DOCKER_CONFIG=/work/…`),
   * passed as `-e NAME=value`, so the host's Docker CLI never sees a container path in its own
   * environment. A name that looks like a secret is refused.
   */
  plainEnv?: Record<string, string>;
  /** Inside the container; default /work. */
  workdir?: string;
  /** Kill the tool after this long (run's timeoutMs). */
  timeoutMs?: number;
  /** uid:gid; default hostUser(). */
  user?: string;
}

export function hostUser(): string | undefined {
  return typeof process.getuid === 'function' && typeof process.getgid === 'function'
    ? `${process.getuid()}:${process.getgid()}`
    : undefined;
}

/** release.md §9: the networks a tool may name besides 'none', and which tools may name each. */
export const NETWORKS: readonly {
  kind: 'dry-run' | 'smoke' | 'publish';
  matches: (network: string) => boolean;
  tools: readonly Tool[];
}[] = [
  // The internal dry-run network (§10): pushes, signatures and SBOMs against the throwaway registry.
  {
    kind: 'dry-run',
    matches: (n) => n.startsWith(DRY_RUN_NETWORK_PREFIX),
    tools: ['helm', 'cosign', 'syft'],
  },
  // The smoke cluster's own network namespace (ruling RE2): only Helm talks to it.
  {
    kind: 'smoke',
    matches: (n) => n.startsWith(`container:${SMOKE_CONTAINER_PREFIX}`),
    tools: ['helm'],
  },
  // release:publish only, after its gate (§11): helm push and cosign sign/attest.
  { kind: 'publish', matches: (n) => n === 'bridge', tools: ['helm', 'cosign'] },
];

export function checkNetwork(tool: Tool, network: string, allowPublish: boolean): void {
  if (network === 'none') return;
  const rule = NETWORKS.find((r) => r.matches(network));
  if (rule?.kind === 'publish' && !allowPublish) {
    throw new Error(
      `toolbox: the network "${network}" is only for release:publish (release.md §9)`,
    );
  }
  if (rule === undefined) {
    throw new Error(`toolbox: the network "${network}" is not allowed (release.md §9)`);
  }
  if (!rule.tools.includes(tool)) {
    throw new Error(`toolbox: ${tool} may not use the network "${network}" (release.md §9)`);
  }
}

/**
 * release.md §9: a dry-run network must be `--internal`, so nothing on it has a route out.
 * Checked before every run that names one; `docker` is injectable for the unit test.
 */
export function assertInternalNetwork(network: string, docker: typeof run = run): void {
  const r = docker('docker', ['network', 'inspect', '--format', '{{.Internal}}', network]);
  if (r.code !== 0 || r.stdout.trim() !== 'true') {
    throw new Error(
      `toolbox: the dry-run network "${network}" is not an --internal network (release.md §9)`,
    );
  }
}

/** release.md §11: secrets travel by name only, never as an argument. */
const SECRET_NAME = /PASSWORD|TOKEN|SECRET|PRIVATE|KEY/i;
export function assertPlainEnv(name: string): void {
  if (SECRET_NAME.test(name)) {
    throw new Error(`toolbox: ${name} looks like a secret; pass it in env (by name), not plainEnv`);
  }
}

export function toolboxArgs(tool: Tool, args: readonly string[], o: ToolboxOptions = {}): string[] {
  const network = o.network ?? 'none';
  checkNetwork(tool, network, o.allowPublishNetwork === true);
  const out = [
    'run',
    '--rm',
    '--network',
    network,
    '--read-only',
    '--tmpfs',
    '/tmp:rw,exec,size=4g',
    '--cap-drop',
    'ALL',
    '--security-opt',
    'no-new-privileges',
    '--mount',
    `type=bind,source=${REPO_ROOT},target=/work,readonly`,
    '--mount',
    `type=bind,source=${path.join(REPO_ROOT, '.tmp')},target=/work/.tmp`,
  ];
  for (const m of o.mounts ?? []) {
    out.push(
      '--mount',
      `type=bind,source=${m.source},target=${m.target}${m.readOnly ? ',readonly' : ''}`,
    );
  }
  for (const name of Object.keys(o.env ?? {})) out.push('-e', name);
  for (const [name, value] of Object.entries(o.plainEnv ?? {})) {
    assertPlainEnv(name);
    out.push('-e', `${name}=${value}`);
  }
  out.push('-w', o.workdir ?? '/work');
  const user = o.user ?? hostUser();
  if (user !== undefined) out.push('--user', user);
  out.push(TOOLBOX_IMAGE, tool, ...args);
  return out;
}

/** `/work/...` → `<root>/...`, at the start of an argument or after "=" (direct mode). */
export function mapWorkPaths(args: readonly string[], root: string): string[] {
  const posixRoot = root.split(path.sep).join('/');
  return args.map((a) => a.replace(/(^|=)\/work(?=\/|$)/g, `$1${posixRoot}`));
}

/**
 * Direct mode's environment: the caller's, without the host's cluster and registry credentials.
 * A call that needs KUBECONFIG or DOCKER_CONFIG passes it in `env`.
 */
export function directEnv(env: Record<string, string> = {}): Record<string, string | undefined> {
  return { KUBECONFIG: undefined, DOCKER_CONFIG: undefined, ...env };
}

export function runTool(tool: Tool, args: readonly string[], o: ToolboxOptions = {}): RunResult {
  if (process.env['QUALOR_TOOLBOX'] === 'direct') {
    checkNetwork(tool, o.network ?? 'none', o.allowPublishNetwork === true);
    const workdir = mapWorkPaths([o.workdir ?? '/work'], REPO_ROOT)[0] ?? REPO_ROOT;
    const plain: Record<string, string> = {};
    for (const [name, value] of Object.entries(o.plainEnv ?? {})) {
      assertPlainEnv(name);
      plain[name] = mapWorkPaths([value], REPO_ROOT)[0] ?? value;
    }
    return run(tool, mapWorkPaths(args, REPO_ROOT), {
      cwd: workdir,
      env: directEnv({ ...plain, ...o.env }),
      timeoutMs: o.timeoutMs,
    });
  }
  const argv = toolboxArgs(tool, args, o);
  if (o.network?.startsWith(DRY_RUN_NETWORK_PREFIX)) assertInternalNetwork(o.network);
  mkdirSync(path.join(REPO_ROOT, '.tmp'), { recursive: true });
  return run('docker', argv, { env: o.env, timeoutMs: o.timeoutMs });
}

/** A host path inside the repository, as the toolbox sees it. */
export function toWork(hostPath: string): string {
  const rel = path.relative(REPO_ROOT, path.resolve(hostPath));
  // `..foo` is a directory inside the repository; only `..` itself or `../…` leaves it.
  if (rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) {
    throw new Error(`${hostPath} is outside the repository; the toolbox sees only /work`);
  }
  return rel === '' ? '/work' : `/work/${rel.split(path.sep).join('/')}`;
}

export function buildToolbox(): void {
  if (process.env['QUALOR_TOOLBOX'] === 'direct') return;
  must(
    run(
      'docker',
      ['build', '-t', TOOLBOX_IMAGE, '-f', 'tools/release/Dockerfile', 'tools/release'],
      {
        inherit: true,
      },
    ),
    `docker build ${TOOLBOX_IMAGE}`,
  );
}
