import { randomBytes } from 'node:crypto';
import { must, run } from '../deploy/stack';
import { attestArgs, signImageArgs, type RegistryOptions } from './cosign';
import { assertInternalNetwork, DRY_RUN_NETWORK_PREFIX, runTool } from './toolbox';

/**
 * The dry run's registry (release.md §10, ruling RE3): registry:3.0.0, published on 127.0.0.1
 * only (for the Docker engine's pushes) and attached to an --internal network (for cosign, Helm
 * and Syft in the toolbox, which reach it as qualor-registry:5000). Removed after every run.
 */
export const REGISTRY_IMAGE =
  'registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e';
export const REGISTRY_ALIAS = 'qualor-registry';

export interface DryRunRegistry {
  container: string;
  network: string;
  port: number;
}

export function newRegistry(port: number): DryRunRegistry {
  const id = randomBytes(4).toString('hex');
  return {
    container: `qualor-release-registry-${id}`,
    network: `${DRY_RUN_NETWORK_PREFIX}${id}`,
    port,
  };
}

export const registryStartCommands = (r: DryRunRegistry): string[][] => [
  ['network', 'create', '--internal', r.network],
  ['run', '-d', '--name', r.container, '-p', `127.0.0.1:${r.port}:5000`, REGISTRY_IMAGE],
  ['network', 'connect', '--alias', REGISTRY_ALIAS, r.network, r.container],
];
export const registryStopCommands = (r: DryRunRegistry): string[][] => [
  ['rm', '-f', '-v', r.container],
  ['network', 'rm', r.network],
];

/**
 * Removes the registry container (with its volume) and the network. Every command runs even when
 * one fails (a container that never started); returns the failures, for the caller to report.
 */
export function stopRegistry(r: DryRunRegistry, docker: typeof run = run): string[] {
  const failures: string[] = [];
  for (const args of registryStopCommands(r)) {
    const res = docker('docker', args);
    if (res.code !== 0) failures.push(`docker ${args.join(' ')}: ${res.stderr.trim()}`);
  }
  return failures;
}

/**
 * Starts the registry. The network is created `--internal` and checked to be so with the one
 * helper the toolbox also uses (assertInternalNetwork) before anything joins it. On any failure
 * it removes what it made and throws; the caller stops it in a `finally` otherwise.
 */
export function startRegistry(r: DryRunRegistry, docker: typeof run = run): void {
  const step = (args: string[]): void => {
    must(docker('docker', args), `docker ${args.join(' ')}`);
  };
  const [create, ...rest] = registryStartCommands(r);
  try {
    if (create) step(create);
    assertInternalNetwork(r.network, docker);
    for (const args of rest) step(args);
  } catch (error) {
    stopRegistry(r, docker);
    throw error;
  }
}

/**
 * The only references the dry run pushes (release.md §10, "The registry guard"): the registry is
 * exactly `127.0.0.1:<port>` or `localhost:<port>` (port 1–65535), followed by a lower-case
 * repository path and a tag. Every other spelling of loopback (`[::1]`, `127.1`, …), every
 * lookalike host and every unqualified name (which Docker sends to Docker Hub) is refused.
 */
const COMPONENT = '[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*';
const LOOPBACK_REF = new RegExp(
  `^(?:127\\.0\\.0\\.1|localhost):([1-9][0-9]{0,4})/${COMPONENT}(?:/${COMPONENT})*` +
    ':[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$',
);
export function assertLoopbackRef(ref: string): void {
  const m = LOOPBACK_REF.exec(ref);
  if (!m || Number(m[1]) > 65535) {
    throw new Error(
      `refusing to push ${JSON.stringify(ref)}: the dry run pushes only ` +
        '127.0.0.1:<port>/<repository>:<tag> or localhost:<port>/<repository>:<tag>',
    );
  }
}

export const hostRef = (r: DryRunRegistry, repository: string, tag: string): string =>
  `127.0.0.1:${r.port}/${repository}:${tag}`;
export const internalRef = (repository: string, digest: string): string =>
  `${REGISTRY_ALIAS}:5000/${repository}@${digest}`;

export function parsePushDigest(stdout: string): string {
  const m = /digest: (sha256:[0-9a-f]{64})/.exec(stdout);
  if (!m?.[1]) throw new Error(`docker push printed no digest:\n${stdout.slice(-500)}`);
  return m[1];
}

/**
 * Every upload of the dry run lives in this module (ruling R-REGOPTS; gating.test.ts checks that
 * no other module but publish.ts pushes, logs in or uploads a signature). The dry-run registry
 * speaks plain HTTP and nothing goes to Rekor.
 */
export const DRY_RUN_OPTIONS: RegistryOptions = { offline: true, plainHttp: true };

/** `docker push` to the dry-run registry only; the guard runs before Docker is called. */
export function pushToDryRun(ref: string, docker: typeof run = run): string {
  assertLoopbackRef(ref);
  return parsePushDigest(must(docker('docker', ['push', ref]), `docker push ${ref}`).stdout);
}

function assertInRegistry(ref: string): void {
  if (!ref.startsWith(`${REGISTRY_ALIAS}:5000/`)) {
    throw new Error(`refusing to upload to ${JSON.stringify(ref)}: not the dry-run registry`);
  }
}

/**
 * Signs `ref` (repository@digest in the dry-run registry) with the throwaway key, and attests
 * `sbom` (a /work path) when given, over the registry's internal network.
 */
export function signInDryRun(
  r: DryRunRegistry,
  keys: { key: string; password: string },
  ref: string,
  sbom: string | null,
  tool: typeof runTool = runTool,
): void {
  assertInRegistry(ref);
  const o = { network: r.network, env: { COSIGN_PASSWORD: keys.password } };
  must(tool('cosign', signImageArgs(keys.key, ref, DRY_RUN_OPTIONS), o), `cosign sign ${ref}`);
  if (sbom !== null) {
    must(
      tool('cosign', attestArgs(keys.key, ref, sbom, DRY_RUN_OPTIONS), o),
      `cosign attest ${ref}`,
    );
  }
}

/** Pushes the packaged chart (a /work path) to the dry-run registry; returns its digest. */
export function pushChartToDryRun(
  r: DryRunRegistry,
  chart: string,
  tool: typeof runTool = runTool,
): string {
  const pushed = must(
    tool('helm', ['push', chart, `oci://${REGISTRY_ALIAS}:5000/qualor`, '--plain-http'], {
      network: r.network,
    }),
    'helm push to the dry-run registry',
  );
  const digest = /Digest: (sha256:[0-9a-f]{64})/.exec(pushed.stdout + pushed.stderr)?.[1];
  if (digest === undefined) throw new Error('helm push printed no digest');
  return digest;
}
