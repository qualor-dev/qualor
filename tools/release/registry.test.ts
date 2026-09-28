import { describe, expect, it } from 'vitest';
import type { RunResult } from '../deploy/stack';
import { PLAIN_HTTP, SIGN_OFFLINE } from './cosign';
import {
  assertLoopbackRef,
  DRY_RUN_OPTIONS,
  hostRef,
  internalRef,
  newRegistry,
  parsePushDigest,
  pushChartToDryRun,
  pushToDryRun,
  REGISTRY_ALIAS,
  REGISTRY_IMAGE,
  registryStartCommands,
  registryStopCommands,
  signInDryRun,
  startRegistry,
  stopRegistry,
} from './registry';

/** A docker that records every call; `inspect` is what `network inspect` prints. */
function fakeDocker(inspect = 'true\n', failOn?: string) {
  const calls: string[] = [];
  const docker = (command: string, args: readonly string[]): RunResult => {
    const line = `${command} ${args.join(' ')}`;
    calls.push(line);
    if (failOn !== undefined && line.includes(failOn)) return { code: 1, stdout: '', stderr: 'x' };
    if (args[0] === 'network' && args[1] === 'inspect') {
      return { code: 0, stdout: inspect, stderr: '' };
    }
    return { code: 0, stdout: '', stderr: '' };
  };
  return { calls, docker };
}

describe('the dry-run registry (release.md §10, ruling RE3)', () => {
  it('is a digest-pinned registry on 127.0.0.1 and an internal network', () => {
    expect(REGISTRY_IMAGE).toMatch(/^registry:3\.0\.0@sha256:[0-9a-f]{64}$/);
    const r = newRegistry(45123);
    expect(r.network).toMatch(/^qualor-release-dry-run-[0-9a-f]{8}$/);
    const [net, start, connect] = registryStartCommands(r);
    expect(net).toEqual(['network', 'create', '--internal', r.network]);
    expect(start).toEqual([
      'run',
      '-d',
      '--name',
      r.container,
      '-p',
      '127.0.0.1:45123:5000',
      REGISTRY_IMAGE,
    ]);
    expect(connect).toEqual([
      'network',
      'connect',
      '--alias',
      REGISTRY_ALIAS,
      r.network,
      r.container,
    ]);
    expect(registryStopCommands(r)).toEqual([
      ['rm', '-f', '-v', r.container],
      ['network', 'rm', r.network],
    ]);
    expect(hostRef(r, 'qualor/server', '1.0.0')).toBe('127.0.0.1:45123/qualor/server:1.0.0');
    const d = `sha256:${'d'.repeat(64)}`;
    expect(internalRef('qualor/server', d)).toBe(`${REGISTRY_ALIAS}:5000/qualor/server@${d}`);
  });

  it('creates the network, checks that it is --internal, then starts the registry', () => {
    const r = newRegistry(45123);
    const { calls, docker } = fakeDocker();
    startRegistry(r, docker);
    expect(calls).toEqual([
      `docker network create --internal ${r.network}`,
      `docker network inspect --format {{.Internal}} ${r.network}`,
      `docker run -d --name ${r.container} -p 127.0.0.1:45123:5000 ${REGISTRY_IMAGE}`,
      `docker network connect --alias ${REGISTRY_ALIAS} ${r.network} ${r.container}`,
    ]);
  });

  it('starts no registry on a network that is not --internal, and removes what it made', () => {
    const r = newRegistry(45123);
    const { calls, docker } = fakeDocker('false\n');
    expect(() => startRegistry(r, docker)).toThrow(/not an --internal network/);
    expect(calls.some((c) => c.startsWith('docker run'))).toBe(false);
    expect(calls.slice(-2)).toEqual([
      `docker rm -f -v ${r.container}`,
      `docker network rm ${r.network}`,
    ]);
  });

  it('removes the network when the registry fails to start, and stops quietly', () => {
    const r = newRegistry(45123);
    const failing = fakeDocker('true\n', 'docker run');
    expect(() => startRegistry(r, failing.docker)).toThrow(/docker run/);
    expect(failing.calls.slice(-2)).toEqual([
      `docker rm -f -v ${r.container}`,
      `docker network rm ${r.network}`,
    ]);
    // Teardown runs every command even when one fails (a container that never started).
    const stopping = fakeDocker('true\n', 'docker rm');
    expect(stopRegistry(r, stopping.docker)).toEqual([
      expect.stringContaining(`docker rm -f -v ${r.container}`),
    ]);
    expect(stopping.calls).toHaveLength(2);
  });

  it('refuses to push anywhere but 127.0.0.1 or localhost, before calling Docker', () => {
    const refused = [
      'qualor/server:1.0.0',
      'docker.io/qualor/server:1',
      'registry-1.docker.io/qualor/server:1',
      '127.0.0.2:5000/x:1',
      'localhost.evil.test:5000/x:1',
      '127.0.0.1/x:1',
      // Lookalikes: other hosts that start or end like the loopback names.
      '127.0.0.1.evil.com:5000/x:1',
      '127.0.0.1.nip.io:5000/x:1',
      'localhost.localdomain:5000/x:1',
      'localhost@evil.com:5000/x:1',
      'user:pass@127.0.0.1:5000/x:1',
      'evil.com/127.0.0.1:5000/x:1',
      'LOCALHOST:5000/x:1',
      // Other spellings of loopback, which the guard does not try to understand.
      '[::1]:5000/x:1',
      '[0:0:0:0:0:0:0:1]:5000/x:1',
      '[::ffff:127.0.0.1]:5000/x:1',
      '127.1:5000/x:1',
      '2130706433:5000/x:1',
      '0x7f000001:5000/x:1',
      '0.0.0.0:5000/x:1',
      // Unqualified names that Docker resolves to Docker Hub.
      'localhost:5000',
      '127.0.0.1:5000',
      'library/localhost:5000',
      'x:1',
      // A loopback registry, but a malformed or dangerous rest.
      'localhost/x:1',
      '127.0.0.1:0/x:1',
      '127.0.0.1:65536/x:1',
      '127.0.0.1:5000/x',
      '127.0.0.1:5000/X:1',
      '127.0.0.1:5000/x:1 docker.io/x:1',
      '127.0.0.1:5000/x:1\ndocker.io/x:1',
      '127.0.0.1:5000/../x:1',
      `127.0.0.1:5000/x@sha256:${'a'.repeat(64)}`,
      ' 127.0.0.1:5000/x:1',
    ];
    for (const ref of refused) {
      expect(() => assertLoopbackRef(ref), ref).toThrow(/refusing to push/);
      let called = false;
      const docker = () => {
        called = true;
        return { code: 0, stdout: '', stderr: '' };
      };
      expect(() => pushToDryRun(ref, docker), ref).toThrow(/refusing to push/);
      expect(called, ref).toBe(false);
    }
    expect(() => assertLoopbackRef('127.0.0.1:45123/qualor/server:1.0.0')).not.toThrow();
    expect(() => assertLoopbackRef('localhost:45123/qualor/server:1.0.0')).not.toThrow();
    expect(() => assertLoopbackRef('127.0.0.1:65535/qualor/scanner-sources:0.1')).not.toThrow();
  });

  it('pushes an accepted reference and returns its digest', () => {
    const d = `sha256:${'f'.repeat(64)}`;
    const calls: string[] = [];
    const docker = (command: string, args: readonly string[]): RunResult => {
      calls.push(`${command} ${args.join(' ')}`);
      return { code: 0, stdout: `0.1.0: digest: ${d} size: 1234\n`, stderr: '' };
    };
    expect(pushToDryRun('127.0.0.1:45123/qualor/server:0.1.0', docker)).toBe(d);
    expect(calls).toEqual(['docker push 127.0.0.1:45123/qualor/server:0.1.0']);
  });

  it('reads the digest docker push prints', () => {
    const d = `sha256:${'e'.repeat(64)}`;
    expect(parsePushDigest(`1.0.0: digest: ${d} size: 2417\n`)).toBe(d);
    expect(() => parsePushDigest('nothing')).toThrow(/no digest/);
  });

  it('signs, attests and pushes the chart only in the dry-run registry, offline, over plain HTTP', () => {
    expect(DRY_RUN_OPTIONS).toEqual({ offline: true, plainHttp: true });
    const r = newRegistry(45123);
    const calls: { tool: string; args: readonly string[]; network?: string; env?: object }[] = [];
    const d = `sha256:${'a'.repeat(64)}`;
    const tool = (
      t: string,
      args: readonly string[],
      o: { network?: string; env?: object } = {},
    ): RunResult => {
      calls.push({ tool: t, args, network: o.network, env: o.env });
      return {
        code: 0,
        stdout: '',
        stderr: `Digest: ${d}
`,
      };
    };
    const keys = { key: '/work/.tmp/k/cosign.key', password: 'pw' };
    const ref = internalRef('qualor/server', d);
    signInDryRun(r, keys, ref, '/work/sbom.json', tool);
    expect(pushChartToDryRun(r, '/work/qualor-0.1.0.tgz', tool)).toBe(d);
    expect(calls.map((c) => [c.tool, c.args[0]])).toEqual([
      ['cosign', 'sign'],
      ['cosign', 'attest'],
      ['helm', 'push'],
    ]);
    for (const c of calls) expect(c.network).toBe(r.network);
    for (const c of calls.slice(0, 2)) {
      expect(c.args).toEqual(expect.arrayContaining([...SIGN_OFFLINE, ...PLAIN_HTTP, ref]));
      expect(c.env).toEqual({ COSIGN_PASSWORD: 'pw' });
    }
    expect(calls[2]?.args).toEqual([
      'push',
      '/work/qualor-0.1.0.tgz',
      `oci://${REGISTRY_ALIAS}:5000/qualor`,
      '--plain-http',
    ]);
    calls.length = 0;
    expect(() => signInDryRun(r, keys, `docker.io/qualor/server@${d}`, null, tool)).toThrow(
      /not the dry-run registry/,
    );
    expect(calls).toEqual([]);
  });
});
