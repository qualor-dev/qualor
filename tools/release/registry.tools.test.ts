import { randomBytes } from 'node:crypto';
import { rmSync } from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { freePort, must, REPO_ROOT, run } from '../deploy/stack';
import { verifyImageArgs } from './cosign';
import { generateKeys, removeKeys, type Keys } from './keys';
import {
  hostRef,
  internalRef,
  newRegistry,
  pushToDryRun,
  DRY_RUN_OPTIONS,
  REGISTRY_IMAGE,
  signInDryRun,
  startRegistry,
  stopRegistry,
  type DryRunRegistry,
} from './registry';
import { runTool } from './toolbox';

/**
 * The dry-run registry for real (release.md §10, ruling RE3): an --internal network, a port on
 * 127.0.0.1 only, a push through the guard, and an offline cosign signature by digest on the
 * internal network with a throwaway key. Everything is removed afterwards.
 */
const dir = path.join(REPO_ROOT, '.tmp', 'release-test', randomBytes(4).toString('hex'));
const REPOSITORY = 'qualor/registry-test';
let r: DryRunRegistry | undefined;
let keys: Keys | undefined;
let other: Keys | undefined;
let pushed = '';
let digest = '';

beforeAll(async () => {
  r = newRegistry(await freePort());
  startRegistry(r);
  keys = generateKeys(path.join(dir, 'keys'));
  other = generateKeys(path.join(dir, 'other'));
  // Any small local image will do: the registry image itself, already pulled by digest.
  pushed = hostRef(r, REPOSITORY, '0.0.0-test');
  must(run('docker', ['tag', REGISTRY_IMAGE, pushed]), `docker tag ${pushed}`);
  digest = pushToDryRun(pushed);
}, 180_000);

afterAll(() => {
  if (pushed !== '') run('docker', ['image', 'rm', pushed]);
  const failures = r ? stopRegistry(r) : [];
  if (keys) removeKeys(keys);
  if (other) removeKeys(other);
  rmSync(dir, { recursive: true, force: true });
  expect(failures).toEqual([]);
  if (r) {
    expect(run('docker', ['container', 'inspect', r.container]).code).not.toBe(0);
    expect(run('docker', ['network', 'inspect', r.network]).code).not.toBe(0);
  }
});

describe('the dry-run registry in Docker (release.md §10)', () => {
  it('sits on an --internal network and publishes its port on 127.0.0.1 only', () => {
    const reg = r!;
    const internal = must(
      run('docker', ['network', 'inspect', '--format', '{{.Internal}}', reg.network]),
      'inspect',
    );
    expect(internal.stdout.trim()).toBe('true');
    const ports = must(run('docker', ['port', reg.container, '5000/tcp']), 'docker port');
    expect(ports.stdout.trim().split(/\r?\n/)).toEqual([`127.0.0.1:${reg.port}`]);
    expect(digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('signs and verifies by digest over the internal network, offline, with the throwaway key', () => {
    const reg = r!;
    const ref = internalRef(REPOSITORY, digest);
    signInDryRun(reg, keys!, ref, null);
    const net = { network: reg.network };
    const ok = runTool('cosign', verifyImageArgs(keys!.pub, ref, DRY_RUN_OPTIONS), net);
    expect(ok.code, ok.stderr).toBe(0);
    const wrong = runTool('cosign', verifyImageArgs(other!.pub, ref, DRY_RUN_OPTIONS), net);
    expect(wrong.code).not.toBe(0);
  });
});
