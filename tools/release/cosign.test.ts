import { describe, expect, it } from 'vitest';
import {
  assertDigestRef,
  attestArgs,
  PLAIN_HTTP,
  SIGN_OFFLINE,
  signBlobArgs,
  signImageArgs,
  verifyBlobArgs,
  VERIFY_OFFLINE,
  verifyImageArgs,
} from './cosign';

const DIGEST = `sha256:${'c'.repeat(64)}`;
const REF = `qualor-registry:5000/qualor/server@${DIGEST}`;
const DRY = { offline: true, plainHttp: true };

describe('cosign arguments (release.md §7)', () => {
  it('signs and verifies blobs with a key, a bundle and no transparency log', () => {
    const blob = signBlobArgs('/k/cosign.key', '/r/SHA256SUMS', '/r/SHA256SUMS.bundle', {
      offline: true,
    });
    expect(blob).toEqual([
      'sign-blob',
      '--yes',
      '--key',
      '/k/cosign.key',
      '--bundle',
      '/r/SHA256SUMS.bundle',
      ...SIGN_OFFLINE,
      '/r/SHA256SUMS',
    ]);
    expect(verifyBlobArgs('/r/cosign.pub', '/r/SHA256SUMS', '/r/SHA256SUMS.bundle')).toEqual([
      'verify-blob',
      '--key',
      '/r/cosign.pub',
      '--bundle',
      '/r/SHA256SUMS.bundle',
      ...VERIFY_OFFLINE,
      '/r/SHA256SUMS',
    ]);
  });

  it('signs, attests and verifies images only by digest, over plain HTTP only in the dry run', () => {
    expect(signImageArgs('/k/cosign.key', REF, DRY)).toEqual(
      expect.arrayContaining(['sign', '--key', '/k/cosign.key', '--allow-http-registry', REF]),
    );
    expect(attestArgs('/k/cosign.key', REF, '/r/sbom/server.spdx.json', DRY)).toEqual(
      expect.arrayContaining([
        'attest',
        '--type',
        'spdxjson',
        '--predicate',
        '/r/sbom/server.spdx.json',
      ]),
    );
    expect(verifyImageArgs('/r/cosign.pub', REF, DRY)).toEqual(
      expect.arrayContaining(['verify', ...VERIFY_OFFLINE]),
    );
    const publish = signImageArgs('/k/cosign.key', `qualor/server@${DIGEST}`, {
      offline: false,
      plainHttp: false,
    });
    for (const flag of [...PLAIN_HTTP, ...SIGN_OFFLINE]) expect(publish).not.toContain(flag);
    const noRekor = signImageArgs('/k/cosign.key', `qualor/server@${DIGEST}`, {
      offline: true,
      plainHttp: false,
    });
    expect(noRekor).toEqual(expect.arrayContaining([...SIGN_OFFLINE]));
    for (const flag of PLAIN_HTTP) expect(noRekor).not.toContain(flag);
    const online = signBlobArgs('/k/cosign.key', '/r/SHA256SUMS', '/r/SHA256SUMS.bundle', {
      offline: false,
    });
    for (const flag of SIGN_OFFLINE) expect(online).not.toContain(flag);
    for (const tagged of [
      'qualor/server:1.0.0',
      'qualor/server',
      `qualor/server@sha256:${'c'.repeat(63)}`,
    ]) {
      expect(() => assertDigestRef(tagged), tagged).toThrow(/by digest/);
      expect(() => signImageArgs('/k', tagged, DRY), tagged).toThrow(/by digest/);
    }
  });
});
