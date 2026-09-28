import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  LAYER_MEDIA_TYPE,
  parseDbManifest,
  pinDatabase,
  pinGitLabCi,
  pinInstallSh,
} from './trivy-db-pin';

/** ghcr.io/aquasecurity/trivy-db:2 as the registry answered on 2026-09-25. */
const MANIFEST = JSON.stringify({
  schemaVersion: 2,
  mediaType: 'application/vnd.oci.image.manifest.v1+json',
  artifactType: 'application/vnd.aquasec.trivy.config.v1+json',
  config: {
    mediaType: 'application/vnd.oci.empty.v1+json',
    digest: 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
    size: 2,
    data: 'e30=',
  },
  layers: [
    {
      mediaType: LAYER_MEDIA_TYPE,
      digest: 'sha256:7d0ae3ee84ece1ecae274d9ac146c7241ae483c981f68aeb3f4953f6c2fbc6b0',
      size: 122707413,
      annotations: { 'org.opencontainers.image.title': 'db.tar.gz' },
    },
  ],
  annotations: { 'org.opencontainers.image.created': '2026-09-25T06:43:29Z' },
});

describe('pnpm trivy-db:pin (plan 2B)', () => {
  it('reads the database layer and the creation time of the manifest', () => {
    expect(parseDbManifest(MANIFEST)).toEqual({
      digest: 'sha256:7d0ae3ee84ece1ecae274d9ac146c7241ae483c981f68aeb3f4953f6c2fbc6b0',
      created: '2026-09-25T06:43:29Z',
    });
  });

  it('refuses a manifest it does not recognise', () => {
    const m = JSON.parse(MANIFEST) as { layers: { mediaType: string; digest: string }[] };
    const variant = (patch: (x: typeof m) => void) => {
      const copy = JSON.parse(MANIFEST) as typeof m;
      patch(copy);
      return () => parseDbManifest(JSON.stringify(copy));
    };
    expect(variant((x) => (x.layers[0]!.mediaType = 'application/octet-stream'))).toThrow(
      /exactly one database layer/,
    );
    expect(variant((x) => x.layers.push({ ...m.layers[0]! }))).toThrow(/exactly one/);
    expect(variant((x) => (x.layers[0]!.digest = 'sha256:../../x'))).toThrow(/digest/);
    expect(variant((x) => delete (x as { annotations?: unknown }).annotations)).toThrow(/created/);
  });

  it('rewrites exactly the two pin lines of install.sh', () => {
    const script = readFileSync('tools/analyzers/install.sh', 'utf8');
    const pinned = pinInstallSh(script, {
      digest: `sha256:${'a'.repeat(64)}`,
      created: '2026-10-01T00:00:00Z',
    });
    expect(pinned).toContain(`\nTRIVY_DB_DIGEST=sha256:${'a'.repeat(64)}\n`);
    expect(pinned).toContain('\nTRIVY_DB_CREATED=2026-10-01T00:00:00Z\n');
    const changed = pinned.split('\n').filter((line, i) => line !== script.split('\n')[i]);
    expect(changed).toHaveLength(2);
    expect(() => pinInstallSh('#!/bin/sh\n', { digest: 'x', created: 'y' })).toThrow(
      /TRIVY_DB_DIGEST/,
    );
  });
});

describe('pinGitLabCi: the GitLab cache key follows the pin', () => {
  it('rewrites exactly the QUALOR_TRIVY_DB_SHA256 line of .gitlab-ci.yml', () => {
    const ci = readFileSync('.gitlab-ci.yml', 'utf8');
    const pinned = pinGitLabCi(ci, { digest: `sha256:${'a'.repeat(64)}`, created: 'x' });
    expect(pinned).toMatch(new RegExp(`\n {4}QUALOR_TRIVY_DB_SHA256: ${'a'.repeat(64)}\n`));
    const changed = pinned.split('\n').filter((line, i) => line !== ci.split('\n')[i]);
    expect(changed).toHaveLength(1);
    expect(() => pinGitLabCi('stages: [check]\n', { digest: 'x', created: 'y' })).toThrow(
      /QUALOR_TRIVY_DB_SHA256/,
    );
  });
});

describe('pinDatabase: the registry round trip of pnpm trivy-db:pin', () => {
  const script = readFileSync('tools/analyzers/install.sh', 'utf8');
  const gitlabCi = readFileSync('.gitlab-ci.yml', 'utf8');
  const registry = (blobStatus: number, manifest = MANIFEST) => {
    const heads: string[] = [];
    return {
      heads,
      get: (url: string) =>
        Promise.resolve(url.includes('/token?') ? JSON.stringify({ token: 't' }) : manifest),
      head: (url: string) => {
        heads.push(url);
        return Promise.resolve(blobStatus);
      },
    };
  };
  const file = (text: string) => {
    const writes: string[] = [];
    return { writes, read: () => text, write: (t: string) => void writes.push(t) };
  };
  const newer = (() => {
    const m = JSON.parse(MANIFEST) as {
      layers: { digest: string }[];
      annotations: Record<string, string>;
    };
    m.layers[0]!.digest = `sha256:${'b'.repeat(64)}`;
    m.annotations['org.opencontainers.image.created'] = '2026-10-01T00:00:00Z';
    return JSON.stringify(m);
  })();

  it('confirms that the new layer can be downloaded before it pins it', async () => {
    const r = registry(307, newer);
    const f = file(script);
    const ci = file(gitlabCi);
    await expect(pinDatabase(r, f, ci)).resolves.toMatch(/^pinned the Trivy database sha256:b{64}/);
    expect(ci.writes).toHaveLength(1);
    expect(ci.writes[0]).toContain(`QUALOR_TRIVY_DB_SHA256: ${'b'.repeat(64)}\n`);
    expect(r.heads).toEqual([
      `https://ghcr.io/v2/aquasecurity/trivy-db/blobs/sha256:${'b'.repeat(64)}`,
    ]);
    expect(f.writes).toHaveLength(1);
    expect(f.writes[0]).toContain(`\nTRIVY_DB_DIGEST=sha256:${'b'.repeat(64)}\n`);
  });

  it('refuses a layer the registry does not serve, and writes nothing', async () => {
    const f = file(script);
    const ci = file(gitlabCi);
    await expect(pinDatabase(registry(404, newer), f, ci)).rejects.toThrow(/HTTP 404/);
    expect(f.writes).toEqual([]);
    expect(ci.writes).toEqual([]);
  });

  it('leaves install.sh untouched when the pin does not move', async () => {
    const f = file(script);
    const ci = file(gitlabCi);
    await expect(pinDatabase(registry(200), f, ci)).resolves.toMatch(/already pinned/);
    expect(f.writes).toEqual([]);
    expect(ci.writes).toEqual([]);
  });
});
