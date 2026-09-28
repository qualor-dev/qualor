import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * `pnpm trivy-db:pin`: moves the Trivy database pin of tools/analyzers/install.sh
 * (`TRIVY_DB_DIGEST`, `TRIVY_DB_CREATED`), and the GitLab CI cache key that follows it
 * (`QUALOR_TRIVY_DB_SHA256` in .gitlab-ci.yml), to the newest snapshot of
 * ghcr.io/aquasecurity/trivy-db:2 (plan 2B). Upstream builds a snapshot every
 * 6 hours and deletes old ones after a time it does not document, so the pin must move before an image build when the pinned
 * layer is gone; the scanner image is then rebuilt to ship it. It reads two public registry
 * answers and writes two files; it downloads no database.
 */
export const REPOSITORY = 'aquasecurity/trivy-db';
export const TAG = '2';
export const LAYER_MEDIA_TYPE = 'application/vnd.aquasec.trivy.db.layer.v1.tar+gzip';
const INSTALL_SH = path.join(path.dirname(fileURLToPath(import.meta.url)), 'install.sh');
const GITLAB_CI = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  '.gitlab-ci.yml',
);

export interface DbPin {
  digest: string;
  created: string;
}

/** The single database layer of the OCI manifest, and when the snapshot was created. */
export function parseDbManifest(json: string): DbPin {
  const m = JSON.parse(json) as {
    layers?: { mediaType?: unknown; digest?: unknown }[];
    annotations?: Record<string, unknown>;
  };
  const layers = (m.layers ?? []).filter((l) => l.mediaType === LAYER_MEDIA_TYPE);
  if (layers.length !== 1 || typeof layers[0]?.digest !== 'string') {
    throw new Error(`the ${REPOSITORY}:${TAG} manifest does not have exactly one database layer`);
  }
  const digest = layers[0].digest;
  if (!/^sha256:[0-9a-f]{64}$/.test(digest)) throw new Error(`unexpected layer digest ${digest}`);
  const created = m.annotations?.['org.opencontainers.image.created'];
  if (typeof created !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(created)) {
    throw new Error('the manifest has no org.opencontainers.image.created annotation');
  }
  return { digest, created };
}

/** install.sh with the pin replaced; throws when either line is missing. */
export function pinInstallSh(text: string, pin: DbPin): string {
  let out = text;
  for (const [name, value] of [
    ['TRIVY_DB_DIGEST', pin.digest],
    ['TRIVY_DB_CREATED', pin.created],
  ] as const) {
    const line = new RegExp(`^${name}=.*$`, 'm');
    if (!line.test(out)) throw new Error(`install.sh has no ${name}=`);
    out = out.replace(line, `${name}=${value}`);
  }
  return out;
}

/**
 * .gitlab-ci.yml with the cache key of Trivy's downloads (`QUALOR_TRIVY_DB_SHA256`, the digest
 * without its `sha256:`) moved to the pin; throws when the line is missing.
 */
export function pinGitLabCi(text: string, pin: DbPin): string {
  const line = /^( +QUALOR_TRIVY_DB_SHA256: ).*$/m;
  if (!line.test(text)) throw new Error('.gitlab-ci.yml has no QUALOR_TRIVY_DB_SHA256:');
  return text.replace(line, `$1${pin.digest.replace(/^sha256:/, '')}`);
}

/** The two registry calls the pin needs (injected by the tests). */
export interface Registry {
  /** The body of a GET; throws on a status other than 2xx. */
  get(url: string, headers: Record<string, string>): Promise<string>;
  /** The status of a HEAD, redirects not followed. */
  head(url: string, headers: Record<string, string>): Promise<number>;
}

/** install.sh or .gitlab-ci.yml, read and written (injected by the tests). */
export interface PinFile {
  read(): string;
  write(text: string): void;
}

/**
 * Reads the newest snapshot of the manifest, confirms that its layer can be downloaded (ghcr.io
 * answers a blob HEAD with 200, or a redirect to its storage; a deleted layer is a 404), and moves
 * the pin in install.sh and, when given, the GitLab cache key in .gitlab-ci.yml. A file is written
 * only when its pin moves. Returns the line to print.
 */
export async function pinDatabase(
  registry: Registry,
  file: PinFile,
  gitlabCi?: PinFile,
): Promise<string> {
  const token = (
    JSON.parse(
      await registry.get(`https://ghcr.io/token?scope=repository:${REPOSITORY}:pull`, {}),
    ) as { token?: unknown }
  ).token;
  if (typeof token !== 'string') throw new Error('no pull token from ghcr.io');
  const auth = { Authorization: `Bearer ${token}` };
  const pin = parseDbManifest(
    await registry.get(`https://ghcr.io/v2/${REPOSITORY}/manifests/${TAG}`, {
      ...auth,
      Accept: 'application/vnd.oci.image.manifest.v1+json',
    }),
  );
  const blob = `https://ghcr.io/v2/${REPOSITORY}/blobs/${pin.digest}`;
  const status = await registry.head(blob, auth);
  if (!(status === 200 || status === 302 || status === 303 || status === 307 || status === 308)) {
    throw new Error(
      `the database layer ${pin.digest} cannot be downloaded: ${blob}: HTTP ${status}`,
    );
  }
  const current = file.read();
  const next = pinInstallSh(current, pin);
  // Both are computed before either is written, so a missing line leaves both files alone.
  const ciCurrent = gitlabCi?.read();
  const ciNext = ciCurrent === undefined ? undefined : pinGitLabCi(ciCurrent, pin);
  if (ciNext !== undefined && ciNext !== ciCurrent) gitlabCi?.write(ciNext);
  if (next === current)
    return `already pinned: the Trivy database ${pin.digest} (built ${pin.created})`;
  file.write(next);
  return `pinned the Trivy database ${pin.digest} (built ${pin.created})`;
}

const registry: Registry = {
  async get(url, headers) {
    const res = await fetch(url, {
      headers,
      redirect: 'error',
      signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
    return res.text();
  },
  async head(url, headers) {
    const res = await fetch(url, {
      method: 'HEAD',
      headers,
      redirect: 'manual',
      signal: AbortSignal.timeout(30_000),
    });
    return res.status;
  },
};

async function main(): Promise<void> {
  const line = await pinDatabase(
    registry,
    {
      read: () => readFileSync(INSTALL_SH, 'utf8'),
      write: (text) => writeFileSync(INSTALL_SH, text),
    },
    {
      read: () => readFileSync(GITLAB_CI, 'utf8'),
      write: (text) => writeFileSync(GITLAB_CI, text),
    },
  );
  process.stdout.write(`${line}\n`);
}

if (
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
