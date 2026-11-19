import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { compareSemver } from '../src/fix/versions/semver';
import { tarGz } from './trivy-archive';

/** One published version of a fake package: what its `package.json` says. */
export interface FakeNpmVersion {
  version: string;
  dependencies?: Record<string, string>;
  scripts?: Record<string, string>;
}

export interface FakeNpmRegistry {
  /** `http://127.0.0.1:<port>`, without a trailing slash. */
  url: string;
  /** The path (and query) of every request, in order. */
  requests: string[];
  /**
   * The `authorization` header of every request, in the same order as `requests`; null for a request
   * without one. A test reads where a registry token went (B9).
   */
  authorizations: (string | null)[];
  close(): Promise<void>;
}

/** A tarball and its hashes, as `dist` names them. */
interface Packed {
  bytes: Buffer;
  integrity: string;
  shasum: string;
}

/** Every version was published long ago, so no release-age gate of a package manager holds one back. */
const PUBLISHED = '2020-01-01T00:00:00.000Z';

/** The name without its scope: what the tarball's file name starts with. */
function baseName(name: string): string {
  return name.startsWith('@') ? name.slice(name.indexOf('/') + 1) : name;
}

function pack(name: string, v: FakeNpmVersion): Packed {
  const manifest = {
    name,
    version: v.version,
    ...(v.dependencies !== undefined && { dependencies: v.dependencies }),
    ...(v.scripts !== undefined && { scripts: v.scripts }),
  };
  const bytes = tarGz([
    { name: 'package/package.json', data: `${JSON.stringify(manifest, null, 2)}\n` },
    { name: 'package/index.js', data: 'module.exports = {};\n' },
  ]);
  return {
    bytes,
    integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}`,
    shasum: createHash('sha1').update(bytes).digest('hex'),
  };
}

function send(res: ServerResponse, status: number, type: string, body: string | Buffer): void {
  res.writeHead(status, { 'content-type': type, 'cache-control': 'no-cache' });
  res.end(body);
}

/**
 * A local npm registry for the fix adapters' tests (R27): packuments and in-memory tarballs
 * (`tarGz`) with their real `integrity` and `shasum`, on `127.0.0.1`. `packages` is read on each
 * request, so a version pushed to it later is "published" from then on (a test locks the old
 * version first, then publishes the fix). Unknown names, versions and paths answer 404.
 */
export async function createFakeNpmRegistry(
  packages: Record<string, FakeNpmVersion[]>,
): Promise<FakeNpmRegistry> {
  const requests: string[] = [];
  const authorizations: (string | null)[] = [];
  const packed = new Map<string, Packed>();
  let url = '';

  const versionsOf = (name: string): FakeNpmVersion[] =>
    Object.hasOwn(packages, name) ? (packages[name] ?? []) : [];

  const packedOf = (name: string, v: FakeNpmVersion): Packed => {
    const key = `${name}@${v.version}`;
    const known = packed.get(key);
    if (known !== undefined) return known;
    const made = pack(name, v);
    packed.set(key, made);
    return made;
  };

  const tarballUrl = (name: string, version: string) =>
    `${url}/${name}/-/${baseName(name)}-${version}.tgz`;

  const packument = (name: string, versions: readonly FakeNpmVersion[]): string => {
    const sorted = versions.map((v) => v.version).toSorted((a, b) => compareSemver(a, b) ?? 0);
    const latest = sorted.filter((v) => !v.includes('-')).at(-1) ?? sorted.at(-1) ?? '';
    const docs = Object.fromEntries(
      versions.map((v) => {
        const p = packedOf(name, v);
        const doc = {
          name,
          version: v.version,
          _id: `${name}@${v.version}`,
          ...(v.dependencies !== undefined && { dependencies: v.dependencies }),
          ...(v.scripts !== undefined && { scripts: v.scripts }),
          dist: { tarball: tarballUrl(name, v.version), integrity: p.integrity, shasum: p.shasum },
        };
        return [v.version, doc];
      }),
    );
    const time = Object.fromEntries(versions.map((v) => [v.version, PUBLISHED]));
    return JSON.stringify({
      _id: name,
      name,
      'dist-tags': { latest },
      versions: docs,
      time: { created: PUBLISHED, modified: PUBLISHED, ...time },
    });
  };

  /** `/<name>/-/<base>-<version>.tgz`: the tarball, or null for any other path. */
  const tarball = (pathname: string): Buffer | null => {
    const cut = pathname.indexOf('/-/');
    if (cut < 0) return null;
    const name = pathname.slice(1, cut);
    const file = pathname.slice(cut + 3);
    const v = versionsOf(name).find((x) => file === `${baseName(name)}-${x.version}.tgz`);
    return v === undefined ? null : packedOf(name, v).bytes;
  };

  const handle = (req: IncomingMessage, res: ServerResponse): void => {
    const raw = req.url ?? '/';
    requests.push(raw);
    authorizations.push(req.headers.authorization ?? null);
    const pathname = decodeURIComponent(new URL(raw, 'http://registry.invalid').pathname);
    const bytes = tarball(pathname);
    if (bytes !== null) {
      send(res, 200, 'application/octet-stream', bytes);
      return;
    }
    const versions = versionsOf(pathname.slice(1));
    if (versions.length === 0) {
      send(res, 404, 'application/json', '{"error":"Not found"}');
      return;
    }
    send(res, 200, 'application/json', packument(pathname.slice(1), versions));
  };

  const server = createServer(handle);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    url,
    requests,
    authorizations,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      }),
  };
}
