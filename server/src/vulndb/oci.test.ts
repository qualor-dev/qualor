import { createHash, randomBytes } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { parseInternalHosts } from '../scm/url';
import {
  DOCKER_MANIFEST_TYPE,
  fetchLayerDescriptor,
  OCI_MANIFEST_TYPE,
  openBlob,
  parseReference,
  TRIVY_LAYER_MEDIA_TYPE,
  type OciOptions,
  type OciProblem,
} from './oci';

const sha256 = (bytes: Buffer | string): string =>
  `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

const BLOB = randomBytes(200_000);
const LAYER_DIGEST = sha256(BLOB);
const USER = { username: 'robot', password: 's3cret' };
const BASIC = `Basic ${Buffer.from(`${USER.username}:${USER.password}`).toString('base64')}`;

function manifestOf(
  layers: unknown[] = [
    { mediaType: TRIVY_LAYER_MEDIA_TYPE, digest: LAYER_DIGEST, size: BLOB.length },
  ],
  mediaType = OCI_MANIFEST_TYPE,
): string {
  return JSON.stringify({
    schemaVersion: 2,
    mediaType,
    config: {
      mediaType: 'application/vnd.oci.empty.v1+json',
      digest: sha256('{}'),
      size: 2,
    },
    layers,
  });
}

interface Seen {
  path: string;
  authorization: string | undefined;
}

/** How the fake registry answers; reset before each test. */
interface Behaviour {
  /** The token realm demands these (HTTP Basic); null: anonymous tokens. */
  credentials: typeof USER | null;
  /** The challenge of a 401; null sends none. */
  challenge: string | null;
  /** The registry itself takes Basic credentials (a `Basic` challenge). */
  basicAtRegistry: boolean;
  manifestStatus: number;
  manifest: string;
  manifestType: string;
  blobStatus: number;
  /** Where the blob redirects to; null serves it from the registry. */
  blobLocation: string | null;
}

interface Host {
  host: string;
  seen: Seen[];
  /** Connections that spoke no HTTP: the client's TLS handshake to this plain-http server. */
  tlsAttempts: () => number;
  close: () => Promise<void>;
}

async function serve(
  handle: (req: IncomingMessage, res: ServerResponse, host: string) => void,
): Promise<Host> {
  const seen: Seen[] = [];
  let host = '';
  const server = createServer((req, res) => {
    seen.push({ path: req.url ?? '', authorization: req.headers.authorization });
    handle(req, res, host);
  });
  let tlsAttempts = 0;
  server.on('clientError', (_err, socket) => {
    tlsAttempts++;
    socket.destroy();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  host = `127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    host,
    seen,
    tlsAttempts: () => tlsAttempts,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

describe('parseReference', () => {
  it.each([
    [
      'ghcr.io/aquasecurity/trivy-db:2',
      { registry: 'ghcr.io', repository: 'aquasecurity/trivy-db', reference: '2' },
    ],
    [
      'registry.acme.example:5000/mirror/trivy-db:2',
      { registry: 'registry.acme.example:5000', repository: 'mirror/trivy-db', reference: '2' },
    ],
    [
      `ghcr.io/aquasecurity/trivy-db@sha256:${'ab'.repeat(32)}`,
      {
        registry: 'ghcr.io',
        repository: 'aquasecurity/trivy-db',
        reference: `sha256:${'ab'.repeat(32)}`,
      },
    ],
  ])('%s', (ref, parsed) => {
    expect(parseReference(ref)).toEqual(parsed);
  });

  it.each(['trivy-db:2', 'ghcr.io/aquasecurity/trivy-db', 'https://ghcr.io/a/b:2', 'GHCR.io/a:2'])(
    'refuses %s',
    (ref) => {
      expect(() => parseReference(ref)).toThrow(/not an OCI reference/);
    },
  );
});

describe('the OCI client', () => {
  let registry: Host;
  let cdn: Host;
  let behaviour: Behaviour;
  let opts: OciOptions;
  let ref: string;

  const tokenFor = (b: Behaviour): string => (b.credentials ? 'user-token' : 'anon-token');

  beforeAll(async () => {
    registry = await serve((req, res, host) => {
      const url = new URL(req.url ?? '/', `http://${host}`);
      const authorization = req.headers.authorization;
      if (url.pathname === '/token') {
        if (behaviour.credentials && authorization !== BASIC) {
          res.writeHead(401, { 'content-type': 'application/json' }).end('{"errors":[]}');
          return;
        }
        res
          .writeHead(200, { 'content-type': 'application/json' })
          .end(JSON.stringify({ token: tokenFor(behaviour) }));
        return;
      }
      const hop = /^\/hop\/(\d+)$/.exec(url.pathname);
      if (hop) {
        const n = Number(hop[1]);
        if (n === 0) res.writeHead(200).end(BLOB);
        else res.writeHead(302, { location: `/hop/${n - 1}` }).end();
        return;
      }
      const authorised =
        authorization === `Bearer ${tokenFor(behaviour)}` ||
        (behaviour.basicAtRegistry && authorization === BASIC);
      if (!authorised) {
        res.writeHead(
          401,
          behaviour.challenge === null ? {} : { 'www-authenticate': behaviour.challenge },
        );
        res.end('{"errors":[{"code":"UNAUTHORIZED"}]}');
        return;
      }
      if (url.pathname.startsWith('/v2/mirror/trivy-db/manifests/')) {
        res
          .writeHead(behaviour.manifestStatus, { 'content-type': behaviour.manifestType })
          .end(behaviour.manifestStatus === 200 ? behaviour.manifest : '{"errors":[]}');
        return;
      }
      if (url.pathname === `/v2/mirror/trivy-db/blobs/${LAYER_DIGEST}`) {
        if (behaviour.blobStatus !== 200) res.writeHead(behaviour.blobStatus).end();
        else if (behaviour.blobLocation !== null) {
          res.writeHead(307, { location: behaviour.blobLocation }).end();
        } else res.writeHead(200).end(BLOB);
        return;
      }
      res.writeHead(404).end();
    });
    cdn = await serve((req, res) => {
      if (req.url?.startsWith('/cdn/')) res.writeHead(200).end(BLOB);
      else if (req.url?.startsWith('/cut/')) {
        res.writeHead(200, { 'content-length': String(BLOB.length) });
        res.write(BLOB.subarray(0, BLOB.length / 2), () => res.destroy());
      } else res.writeHead(404).end();
    });
  });

  afterAll(async () => {
    await registry.close();
    await cdn.close();
  });

  beforeEach(() => {
    registry.seen.length = 0;
    cdn.seen.length = 0;
    behaviour = {
      credentials: null,
      challenge: `Bearer realm="http://${registry.host}/token",service="fake-registry",scope="repository:mirror/trivy-db:pull"`,
      basicAtRegistry: false,
      manifestStatus: 200,
      manifest: manifestOf(),
      manifestType: OCI_MANIFEST_TYPE,
      blobStatus: 200,
      blobLocation: `http://${cdn.host}/cdn/blob?sig=signed`,
    };
    opts = { internalHosts: parseInternalHosts(`${registry.host},${cdn.host}`) };
    ref = `${registry.host}/mirror/trivy-db:2`;
  });

  const tokenRequests = () => registry.seen.filter((s) => s.path.startsWith('/token'));

  async function bytesOf(blob: AsyncIterable<Buffer> | OciProblem): Promise<Buffer> {
    if (!(Symbol.asyncIterator in blob)) throw new Error(`a problem: ${JSON.stringify(blob)}`);
    const parts: Buffer[] = [];
    for await (const part of blob) parts.push(part);
    return Buffer.concat(parts);
  }

  describe('fetchLayerDescriptor', () => {
    it('gets an anonymous token from the realm and picks the Trivy layer', async () => {
      expect(await fetchLayerDescriptor(ref, {}, opts)).toEqual({
        digest: LAYER_DIGEST,
        size: BLOB.length,
      });
      const [token] = tokenRequests();
      expect(token?.authorization).toBeUndefined();
      const query = new URL(token?.path ?? '', 'http://x').searchParams;
      expect(query.get('service')).toBe('fake-registry');
      expect(query.get('scope')).toBe('repository:mirror/trivy-db:pull');
      const manifests = registry.seen.filter((s) => s.path.includes('/manifests/'));
      expect(manifests.map((s) => s.authorization)).toEqual([undefined, 'Bearer anon-token']);
    });

    it('tries a listed registry over https first, then keeps to plain http', async () => {
      const before = registry.tlsAttempts();
      expect(await fetchLayerDescriptor(ref, {}, opts)).toMatchObject({ digest: LAYER_DIGEST });
      // One https attempt for the session; the token realm and the retry go straight to http.
      expect(registry.tlsAttempts() - before).toBe(1);
      expect(registry.seen).toHaveLength(3);
    });

    it('sends basic credentials to the token realm only', async () => {
      behaviour.credentials = USER;
      expect(await fetchLayerDescriptor(ref, USER, opts)).toEqual({
        digest: LAYER_DIGEST,
        size: BLOB.length,
      });
      expect(tokenRequests().map((s) => s.authorization)).toEqual([BASIC]);
      const manifests = registry.seen.filter((s) => s.path.includes('/manifests/'));
      expect(manifests.map((s) => s.authorization)).toEqual([undefined, 'Bearer user-token']);
    });

    it('answers AUTH when the token realm refuses the credentials', async () => {
      behaviour.credentials = USER;
      const got = await fetchLayerDescriptor(ref, { ...USER, password: 'wrong' }, opts);
      expect(got).toMatchObject({ code: 'AUTH' });
      expect((got as OciProblem).message).toMatch(/401/);
    });

    it('answers AUTH when credentials are needed and none are set', async () => {
      behaviour.credentials = USER;
      expect(await fetchLayerDescriptor(ref, {}, opts)).toMatchObject({ code: 'AUTH' });
    });

    it.each([
      ['no challenge', null],
      ['a Bearer challenge without a realm', 'Bearer service="fake-registry"'],
    ])('answers AUTH for a 401 with %s', async (_what, challenge) => {
      behaviour.challenge = challenge;
      expect(await fetchLayerDescriptor(ref, {}, opts)).toMatchObject({ code: 'AUTH' });
      expect(tokenRequests()).toEqual([]);
    });

    it('sends basic credentials to a registry that asks for them', async () => {
      behaviour.challenge = 'Basic realm="fake-registry"';
      behaviour.basicAtRegistry = true;
      expect(await fetchLayerDescriptor(ref, USER, opts)).toMatchObject({ digest: LAYER_DIGEST });
      expect(await fetchLayerDescriptor(ref, {}, opts)).toMatchObject({ code: 'AUTH' });
    });

    it('answers NOT_FOUND for a 404 manifest', async () => {
      behaviour.manifestStatus = 404;
      expect(await fetchLayerDescriptor(ref, {}, opts)).toMatchObject({ code: 'NOT_FOUND' });
    });

    it('answers BAD_ANSWER for a 500', async () => {
      behaviour.manifestStatus = 500;
      const got = await fetchLayerDescriptor(ref, {}, opts);
      expect(got).toMatchObject({ code: 'BAD_ANSWER' });
      expect((got as OciProblem).message).toMatch(/500/);
    });

    it('answers NO_LAYER for a manifest without the Trivy layer', async () => {
      behaviour.manifest = manifestOf([
        { mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip', digest: LAYER_DIGEST, size: 9 },
      ]);
      expect(await fetchLayerDescriptor(ref, {}, opts)).toMatchObject({ code: 'NO_LAYER' });
    });

    it('accepts a Docker v2 manifest', async () => {
      behaviour.manifest = manifestOf(undefined, DOCKER_MANIFEST_TYPE);
      behaviour.manifestType = DOCKER_MANIFEST_TYPE;
      expect(await fetchLayerDescriptor(ref, {}, opts)).toMatchObject({ digest: LAYER_DIGEST });
    });

    it('answers BAD_ANSWER for an image index', async () => {
      behaviour.manifest = JSON.stringify({
        schemaVersion: 2,
        mediaType: 'application/vnd.oci.image.index.v1+json',
        manifests: [],
      });
      behaviour.manifestType = 'application/vnd.oci.image.index.v1+json';
      expect(await fetchLayerDescriptor(ref, {}, opts)).toMatchObject({ code: 'BAD_ANSWER' });
    });

    it('answers BAD_ANSWER for a layer whose digest is not sha256', async () => {
      behaviour.manifest = manifestOf([
        { mediaType: TRIVY_LAYER_MEDIA_TYPE, digest: 'sha512:abc', size: 9 },
      ]);
      expect(await fetchLayerDescriptor(ref, {}, opts)).toMatchObject({ code: 'BAD_ANSWER' });
    });

    it('answers TOO_LARGE for a layer over 2 GiB', async () => {
      behaviour.manifest = manifestOf([
        { mediaType: TRIVY_LAYER_MEDIA_TYPE, digest: LAYER_DIGEST, size: 2 * 1024 ** 3 + 1 },
      ]);
      expect(await fetchLayerDescriptor(ref, {}, opts)).toMatchObject({ code: 'TOO_LARGE' });
    });

    it('checks the manifest of a digest reference against the digest', async () => {
      const pinned = `${registry.host}/mirror/trivy-db@${sha256(behaviour.manifest)}`;
      expect(await fetchLayerDescriptor(pinned, {}, opts)).toMatchObject({
        digest: LAYER_DIGEST,
      });
      const other = `${registry.host}/mirror/trivy-db@${sha256('another manifest')}`;
      expect(await fetchLayerDescriptor(other, {}, opts)).toMatchObject({ code: 'BAD_ANSWER' });
    });

    it('answers BLOCKED for a registry on a private address that is not listed', async () => {
      const got = await fetchLayerDescriptor(ref, {}, { internalHosts: new Set() });
      expect(got).toMatchObject({ code: 'BLOCKED' });
      expect((got as OciProblem).message).toMatch(/QUALOR_VULNDB_INTERNAL_HOSTS/);
      expect(registry.seen).toEqual([]);
    });

    it('answers UNREACHABLE when nothing listens', async () => {
      const gone = await serve(() => undefined);
      await gone.close();
      const got = await fetchLayerDescriptor(
        `${gone.host}/mirror/trivy-db:2`,
        {},
        {
          internalHosts: parseInternalHosts(gone.host),
        },
      );
      expect(got).toMatchObject({ code: 'UNREACHABLE' });
    });
  });

  describe('openBlob', () => {
    it('follows the redirect to a listed host and never sends the token there', async () => {
      const bytes = await bytesOf(await openBlob(ref, LAYER_DIGEST, {}, opts));
      expect(bytes.equals(BLOB)).toBe(true);
      expect(cdn.seen).toEqual([{ path: '/cdn/blob?sig=signed', authorization: undefined }]);
      const blobs = registry.seen.filter((s) => s.path.includes('/blobs/'));
      expect(blobs.map((s) => s.authorization)).toEqual([undefined, 'Bearer anon-token']);
    });

    it('throws from the chunks when the download is cut halfway', async () => {
      behaviour.blobLocation = `http://${cdn.host}/cut/blob`;
      const blob = await openBlob(ref, LAYER_DIGEST, {}, opts);
      await expect(bytesOf(blob)).rejects.toMatchObject({
        name: 'OutboundStreamError',
        cause: 'connection',
      });
    });

    it('streams a blob the registry serves itself', async () => {
      behaviour.blobLocation = null;
      const bytes = await bytesOf(await openBlob(ref, LAYER_DIGEST, {}, opts));
      expect(bytes.equals(BLOB)).toBe(true);
    });

    it.each([
      ['https', 'https'],
      ['http', 'http'],
    ])('answers BLOCKED for a redirect over %s to a host outside the list', async (_s, scheme) => {
      const port = cdn.host.split(':')[1] ?? '';
      behaviour.blobLocation = `${scheme}://localhost:${port}/cdn/blob`;
      const got = await openBlob(ref, LAYER_DIGEST, {}, opts);
      expect(got).toMatchObject({ code: 'BLOCKED' });
      expect((got as OciProblem).message).toMatch(/localhost/);
      expect(cdn.seen).toEqual([]);
    });

    it('follows at most 5 redirects', async () => {
      behaviour.blobLocation = `http://${registry.host}/hop/4`;
      const bytes = await bytesOf(await openBlob(ref, LAYER_DIGEST, {}, opts));
      expect(bytes.equals(BLOB)).toBe(true);

      behaviour.blobLocation = `http://${registry.host}/hop/5`;
      const got = await openBlob(ref, LAYER_DIGEST, {}, opts);
      expect(got).toMatchObject({ code: 'BAD_ANSWER' });
      expect((got as OciProblem).message).toMatch(/redirect/);
    });

    it('answers NOT_FOUND for a 404 blob', async () => {
      behaviour.blobStatus = 404;
      expect(await openBlob(ref, LAYER_DIGEST, {}, opts)).toMatchObject({ code: 'NOT_FOUND' });
    });

    it('answers AUTH when the blob needs credentials that are wrong', async () => {
      behaviour.credentials = USER;
      expect(await openBlob(ref, LAYER_DIGEST, { ...USER, password: 'no' }, opts)).toMatchObject({
        code: 'AUTH',
      });
    });
  });
});
