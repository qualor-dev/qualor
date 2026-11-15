import net, { type AddressInfo, type Socket } from 'node:net';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  addMember,
  ADMIN_PASSWORD,
  createTestContext,
  createUser,
  login,
  organizationId,
  type Session,
  type TestContext,
} from '../../test/app';
import { rawExchange } from '../../test/raw-socket';
import { rbacContext } from '../../test/rbac';
import { auditRows } from '../../test/sso';
import { trivyArchive } from '../../../packages/shared/test/trivy-archive';
import { instanceSettings, vulndbDatasets, vulnerabilityKev } from '../db/schema';

const MiB = 1024 * 1024;

/** An admin and an org admin (not an instance admin) of `ctx`. */
async function sessions(ctx: TestContext, name: string): Promise<[Session, Session]> {
  const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
  const u = await createUser(ctx, { username: name });
  await addMember(ctx, await organizationId(ctx, 'default'), u.id, 'admin');
  return [admin, await login(ctx, u.username, u.password)];
}

async function listen(ctx: TestContext): Promise<number> {
  await ctx.app.listen({ port: 0, host: '127.0.0.1' });
  return (ctx.app.server.address() as AddressInfo).port;
}

/** A request head with the session's cookie and CSRF header, ending in the blank line. */
function head(path: string, session: Session, lines: string[]): string {
  const auth = Object.entries(session.headers).map(([name, value]) => `${name}: ${value}`);
  return [`PUT /api/v0${path} HTTP/1.1`, 'Host: 127.0.0.1', ...auth, ...lines, '', ''].join('\r\n');
}

/** Writes `body` once the server sent `100 Continue`; done on the final answer's body. */
function afterContinue(body: Buffer | Buffer[], end: string) {
  let sent = false;
  return {
    onData: (text: string, socket: Socket) => {
      if (sent || !text.includes('100 Continue\r\n\r\n')) return;
      sent = true;
      for (const part of Array.isArray(body) ? body : [body]) socket.write(part);
    },
    done: (text: string) => text.includes(end),
    sent: () => sent,
  };
}

const kevFile = (ids: string[]): Buffer =>
  Buffer.from(
    JSON.stringify({
      catalogVersion: '2026.10.30',
      dateReleased: '2026-10-30T14:22:10.123Z',
      vulnerabilities: ids.map((cveID) => ({
        cveID,
        dateAdded: '2026-02-03',
        knownRansomwareCampaignUse: 'Unknown',
      })),
    }),
  );

/** Waits until `done()`, for at most 5 s. */
async function until(done: () => boolean | Promise<boolean>): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (!(await done())) {
    if (Date.now() > deadline) throw new Error('timed out waiting');
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

/** One chunk of a `Transfer-Encoding: chunked` body. */
const chunk = (data: Buffer): Buffer =>
  Buffer.concat([Buffer.from(`${data.length.toString(16)}\r\n`), data, Buffer.from('\r\n')]);

/**
 * The vulnerability database uploads over a real socket (D11-15): `app.inject` sends no
 * `100 Continue`, so only a socket shows that a refusal never asks for the body.
 */
describe('vulnerability database uploads over a real socket', () => {
  let ctx: TestContext;
  let port: number;
  let admin: Session;
  let orgAdmin: Session;
  /** The status of every answer to a Trivy upload, sent or not (the client may be gone). */
  const answered: number[] = [];

  beforeAll(async () => {
    ctx = await createTestContext({
      beforeReady: (app) => {
        app.addHook('onSend', async (request, reply, payload) => {
          if (request.url.endsWith('/system/vulnerability-db/file'))
            answered.push(reply.statusCode);
          return payload;
        });
      },
    });
    [admin, orgAdmin] = await sessions(ctx, 'vulndb-socket-org-admin');
    port = await listen(ctx);
  });
  afterAll(async () => {
    await ctx.close();
  });

  describe('PUT /system/vulnerability-db/file', () => {
    const lines = (length: number) => [
      'Content-Type: application/gzip',
      `Content-Length: ${length}`,
      'Expect: 100-continue',
    ];

    it('refuses a non-admin without 100 Continue', async () => {
      const text = await rawExchange(
        port,
        head('/system/vulnerability-db/file', orgAdmin, lines(MiB)),
        {
          done: (received) => received.includes('"code"'),
        },
      );
      expect(text.startsWith('HTTP/1.1 403 '), text).toBe(true);
      expect(text).not.toContain('100 Continue');
    });

    it('sends 100 Continue to an admin, then stores the database', async () => {
      const archive = trivyArchive();
      const exchange = afterContinue(archive, '"officialRepository"');
      const text = await rawExchange(
        port,
        head('/system/vulnerability-db/file', admin, lines(archive.length)),
        exchange,
      );
      expect(exchange.sent()).toBe(true);
      expect(text).toMatch(/^HTTP\/1\.1 100 Continue\r\n\r\nHTTP\/1\.1 200 /);
    });

    it('answers no 422 to an upload the client aborted', async () => {
      await ctx.db.delete(vulndbDatasets);
      const before = answered.length;
      const logsBefore = ctx.logs.length;
      // Half of the declared megabyte, then the client hangs up.
      await new Promise<void>((resolve) => {
        const socket = net.createConnection({ host: '127.0.0.1', port }, () => {
          socket.write(
            head('/system/vulnerability-db/file', admin, [
              'Content-Type: application/gzip',
              `Content-Length: ${MiB}`,
            ]),
          );
          socket.write(Buffer.alloc(MiB / 2, 1), () => setTimeout(() => socket.destroy(), 100));
        });
        socket.on('error', () => {});
        socket.on('close', () => resolve());
      });
      await until(() => answered.length > before);
      const logged = ctx.logs.slice(logsBefore).join('\n');
      expect(logged).not.toContain('INVALID_DATABASE');
      expect(logged).not.toContain('"statusCode":422');
      expect(logged).not.toContain('request errored');
      expect(await ctx.db.select().from(vulndbDatasets)).toHaveLength(0);
      // Nobody reads it, but the answer is the abort's, not a bad file's.
      expect(answered.at(-1)).toBe(499);
    });

    // Here, not with inject: the response, not the request, tells an abort from an expiry. A
    // server's request is destroyed after any full read, so this 422 would read as an abort (499).
    it('answers 422 to an upload that expired while it was sent, not 499', async () => {
      await ctx.db.delete(vulndbDatasets);
      const archive = trivyArchive();
      const half = Math.floor(archive.length / 2);
      let text = '';
      const socket = net.createConnection({ host: '127.0.0.1', port });
      socket.on('data', (d: Buffer) => {
        text += d.toString('utf8');
      });
      socket.on('error', () => {});
      try {
        await new Promise<void>((resolve) => socket.once('connect', resolve));
        socket.write(
          head('/system/vulnerability-db/file', admin, [
            'Content-Type: application/gzip',
            `Content-Length: ${archive.length}`,
          ]),
        );
        socket.write(archive.subarray(0, half));
        // The store's row exists before it reads a byte; a prune of an hour-old upload deletes it.
        let incomplete: { id: string }[] = [];
        await until(async () => {
          incomplete = await ctx.db
            .select({ id: vulndbDatasets.id })
            .from(vulndbDatasets)
            .where(eq(vulndbDatasets.status, 'incomplete'));
          return incomplete.length > 0;
        });
        await ctx.db.delete(vulndbDatasets).where(eq(vulndbDatasets.id, incomplete[0]!.id));
        socket.write(archive.subarray(half));
        await until(() => text.includes('"code"'));
      } finally {
        socket.destroy();
      }
      expect(text.startsWith('HTTP/1.1 422 '), text).toBe(true);
      expect(text).toContain('"code":"INVALID_DATABASE"');
      expect(text).toContain(
        'The upload expired before it was stored, because it took too long. Upload the file again',
      );
      expect(await ctx.db.select().from(vulndbDatasets)).toHaveLength(0);
    });

    // Here, not with inject: the store stops reading the request early, and light-my-request's
    // request then fails the whole inject (a server's request only stops).
    it('answers 413 to a file sent chunked past the limit and keeps no dataset', async () => {
      const small = await createTestContext({
        config: {
          vulndb: {
            dir: '/var/cache/qualor/vulndb',
            trivyPath: '/usr/local/bin/trivy',
            internalHosts: new Set(),
            uploadMaxBytes: 64,
            maxDownloads: 4,
          },
        },
      });
      try {
        const smallAdmin = await login(small, 'admin', ADMIN_PASSWORD);
        const smallPort = await listen(small);
        // No Content-Length to refuse up front: 80 bytes in two chunks.
        const body = [chunk(Buffer.alloc(40, 'a')), chunk(Buffer.alloc(40, 'a')), '0\r\n\r\n'];
        const text = await rawExchange(
          smallPort,
          head('/system/vulnerability-db/file', smallAdmin, [
            'Content-Type: application/gzip',
            'Transfer-Encoding: chunked',
          ]) + body.join(''),
          { done: (received) => received.includes('"code"') },
        );
        expect(text.startsWith('HTTP/1.1 413 '), text).toBe(true);
        expect(text).toContain('"code":"TOO_LARGE"');
        expect(await small.db.select().from(vulndbDatasets)).toHaveLength(0);
      } finally {
        await small.close();
      }
    });
  });

  describe('PUT /system/vulnerability-db/file/kev', () => {
    let licensed: TestContext;
    let licensedPort: number;
    let licensedAdmin: Session;
    let licensedOrgAdmin: Session;
    const lines = (extra: string[]) => [
      'Content-Type: application/octet-stream',
      ...extra,
      'Expect: 100-continue',
    ];

    beforeAll(async () => {
      licensed = await rbacContext({
        now: () => new Date('2027-01-01T00:00:00Z'),
        edition: (edition) => ({
          ...edition,
          limits: () => ({
            ...edition.limits(),
            vulnerabilities: { ...edition.limits().vulnerabilities, priority: true },
          }),
        }),
      });
      [licensedAdmin, licensedOrgAdmin] = await sessions(licensed, 'kev-socket-org-admin');
      licensedPort = await listen(licensed);
    });
    beforeEach(async () => {
      await licensed.db.delete(vulnerabilityKev);
      await licensed.db
        .delete(instanceSettings)
        .where(eq(instanceSettings.key, 'vulndb_priority_state'));
    });
    afterAll(async () => {
      await licensed.close();
    });

    it('refuses a non-admin without 100 Continue', async () => {
      const text = await rawExchange(
        licensedPort,
        head(
          '/system/vulnerability-db/file/kev',
          licensedOrgAdmin,
          lines([`Content-Length: ${MiB}`]),
        ),
        { done: (received) => received.includes('"code"') },
      );
      expect(text.startsWith('HTTP/1.1 403 '), text).toBe(true);
      expect(text).not.toContain('100 Continue');
    });

    it('sends 100 Continue to an admin, then stores the catalog', async () => {
      const body = kevFile(['CVE-2024-0001']);
      const exchange = afterContinue(body, '"officialRepository"');
      const text = await rawExchange(
        licensedPort,
        head(
          '/system/vulnerability-db/file/kev',
          licensedAdmin,
          lines([`Content-Length: ${body.length}`]),
        ),
        exchange,
      );
      expect(exchange.sent()).toBe(true);
      expect(text).toMatch(/^HTTP\/1\.1 100 Continue\r\n\r\nHTTP\/1\.1 200 /);
      expect(await licensed.db.select().from(vulnerabilityKev)).toHaveLength(1);
    });

    // D11-14. Chunked, so there is no length to refuse up front: the route counts the bytes as they
    // come. The overrun is the last byte, sent with the body's end once the server has read the
    // rest, so the request is complete when the route stops reading. Stopping earlier leaves it
    // unread, and Node destroys the socket with it: the client then gets no answer at all.
    it('answers 413 to a KEV file sent chunked past 32 MiB and stores nothing', async () => {
      let accepted: Socket | undefined;
      licensed.app.server.once('connection', (s: Socket) => {
        accepted = s;
      });
      let text = '';
      const socket = net.createConnection({ host: '127.0.0.1', port: licensedPort });
      socket.on('data', (d: Buffer) => {
        text += d.toString('utf8');
      });
      socket.on('error', () => {});
      try {
        await new Promise<void>((resolve) => socket.once('connect', resolve));
        const start = head('/system/vulnerability-db/file/kev', licensedAdmin, [
          'Content-Type: application/octet-stream',
          'Transfer-Encoding: chunked',
        ]);
        const piece = chunk(Buffer.alloc(MiB, 0x20));
        socket.write(start);
        for (let i = 0; i < 32; i++) socket.write(piece);
        const sent = Buffer.byteLength(start) + 32 * piece.length;
        await until(() => accepted?.bytesRead === sent);
        socket.write(Buffer.concat([chunk(Buffer.from('x')), Buffer.from('0\r\n\r\n')]));
        await until(() => text.includes('"code"'));
      } finally {
        socket.destroy();
      }
      expect(text.startsWith('HTTP/1.1 413 '), text.slice(0, 200)).toBe(true);
      expect(text).toContain('"code":"TOO_LARGE"');
      expect(text).toContain('The file is larger than 33554432 bytes');
      expect(await licensed.db.select().from(vulnerabilityKev)).toHaveLength(0);
    });

    it('stores a KEV file sent chunked after 100 Continue, as a proxy sends it', async () => {
      const body = kevFile(['CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0003']);
      const third = Math.ceil(body.length / 3);
      const parts = [0, 1, 2].map((i) => chunk(body.subarray(i * third, (i + 1) * third)));
      const uploadsBefore = (await auditRows(licensed)).filter(
        (e) => e.action === 'vulndb.file_uploaded',
      ).length;
      const exchange = afterContinue([...parts, Buffer.from('0\r\n\r\n')], '"officialRepository"');
      const text = await rawExchange(
        licensedPort,
        head(
          '/system/vulnerability-db/file/kev',
          licensedAdmin,
          lines(['Transfer-Encoding: chunked']),
        ),
        exchange,
      );
      expect(exchange.sent()).toBe(true);
      expect(text).toMatch(/^HTTP\/1\.1 100 Continue\r\n\r\nHTTP\/1\.1 200 /);
      expect(await licensed.db.select().from(vulnerabilityKev)).toHaveLength(3);
      const uploads = (await auditRows(licensed)).filter(
        (e) => e.action === 'vulndb.file_uploaded',
      );
      expect(uploads).toHaveLength(uploadsBefore + 1);
      expect(uploads.at(-1)?.details).toMatchObject({ dataset: 'kev', sizeBytes: body.length });
    });
  });
});
