import { Readable } from 'node:stream';
import { and, desc, eq } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { requirePrincipal } from '../auth/access';
import { isDemoUser } from '../auth/demo';
import type { Principal } from '../auth/principal';
import { vulndbDatasets } from '../db/schema';
import { UploadSlots } from '../ingest/upload';
import { notFound, ProblemError } from '../http/problem';
import { isoOrNull } from '../http/schemas';
import { readVulndbSettings, VULNDB_SCANNER_POLICIES } from '../vulndb/settings';
import { readVulndbState } from '../vulndb/state';
import { currentDataset, readDatasetChunks } from '../vulndb/store';

const SHA256_HEX = /^[0-9a-f]{64}$/;
/** Seconds a scanner waits before it asks again when the gate is full. */
const RETRY_AFTER_SECONDS = 5;

/** Seconds-scale knob: a download that takes no bytes for this long is cut off (tests shorten it). */
export const downloadTimeouts = { stallMs: 60_000 };

/**
 * 0.15 plan 3: what a scanner needs to take the Trivy database from this server. Any token may
 * read it (P2): the database is public advisory data.
 */
export const scannerVulndbRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (
  app,
  { deps },
) => {
  // P7: one gate per app on the archives sent at once (QUALOR_VULNDB_MAX_DOWNLOADS).
  const slots = new UploadSlots(deps.config.vulndb.maxDownloads, {
    code: 'DOWNLOADS_BUSY',
    title: 'Too many concurrent database downloads; retry shortly',
    retryAfter: RETRY_AFTER_SECONDS,
  });

  /**
   * The public demo account (QUALOR_DEMO_USER) is offered no database: anyone may sign in as it,
   * and an archive is over 100 MiB.
   */
  const isDemo = (principal: Principal): boolean =>
    principal.kind !== 'project' && isDemoUser(deps.config.demoUser, principal.user);

  /** The database this server serves, or null when it serves none. */
  async function served() {
    const settings = await readVulndbSettings(deps.db);
    if (!settings.enabled || !settings.scanners.enabled) return null;
    const current = await currentDataset(deps.db, await readVulndbState(deps.db));
    if (current === null || current.status !== 'ready') return null;
    return { policy: settings.scanners.policy, current };
  }

  app.get(
    '/scanner/vulnerability-db',
    {
      schema: {
        tags: ['scanner'],
        summary: 'The vulnerability database this server offers scanners',
        response: {
          200: z.object({
            serve: z.boolean().describe('False: the scanner uses the database in its image'),
            policy: z.enum(VULNDB_SCANNER_POLICIES),
            current: z
              .object({
                digest: z.string(),
                sizeBytes: z.number().int(),
                builtAt: z.string().nullable(),
              })
              .nullable(),
            accepted: z
              .array(z.string())
              .describe('The digests of the archives the server serves, current first'),
          }),
        },
      },
    },
    async (request) => {
      const offer = isDemo(requirePrincipal(request)) ? null : await served();
      if (offer === null) {
        const { scanners } = await readVulndbSettings(deps.db);
        return { serve: false, policy: scanners.policy, current: null, accepted: [] };
      }
      const { current } = offer;
      const ready = await deps.db
        .select({ digest: vulndbDatasets.digest })
        .from(vulndbDatasets)
        .where(and(eq(vulndbDatasets.kind, 'trivy'), eq(vulndbDatasets.status, 'ready')))
        .orderBy(desc(vulndbDatasets.createdAt));
      const accepted = [current.digest, ...ready.map((r) => r.digest)].filter(
        (digest, i, all) => all.indexOf(digest) === i,
      );
      return {
        serve: true,
        policy: offer.policy,
        current: {
          digest: current.digest,
          sizeBytes: current.sizeBytes,
          builtAt: isoOrNull(current.builtAt),
        },
        accepted,
      };
    },
  );

  app.get(
    '/scanner/vulnerability-db/:sha256',
    {
      schema: {
        tags: ['scanner'],
        summary: 'Download a vulnerability database archive by its sha256',
        params: z.object({
          sha256: z.string().describe('The archive digest: 64 lowercase hex characters'),
        }),
        response: {
          200: z
            .string()
            .meta({ format: 'binary' })
            .describe('The Trivy database archive (db.tar.gz)'),
        },
      },
    },
    async (request, reply) => {
      const principal = requirePrincipal(request);
      const { sha256 } = request.params;
      if (!SHA256_HEX.test(sha256)) {
        throw new ProblemError(400, 'BAD_REQUEST', 'The digest is not 64 lowercase hex characters');
      }
      const digest = `sha256:${sha256}`;
      if (isDemo(principal) || (await served()) === null) {
        throw notFound('Vulnerability database');
      }
      const [dataset] = await deps.db
        .select()
        .from(vulndbDatasets)
        .where(
          and(
            eq(vulndbDatasets.kind, 'trivy'),
            eq(vulndbDatasets.digest, digest),
            eq(vulndbDatasets.status, 'ready'),
          ),
        );
      if (dataset === undefined) throw notFound('Vulnerability database');

      // The scanner may have gone while the lookups ran: its 'close' has fired and a listener
      // added now would never run, so a slot taken now would never be freed.
      if (request.raw.destroyed || reply.raw.destroyed || reply.raw.writableEnded) {
        reply.hijack();
        return reply;
      }
      // Taken and hooked in one synchronous step, and freed exactly once on every path.
      slots.take();
      const datasetId = dataset.id;
      let released = false;
      let stall: NodeJS.Timeout | undefined;
      const release = (): void => {
        if (released) return;
        released = true;
        clearTimeout(stall);
        slots.release();
      };
      // A reader that takes no bytes for stallMs is cut off, and its slot freed.
      const arm = (): void => {
        clearTimeout(stall);
        stall = setTimeout(() => {
          stream.destroy();
          reply.raw.destroy();
          release();
        }, downloadTimeouts.stallMs);
        stall.unref();
      };
      // The stream pulls the next chunk only when the socket has taken the last: a pull is progress.
      async function* paced(): AsyncGenerator<Buffer, void, undefined> {
        for await (const chunk of readDatasetChunks(deps.db, datasetId)) {
          arm();
          yield chunk;
        }
      }
      const stream = Readable.from(paced());
      arm();
      stream.on('error', release);
      reply.raw.once('close', () => {
        stream.destroy();
        release();
      });
      request.log.info({ digest, principal: principal.kind }, 'vulndb archive download');
      return reply
        .header('content-type', 'application/gzip')
        .header('content-length', String(dataset.sizeBytes))
        .header('etag', `"${digest}"`)
        .send(stream as never);
    },
  );
};
