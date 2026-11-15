// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import type { FastifyPluginAsync } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { PluginContext } from '@qualor/server/plugin-contract';

/**
 * 4E-3b §4: the bundle in flight on this instance, by its own token (null when none). One at a
 * time: collecting reads the database and the archive is up to 20 MiB.
 */
let inFlight: symbol | null = null;

/** The only file names the content-disposition header carries: no quote, slash or line break. */
const SAFE_FILE_NAME = /^[\w.-]+$/;

/**
 * 4E-3b §4: the support bundle download, feature `support-bundle`. Core's `ctx.support` checks
 * the caller (an instance admin), collects the archive and records the audit event; this route
 * holds the slot and sends the stream.
 */
export function supportRoutes(ctx: PluginContext): FastifyPluginAsync {
  return async (plain) => {
    const app = plain.withTypeProvider<ZodTypeProvider>();

    app.get(
      '/support/bundle',
      {
        config: {
          openapi: {
            problems: [429],
            problemDescriptions: {
              403: 'FEATURE_NOT_LICENSED: the feature is not licensed; instance administrators only',
              429: 'A support bundle is already being prepared on this instance (RATE_LIMITED)',
            },
          },
        },
        schema: {
          tags: ['enterprise'],
          summary:
            'Download the support bundle: one zip with versions, configuration without secrets, health, queues, recent failures and recent server logs',
          response: {
            200: {
              description:
                'The archive, as an attachment named qualor-support-<yyyymmdd-hhmmss>.zip (at most 20 MiB)',
              content: { 'application/zip': { schema: z.string() } },
            },
          },
        },
      },
      async (request, reply) => {
        if (inFlight !== null) {
          throw ctx.access.problem(
            429,
            'RATE_LIMITED',
            'A support bundle is already being prepared',
          );
        }
        const token = Symbol('support-bundle');
        inFlight = token;
        // Frees only this bundle's slot: a late 'close' never frees the next one.
        const release = () => {
          if (inFlight === token) inFlight = null;
        };
        let streaming = false;
        try {
          const { fileName, stream } = await ctx.support.bundle(request);
          // Defence in depth: core names the file, and only a plain name goes into the header.
          if (!SAFE_FILE_NAME.test(fileName)) {
            stream.destroy();
            throw ctx.access.problem(
              500,
              'INTERNAL_ERROR',
              'The support bundle has an unexpected file name',
            );
          }
          if (request.raw.destroyed || reply.raw.destroyed) {
            stream.destroy();
            throw ctx.access.problem(499, 'CLIENT_ABORTED', 'The client closed the connection');
          }
          streaming = true;
          // Attached with no await before the send: a client that goes away before the stream
          // is ever read frees the slot too. The stream's own end frees it as well.
          reply.raw.once('close', () => {
            stream.destroy();
            release();
          });
          stream.once('close', release);
          return reply
            .header('cache-control', 'no-store')
            .header('content-disposition', `attachment; filename="${fileName}"`)
            .header('content-type', 'application/zip')
            .send(stream as unknown as string);
        } finally {
          if (!streaming) release();
        }
      },
    );
  };
}
