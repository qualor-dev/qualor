import { Readable } from 'node:stream';
import { and, desc, eq, lt } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { accessOf, requirePrincipal, requireUser } from '../auth/access';
import { analyses, branches } from '../db/schema';
import { createQueuedAnalysis } from '../ingest/service';
import {
  readGzipUpload,
  reportTooLarge,
  TransferSlots,
  type UploadedReport,
} from '../ingest/upload';
import { continueUnlessUpload, sendContinue } from '../http/expect-continue';
import { closeAfterRefusal } from '../http/lingering-close';
import { decodeCursor, pageQuery, pageSchema, toPage } from '../http/pagination';
import { notFound, ProblemError } from '../http/problem';
import { idParams } from '../http/schemas';
import { analysisForPrincipal, projectForUpload, projectForUser } from '../projects/access';
import { PROJECT_KEY_PATTERN } from '../patterns';
import { analysisDto, analysisSchema } from '../analyses/dto';

export const REPORT_CONTENT_TYPE = 'application/vnd.qualor.report+json';

export const analysisRoutes: FastifyPluginAsyncZod<{
  deps: RouteDeps;
  /** S11: the app's upload slots, shared with the review snapshot upload (routes/index.ts). */
  uploadSlots?: TransferSlots;
}> = async (app, { deps, uploadSlots }) => {
  // Hand the raw request stream to the handler; readGzipUpload enforces the limits.
  app.addContentTypeParser(REPORT_CONTENT_TYPE, (_request, payload, done) => {
    done(null, payload);
  });

  // S11: per app instance (this function runs once per buildApp() call), not global state.
  const slots = uploadSlots ?? new TransferSlots(deps.config.maxConcurrentUploads);

  app.post(
    '/analyses',
    {
      // `100 Continue` is written by the handler, only once every check below has passed.
      config: {
        deferContinue: true,
        openapi: {
          problems: [404, 413, 415, 503],
          requestBody: {
            required: true,
            description:
              'The scan report (report-format.md) as gzip-compressed JSON: at most maxCompressedBytes (default 50 MiB) as sent and maxDecompressedBytes (default 500 MiB) inflated.',
            content: {
              [REPORT_CONTENT_TYPE]: { schema: { type: 'string', format: 'binary' } },
            },
          },
          headers: [
            {
              in: 'header',
              name: 'Content-Encoding',
              required: true,
              schema: { type: 'string', enum: ['gzip'] },
            },
            {
              in: 'header',
              name: 'Expect',
              required: false,
              description:
                'Send `100-continue` to have every check (auth, project, encoding, declared length, upload slots) run before the body is sent.',
              schema: { type: 'string', enum: ['100-continue'] },
            },
          ],
        },
      },
      schema: {
        tags: ['analyses'],
        summary:
          'Upload a scan report (gzip body, Content-Type application/vnd.qualor.report+json, Content-Encoding gzip)',
        querystring: z.strictObject({ projectKey: z.string().regex(PROJECT_KEY_PATTERN) }),
        response: {
          202: z.object({
            analysisId: z.uuid(),
            status: z.literal('queued'),
            statusUrl: z.string(),
          }),
        },
      },
      // S11/S12/S15: every rejection here closes the connection without losing the answer
      // (closeAfterRefusal). Scoped to just this route: the GET routes below have no body to drain.
      preParsing: async (request, reply, payload) => {
        continueUnlessUpload(request, reply, REPORT_CONTENT_TYPE);
        return payload;
      },
      onSend: async (request, reply, payload) => {
        closeAfterRefusal(request, reply, deps.config.upload.maxCompressedBytes);
        return payload;
      },
    },
    async (request, reply) => {
      const principal = requirePrincipal(request);
      const project = await projectForUpload(accessOf(deps), principal, request.query.projectKey);
      // RFC 9110 §8.4: header values for a token like this one are compared case-insensitively.
      if (request.headers['content-encoding']?.toLowerCase() !== 'gzip') {
        throw new ProblemError(
          415,
          'UNSUPPORTED_ENCODING',
          'Reports must be sent with Content-Encoding: gzip',
        );
      }
      const declared = Number(request.headers['content-length']);
      if (Number.isFinite(declared) && declared > deps.config.upload.maxCompressedBytes) {
        throw reportTooLarge('compressed', deps.config.upload.maxCompressedBytes);
      }
      if (!(request.body instanceof Readable)) {
        throw new ProblemError(
          415,
          'UNSUPPORTED_MEDIA_TYPE',
          `Reports must be sent as ${REPORT_CONTENT_TYPE}`,
        );
      }
      // S11: bound concurrent uploads before touching the body at all.
      slots.take();
      try {
        sendContinue(request, reply);
        let upload: UploadedReport;
        try {
          upload = await readGzipUpload(request.body, deps.config.upload);
        } catch (err) {
          // S11 (minor): the client hanging up mid-upload is routine, not a server fault — quiet
          // log, and readGzipUpload already turned it into a non-500 ProblemError.
          if (err instanceof ProblemError && err.code === 'CLIENT_ABORTED') {
            request.log.debug({ err }, 'client aborted the report upload');
          }
          throw err;
        }
        const analysisId = await createQueuedAnalysis(deps.db, {
          projectId: project.id,
          uploadedByTokenId:
            principal.kind === 'personal' || principal.kind === 'project'
              ? principal.tokenId
              : null,
          body: upload.body,
        });
        return reply.code(202).send({
          analysisId,
          status: 'queued' as const,
          statusUrl: `/api/v0/analyses/${analysisId}`,
        });
      } finally {
        // S11 fix round 2: released only after the report row and job are persisted, so the
        // counter really bounds how many buffered compressed bodies exist at once — not just how
        // many are still being decompressed.
        slots.release();
      }
    },
  );

  app.get(
    '/analyses/:id',
    {
      schema: {
        tags: ['analyses'],
        summary: 'Analysis status (the CLI polls this)',
        params: idParams,
        response: { 200: analysisSchema },
      },
    },
    async (request, reply) => {
      const row = await analysisForPrincipal(
        accessOf(deps),
        requirePrincipal(request),
        request.params.id,
      );
      if (row.analysis.status === 'queued' || row.analysis.status === 'processing')
        reply.header('retry-after', '2');
      return analysisDto(row.analysis, row.branch);
    },
  );

  app.get(
    '/branches/:id/analyses',
    {
      schema: {
        tags: ['analyses'],
        summary: 'Analysis history of a branch, newest first',
        params: idParams,
        querystring: z.strictObject(pageQuery),
        response: { 200: pageSchema(analysisSchema) },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const [branch] = await deps.db
        .select()
        .from(branches)
        .where(eq(branches.id, request.params.id));
      if (!branch) throw notFound('Branch');
      await projectForUser(accessOf(deps), principal, branch.projectId, 'project.read');
      const before = decodeCursor(request.query.cursor);
      const rows = await deps.db
        .select()
        .from(analyses)
        .where(and(eq(analyses.branchId, branch.id), before ? lt(analyses.id, before) : undefined))
        .orderBy(desc(analyses.id))
        .limit(request.query.limit + 1);
      const page = toPage(rows, request.query.limit);
      return { items: page.items.map((a) => analysisDto(a, branch)), nextCursor: page.nextCursor };
    },
  );
};
