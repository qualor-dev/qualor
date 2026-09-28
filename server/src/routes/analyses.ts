import { Readable } from 'node:stream';
import { and, desc, eq, lt } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { accessOf, requirePrincipal, requireUser } from '../auth/access';
import { analyses, branches } from '../db/schema';
import { createQueuedAnalysis } from '../ingest/service';
import { readGzipUpload, reportTooLarge, type UploadedReport } from '../ingest/upload';
import { sendContinue } from '../http/expect-continue';
import { lingerBeforeClosing } from '../http/lingering-close';
import { decodeCursor, pageQuery, pageSchema, toPage } from '../http/pagination';
import { notFound, ProblemError } from '../http/problem';
import { idParams } from '../http/schemas';
import { analysisForPrincipal, projectForUpload, projectForUser } from '../projects/access';
import { PROJECT_KEY_PATTERN } from '../patterns';
import { analysisDto, analysisSchema } from '../analyses/dto';

export const REPORT_CONTENT_TYPE = 'application/vnd.qualor.report+json';

export const analysisRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (app, { deps }) => {
  // Hand the raw request stream to the handler; readGzipUpload enforces the limits.
  app.addContentTypeParser(REPORT_CONTENT_TYPE, (_request, payload, done) => {
    done(null, payload);
  });

  // S11: how many uploads currently hold a buffered compressed body — from just before it is
  // read to just after its analysis row and job are persisted. Scoped to this plugin's closure,
  // so it is per app instance (this function runs once per buildApp() call) rather than shared
  // global state.
  let activeUploads = 0;

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
      // S11/S12: every rejection here (pre-read: 401/403/404/415/413/503; post-read: 413/422) must
      // close the connection, or Node keeps the socket alive and — for a rejection that never
      // touched the body — drains and discards the whole declared Content-Length before the next
      // request on that socket can be parsed (observed: 200 MiB read after a 413 for a project the
      // caller can't see). But an immediate close is its own bug: if the client is still mid-write
      // when the socket is destroyed, the kernel still has unread bytes queued and the close
      // becomes a TCP RST — the client gets ECONNRESET and never sees this very response
      // (reproduced with a client still posting a large body). lingerBeforeClosing keeps
      // `Connection: close` but drains up to maxCompressedBytes (plus its own margin) or a short
      // deadline before actually tearing the socket down — see that module for why it measures
      // with socket.bytesRead rather than the request stream's own 'data' events.
      // Scoped to just this route: the GET routes below have no body to drain.
      preParsing: async (request, reply, payload) => {
        // Any other content type is parsed (buffered) by Fastify before the handler runs, so
        // holding back `100 Continue` would stall that parser; the handler rejects it with 415
        // afterwards, exactly as without Expect.
        const mime = request.headers['content-type']?.split(';')[0]?.trim().toLowerCase();
        if (mime !== REPORT_CONTENT_TYPE) sendContinue(request, reply);
        return payload;
      },
      onSend: async (request, reply, payload) => {
        if (reply.statusCode >= 400) {
          reply.header('connection', 'close');
          const socket = reply.raw.socket;
          // S15: linger even when `100 Continue` was never sent. A client that honours Expect
          // sends nothing and closes on the final answer (lingering then ends at once), but one
          // that stopped waiting (RFC 9110 lets it) may already be writing the body, and an
          // immediate close would turn that into a TCP RST that loses this response.
          if (socket) {
            lingerBeforeClosing(request.raw, socket, {
              maxBytes: deps.config.upload.maxCompressedBytes,
            });
          }
        }
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
      if (activeUploads >= deps.config.maxConcurrentUploads) {
        throw new ProblemError(503, 'UPLOADS_BUSY', 'Too many concurrent uploads; retry shortly', {
          headers: { 'retry-after': '1' },
        });
      }
      activeUploads += 1;
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
          uploadedByTokenId: principal.kind === 'session' ? null : principal.tokenId,
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
        activeUploads -= 1;
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
