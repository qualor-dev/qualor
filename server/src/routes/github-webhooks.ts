import { and, eq } from 'drizzle-orm';
import type { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { LoginThrottle } from '../auth/throttle';
import { encryptionKey } from '../crypto/secrets';
import { analyses, branches, projects, scmConnections } from '../db/schema';
import { notFound, ProblemError } from '../http/problem';
import { readScmContext } from '../scm/context';
import { verifyWebhookSignature } from '../scm/github/app-auth';
import { decryptWebhookSecret } from '../scm/github/credentials';
import { parseCheckRunExternalId } from '../scm/github/render';
import { enqueueDecoration } from '../scm/queue';

/** github.md §9: the events Qualor reads are a few KiB; GitHub caps payloads at 25 MB. */
export const WEBHOOK_BODY_LIMIT = 1024 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EVENT = /^[a-z_]{1,64}$/;
const DELIVERY_TTL_MS = 60 * 60_000;
const MAX_DELIVERIES = 10_000;

/** Delivery ids seen in the last hour by this process (github.md §9). */
export class DeliveryIds {
  readonly #seen = new Map<string, number>();

  constructor(private readonly now: () => number = Date.now) {}

  /** True the first time an id is seen within the hour. */
  remember(id: string): boolean {
    const t = this.now();
    const key = id.toLowerCase();
    const at = this.#seen.get(key);
    if (at !== undefined && t - at < DELIVERY_TTL_MS) return false;
    this.#seen.delete(key);
    while (this.#seen.size >= MAX_DELIVERIES) {
      const oldest = this.#seen.keys().next().value;
      if (oldest === undefined) break;
      this.#seen.delete(oldest);
    }
    this.#seen.set(key, t);
    return true;
  }

  /** Forgets an id whose processing failed, so GitHub's redelivery of it is processed. */
  forget(id: string): void {
    this.#seen.delete(id.toLowerCase());
  }
}

const checkRunEvent = z.looseObject({
  action: z.string().max(64),
  check_run: z.looseObject({
    external_id: z.string().max(200).nullable(),
    app: z.looseObject({ id: z.number().int() }).nullable(),
  }),
  repository: z.looseObject({ id: z.number().int() }),
});

const header = (value: string | string[] | undefined): string =>
  typeof value === 'string' ? value : '';

/** github.md §9: the App's webhook. Public; everything is decided by the signature. */
export const githubWebhookRoutes: FastifyPluginAsync<{ deps: RouteDeps }> = async (
  app,
  { deps },
) => {
  const key = encryptionKey(deps.config.secretKey);
  const failures = new LoginThrottle({ max: 60, windowMs: 60_000 });
  const deliveries = new DeliveryIds();
  const missing = () => notFound('GitHub webhook');

  // The raw bytes: the signature is over the body exactly as sent (github.md §9). Only JSON is
  // parsed, as a Buffer: the inherited parsers (text/plain gives a string) are removed in this
  // plugin's context, so any other type is a 415 before the handler runs.
  app.removeAllContentTypeParsers();
  app.addContentTypeParser(
    'application/json',
    { parseAs: 'buffer', bodyLimit: WEBHOOK_BODY_LIMIT },
    (_request, body, done) => done(null, body),
  );

  app.post<{ Params: { connectionId: string } }>(
    '/api/v0/github/webhooks/:connectionId',
    { config: { public: true }, bodyLimit: WEBHOOK_BODY_LIMIT, schema: { hide: true } },
    async (request, reply) => {
      const { connectionId } = request.params;
      if (!UUID.test(connectionId)) throw missing();
      const [row] = await deps.db
        .select()
        .from(scmConnections)
        .where(eq(scmConnections.id, connectionId));
      const secret =
        row?.provider === 'github' ? decryptWebhookSecret(key, row.webhookSecretEnc) : null;
      if (!row || row.appId === null || secret === null) throw missing();
      // Never the signature of an empty body in place of one that was not read as bytes.
      if (!Buffer.isBuffer(request.body)) {
        throw new ProblemError(415, 'UNSUPPORTED_MEDIA_TYPE', 'The body must be JSON');
      }
      const body = request.body;
      if (!verifyWebhookSignature(secret, body, header(request.headers['x-hub-signature-256']))) {
        if (!failures.hit(request.ip)) {
          throw new ProblemError(
            429,
            'RATE_LIMITED',
            'Too many deliveries with a wrong signature',
            {
              headers: { 'retry-after': '60' },
            },
          );
        }
        throw new ProblemError(
          401,
          'UNAUTHENTICATED',
          'The signature does not match the webhook secret',
        );
      }
      const event = header(request.headers['x-github-event']);
      const delivery = header(request.headers['x-github-delivery']);
      if (!EVENT.test(event) || !UUID.test(delivery)) {
        throw new ProblemError(400, 'BAD_REQUEST', 'Not a GitHub delivery');
      }
      // Only check_run is read (github.md §9); any other event is acknowledged unread.
      if (event !== 'check_run') return reply.code(204).send();
      let payload: unknown;
      try {
        payload = JSON.parse(body.toString('utf8'));
      } catch {
        throw new ProblemError(400, 'BAD_REQUEST', 'The body is not JSON');
      }
      if (!deliveries.remember(delivery)) return reply.code(204).send();
      try {
        await rerequested(deps, row.id, row.appId, payload);
      } catch (err) {
        // Not processed: GitHub's redelivery of this id must not be taken for a repeat.
        deliveries.forget(delivery);
        throw err;
      }
      return reply.code(204).send();
    },
  );
};

/**
 * github.md §9: the Re-run button of Qualor's own check run re-decorates its analysis, when that
 * analysis belongs to a project mapped to this connection, its repository matches, and it is still
 * its branch's latest. Bounded like a re-evaluation (G7). Anything else does nothing.
 */
async function rerequested(
  deps: RouteDeps,
  connectionId: string,
  appId: string,
  payload: unknown,
): Promise<void> {
  const parsed = checkRunEvent.safeParse(payload);
  if (!parsed.success || parsed.data.action !== 'rerequested') return;
  const { check_run: run, repository } = parsed.data;
  if (run.app === null || String(run.app.id) !== appId) return;
  const ids = parseCheckRunExternalId(run.external_id);
  if (ids === null) return;
  await deps.db.transaction(async (tx) => {
    const [found] = await tx
      .select({ analysis: analyses, branch: branches })
      .from(analyses)
      .innerJoin(branches, eq(branches.id, analyses.branchId))
      .innerJoin(projects, eq(projects.id, analyses.projectId))
      .where(and(eq(analyses.id, ids.analysisId), eq(projects.scmConnectionId, connectionId)));
    if (!found || found.branch.lastAnalysisId !== found.analysis.id) return;
    const stored = readScmContext(found.analysis.scmContext);
    if (stored.kind !== 'ok' || stored.context.provider !== 'github') return;
    // Ruling C1, as a re-evaluation (gates/reevaluate.ts): without the GitHub context (an older
    // CLI), or without the repository it came from, nothing is re-decorated (fail closed).
    const github = stored.context.github ?? null;
    if (github?.repositoryId === undefined || github.repositoryId !== String(repository.id)) {
      return;
    }
    await enqueueDecoration(tx, {
      analysisId: found.analysis.id,
      branchId: found.branch.id,
      gitlab: null,
      github,
      reevaluation: true,
    });
  });
}
