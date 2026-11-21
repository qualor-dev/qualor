import { and, eq, or, sql } from 'drizzle-orm';
import type { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { safeEqual } from '../auth/sessions';
import { LoginThrottle } from '../auth/throttle';
import { encryptionKey } from '../crypto/secrets';
import { branches, projects, scmConnections } from '../db/schema';
import { notFound, ProblemError } from '../http/problem';
import { readLlmSettings } from '../llm/settings';
import { queueScan } from '../review/reply-queue';
import { reviewActive } from '../review/settings';
import { decryptWebhookSecret } from '../scm/github/credentials';
import {
  DeliveryIds,
  header,
  jsonBufferParser,
  UUID,
  WEBHOOK_BODY_LIMIT,
} from './inbound-webhooks';

/*
 * GitLab's webhook (6I-4): a note on a merge request queues a scan of that merge request's notes
 * (review/reply-scan.ts), so that a reply in one of Qualor's threads, or a `qualor review`, is
 * answered at once rather than at the next analysis. The payload is only a pointer: the merge
 * request it names is the one scanned, and the note's text, its author and its id are never read.
 * The scan reads the notes through the API.
 *
 * GitLab counts any 4xx or 5xx answer, and a timeout, as a failure of the delivery: it backs off
 * a hook that fails four times in a row, and disables it for good after forty. So every delivery
 * GitLab really made is answered 204, whatever Qualor makes of it: an event it does not read, a
 * project or a merge request it does not know, a project without AI review, a payload it does not
 * understand. An error is for a caller that is not GitLab (a wrong token, an unknown connection),
 * for a body that is no JSON, and for Qualor's own failure.
 */

/** The event of a comment; a note on an issue or a commit comes with `noteable_type` of its own. */
const NOTE_EVENT = 'Note Hook';
/** What identifies one delivery across its retries: 1 to 128 characters of this set. */
const DELIVERY_KEY = /^[A-Za-z0-9._:-]{1,128}$/;

/** What is read of a note event: which merge request it is on, never the note itself. */
const noteEvent = z.looseObject({
  object_kind: z.literal('note'),
  object_attributes: z.looseObject({ noteable_type: z.literal('MergeRequest') }),
  project: z.looseObject({
    id: z.number().int(),
    path_with_namespace: z.string().max(2_048),
  }),
  merge_request: z.looseObject({ iid: z.number().int() }),
});

/**
 * The key that tells the retries of one delivery: `Idempotency-Key` (GitLab 17.4 and later), else
 * `webhook-id` (19.0 and later, which carries the same value). A value of another shape counts as
 * absent. GitLab's `X-Gitlab-Event-UUID` is documented per event, not per retry of a delivery, so
 * it is not used.
 */
function deliveryKey(headers: Record<string, string | string[] | undefined>): string | null {
  for (const name of ['idempotency-key', 'webhook-id']) {
    const value = header(headers[name]);
    if (DELIVERY_KEY.test(value)) return value;
  }
  return null;
}

/** The webhook of a GitLab connection. Public; everything is decided by the secret token. */
export const gitlabWebhookRoutes: FastifyPluginAsync<{ deps: RouteDeps }> = async (
  app,
  { deps },
) => {
  const key = encryptionKey(deps.config.secretKey);
  const failures = new LoginThrottle({ max: 60, windowMs: 60_000 });
  const deliveries = new DeliveryIds();
  const missing = () => notFound('GitLab webhook');

  jsonBufferParser(app);

  app.post<{ Params: { connectionId: string } }>(
    '/api/v0/gitlab/webhooks/:connectionId',
    { config: { public: true }, bodyLimit: WEBHOOK_BODY_LIMIT, schema: { hide: true } },
    async (request, reply) => {
      const { connectionId } = request.params;
      if (!UUID.test(connectionId)) throw missing();
      const [row] = await deps.db
        .select()
        .from(scmConnections)
        .where(eq(scmConnections.id, connectionId));
      const secret =
        row?.provider === 'gitlab' ? decryptWebhookSecret(key, row.webhookSecretEnc) : null; // provider-guard: this route serves only its own provider
      if (!row || secret === null) throw missing();
      if (!Buffer.isBuffer(request.body)) {
        throw new ProblemError(415, 'UNSUPPORTED_MEDIA_TYPE', 'The body must be JSON');
      }
      const body = request.body;
      if (!safeEqual(header(request.headers['x-gitlab-token']), secret)) {
        // As GitHub's webhook does, the throttle counts only the deliveries with a wrong token. One
        // that counted every delivery would let someone who shares GitLab's address turn GitLab's
        // own deliveries into 429s. What stops a guess is the secret: 16 characters at the least.
        if (!failures.hit(request.ip)) {
          throw new ProblemError(429, 'RATE_LIMITED', 'Too many deliveries with a wrong token', {
            headers: { 'retry-after': '60' },
          });
        }
        throw new ProblemError(
          401,
          'UNAUTHENTICATED',
          'The token does not match the webhook secret',
        );
      }
      // Only a note is read; any other event is acknowledged unread.
      if (header(request.headers['x-gitlab-event']) !== NOTE_EVENT) return reply.code(204).send();
      let payload: unknown;
      try {
        payload = JSON.parse(body.toString('utf8'));
      } catch {
        throw new ProblemError(400, 'BAD_REQUEST', 'The body is not JSON');
      }
      // A delivery id is kept per connection: another connection's hook is another delivery.
      const delivery = deliveryKey(request.headers);
      const remembered = delivery === null ? null : `${row.id}:${delivery}`;
      if (remembered !== null && !deliveries.remember(remembered)) {
        return reply.code(204).send();
      }
      try {
        await queueScans(deps, row.id, payload);
      } catch (err) {
        // Not processed: GitLab's retry of this delivery must not be taken for a repeat.
        if (remembered !== null) deliveries.forget(remembered);
        throw err;
      }
      return reply.code(204).send();
    },
  );
};

/**
 * Queues a scan for the merge request a note event is on, for each Qualor project of this
 * connection that is mapped to its GitLab project (by the project's id, or by its path, which GitLab
 * matches without case: a monorepo has several) and has analysed that merge request, and has AI
 * review active now. At most one scan waits for a merge request (`queueScan`). Anything else does
 * nothing.
 */
async function queueScans(deps: RouteDeps, connectionId: string, payload: unknown): Promise<void> {
  const parsed = noteEvent.safeParse(payload);
  if (!parsed.success) return;
  const { project, merge_request: mergeRequest } = parsed.data;
  const found = await deps.db
    .select({
      branchId: branches.id,
      project: {
        id: projects.id,
        organizationId: projects.organizationId,
        scmConnectionId: projects.scmConnectionId,
      },
    })
    .from(projects)
    .innerJoin(
      branches,
      and(
        eq(branches.projectId, projects.id),
        eq(branches.kind, 'merge_request'),
        eq(branches.name, String(mergeRequest.iid)),
      ),
    )
    .where(
      and(
        eq(projects.scmConnectionId, connectionId),
        or(
          eq(projects.scmProjectRef, String(project.id)),
          sql`lower(${projects.scmProjectRef}) = lower(${project.path_with_namespace})`,
        ),
      ),
    );
  if (found.length === 0) return;
  const settings = await readLlmSettings(deps.db);
  for (const { branchId, project: mapped } of found) {
    if (reviewActive(settings, mapped).active) await queueScan(deps.db, branchId);
  }
}
