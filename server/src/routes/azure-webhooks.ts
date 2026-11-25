import { and, eq, sql } from 'drizzle-orm';
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
import { markHookPasswordHeld } from '../scm/azure/connections';
import { decryptWebhookSecret } from '../scm/github/credentials';
import {
  DeliveryIds,
  header,
  jsonBufferParser,
  UUID,
  WEBHOOK_BODY_LIMIT,
} from './inbound-webhooks';

/*
 * Azure DevOps service hooks: a comment on a pull request, or an update of one, queues a scan of
 * that pull request's notes (review/reply-scan.ts), so that a reply in one of Qualor's threads is
 * answered at once. As with GitLab's webhook, the payload is only a pointer: the pull request it
 * names is the one scanned, and the comment's text and author are never read.
 *
 * Azure DevOps disables a subscription that keeps failing, so every delivery it really made is
 * answered 204 whatever Qualor makes of it: an event it does not read, a repository or pull request
 * it does not know, a replayed delivery, a project without AI review. An error is for a caller that
 * is not Azure DevOps (a wrong credential, an unknown connection), for a body that is no JSON, and
 * for Qualor's own failure.
 */

const COMMENT_EVENT = 'ms.vss-code.git-pullrequest-comment-event';
const UPDATED_EVENT = 'git.pullrequest.updated';
/** The user name of the Basic credential; the password is the connection's webhook secret. */
const BASIC_USER = 'qualor';
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

/** What is read of a delivery: the event, which pull request it is on, never the comment itself. */
const envelope = z.looseObject({
  id: z.string().optional(),
  eventType: z.string(),
  resource: z.looseObject({
    pullRequestId: z.number().int().optional(),
    repository: z.looseObject({ id: z.string() }).optional(),
    pullRequest: z
      .looseObject({
        pullRequestId: z.number().int(),
        repository: z.looseObject({ id: z.string() }),
      })
      .optional(),
  }),
});

/** The password of a `Basic <base64(qualor:password)>` header, or null for anything else. */
function basicPassword(authorization: string): string | null {
  const match = /^Basic +(\S+)$/i.exec(authorization);
  if (match?.[1] === undefined || !BASE64.test(match[1])) return null;
  const decoded = Buffer.from(match[1], 'base64').toString('utf8');
  const colon = decoded.indexOf(':');
  if (colon < 0 || decoded.slice(0, colon) !== BASIC_USER) return null;
  return decoded.slice(colon + 1);
}

/** The service hooks of an Azure DevOps connection. Public; everything is decided by the secret. */
export const azureWebhookRoutes: FastifyPluginAsync<{ deps: RouteDeps }> = async (
  app,
  { deps },
) => {
  const key = encryptionKey(deps.config.secretKey);
  const failures = new LoginThrottle({ max: 60, windowMs: 60_000 });
  const deliveries = new DeliveryIds();
  const missing = () => notFound('Azure DevOps webhook');

  jsonBufferParser(app);

  app.post<{ Params: { connectionId: string } }>(
    '/api/v0/azure-devops/webhooks/:connectionId',
    { config: { public: true }, bodyLimit: WEBHOOK_BODY_LIMIT, schema: { hide: true } },
    async (request, reply) => {
      const { connectionId } = request.params;
      if (!UUID.test(connectionId)) throw missing();
      const [row] = await deps.db
        .select()
        .from(scmConnections)
        .where(eq(scmConnections.id, connectionId));
      const secret =
        row?.provider === 'azure' ? decryptWebhookSecret(key, row.webhookSecretEnc) : null; // provider-guard: this route serves only its own provider
      if (!row || secret === null) throw missing();
      if (!Buffer.isBuffer(request.body)) {
        throw new ProblemError(415, 'UNSUPPORTED_MEDIA_TYPE', 'The body must be JSON');
      }
      const body = request.body;
      checkCredential(failures, request.ip, header(request.headers.authorization), secret);
      // The delivery proves that Azure DevOps holds this password (a subscription made by hand,
      // say): it is marked so, as a complete subscribe marks it. Not awaited, so it never delays
      // or fails the answer; a failure is logged without its text.
      if (row.webhookSecretEnc?.hooksPushed !== true) {
        markHookPasswordHeld(deps.db, row).catch(() => {
          request.log.warn(
            { connectionId: row.id },
            'could not mark the Azure DevOps hook password as held',
          );
        });
      }
      const payload = jsonBody(body);
      // Only a comment and an update are read; any other event, or a body of another shape, is
      // acknowledged unread.
      const parsed = envelope.safeParse(payload);
      if (parsed.success) await handleEvent(deps, deliveries, row.id, parsed.data);
      return reply.code(204).send();
    },
  );
};

type Envelope = z.infer<typeof envelope>;

/** Queues the scans an event asks for; any other event than a comment and an update is unread. */
async function handleEvent(
  deps: RouteDeps,
  deliveries: DeliveryIds,
  connectionId: string,
  event: Envelope,
): Promise<void> {
  if (event.eventType !== COMMENT_EVENT && event.eventType !== UPDATED_EVENT) return;
  // A delivery id is kept per connection: another connection's hook is another delivery.
  const remembered =
    event.id !== undefined && UUID.test(event.id) ? `${connectionId}:${event.id}` : null;
  if (remembered !== null && !deliveries.remember(remembered)) return;
  try {
    const { repositoryId, pullRequestId } = pullRequestOf(event);
    if (repositoryId !== undefined && pullRequestId !== undefined) {
      await queueScans(deps, connectionId, repositoryId, pullRequestId);
    }
  } catch (err) {
    // Not processed: the retry of this delivery must not be taken for a repeat.
    if (remembered !== null) deliveries.forget(remembered);
    throw err;
  }
}

/**
 * The delivery's basic-auth password must be the webhook secret. As with GitLab's webhook, only a
 * wrong credential is counted: one that counted every delivery would let someone who shares the
 * sender's address turn its deliveries into 429s.
 */
function checkCredential(
  failures: LoginThrottle,
  ip: string,
  authorization: string,
  secret: string,
): void {
  const password = basicPassword(authorization);
  if (password !== null && safeEqual(password, secret)) return;
  if (!failures.hit(ip)) {
    throw new ProblemError(429, 'RATE_LIMITED', 'Too many deliveries with a wrong credential', {
      headers: { 'retry-after': '60' },
    });
  }
  throw new ProblemError(
    401,
    'UNAUTHENTICATED',
    'The credential does not match the webhook secret',
  );
}

function jsonBody(body: Buffer): unknown {
  try {
    return JSON.parse(body.toString('utf8'));
  } catch {
    throw new ProblemError(400, 'BAD_REQUEST', 'The body is not JSON');
  }
}

/** The repository and pull request an event is on, each undefined when the event has none. */
function pullRequestOf(event: Envelope): {
  repositoryId: string | undefined;
  pullRequestId: number | undefined;
} {
  const { resource } = event;
  if (event.eventType === COMMENT_EVENT) {
    return {
      repositoryId: resource.pullRequest?.repository.id,
      pullRequestId: resource.pullRequest?.pullRequestId,
    };
  }
  return { repositoryId: resource.repository?.id, pullRequestId: resource.pullRequestId };
}

/**
 * Queues a scan for the pull request an event is on, for each Qualor project of this connection
 * that is mapped to its repository (by the repository's id, which Azure DevOps matches without
 * case: a monorepo has several) and has analysed that pull request, and has AI review active now.
 * At most one scan waits for a pull request (`queueScan`). Anything else does nothing.
 */
async function queueScans(
  deps: RouteDeps,
  connectionId: string,
  repositoryId: string,
  pullRequestId: number,
): Promise<void> {
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
        eq(branches.name, String(pullRequestId)),
      ),
    )
    .where(
      and(
        eq(projects.scmConnectionId, connectionId),
        sql`lower(${projects.scmProjectRef}) = lower(${repositoryId})`,
      ),
    );
  if (found.length === 0) return;
  const settings = await readLlmSettings(deps.db);
  for (const { branchId, project } of found) {
    if (reviewActive(settings, project).active) await queueScan(deps.db, branchId);
  }
}
