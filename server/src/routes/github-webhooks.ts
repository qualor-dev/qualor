import { and, eq } from 'drizzle-orm';
import type { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { LoginThrottle } from '../auth/throttle';
import { encryptionKey } from '../crypto/secrets';
import { analyses, branches, projects, scmConnections } from '../db/schema';
import { notFound, ProblemError } from '../http/problem';
import { readLlmSettings } from '../llm/settings';
import { queueScan } from '../review/reply-queue';
import { reviewActive } from '../review/settings';
import { readScmContext } from '../scm/context';
import { verifyWebhookSignature } from '../scm/github/app-auth';
import { decryptWebhookSecret } from '../scm/github/credentials';
import { parseCheckRunExternalId } from '../scm/github/render';
import { enqueueDecoration } from '../scm/queue';
import {
  DeliveryIds,
  header,
  jsonBufferParser,
  UUID,
  WEBHOOK_BODY_LIMIT,
} from './inbound-webhooks';

const EVENT = /^[a-z_]{1,64}$/;

const checkRunEvent = z.looseObject({
  action: z.string().max(64),
  check_run: z.looseObject({
    external_id: z.string().max(200).nullable(),
    app: z.looseObject({ id: z.number().int() }).nullable(),
  }),
  repository: z.looseObject({ id: z.number().int() }),
});

/** The events of a new comment on a pull request: a reply in a review thread, and a note on its page. */
const COMMENT_EVENTS: ReadonlySet<string> = new Set([
  'pull_request_review_comment',
  'issue_comment',
]);

/**
 * What is read of the two comment events: the repository and the pull request a comment is on, and
 * who wrote it, never the comment itself. A payload that does not fit, a comment without an author
 * included, is none (fail closed: the next scan or decoration finds the comment all the same).
 */
const commentAuthor = z.looseObject({ user: z.looseObject({ type: z.string().max(64) }) });
const reviewCommentEvent = z.looseObject({
  action: z.string().max(64),
  comment: commentAuthor,
  pull_request: z.looseObject({ number: z.number().int() }),
  repository: z.looseObject({ id: z.number().int() }),
});
const issueCommentEvent = z.looseObject({
  action: z.string().max(64),
  comment: commentAuthor,
  // GitHub gives a pull request's comments as an issue's: only a pull request's issue has this.
  issue: z.looseObject({ number: z.number().int(), pull_request: z.looseObject({}).optional() }),
  repository: z.looseObject({ id: z.number().int() }),
});

/**
 * github.md §9: the App's webhook. Public; everything is decided by the signature. It acts on the
 * Re-run button of Qualor's check run (`check_run`) and on a person's new comment on a pull request
 * (the two comment events: a reply in a review thread, a note on the pull request's page), which
 * queues a scan of the pull request's notes so that Qualor answers it at once (6I-4). Any other
 * event is acknowledged unread.
 */
export const githubWebhookRoutes: FastifyPluginAsync<{ deps: RouteDeps }> = async (
  app,
  { deps },
) => {
  const key = encryptionKey(deps.config.secretKey);
  const failures = new LoginThrottle({ max: 60, windowMs: 60_000 });
  const deliveries = new DeliveryIds();
  const missing = () => notFound('GitHub webhook');

  // The raw bytes: the signature is over the body exactly as sent (github.md §9).
  jsonBufferParser(app);

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
        row?.provider === 'github' ? decryptWebhookSecret(key, row.webhookSecretEnc) : null; // provider-guard: this route serves only its own provider
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
      // Only check_run and the two comment events are read (github.md §9); any other event is
      // acknowledged unread.
      if (event !== 'check_run' && !COMMENT_EVENTS.has(event)) return reply.code(204).send();
      let payload: unknown;
      try {
        payload = JSON.parse(body.toString('utf8'));
      } catch {
        throw new ProblemError(400, 'BAD_REQUEST', 'The body is not JSON');
      }
      // A delivery id is kept per connection: another connection's App is another delivery.
      const remembered = `${row.id}:${delivery}`;
      if (!deliveries.remember(remembered)) return reply.code(204).send();
      try {
        if (event === 'check_run') await rerequested(deps, row.id, row.appId, payload);
        else await queueScans(deps, row.id, event, payload);
      } catch (err) {
        // Not processed: GitHub's redelivery of this id must not be taken for a repeat.
        deliveries.forget(remembered);
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
    if (stored.kind !== 'ok' || stored.context.provider !== 'github') return; // provider-guard: this route serves only its own provider
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

/**
 * The pull request that a person's new comment is on, as `repositoryId` and `number`; null for
 * anything that calls for no scan: a payload that does not fit, an action other than `created` (an
 * edit or a deletion adds no note), a comment on an issue, and a comment by a Bot. Qualor's own
 * answers are notes by a Bot, and detection answers people only: each answer would start a scan that
 * finds nothing. The payload is signed, so the account type can be believed, and a comment skipped
 * wrongly is only found by the next scan or decoration.
 */
function commentOn(
  event: string,
  payload: unknown,
): { repositoryId: string; number: string } | null {
  if (event === 'issue_comment') {
    const parsed = issueCommentEvent.safeParse(payload);
    if (!parsed.success) return null;
    const { action, comment, issue, repository } = parsed.data;
    if (action !== 'created' || comment.user.type === 'Bot') return null;
    if (issue.pull_request === undefined) return null;
    return { repositoryId: String(repository.id), number: String(issue.number) };
  }
  const parsed = reviewCommentEvent.safeParse(payload);
  if (!parsed.success) return null;
  const { action, comment, pull_request: pull, repository } = parsed.data;
  if (action !== 'created' || comment.user.type === 'Bot') return null;
  return { repositoryId: String(repository.id), number: String(pull.number) };
}

/**
 * Queues a scan (review/reply-scan.ts) of the pull request that a person's new comment is on, so
 * that a reply in one of Qualor's threads, or a `qualor review`, is answered at once rather than at
 * the next analysis. One for each project mapped to this connection that has analysed that pull
 * request in the repository the event names, and has AI review active now. The payload is only a
 * pointer: the comment's words and its id are never read, and the scan reads the notes through the
 * API. The repository is told by the id that the pull request's newest analysis stored, which a
 * repository keeps when it is renamed or transferred (its name does not stay): an analysis without
 * it, as an older scanner made, queues nothing (fail closed, as a re-run does). At most one scan
 * waits for a pull request (`queueScan`). Anything else does nothing.
 */
async function queueScans(
  deps: RouteDeps,
  connectionId: string,
  event: string,
  payload: unknown,
): Promise<void> {
  const comment = commentOn(event, payload);
  if (comment === null) return;
  const found = await deps.db
    .select({
      branchId: branches.id,
      scmContext: analyses.scmContext,
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
        eq(branches.name, comment.number),
      ),
    )
    .innerJoin(analyses, eq(analyses.id, branches.lastAnalysisId))
    .where(eq(projects.scmConnectionId, connectionId));
  const own = found.filter(({ scmContext }) => {
    const stored = readScmContext(scmContext);
    return (
      stored.kind === 'ok' &&
      stored.context.provider === 'github' && // provider-guard: this route serves only its own provider
      stored.context.github?.repositoryId === comment.repositoryId
    );
  });
  if (own.length === 0) return;
  const settings = await readLlmSettings(deps.db);
  for (const { branchId, project } of own) {
    if (reviewActive(settings, project).active) await queueScan(deps.db, branchId);
  }
}
