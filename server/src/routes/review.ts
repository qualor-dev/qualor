import { Readable } from 'node:stream';
import {
  MAX_SNAPSHOT_FILE_BYTES,
  MAX_SNAPSHOT_FILES,
  REVIEW_SNAPSHOT_CONTENT_TYPE,
} from '@qualor/shared';
import { eq } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { actorOf } from '../audit/recorder';
import { accessOf, requireOrganizationAccess, requirePrincipal, requireUser } from '../auth/access';
import { analyses, organizations } from '../db/schema';
import { retentionSettings } from '../housekeeping/run';
import { continueUnlessUpload, sendContinue } from '../http/expect-continue';
import { closeAfterRefusal } from '../http/lingering-close';
import { conflict, notFound, ProblemError, type FieldError } from '../http/problem';
import { idParams } from '../http/schemas';
import {
  readGzipUpload,
  UploadSlots,
  type UploadedReport,
  type UploadProblems,
} from '../ingest/upload';
import { lockLlmSettings } from '../llm/auto-fix-settings';
import { providerTestOf, readStoredTest, type StoredTest } from '../llm/last-test';
import {
  organizationSettings,
  projectOwners,
  readLlmSettings,
  writeLlmSettings,
  type StoredLlmSettings,
} from '../llm/settings';
import { PROJECT_KEY_PATTERN } from '../patterns';
import { projectForUpload } from '../projects/access';
import { queueSnapshotPurge } from '../review/jobs';
import {
  acknowledgesProvider,
  consentCurrent,
  dataSharingNotice,
  MAX_REVIEW_PROJECT_IDS,
  REVIEW_INACTIVE_REASONS,
  REVIEW_SCOPES,
  reviewActive,
  reviewBudgetsSchema,
  reviewConsentSchema,
  reviewProvider,
  reviewSettingsOf,
  sameReview,
  withOrganizationReview,
  type ReviewConsent,
  type ReviewSettings,
} from '../review/settings';
import { lastReviewedCommit } from '../review/runs';
import { hasSnapshot, snapshotExists, storeSnapshotUpload } from '../review/snapshot-store';
import { reviewUsageToday, type ReviewUsage } from '../review/usage';

/**
 * The project DTO's `aiReview` (6I-2): whether AI review is on for the project, whether its
 * organisation has it on, and why it does not run, so the project settings can name the reason and
 * who changes it.
 */
export const projectAiReviewSchema = z.object({
  /**
   * AI review is on for the project: the organisation has it on (a provider configured, the
   * organisation enabled for the AI assistant, review switched on with a consent that covers the
   * provider) and selects the project (the scope `all`, or the project listed), and does not
   * exclude it from the AI assistant. Whether the project is mapped to an SCM connection is not
   * part of it: `reason` says so (`not_mapped`), and so does `GET /projects/review-context`.
   */
  enabled: z.boolean().meta({
    description:
      'The project is chosen for AI review in an organisation where review is on, whatever its repository mapping',
  }),
  /** The organisation has AI review on, as above, whichever projects it selects. */
  organizationEnabled: z.boolean(),
  reason: z.enum(REVIEW_INACTIVE_REASONS).nullable().meta({
    description:
      "Why AI review does not run for the project: the first condition that fails, in the order the values are listed; null while it runs. no_provider: no AI provider is configured; organization_disabled: AI is not enabled for the organisation; review_disabled: the organisation has not switched AI review on; consent_outdated: the organisation's consent does not cover the provider configured now; project_not_selected: the organisation does not review this project; not_mapped: the project is not mapped to a repository",
  }),
});

/**
 * The consent as the organisation's answers show it: who acknowledged the notice, for which host
 * and model, and when. Not the provider's base URL: a gateway's path can hold a tenant or account
 * id, which organisation admins otherwise never see (`GET /organizations/{id}/ai` shows the host
 * only), and not its list of models (the answer's `provider` has them, and `consentCurrent` says
 * whether the consent covers them). The stored consent keeps both, and `consentCurrent` still
 * compares them.
 */
const consentAnswerSchema = reviewConsentSchema.omit({ providerUrl: true, models: true });
type ConsentAnswer = z.infer<typeof consentAnswerSchema>;

/**
 * The stored consent as answered, field by field: a field added to the record is not shown by
 * default.
 */
function consentAnswer(consent: ReviewConsent | null): ConsentAnswer | null {
  if (consent === null) return null;
  return {
    providerHost: consent.providerHost,
    model: consent.model,
    userId: consent.userId,
    at: consent.at,
  };
}

/** What the organisation's reviews have used since the UTC day began. */
const reviewUsageSchema = z.object({
  /** Tokens, input and output, of the day's review calls. */
  tokensToday: z.number().int(),
  /** The estimated cost of those calls; null while the instance sets no model prices. */
  costTodayUsd: z.number().nullable(),
  /** Reviews that began the day and spent, or were spending: not the ones skipped. */
  reviewsToday: z.number().int(),
});

/**
 * What the instance admin's last Test of the provider says of its models: whether they can call
 * tools, which AI review needs. Names models only, as `provider` does.
 */
const providerTestSchema = z
  .object({
    at: z.iso.datetime().nullable().meta({
      description:
        'When the Test ran; null while there is no Test of the provider as it is configured now',
    }),
    toolCalling: z.enum(['supported', 'not_supported', 'unknown']).meta({
      description:
        'supported: every model of the provider called the tool. not_supported: the models of modelsWithoutTools did not. unknown: the provider has not been tested since it changed (another address, model or setting, or the key set again), or the Test could not tell for one of its models',
    }),
    modelsWithoutTools: z.array(z.string()).meta({
      description: 'The models that did not call the tool in the Test, once each and sorted',
    }),
  })
  .meta({
    description:
      "From the instance admin's last Test of the provider (`POST /system/llm/test`): whether its models can call tools, which AI review needs",
  });

/** `GET`/`PUT /organizations/{id}/ai/review` (6I-2, spec C1, D4, R10). */
export const organizationReviewSchema = z.object({
  /** AI review can be switched on: a provider is configured and the organisation is enabled. */
  available: z.boolean(),
  unavailableReason: z.enum(['no_provider', 'organization_disabled']).nullable(),
  /**
   * The configured provider as the notice names it (its host includes the port); null without one.
   * `models` are every model it names, once each and sorted, the standard `model` among them.
   */
  provider: z
    .object({ host: z.string(), model: z.string(), models: z.array(z.string()) })
    .nullable(),
  /** The data-sharing warning to show to whoever switches review on, word for word; null without a provider. */
  notice: z.string().nullable(),
  enabled: z.boolean(),
  scope: z.enum(REVIEW_SCOPES),
  /** The projects of the scope `selected` (kept while the scope is `all`); deleted projects are left out. */
  projectIds: z.array(z.uuid()),
  /** The organisation's own budgets; the instance ceiling caps `tokensPerDay` when a review runs. */
  budgets: reviewBudgetsSchema,
  /** Who acknowledged the notice, for which provider host and model, and when; null before any. */
  consent: consentAnswerSchema.nullable(),
  /**
   * The consent names the configured provider (its base URL, host, model and models); false after
   * any of them changed (R10).
   */
  consentCurrent: z.boolean(),
  instanceCeiling: z.object({
    /** The most tokens per organisation per day the instance administrator allows; null: none. */
    tokensPerDay: z.number().int().nullable(),
  }),
  /** The use of the whole organisation today (UTC), against the budgets above. */
  usage: reviewUsageSchema,
  /** Whether the provider's models can call tools, so that switching AI review on can warn. */
  providerTest: providerTestSchema,
});
type OrganizationReview = z.infer<typeof organizationReviewSchema>;

/**
 * R10 (amended): the acknowledgement names the provider the admin was shown, the `provider` of the
 * GET answer, not just "yes": a provider switched between the GET and the PUT must not get a
 * consent nobody saw. It names the models the notice named too. A provider's models are at
 * most three.
 */
const acknowledgementSchema = z.strictObject({
  host: z.string().min(1).max(300),
  model: z.string().min(1).max(200),
  models: z
    .array(z.string().min(1).max(200))
    .min(1)
    .max(3)
    .optional()
    .meta({ description: 'Absent: the model alone' }),
});

const reviewBody = z.strictObject({
  enabled: z.boolean(),
  scope: z.enum(REVIEW_SCOPES),
  projectIds: z.array(z.uuid()).max(MAX_REVIEW_PROJECT_IDS),
  budgets: reviewBudgetsSchema,
  acknowledgeDataSharing: acknowledgementSchema.optional().meta({
    description:
      'The provider the notice named: the `provider` of the GET answer. Needed to switch review on from off, and while consentCurrent is false; ignored otherwise. Absent: 409 AI_REVIEW_CONSENT_REQUIRED. A host, model or set of models other than the provider configured now: 409 AI_REVIEW_PROVIDER_CHANGED (nothing is stored)',
  }),
});

const reviewContextSchema = z.object({
  /** The scanner should upload a repository snapshot of the merge request. */
  review: z.boolean(),
  /** Why not, when `review` is false. */
  reason: z.enum(REVIEW_INACTIVE_REASONS).nullable(),
  /** The head commit of this merge request the last review that was done covered; null before one. */
  lastReviewedCommit: z.string().nullable(),
  /** The snapshot limits this server accepts: the scanner stays within them. */
  limits: z.object({
    maxCompressedBytes: z.number().int(),
    maxDecompressedBytes: z.number().int(),
    maxFileBytes: z.number().int(),
    maxFiles: z.number().int(),
  }),
});

const FOREIGN_PROJECT_TEXT = 'Not a project of this organisation';

/**
 * 413 SNAPSHOT_TOO_LARGE: over a limit of `config.reviewSnapshot` (the review context answers both).
 */
function snapshotTooLarge(which: 'compressed' | 'decompressed', limit: number): ProblemError {
  return new ProblemError(413, 'SNAPSHOT_TOO_LARGE', 'The review snapshot is too large', {
    detail: `The ${which} snapshot exceeds ${limit} bytes`,
  });
}

/**
 * The refusals of the snapshot upload while it is read: the report's checks with the snapshot's
 * codes.
 */
const SNAPSHOT_UPLOAD_PROBLEMS: UploadProblems = {
  tooLarge: snapshotTooLarge,
  invalidGzip: (message) =>
    new ProblemError(422, 'SNAPSHOT_INVALID', 'The review snapshot is not a valid gzip stream', {
      errors: [{ path: 'body', message }],
    }),
};

/**
 * The day's use as the answer shows it. The cost is known only while the instance sets prices
 * (as `GET /organizations/{id}/ai` shows it).
 */
function usageAnswer(settings: StoredLlmSettings, spent: ReviewUsage): OrganizationReview['usage'] {
  return {
    tokensToday: spent.tokens,
    costTodayUsd: settings.pricing === null ? null : spent.costMicroUsd / 1e6,
    reviewsToday: spent.reviews,
  };
}

/** llm.md §3.3: each project once, in order; the id of a project deleted since is dropped. */
function ownProjectIds(
  ids: readonly string[],
  owners: ReadonlyMap<string, string>,
  organizationId: string,
): string[] {
  return [...new Set(ids)].filter((id) => owners.get(id) === organizationId).sort();
}

/** Why AI review cannot run for the organisation, or null when it can. */
export function reviewUnavailableReason(
  settings: StoredLlmSettings,
  organizationId: string,
): 'no_provider' | 'organization_disabled' | null {
  if (reviewProvider(settings) === null) return 'no_provider';
  return organizationSettings(settings, organizationId).enabled ? null : 'organization_disabled';
}

/**
 * The answer for the organisation: `projectIds` are those of its projects that still exist, and
 * `test` is the stored last Test of the provider, fresh or not.
 */
function organizationReview(
  settings: StoredLlmSettings,
  organizationId: string,
  retentionDays: number,
  projectIds: readonly string[],
  spent: ReviewUsage,
  test: StoredTest | null,
): OrganizationReview {
  const provider = reviewProvider(settings);
  const organization = organizationSettings(settings, organizationId);
  const unavailableReason = reviewUnavailableReason(settings, organizationId);
  const review = organization.review;
  return {
    available: unavailableReason === null,
    unavailableReason,
    provider:
      provider === null
        ? null
        : { host: provider.host, model: provider.model, models: provider.models },
    notice:
      provider === null ? null : dataSharingNotice(provider.host, provider.models, retentionDays),
    enabled: review.enabled,
    scope: review.scope,
    projectIds: [...projectIds],
    budgets: review.budgets,
    consent: consentAnswer(review.consent),
    consentCurrent: consentCurrent(settings, review),
    instanceCeiling: { tokensPerDay: settings.budgets.reviewTokensPerOrganizationPerDay },
    usage: usageAnswer(settings, spent),
    providerTest: providerTestOf(settings, test),
  };
}

/**
 * AI review (6I-2): an organisation admin switches it on for the organisation, acknowledging that
 * repository code goes to the instance's AI provider (D4, C1); the scanner asks whether to upload
 * a snapshot. The provider and the organisation's enablement stay the instance admin's
 * (`/system/llm`, llm.md §3.1).
 */
export const reviewRoutes: FastifyPluginAsyncZod<{
  deps: RouteDeps;
  /** S11: the app's upload slots, shared with the report upload (routes/index.ts). */
  uploadSlots?: UploadSlots;
}> = async (app, { deps, uploadSlots }) => {
  // The snapshot upload: the raw request stream goes to the handler, readGzipUpload bounds it.
  app.addContentTypeParser(REVIEW_SNAPSHOT_CONTENT_TYPE, (_request, payload, done) => {
    done(null, payload);
  });
  const slots = uploadSlots ?? new UploadSlots(deps.config.maxConcurrentUploads);

  app.get(
    '/organizations/:id/ai/review',
    {
      schema: {
        tags: ['ai'],
        summary:
          "The organisation's AI review settings and the data-sharing notice (org.ai.manage); `available` is false without a provider or an organization that may use AI",
        params: idParams,
        response: { 200: organizationReviewSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const organizationId = request.params.id;
      await requireOrganizationAccess(accessOf(deps), principal, organizationId, 'org.ai.manage');
      const [settings, retention, spent, test] = await Promise.all([
        readLlmSettings(deps.db),
        retentionSettings(deps.db),
        reviewUsageToday(deps.db, organizationId),
        readStoredTest(deps.db),
      ]);
      // llm.md §3.3: the id of a project deleted since is left out.
      const listed = reviewSettingsOf(settings, organizationId).projectIds;
      const owners = await projectOwners(deps.db, listed);
      return organizationReview(
        settings,
        organizationId,
        retention.reviewSnapshotsDays,
        listed.filter((id) => owners.get(id) === organizationId),
        spent,
        test,
      );
    },
  );

  app.put(
    '/organizations/:id/ai/review',
    {
      config: {
        openapi: {
          problems: [409],
          problemDescriptions: {
            403: 'FORBIDDEN or INSUFFICIENT_SCOPE',
            409: 'AI_DISABLED (switching it on needs the AI provider configured, in an organisation that may use AI), AI_REVIEW_CONSENT_REQUIRED (switching it on, from off or while consentCurrent is false, needs acknowledgeDataSharing), or AI_REVIEW_PROVIDER_CHANGED (the acknowledgement names another host, model or set of models than the provider configured now; nothing is stored)',
            422: 'VALIDATION_FAILED, or PROJECT_NOT_IN_ORGANIZATION (a project id belongs to another organisation; errors[] names it)',
          },
        },
      },
      schema: {
        tags: ['ai'],
        summary:
          "Set the organisation's AI review (org.ai.manage). Switching it on needs acknowledgeDataSharing, the provider the notice named, which records the provider's base URL, host, model and models, the user and the time; a change of any of them makes the consent outdated until it is given again",
        params: idParams,
        body: reviewBody,
        response: { 200: organizationReviewSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const organizationId = request.params.id;
      const organization = await requireOrganizationAccess(
        accessOf(deps),
        principal,
        organizationId,
        'org.ai.manage',
      );
      const body = request.body;
      const retentionDays = (await retentionSettings(deps.db)).reviewSnapshotsDays;
      // The settings the answer shows, and the projects of the review among them.
      const shown = await deps.db.transaction(async (tx) => {
        const settings = await lockLlmSettings(tx);
        const current = reviewSettingsOf(settings, organizationId);
        // UUIDs compare in lower case, as the database returns them.
        const requested = body.projectIds.map((id) => id.toLowerCase());
        const owners = await projectOwners(tx, [...requested, ...current.projectIds]);
        const foreign: FieldError[] = requested.flatMap((id, i) => {
          const owner = owners.get(id);
          return owner !== undefined && owner !== organizationId
            ? [{ path: `body.projectIds.${i}`, message: FOREIGN_PROJECT_TEXT }]
            : [];
        });
        if (foreign.length > 0) {
          throw new ProblemError(
            422,
            'PROJECT_NOT_IN_ORGANIZATION',
            'Some of the projects belong to another organisation',
            { errors: foreign },
          );
        }
        const stored: ReviewSettings = {
          ...current,
          projectIds: ownProjectIds(current.projectIds, owners, organizationId),
        };
        const provider = reviewProvider(settings);
        // Switching it on: from off, or confirming again when the provider's address, host or set of
        // models changed (the consent no longer names them all).
        const switchingOn =
          body.enabled && (!current.enabled || !consentCurrent(settings, current));
        let consent = current.consent;
        if (switchingOn) {
          if (provider === null || !organizationSettings(settings, organizationId).enabled) {
            throw conflict(
              'AI_DISABLED',
              'AI review needs the AI provider configured, in an organisation that may use AI',
            );
          }
          const acknowledged = body.acknowledgeDataSharing;
          if (acknowledged === undefined) {
            throw conflict(
              'AI_REVIEW_CONSENT_REQUIRED',
              'Switching AI review on needs the data-sharing notice acknowledged',
            );
          }
          // R10: the consent is for the provider the admin was shown. The instance admin may have
          // switched it since; the new one has a notice nobody has read yet.
          if (!acknowledgesProvider(provider, acknowledged)) {
            throw conflict(
              'AI_REVIEW_PROVIDER_CHANGED',
              'The AI provider changed since the notice was shown; read the new notice and confirm again',
            );
          }
          consent = {
            providerUrl: provider.url,
            providerHost: provider.host,
            model: provider.model,
            models: provider.models,
            userId: principal.user.id,
            at: new Date().toISOString(),
          };
        }
        const next: ReviewSettings = {
          enabled: body.enabled,
          scope: body.scope,
          projectIds: ownProjectIds(requested, owners, organizationId),
          budgets: body.budgets,
          consent,
        };
        // Nothing to save: the stored block already holds these values.
        if (sameReview(current, next)) return { settings, projectIds: next.projectIds };
        const saved = withOrganizationReview(settings, organizationId, next);
        await writeLlmSettings(tx, saved);
        // Projects may have left the review (switched off, out of the selection): a job deletes
        // their snapshots once this write is committed, never in this transaction.
        await queueSnapshotPurge(tx, organizationId);
        // The audit event names a change a person can see: the ids of deleted projects, which a
        // save drops, are not one (nor is the same save again).
        if (!sameReview(stored, next) && deps.audit.active()) {
          const [row] = await tx
            .select({ name: organizations.name })
            .from(organizations)
            .where(eq(organizations.id, organizationId));
          await deps.audit.record(tx, actorOf(request), [
            {
              action: 'organization.ai_review_changed',
              organization: { id: organizationId, key: organization.organizationKey },
              target: { type: 'organization', id: organizationId, label: row?.name ?? null },
              details: {
                enabled: next.enabled,
                scope: next.scope,
                projects: next.projectIds.length,
                consentGiven: switchingOn,
                providerHost: provider?.host ?? null,
                model: provider?.model ?? null,
              },
            },
          ]);
        }
        return { settings: saved, projectIds: next.projectIds };
      });
      // Read after the commit, so that the settings lock is held for the write alone.
      const [spent, test] = await Promise.all([
        reviewUsageToday(deps.db, organizationId),
        readStoredTest(deps.db),
      ]);
      return organizationReview(
        shown.settings,
        organizationId,
        retentionDays,
        shown.projectIds,
        spent,
        test,
      );
    },
  );

  app.get(
    '/projects/review-context',
    {
      config: {
        openapi: {
          problems: [404],
          problemDescriptions: {
            404: 'PROJECT_NOT_FOUND: the project does not exist, the token belongs to another project, or the caller cannot see it (a server without this route answers NOT_FOUND)',
          },
        },
      },
      schema: {
        tags: ['projects'],
        summary:
          'Whether the scanner should upload a repository snapshot of a merge request (AI review is on for the project), and the limits of a snapshot; the CLI calls this before a merge request scan uploads',
        querystring: z.strictObject({
          projectKey: z.string().regex(PROJECT_KEY_PATTERN),
          // The merge request's number: `lastReviewedCommit` is that merge request's.
          mergeRequest: z.string().regex(/^[0-9]{1,10}$/),
        }),
        response: { 200: reviewContextSchema },
      },
    },
    async (request) => {
      const principal = requirePrincipal(request);
      const project = await projectForUpload(accessOf(deps), principal, request.query.projectKey);
      const verdict = reviewActive(await readLlmSettings(deps.db), project);
      return {
        review: verdict.active,
        reason: verdict.active ? null : verdict.reason,
        // R4: the scanner sends the lines changed since this commit (`since`).
        lastReviewedCommit: await lastReviewedCommit(
          deps.db,
          project.id,
          request.query.mergeRequest,
        ),
        limits: {
          maxCompressedBytes: deps.config.reviewSnapshot.maxCompressedBytes,
          maxDecompressedBytes: deps.config.reviewSnapshot.maxDecompressedBytes,
          maxFileBytes: MAX_SNAPSHOT_FILE_BYTES,
          maxFiles: MAX_SNAPSHOT_FILES,
        },
      };
    },
  );

  app.post(
    '/analyses/:id/review-snapshot',
    {
      // `100 Continue` is written by the handler, only once every check below has passed.
      config: {
        deferContinue: true,
        openapi: {
          problems: [404, 409, 413, 415, 503],
          problemDescriptions: {
            404: "PROJECT_NOT_FOUND (the project does not exist, the token belongs to another project, or the caller cannot see it), or ANALYSIS_NOT_FOUND (the analysis is not one of the project's)",
            409: 'AI_REVIEW_OFF (AI review does not run for the project; GET /projects/review-context says why), or SNAPSHOT_EXISTS (the analysis has a snapshot already)',
            413: 'SNAPSHOT_TOO_LARGE: over maxCompressedBytes as sent or maxDecompressedBytes inflated (GET /projects/review-context answers both)',
            415: 'UNSUPPORTED_MEDIA_TYPE, or UNSUPPORTED_ENCODING (Content-Encoding must be gzip)',
            422: 'VALIDATION_FAILED, or SNAPSHOT_INVALID (the body is not gzip)',
            503: 'UPLOADS_BUSY: every upload slot is taken, or all but the last one, which is kept for report uploads (with a single slot, reports and snapshots share it); retry after Retry-After',
          },
          requestBody: {
            required: true,
            description:
              "The merge request's repository snapshot as gzip'd JSON Lines: a header line, the instruction files, one line per change, file and omitted file, and an end line with the counts; at most maxCompressedBytes (default 50 MiB) as sent and maxDecompressedBytes (default 500 MiB) inflated.",
            content: {
              [REVIEW_SNAPSHOT_CONTENT_TYPE]: { schema: { type: 'string', format: 'binary' } },
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
                'Send `100-continue` to have every check (auth, project, encoding, analysis, AI review, existing snapshot, declared length, upload slots) run before the body is sent.',
              schema: { type: 'string', enum: ['100-continue'] },
            },
          ],
        },
      },
      schema: {
        tags: ['analyses'],
        summary:
          "Upload the repository snapshot of a merge request's analysis for AI review (gzip body, Content-Type application/vnd.qualor.review-snapshot+jsonl, Content-Encoding gzip), right after its report; refused while AI review is off for the project. A job unpacks it; it is never served back",
        params: idParams,
        querystring: z.strictObject({ projectKey: z.string().regex(PROJECT_KEY_PATTERN) }),
        response: {
          202: z.object({ snapshotId: z.uuid(), status: z.literal('uploaded') }),
        },
      },
      // S11/S12/S15: every rejection closes the connection without losing the answer.
      preParsing: async (request, reply, payload) => {
        continueUnlessUpload(request, reply, REVIEW_SNAPSHOT_CONTENT_TYPE);
        return payload;
      },
      onSend: async (request, reply, payload) => {
        closeAfterRefusal(request, reply, deps.config.reviewSnapshot.maxCompressedBytes);
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
          'Review snapshots must be sent with Content-Encoding: gzip',
        );
      }
      if (!(request.body instanceof Readable)) {
        throw new ProblemError(
          415,
          'UNSUPPORTED_MEDIA_TYPE',
          `Review snapshots must be sent as ${REVIEW_SNAPSHOT_CONTENT_TYPE}`,
        );
      }
      const source = request.body;
      // Review Focus 4: the snapshot is of an analysis of this project; it is stored with the
      // analysis's project, never the request's.
      const [analysis] = await deps.db
        .select({ id: analyses.id, projectId: analyses.projectId })
        .from(analyses)
        .where(eq(analyses.id, request.params.id));
      if (!analysis || analysis.projectId !== project.id) {
        throw notFound('Analysis', 'ANALYSIS_NOT_FOUND');
      }
      const verdict = reviewActive(await readLlmSettings(deps.db), project);
      if (!verdict.active) {
        throw new ProblemError(409, 'AI_REVIEW_OFF', 'AI review is off for this project', {
          detail: `AI review does not run for this project: ${verdict.reason}`,
        });
      }
      // Asked before the body is read; two uploads racing meet at the insert (storeSnapshotUpload).
      if (await hasSnapshot(deps.db, analysis.id)) throw snapshotExists();
      const limits = deps.config.reviewSnapshot;
      const declared = Number(request.headers['content-length']);
      if (Number.isFinite(declared) && declared > limits.maxCompressedBytes) {
        throw snapshotTooLarge('compressed', limits.maxCompressedBytes);
      }
      // S11: one bound with the report uploads, taken before the body is touched. A snapshot is
      // optional and holds its slot for the whole transfer of a repository, far longer than a
      // report does, while the report upload of another scan gives up after a few seconds of 503
      // and fails that scan. So a snapshot leaves one slot to the reports: snapshots alone can
      // never fill every slot. With a single slot there is none to leave, and the two share it.
      slots.take(slots.max > 1 ? { reserve: 1 } : {});
      try {
        sendContinue(request, reply);
        let upload: UploadedReport;
        try {
          upload = await readGzipUpload(source, limits, SNAPSHOT_UPLOAD_PROBLEMS);
        } catch (err) {
          // A client hanging up mid-upload is routine: readGzipUpload made it a non-500 problem.
          if (err instanceof ProblemError && err.code === 'CLIENT_ABORTED') {
            request.log.debug({ err }, 'client aborted the review snapshot upload');
          }
          throw err;
        }
        // The uploader's project: the store checks it against the analysis row again, and keeps
        // the row's.
        const snapshotId = await storeSnapshotUpload(deps.db, {
          analysisId: analysis.id,
          projectId: project.id,
          body: upload.body,
          compressedBytes: upload.body.length,
        });
        return reply.code(202).send({ snapshotId, status: 'uploaded' as const });
      } finally {
        // Released once the snapshot and its job are stored, as for the report.
        slots.release();
      }
    },
  );
};
