import { IMPORT_STATUSES, STATUS_IMPORT_MAX_ITEMS, STATUS_IMPORT_OUTCOMES } from '@qualor/shared';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { actorOf } from '../audit/recorder';
import { accessOf, requireUser } from '../auth/access';
import { idParams, noNul } from '../http/schemas';
import { importIssueStatuses, sanitizeImportComment } from '../issues/status-import';
import { projectForUser } from '../projects/access';
import { issueStatusSchema } from './issues';

/** report-format.md §7.1: `<engine>:<rule id>`, the rule id 1–512 characters (≤ 553 in all). */
const RULE_KEY = /^[a-z0-9][a-z0-9-]{0,39}:[\s\S]{1,512}$/;

/** Spec §10.2: relative, with `/`, no empty, `.` or `..` segment, at most 1 024 bytes. */
function relativePath(p: string): boolean {
  if (Buffer.byteLength(p, 'utf8') > 1024 || p.startsWith('/') || p.includes('\\')) return false;
  return p.split('/').every((s) => s !== '' && s !== '.' && s !== '..');
}

const itemFields = {
  ref: z.string().regex(/^[A-Za-z0-9_.:-]{1,100}$/),
  ruleKeys: z
    .array(noNul(z.string().max(553).regex(RULE_KEY)))
    .min(1)
    .max(8),
  path: noNul(z.string().min(1).max(1024))
    .refine(relativePath, 'Must be a relative path without empty, . or .. segments')
    .nullable(),
  line: z.number().int().min(1).max(10_000_000).nullable(),
  sonarLineHash: z
    .string()
    .regex(/^[0-9a-f]{32}$/)
    .nullable(),
  message: noNul(z.string().max(4000)).nullable(),
};
const comment = noNul(z.string().min(1).max(2000));

/** Spec §11.2: an item by its status. Both kinds count toward the 1 000 items of a request. */
const itemSchema = z.discriminatedUnion('status', [
  /** A SonarQube issue a person resolved: applied when matched. */
  z.strictObject({
    ...itemFields,
    status: z.enum(IMPORT_STATUSES),
    comment: comment.refine((c) => sanitizeImportComment(c) !== '', 'Must not be blank'),
    /** SonarQube's open issues of this item's rule could not all be read (spec §10.1). */
    competitorsUnknown: z.boolean().optional(),
  }),
  /** An open SonarQube issue, sent only as a competitor for the matching; never applied. */
  z.strictObject({ ...itemFields, status: z.literal('open'), comment: comment.optional() }),
]);

export const issueStatusImportRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (
  app,
  { deps },
) => {
  app.post(
    '/projects/:id/issue-status-import',
    {
      config: {
        openapi: {
          problems: [409, 413, 503],
          problemDescriptions: {
            409: 'The main branch has no succeeded analysis yet (PROJECT_NOT_ANALYSED)',
            413: 'The body is over 1 MiB (BODY_TOO_LARGE), or the items select more than 20 000 candidate issues (IMPORT_TOO_LARGE); split the request',
            422: 'Validation failed (VALIDATION_FAILED), including a duplicate ref',
            503: 'An issue stayed locked by an ingestion (CONCURRENCY_CONFLICT); see Retry-After',
          },
        },
      },
      schema: {
        tags: ['issues'],
        summary: 'Import false-positive and won’t-fix statuses onto the main branch’s issues',
        params: idParams,
        body: z.strictObject({
          dryRun: z.boolean(),
          items: z.array(itemSchema).min(1).max(STATUS_IMPORT_MAX_ITEMS),
        }),
        response: {
          200: z.object({
            branchId: z.uuid(),
            analysisId: z.uuid(),
            /** One per `false_positive` or `wont_fix` item, in request order. */
            results: z.array(
              z.object({
                ref: z.string(),
                outcome: z.enum(STATUS_IMPORT_OUTCOMES),
                issueId: z.uuid().nullable(),
                status: issueStatusSchema.nullable(),
              }),
            ),
            /** The number of `open` items, taken as competitors only. */
            competitors: z.number().int().min(0),
          }),
        },
      },
    },
    async (request) => {
      // 🛡 (spec §11.2): an admin of the project's organisation, with the `admin` scope; a
      // project of another organisation is 404. Not charged to ruling G7's limit.
      const principal = requireUser(request, 'admin');
      const project = await projectForUser(
        accessOf(deps),
        principal,
        request.params.id,
        'project.issues.import',
      );
      return importIssueStatuses(
        accessOf(deps),
        principal.user,
        project.id,
        request.body.items,
        request.body.dryRun,
        { audit: { recorder: deps.audit, context: actorOf(request) } },
      );
    },
  );
};
