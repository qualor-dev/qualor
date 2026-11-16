import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { accessOf, requireUser } from '../auth/access';
import { visibleProjectsCondition } from '../auth/facts';
import { noNul, text } from '../http/schemas';
import { NOT_A_PURL, packageUsages, usageSearchOf } from '../packages/usages';

/** One package in one branch or version of a project (spec §6.8). */
const usageRowSchema = z.object({
  project: z.object({ id: z.uuid(), key: z.string(), name: z.string() }),
  target: z.object({
    kind: z.enum(['branch', 'version']),
    id: z.uuid(),
    /** The branch name or the version label. */
    name: z.string(),
    /** The project's main branch. */
    main: z.boolean(),
    /** How a version came about: a tag scan, a branch label or an uploaded SBOM; null for a branch. */
    source: z.enum(['tag', 'label', 'sbom']).nullable(),
  }),
  /** As stored: a scan's Trivy type (`npm`, `pip`, `pom`, …) or an SBOM's purl type. */
  ecosystem: z.string(),
  /** The purl type of the ecosystem; null when it has none (the package is not checked). */
  purlType: z.string().nullable(),
  name: z.string(),
  version: z.string(),
  /** The lockfile or manifest, repo-relative; `''` when the scan or SBOM named none. */
  path: z.string(),
  /** `null`: the scan or SBOM did not say. */
  direct: z.boolean().nullable(),
  /** The operating system of an SBOM version; null on branches and other versions. */
  distribution: z.object({ family: z.string(), version: z.string() }).nullable(),
  vulnerabilities: z
    .number()
    .int()
    .nullable()
    .describe(
      'Open vulnerabilities of the package in this branch or version, as the Vulnerabilities tab counts them; null when not known now: the package is not checked, monitoring is off for the instance or the project, the branch or version is not tracked now, or it has no re-check since its last analysis or upload',
    ),
});

const responseSchema = z.object({
  rows: z.array(usageRowSchema),
  page: z.number().int(),
  pageSize: z.number().int(),
  total: z.number().int().describe('The matching rows, at most 10 000'),
  totalCapped: z.boolean().describe('More than 10 000 rows match ("10 000+")'),
});

const querySchema = z.strictObject({
  q: noNul(z.string().trim().min(1).max(300))
    .refine((q) => usageSearchOf(q) !== null, NOT_A_PURL)
    .meta({
      description:
        'A package URL when it starts with pkg: (its type covers every ecosystem that maps to it; name and version exact; for deb, rpm and apk the namespace is the OS family), else a name: 3 or more characters match anywhere in a name, 1–2 a whole name, ignoring case',
    }),
  ecosystem: z
    .string()
    .regex(/^[a-z0-9-]{1,32}$/)
    .optional()
    .describe(
      'A purl type; it keeps every ecosystem that maps to it (pypi also keeps pip, poetry, uv, …)',
    ),
  version: text(256).optional().describe('An exact version'),
  page: z.coerce.number().int().min(1).max(100).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(50),
});

export const packageRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (app, { deps }) => {
  app.get(
    '/packages/usages',
    {
      schema: {
        tags: ['packages'],
        summary:
          'Where a package is used: its rows in every branch and version of the projects you can see',
        querystring: querySchema,
        response: { 200: responseSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const visible = visibleProjectsCondition(accessOf(deps), principal.user);
      return packageUsages(deps.db, visible, request.query);
    },
  );
};
