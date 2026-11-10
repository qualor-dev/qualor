import { randomUUID } from 'node:crypto';
import { eq } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { accessOf, requirePrincipal } from '../auth/access';
import { organizations } from '../db/schema';
import { ProblemError, validationFailed } from '../http/problem';
import { VERSION } from '../index';
import { PROJECT_KEY_PATTERN } from '../patterns';
import { projectForExport, type ProjectRow } from '../projects/access';
import { vulnerabilitySettings } from '../versions/settings';
import { sbomNotLicensed, SBOM_FEATURE } from '../vulnerabilities/export/feature';
import { exportPackages, exportTarget, vexEntries } from '../vulnerabilities/export/query';
import { buildCycloneDxSbom, buildSpdxSbom } from '../vulnerabilities/export/sbom-documents';
import type { ExportDocument } from '../vulnerabilities/export/types';
import { buildCycloneDxVex, buildOpenVex } from '../vulnerabilities/export/vex-documents';
import { hasInventory } from '../dependencies/query';
import { readVulndbSettings } from '../vulndb/settings';

const CYCLONEDX = 'application/vnd.cyclonedx+json; version=1.6';
const SPDX = 'application/spdx+json';
const OPENVEX = 'application/json';

/** Every character outside `[A-Za-z0-9._-]` becomes `-` (a file name for every system). */
const fileSafe = (text: string): string => text.replace(/[^A-Za-z0-9._-]/g, '-');

const targetQuery = {
  projectKey: z.string().regex(PROJECT_KEY_PATTERN),
  /** A branch name; neither `branch` nor `version` means the main branch. */
  branch: z.string().min(1).max(255).optional(),
  /** A version label. */
  version: z.string().min(1).max(100).optional(),
};

const file = (description: string, types: readonly string[]) => ({
  description,
  content: Object.fromEntries(types.map((type) => [type, { schema: z.string() }])),
});

const problemDescriptions = {
  403: `FEATURE_NOT_LICENSED (the enterprise feature ${SBOM_FEATURE} is not licensed), INSUFFICIENT_SCOPE (a personal token needs the \`read\` scope) or TOKEN_NOT_ALLOWED`,
  404: 'PROJECT_NOT_FOUND (the project does not exist, the caller cannot see it, or a project token belongs to another project), or NOT_FOUND (no such branch or version; for the SBOM, a target without a dependency inventory; for the VEX, vulnerability monitoring is off)',
  422: 'Validation failed (VALIDATION_FAILED; also `branch` together with `version`)',
};

export const exportRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (app, { deps }) => {
  /**
   * E3, after the principal and the project (404) that each route checks itself: the feature (403),
   * then the target (404). The target is resolved last, so what an outsider is told never depends
   * on the licence or on the shape of the query.
   */
  async function resolve(project: ProjectRow, query: { branch?: string; version?: string }) {
    if (!deps.edition.limits().vulnerabilities.sbom) throw sbomNotLicensed();
    // Kept out of the route schema (a refinement would answer before the access checks).
    if (query.branch !== undefined && query.version !== undefined) {
      throw validationFailed([
        { path: 'query.version', message: 'Give either branch or version, not both' },
      ]);
    }
    const resolved = await exportTarget(deps.db, project, query);
    const [org] = await deps.db
      .select({ name: organizations.name })
      .from(organizations)
      .where(eq(organizations.id, project.organizationId));
    const doc: ExportDocument = {
      project: { key: project.key, name: project.name },
      organization: org?.name ?? '',
      target: { kind: resolved.kind, name: resolved.name },
      generatedAt: new Date(),
      serial: randomUUID(),
      toolVersion: VERSION,
    };
    return { resolved, doc };
  }

  // A Buffer is sent as it is: Fastify would rewrite the content type of a string (quotes and a charset).
  const attachment = (
    reply: { header(name: string, value: string): unknown },
    type: string,
    name: string,
  ) => {
    reply.header('cache-control', 'no-store');
    reply.header('content-disposition', `attachment; filename="${name}"`);
    reply.header('content-type', type);
  };

  app.get(
    '/projects/sbom',
    {
      config: { openapi: { problems: [403, 404], problemDescriptions } },
      schema: {
        tags: ['vulnerabilities'],
        summary:
          'Download the software bill of materials of a branch or version as CycloneDX or SPDX JSON (enterprise feature sbom)',
        querystring: z.strictObject({
          ...targetQuery,
          format: z.enum(['cyclonedx', 'spdx']).default('cyclonedx'),
        }),
        response: {
          200: file('The SBOM, as an attachment', ['application/vnd.cyclonedx+json', SPDX]),
        },
      },
    },
    async (request, reply) => {
      const { format, ...query } = request.query;
      const project = await projectForExport(
        accessOf(deps),
        requirePrincipal(request),
        query.projectKey,
      );
      const { resolved, doc } = await resolve(project, query);
      const packages = await exportPackages(deps.db, resolved.target);
      if (packages.length === 0 && !(await hasInventory(deps.db, resolved.target, 0))) {
        throw new ProblemError(
          404,
          'NOT_FOUND',
          `This ${resolved.kind} has no dependency inventory yet`,
        );
      }
      const body =
        format === 'spdx' ? buildSpdxSbom(doc, packages) : buildCycloneDxSbom(doc, packages);
      attachment(
        reply,
        format === 'spdx' ? SPDX : CYCLONEDX,
        `${fileSafe(project.key)}-${fileSafe(resolved.name)}${format === 'spdx' ? '.spdx.json' : '.cdx.json'}`,
      );
      return reply.send(Buffer.from(JSON.stringify(body)) as unknown as string);
    },
  );

  app.get(
    '/projects/vex',
    {
      config: { openapi: { problems: [403, 404], problemDescriptions } },
      schema: {
        tags: ['vulnerabilities'],
        summary:
          'Download the triage decisions of a branch or version as a CycloneDX VEX or OpenVEX document (enterprise feature sbom)',
        querystring: z.strictObject({
          ...targetQuery,
          format: z.enum(['cyclonedx', 'openvex']).default('cyclonedx'),
        }),
        response: {
          200: file('The VEX document, as an attachment', [
            'application/vnd.cyclonedx+json',
            OPENVEX,
          ]),
        },
      },
    },
    async (request, reply) => {
      const { format, ...query } = request.query;
      const project = await projectForExport(
        accessOf(deps),
        requirePrincipal(request),
        query.projectKey,
      );
      const { resolved, doc } = await resolve(project, query);
      const [instance, settings] = await Promise.all([
        readVulndbSettings(deps.db),
        vulnerabilitySettings(deps.db, project.id),
      ]);
      if (!instance.enabled || !settings.enabled) {
        throw new ProblemError(
          404,
          'NOT_FOUND',
          'Vulnerability monitoring is off for this project',
        );
      }
      const entries = await vexEntries(deps.db, project.id, resolved.target);
      const body =
        format === 'openvex' ? buildOpenVex(doc, entries) : buildCycloneDxVex(doc, entries);
      attachment(
        reply,
        format === 'openvex' ? OPENVEX : CYCLONEDX,
        `${fileSafe(project.key)}-${fileSafe(resolved.name)}${format === 'openvex' ? '.openvex.json' : '.vex.cdx.json'}`,
      );
      return reply.send(Buffer.from(JSON.stringify(body)) as unknown as string);
    },
  );
};
