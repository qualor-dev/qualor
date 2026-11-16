import { Readable } from 'node:stream';
import { parseSbom, type SbomInventory, type SbomRefusal } from '@qualor/shared';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { actorOf } from '../audit/recorder';
import { projectRefs } from '../audit/refs';
import { accessOf, requirePrincipal } from '../auth/access';
import { sendContinue } from '../http/expect-continue';
import { closeAfterRefusal } from '../http/lingering-close';
import { ProblemError } from '../http/problem';
import { noNul } from '../http/schemas';
import { TransferSlots } from '../ingest/upload';
import { PROJECT_KEY_PATTERN } from '../patterns';
import { projectForUpload } from '../projects/access';
import {
  readSbomText,
  SBOM_BODY_MAX_BYTES,
  SBOM_TEXT_MAX_BYTES,
  sbomLabel,
  sbomTooLarge,
  toVersionEntries,
} from '../sbom/upload';
import { upsertVersion } from '../versions/store';
import { enqueueRecheck } from '../vulnerabilities/recheck';
import { monitoringOn } from '../vulnerabilities/targets';

/** The body's types; the format is read from the content, never from the type (spec §6.1). */
export const SBOM_CONTENT_TYPES = [
  'application/vnd.cyclonedx+json',
  'application/spdx+json',
  'application/json',
] as const;

const TYPE_MESSAGE =
  'Send the SBOM as application/vnd.cyclonedx+json, application/spdx+json or application/json';

/** The longest `detail` a refusal of the parser carries (its messages are bounded already). */
const DETAIL_MAX_CHARS = 2_000;

const TITLES: Record<SbomRefusal['code'], string> = {
  SBOM_INVALID: 'The SBOM cannot be read',
  SBOM_FORMAT_UNSUPPORTED: 'The SBOM format is not supported',
  SBOM_TOO_MANY_PACKAGES: 'The SBOM holds too many packages',
  SBOM_MULTIPLE_OS: 'The SBOM describes more than one operating system',
  SBOM_TOO_LARGE: 'The SBOM is too large',
};

const count = z.number().int().min(0);

/** The answer to an upload: 201 for a new version, 200 for a replaced one (spec §6.1). */
export const sbomUploadAnswerSchema = z.object({
  version: z.object({ id: z.uuid(), label: z.string(), source: z.literal('sbom') }),
  format: z.string().meta({ description: '`CycloneDX 1.6`, `SPDX 2.3`, …' }),
  subject: z
    .string()
    .nullable()
    .meta({ description: 'What the SBOM describes, with its version; null when it names nothing' }),
  distribution: z
    .object({ family: z.string(), version: z.string() })
    .nullable()
    .meta({ description: 'The operating system of an image SBOM, its family as Trivy names it' }),
  packages: count.meta({ description: 'Packages stored, after duplicates were merged' }),
  osPackages: count.meta({ description: 'Of those, operating-system packages (deb, rpm, apk)' }),
  skipped: z
    .object({ noPurl: count, unsupportedType: count, duplicate: count })
    .meta({ description: 'Components not stored, by reason' }),
  warnings: z.array(z.object({ code: z.string(), message: z.string() })),
  monitoring: z.object({ enabled: z.boolean(), recheckQueued: z.boolean() }).meta({
    description:
      'Whether the instance and the project monitor vulnerabilities, and so whether a re-check was queued',
  }),
});
export type SbomUploadAnswer = z.infer<typeof sbomUploadAnswerSchema>;

function refusalProblem(refusal: SbomRefusal): ProblemError {
  const detail = refusal.message.slice(0, DETAIL_MAX_CHARS);
  return new ProblemError(
    refusal.code === 'SBOM_TOO_LARGE' ? 413 : 422,
    refusal.code,
    TITLES[refusal.code],
    { detail },
  );
}

/**
 * The body read and parsed. The text and the parsed document stay inside: only the inventory
 * leaves, so neither is held while the version is written.
 */
async function readInventory(body: Readable, gzip: boolean): Promise<SbomInventory> {
  const result = parseSbom(await readSbomText(body as AsyncIterable<Buffer>, { gzip }));
  if ('refusal' in result) throw refusalProblem(result.refusal);
  return result.inventory;
}

/**
 * 409: a tag scan made the version of this label, and a tag scan outranks an SBOM (spec §6.6). An
 * image's SBOM belongs in a project of its own; another label is never suggested.
 */
function labelTaken(projectKey: string, label: string): ProblemError {
  return new ProblemError(409, 'VERSION_LABEL_TAKEN', 'A tag scan made this version', {
    detail: `A tag scan of this project made version ${label}, and an SBOM never replaces it. Upload the image's SBOM to a project of its own (for example ${projectKey}-image), with the same label.`,
  });
}

/** `gzip` for `Content-Encoding: gzip`; none or `identity` is plain; any other is a 415. */
function gzipOf(encoding: string | undefined): boolean {
  // RFC 9110 §8.4: content codings are compared case-insensitively.
  const coding = encoding?.trim().toLowerCase();
  if (coding === 'gzip') return true;
  if (coding === undefined || coding === '' || coding === 'identity') return false;
  throw new ProblemError(
    415,
    'UNSUPPORTED_ENCODING',
    'Send the SBOM plain or with Content-Encoding: gzip',
  );
}

/**
 * `PUT /projects/sbom` (0.16 SBOM, spec §6.1, §6.6), in a plugin of its own (routes/index.ts): its
 * body parsers stay in its encapsulation context, so every other route keeps its JSON parsing.
 *
 * Every body type here is a raw stream, the three SBOM types and any other: no parser buffers a
 * body before the handler, whose checks all run before a byte is read (the route-wide `bodyLimit`
 * only keeps Fastify's own 413 out of the way). So `100 Continue` waits for the handler for every
 * type, and a refused type never asks for its body.
 */
export const sbomUploadRoutes: FastifyPluginAsyncZod<{
  deps: RouteDeps;
  /** S11: the app's upload slots, shared with the reports and the review snapshots. */
  uploadSlots?: TransferSlots;
  /**
   * Ruling R2: one SBOM read, inflated and parsed at a time per app (a 64 MiB parse can take
   * several hundred MB). Held from before the body is read until the inventory is parsed.
   */
  parseSlots?: TransferSlots;
}> = async (app, { deps, uploadSlots, parseSlots }) => {
  app.removeAllContentTypeParsers();
  for (const type of [...SBOM_CONTENT_TYPES, '*']) {
    app.addContentTypeParser(type, (_request, payload, done) => {
      done(null, payload);
    });
  }
  // Per app instance (this function runs once per buildApp() call), not global state.
  const slots = uploadSlots ?? new TransferSlots(deps.config.maxConcurrentUploads);
  const parses = parseSlots ?? new TransferSlots(1);

  app.put(
    '/projects/sbom',
    {
      bodyLimit: Number.MAX_SAFE_INTEGER,
      config: {
        // `100 Continue` is written by the handler, only once every check below has passed.
        deferContinue: true,
        openapi: {
          problems: [404, 409, 413, 415, 422, 503],
          problemDescriptions: {
            404: 'PROJECT_NOT_FOUND: no such project, one the caller cannot see, or a project token of another project',
            409: 'VERSION_LABEL_TAKEN: a tag scan made the version of this label; upload the image SBOM to a project of its own, with the same label',
            413: `SBOM_TOO_LARGE: the body is over ${SBOM_BODY_MAX_BYTES} bytes (also by its declared Content-Length, before 100 Continue), over ${SBOM_TEXT_MAX_BYTES} bytes inflated, or holds more than 2 000 000 JSON objects and arrays, 6 000 000 JSON keys and values or 10 000 distinct JSON keys`,
            415: 'UNSUPPORTED_MEDIA_TYPE: another Content-Type; UNSUPPORTED_ENCODING: a Content-Encoding other than gzip',
            422: 'VERSION_LABEL_INVALID: `version` blank or over 100 characters, or absent while the SBOM names no version; SBOM_INVALID: not gzip as Content-Encoding says, not UTF-8, not JSON (SPDX tag-value included), neither CycloneDX nor SPDX, or a field of the wrong shape (`detail` names its JSON path); SBOM_FORMAT_UNSUPPORTED: CycloneDX XML, SPDX 3, an attestation or a version outside CycloneDX 1.2–1.7 and SPDX 2.2–2.3 (`detail` says what to export); SBOM_TOO_MANY_PACKAGES: over 50 000 packages; SBOM_MULTIPLE_OS: more than one operating system; VALIDATION_FAILED: the query',
            503: 'UPLOADS_BUSY: the upload slots are taken, or another SBOM is being read; see Retry-After',
          },
          requestBody: {
            required: true,
            description:
              'The SBOM: CycloneDX JSON 1.2 to 1.7, or SPDX 2.2 or 2.3 JSON, read from its content whatever its type. At most 32 MiB as sent and 64 MiB of text, plain or with Content-Encoding: gzip.',
            content: Object.fromEntries(
              SBOM_CONTENT_TYPES.map((type) => [
                type,
                { schema: { type: 'string', format: 'binary' } },
              ]),
            ),
          },
          headers: [
            {
              in: 'header',
              name: 'Content-Encoding',
              required: false,
              description: 'Send `gzip` for a gzipped body; without it the body is plain.',
              schema: { type: 'string', enum: ['gzip'] },
            },
            {
              in: 'header',
              name: 'Expect',
              required: false,
              description:
                'Send `100-continue` to have every check (auth, project, type, encoding, version, declared length, upload slots) run before the body is sent.',
              schema: { type: 'string', enum: ['100-continue'] },
            },
          ],
        },
      },
      schema: {
        tags: ['versions'],
        summary:
          'Upload an SBOM (CycloneDX or SPDX JSON) as a released version of the project; a second upload of a label replaces the first',
        querystring: z.strictObject({
          projectKey: z.string().regex(PROJECT_KEY_PATTERN),
          version: noNul(z.string()).optional().meta({
            description:
              "The version label, 1 to 100 characters after trimming. Without it, the SBOM's own version (CycloneDX metadata.component.version, SPDX versionInfo)",
          }),
        }),
        response: {
          200: sbomUploadAnswerSchema.meta({
            description: 'The SBOM replaced the version of its label',
          }),
          201: sbomUploadAnswerSchema.meta({ description: 'The SBOM is stored as a new version' }),
        },
      },
      onSend: async (request, reply, payload) => {
        closeAfterRefusal(request, reply, SBOM_BODY_MAX_BYTES);
        return payload;
      },
    },
    async (request, reply) => {
      const principal = requirePrincipal(request);
      const project = await projectForUpload(accessOf(deps), principal, request.query.projectKey);
      const mime = request.headers['content-type']?.split(';')[0]?.trim().toLowerCase();
      if (
        !SBOM_CONTENT_TYPES.some((type) => type === mime) ||
        !(request.body instanceof Readable)
      ) {
        throw new ProblemError(415, 'UNSUPPORTED_MEDIA_TYPE', TYPE_MESSAGE);
      }
      const gzip = gzipOf(request.headers['content-encoding']);
      // Ruling R4: a given label is judged before the body; an absent one waits for the SBOM's.
      if (request.query.version !== undefined) sbomLabel(request.query.version, null);
      const declared = Number(request.headers['content-length']);
      if (Number.isFinite(declared) && declared > SBOM_BODY_MAX_BYTES) {
        throw sbomTooLarge(`The body is larger than ${SBOM_BODY_MAX_BYTES} bytes.`);
      }
      slots.take();
      try {
        let inventory: SbomInventory;
        parses.take();
        try {
          sendContinue(request, reply);
          inventory = await readInventory(request.body, gzip);
        } catch (err) {
          if (err instanceof ProblemError && err.code === 'CLIENT_ABORTED') {
            request.log.debug({ err }, 'client aborted the SBOM upload');
          }
          throw err;
        } finally {
          parses.release();
        }
        const label = sbomLabel(request.query.version, inventory.subjectVersion);
        const { format, subject, distribution, osPackages } = inventory;
        const packages = inventory.entries.length;
        const dependencies = toVersionEntries(inventory.entries);
        // One transaction: the version, its rows and the audit entry. The re-check is queued last,
        // as after a tag scan (it holds a global lock until the commit).
        const stored = await deps.db.transaction(async (tx) => {
          const written = await upsertVersion(tx, {
            projectId: project.id,
            label,
            source: 'sbom',
            tag: null,
            analysisId: null,
            analyzedAt: new Date(),
            inventory: { dependencies, ignores: null },
            sbom: { format, subject, distribution },
          });
          if (written === 'taken') throw labelTaken(project.key, label);
          const created = written.previous === null;
          if (deps.audit.active()) {
            const refs = await projectRefs(tx, project.id);
            await deps.audit.record(tx, actorOf(request), [
              {
                action: 'project_version.sbom_uploaded',
                organization: refs.organization,
                project: refs.project,
                target: { type: 'project', id: project.id, label: project.name },
                details: {
                  label,
                  format,
                  packages,
                  osPackages,
                  outcome: created ? 'created' : 'replaced',
                },
              },
            ]);
          }
          const monitored = await monitoringOn(tx, project.id);
          if (monitored) await enqueueRecheck(tx, { projectIds: [project.id] });
          return { version: written.version, created, monitored };
        });
        const answer: SbomUploadAnswer = {
          version: { id: stored.version.id, label: stored.version.label, source: 'sbom' },
          format,
          subject,
          distribution,
          packages,
          osPackages,
          skipped: inventory.skipped,
          warnings: inventory.warnings,
          monitoring: { enabled: stored.monitored, recheckQueued: stored.monitored },
        };
        return reply.code(stored.created ? 201 : 200).send(answer);
      } finally {
        slots.release();
      }
    },
  );
};
