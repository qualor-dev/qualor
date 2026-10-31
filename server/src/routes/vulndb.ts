import { Readable } from 'node:stream';
import { and, eq } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import type { VulndbSettingsChangedField } from '../audit/catalogue';
import { actorOf } from '../audit/recorder';
import { requireInstanceAdmin } from '../auth/access';
import { decryptSecret, encryptionKey } from '../crypto/secrets';
import { jobs } from '../db/schema';
import { sendContinue } from '../http/expect-continue';
import { closeAfterRefusal } from '../http/lingering-close';
import { ProblemError } from '../http/problem';
import { isoOrNull } from '../http/schemas';
import {
  OFFICIAL_REPOSITORY,
  readVulndbSettings,
  VULNDB_INTERVAL_HOURS,
  VULNDB_PASSWORD_AAD,
  VULNDB_REPOSITORY_PATTERN,
  writeVulndbSettings,
  type VulndbSettings,
} from '../vulndb/settings';
import { readVulndbState, VULNDB_UPDATE_QUEUE, vulndbStatus } from '../vulndb/state';
import { enqueueRecheck } from '../vulndb/recheck-queue';
import { currentDataset, makeDatasetCurrent, pruneDatasets, storeDataset } from '../vulndb/store';

const UPLOAD_TYPES = ['application/gzip', 'application/octet-stream'] as const;

const intervalHours = z
  .union([z.literal(1), z.literal(3), z.literal(6), z.literal(12), z.literal(24)])
  .meta({
    description: `Hours between checks for a new database: ${VULNDB_INTERVAL_HOURS.join(', ')}`,
  });

const repository = z
  .string()
  .max(512)
  .regex(VULNDB_REPOSITORY_PATTERN, 'A registry repository with a tag or a sha256 digest')
  .meta({ description: 'host[:port]/path:tag or host[:port]/path@sha256:digest' });

const sourceBody = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('official') }),
  z.strictObject({
    kind: z.literal('mirror'),
    repository,
    username: z.string().min(1).max(256).nullable().optional(),
    password: z.string().min(1).max(1_024).nullable().optional().meta({
      description: 'Write-only. A string sets the password, null removes it, absent keeps it',
    }),
  }),
  z.strictObject({ kind: z.literal('upload') }),
]);

const settingsBody = z.strictObject({
  enabled: z.boolean().optional(),
  intervalHours: intervalHours.optional(),
  source: sourceBody.optional(),
});

const settingsDto = z.object({
  enabled: z.boolean(),
  source: z.object({
    kind: z.enum(['official', 'mirror', 'upload']),
    repository: z.string().optional(),
    username: z.string().nullable().optional(),
    /** A password is stored (never the password itself). */
    passwordSet: z.boolean().optional(),
    /** False when the stored password no longer decrypts (QUALOR_SECRET_KEY changed). */
    passwordReadable: z.boolean().optional(),
  }),
  intervalHours,
  officialRepository: z.string(),
  status: z.enum(['off', 'no_data', 'updating', 'up_to_date', 'stale', 'failed']),
  current: z
    .object({
      builtAt: z.string().nullable(),
      sizeBytes: z.number().int(),
      source: z.enum(['official', 'mirror', 'upload']),
      digest: z.string(),
    })
    .nullable(),
  lastCheckAt: z.string().nullable(),
  nextCheckAt: z.string().nullable(),
  lastError: z.object({ code: z.string(), message: z.string() }).nullable(),
  lastRecheck: z
    .object({
      at: z.string(),
      projects: z.number().int(),
      packages: z.number().int(),
      unchecked: z.number().int(),
      durationMs: z.number().int(),
    })
    .nullable(),
});
type SettingsDto = z.infer<typeof settingsDto>;

/** The names of the fields a write changed (never a value), for the audit event and the log. */
function changedFields(
  before: VulndbSettings,
  after: VulndbSettings,
  passwordSent: boolean,
): VulndbSettingsChangedField[] {
  const fields: VulndbSettingsChangedField[] = [];
  if (before.enabled !== after.enabled) fields.push('enabled');
  if (before.intervalHours !== after.intervalHours) fields.push('intervalHours');
  if (before.source.kind !== after.source.kind) fields.push('source.kind');
  if (after.source.kind === 'mirror') {
    const was = before.source.kind === 'mirror' ? before.source : null;
    if (was?.repository !== after.source.repository) fields.push('source.repository');
    if ((was?.username ?? null) !== after.source.username) fields.push('source.username');
    // A new password is a change; removing one only when there was one.
    const hadPassword = (was?.passwordEnc ?? null) !== null;
    const dropped = !passwordSent && hadPassword && after.source.passwordEnc === null;
    if (dropped || (passwordSent && (after.source.passwordEnc !== null || hadPassword))) {
      fields.push('source.password');
    }
  }
  return fields;
}

export const vulndbRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (app, { deps }) => {
  const readDto = async (): Promise<SettingsDto> => {
    const settings = await readVulndbSettings(deps.db);
    const state = await readVulndbState(deps.db);
    const current = await currentDataset(deps.db, state);
    const [running] = await deps.db
      .select({ id: jobs.id })
      .from(jobs)
      .where(and(eq(jobs.queue, VULNDB_UPDATE_QUEUE), eq(jobs.status, 'running')))
      .limit(1);
    let source: SettingsDto['source'] = { kind: settings.source.kind };
    if (settings.source.kind === 'mirror') {
      const { passwordEnc, username } = settings.source;
      source = {
        kind: 'mirror',
        repository: settings.source.repository,
        username,
        passwordSet: passwordEnc !== null,
        passwordReadable:
          passwordEnc === null ||
          decryptSecret(encryptionKey(deps.config.secretKey), passwordEnc, VULNDB_PASSWORD_AAD) !==
            null,
      };
    }
    return {
      enabled: settings.enabled,
      source,
      intervalHours: settings.intervalHours,
      officialRepository: OFFICIAL_REPOSITORY,
      status: vulndbStatus(settings, state, current, running !== undefined),
      current:
        current === null
          ? null
          : {
              builtAt: isoOrNull(current.builtAt),
              sizeBytes: current.sizeBytes,
              source: current.source,
              digest: current.digest,
            },
      lastCheckAt: state.lastCheckAt,
      nextCheckAt: state.nextCheckAt,
      lastError: state.lastError,
      lastRecheck: state.lastRecheck,
    };
  };

  app.get(
    '/system/vulnerability-db',
    {
      schema: {
        tags: ['system'],
        summary:
          'The vulnerability database settings and status (instance admins); never the mirror password',
        response: { 200: settingsDto },
      },
    },
    async (request) => {
      requireInstanceAdmin(request);
      return readDto();
    },
  );

  app.put(
    '/system/vulnerability-db',
    {
      schema: {
        tags: ['system'],
        summary:
          'Change the vulnerability database settings (instance admins); the mirror password is write-only: a string sets it, null removes it, absent keeps it',
        body: settingsBody,
        response: { 200: settingsDto },
      },
    },
    async (request) => {
      const principal = requireInstanceAdmin(request);
      const body = request.body;
      const passwordSent = body.source?.kind === 'mirror' && body.source.password !== undefined;
      const changed = await deps.db.transaction(async (tx) => {
        const { before, after } = await writeVulndbSettings(
          tx,
          {
            ...(body.enabled === undefined ? {} : { enabled: body.enabled }),
            ...(body.intervalHours === undefined ? {} : { intervalHours: body.intervalHours }),
            ...(body.source === undefined ? {} : { source: body.source }),
          },
          deps.config.secretKey,
        );
        const fields = changedFields(before, after, passwordSent);
        await deps.audit.record(tx, actorOf(request), [
          {
            action: 'vulndb.settings_updated',
            target: { type: 'vulndb_settings', id: 'vulndb' },
            details: { changed: fields },
          },
        ]);
        return fields;
      });
      request.log.info({ userId: principal.user.id, fields: changed }, 'vulndb settings changed');
      return readDto();
    },
  );
  // The upload is handed to the handler as the raw request stream; storeDataset enforces the
  // limit. Scoped to this plugin: no other route sees these content types.
  for (const type of UPLOAD_TYPES) {
    app.addContentTypeParser(type, (_request, payload, done) => {
      done(null, payload);
    });
  }

  app.put(
    '/system/vulnerability-db/file',
    {
      // Fastify's own body limit would answer 413 BODY_TOO_LARGE before the route's own
      // TOO_LARGE; the route enforces config.vulndb.uploadMaxBytes itself.
      bodyLimit: Number.MAX_SAFE_INTEGER,
      config: {
        deferContinue: true,
        openapi: {
          problems: [413, 415, 422],
          requestBody: {
            required: true,
            description:
              'The Trivy database archive (db.tar.gz) as downloaded, at most QUALOR_VULNDB_UPLOAD_MAX_BYTES (default 1 GiB).',
            content: Object.fromEntries(
              UPLOAD_TYPES.map((type) => [type, { schema: { type: 'string', format: 'binary' } }]),
            ),
          },
        },
      },
      schema: {
        tags: ['system'],
        summary:
          'Upload a vulnerability database file, db.tar.gz (instance admins); it becomes the current database',
        response: { 200: settingsDto },
      },
      preParsing: async (request, reply, payload) => {
        const mime = request.headers['content-type']?.split(';')[0]?.trim().toLowerCase();
        if (!UPLOAD_TYPES.some((type) => type === mime)) sendContinue(request, reply);
        return payload;
      },
      onSend: async (request, reply, payload) => {
        closeAfterRefusal(request, reply, deps.config.vulndb.uploadMaxBytes);
        return payload;
      },
    },
    async (request, reply) => {
      const principal = requireInstanceAdmin(request);
      const maxBytes = deps.config.vulndb.uploadMaxBytes;
      const tooLarge = () =>
        new ProblemError(413, 'TOO_LARGE', 'The file is too large', {
          detail: `The file is larger than ${maxBytes} bytes`,
        });
      if (!(request.body instanceof Readable)) {
        throw new ProblemError(
          415,
          'UNSUPPORTED_MEDIA_TYPE',
          'Send the database file as application/gzip or application/octet-stream',
        );
      }
      const declared = Number(request.headers['content-length']);
      if (Number.isFinite(declared) && declared > maxBytes) throw tooLarge();
      sendContinue(request, reply);
      const stored = await storeDataset(deps.db, {
        kind: 'trivy',
        source: 'upload',
        chunks: request.body as AsyncIterable<Buffer>,
        maxBytes,
      });
      if ('problem' in stored) {
        if (stored.problem.code === 'TOO_LARGE') throw tooLarge();
        throw new ProblemError(422, 'INVALID_DATABASE', 'The file is not a usable database', {
          detail: stored.problem.message,
        });
      }
      const { dataset } = stored;
      if (!(await makeDatasetCurrent(deps.db, dataset.id))) {
        throw new ProblemError(422, 'INVALID_DATABASE', 'The file is not a usable database', {
          detail:
            'The upload expired before it was stored, because it took too long. Upload the file again',
        });
      }
      await pruneDatasets(deps.db);
      await enqueueRecheck(deps.db, { all: true });
      await deps.audit.record(deps.db, actorOf(request), [
        {
          action: 'vulndb.file_uploaded',
          target: { type: 'vulndb_settings', id: 'vulndb' },
          details: { sizeBytes: dataset.sizeBytes, builtAt: isoOrNull(dataset.builtAt) },
        },
      ]);
      request.log.info(
        { userId: principal.user.id, sizeBytes: dataset.sizeBytes },
        'vulndb file uploaded',
      );
      return readDto();
    },
  );
};
