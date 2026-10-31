import { Readable } from 'node:stream';
import { and, eq } from 'drizzle-orm';
import type { FastifyReply, FastifyRequest } from 'fastify';
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
  OFFICIAL_EPSS_URL,
  OFFICIAL_KEV_URL,
  OFFICIAL_REPOSITORY,
  readVulndbSettings,
  VULNDB_INTERVAL_HOURS,
  VULNDB_PASSWORD_AAD,
  VULNDB_SCANNER_POLICIES,
  VULNDB_REPOSITORY_PATTERN,
  writeVulndbSettings,
  type PriorityDataset,
  type VulndbSettings,
} from '../vulndb/settings';
import { PRIORITY_FEATURE, priorityNotLicensed } from '../vulndb/priority/feature';
import { PRIORITY_FILE_MAX_BYTES } from '../vulndb/priority/parse';
import { readPriorityState, priorityStatus } from '../vulndb/priority/state';
import { storePriorityFile } from '../vulndb/priority/update';
import { readVulndbState, VULNDB_UPDATE_QUEUE, vulndbStatus } from '../vulndb/state';
import { enqueueRecheck } from '../vulndb/recheck-queue';
import { requestVulndbUpdateNow, rescheduleVulndbUpdate } from '../vulndb/update';
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

const mirrorUrl = z
  .string()
  .max(2048)
  .refine((value) => {
    try {
      const u = new URL(value);
      return u.protocol === 'https:' && u.username === '' && u.password === '' && u.hash === '';
    } catch {
      return false;
    }
  }, 'An https URL without credentials or a fragment')
  .nullable()
  .optional();

const sourceBody = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('official') }),
  z.strictObject({
    kind: z.literal('mirror'),
    repository,
    username: z.string().min(1).max(256).nullable().optional(),
    password: z.string().min(1).max(1_024).nullable().optional().meta({
      description: 'Write-only. A string sets the password, null removes it, absent keeps it',
    }),
    kevUrl: mirrorUrl.meta({
      description: 'Where to download the CISA KEV catalog. Null: the official source',
    }),
    epssUrl: mirrorUrl.meta({
      description: 'Where to download the FIRST EPSS scores. Null: the official source',
    }),
  }),
  z.strictObject({ kind: z.literal('upload') }),
]);

const scannerPolicy = z.enum(VULNDB_SCANNER_POLICIES).meta({
  description: 'daily: scanners refresh their copy once a day; every: before every scan',
});

const settingsBody = z.strictObject({
  enabled: z.boolean().optional(),
  intervalHours: intervalHours.optional(),
  source: sourceBody.optional(),
  scanners: z
    .strictObject({ enabled: z.boolean().optional(), policy: scannerPolicy.optional() })
    .optional()
    .meta({ description: 'Whether scanners take the database from this server, and how often' }),
});

const priorityDatasetDto = z.object({
  status: z.enum(['off', 'no_data', 'updating', 'up_to_date', 'stale', 'failed']),
  officialUrl: z.string(),
  source: z.enum(['official', 'mirror', 'upload']).nullable(),
  dataDate: z.string().nullable(),
  storedAt: z.string().nullable(),
  lastCheckAt: z.string().nullable(),
  sizeBytes: z.number().int().nullable(),
  count: z.number().int().nullable(),
  lastError: z.object({ code: z.string(), message: z.string() }).nullable(),
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
    kevUrl: z.string().nullable().optional(),
    epssUrl: z.string().nullable().optional(),
  }),
  intervalHours,
  scanners: z.object({ enabled: z.boolean(), policy: scannerPolicy }),
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
  lastError: z
    .object({ code: z.string(), message: z.string() })
    .nullable()
    .meta({ description: "The update's last problem: a download, a store or the source" }),
  lastRecheckError: z
    .object({ code: z.string(), message: z.string() })
    .nullable()
    .meta({ description: "The re-check's last problem: DISK or RECHECK_FAILED" }),
  priority: z
    .object({ kev: priorityDatasetDto, epss: priorityDatasetDto })
    .nullable()
    .meta({ description: 'CISA KEV and FIRST EPSS; null without the vuln.priority feature' }),
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
    if ((was?.kevUrl ?? null) !== after.source.kevUrl) fields.push('source.kevUrl');
    if ((was?.epssUrl ?? null) !== after.source.epssUrl) fields.push('source.epssUrl');
    // A new password is a change; removing one only when there was one.
    const hadPassword = (was?.passwordEnc ?? null) !== null;
    const dropped = !passwordSent && hadPassword && after.source.passwordEnc === null;
    if (dropped || (passwordSent && (after.source.passwordEnc !== null || hadPassword))) {
      fields.push('source.password');
    }
  }
  if (before.scanners.enabled !== after.scanners.enabled) fields.push('scanners.enabled');
  if (before.scanners.policy !== after.scanners.policy) fields.push('scanners.policy');
  return fields;
}

/** R5: monitoring switched on, or a download source (official or mirror) newly chosen or changed. */
function wantsUpdateNow(
  before: VulndbSettings,
  after: VulndbSettings,
  passwordSent: boolean,
): boolean {
  if (!after.enabled) return false;
  if (!before.enabled) return true;
  if (after.source.kind === 'official') return before.source.kind !== 'official';
  if (after.source.kind !== 'mirror') return false;
  if (before.source.kind !== 'mirror') return true;
  // A corrected repository, user or password retries at once instead of after the interval.
  return (
    before.source.repository !== after.source.repository ||
    before.source.username !== after.source.username ||
    before.source.kevUrl !== after.source.kevUrl ||
    before.source.epssUrl !== after.source.epssUrl ||
    passwordSent
  );
}

const PRIORITY_FILES = {
  kev: 'known_exploited_vulnerabilities.json',
  epss: 'epss_scores-current.csv.gz',
} as const satisfies Record<PriorityDataset, string>;

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
        kevUrl: settings.source.kevUrl,
        epssUrl: settings.source.epssUrl,
      };
    }
    let priority: SettingsDto['priority'] = null;
    if (deps.edition.limits().vulnerabilities.priority) {
      const states = await readPriorityState(deps.db);
      const now = new Date();
      const one = (dataset: PriorityDataset) => {
        const s = states[dataset];
        return {
          status: priorityStatus(dataset, s, {
            enabled: settings.enabled,
            running: running !== undefined,
            now,
          }),
          officialUrl: dataset === 'kev' ? OFFICIAL_KEV_URL : OFFICIAL_EPSS_URL,
          source: s.source,
          dataDate: s.dataDate,
          storedAt: s.storedAt,
          lastCheckAt: s.lastCheckAt,
          sizeBytes: s.sizeBytes,
          count: s.count,
          lastError: s.lastError,
        };
      };
      priority = { kev: one('kev'), epss: one('epss') };
    }
    return {
      enabled: settings.enabled,
      source,
      intervalHours: settings.intervalHours,
      scanners: settings.scanners,
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
      lastRecheckError: state.lastRecheckError,
      priority,
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
      const {
        fields: changed,
        before,
        after,
      } = await deps.db.transaction(async (tx) => {
        const { before, after } = await writeVulndbSettings(
          tx,
          {
            ...(body.enabled === undefined ? {} : { enabled: body.enabled }),
            ...(body.intervalHours === undefined ? {} : { intervalHours: body.intervalHours }),
            ...(body.source === undefined ? {} : { source: body.source }),
            ...(body.scanners === undefined ? {} : { scanners: body.scanners }),
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
        // R5: switched on, every tracked target is re-checked against the data there is. Last in
        // the transaction: enqueueRecheck holds a global lock until the commit.
        if (!before.enabled && after.enabled) await enqueueRecheck(tx, { all: true });
        return { fields, before, after };
      });
      request.log.info({ userId: principal.user.id, fields: changed }, 'vulndb settings changed');
      // R5: switching monitoring on, or pointing it at another source, fetches data now rather
      // than at the next scheduled check.
      if (wantsUpdateNow(before, after, passwordSent)) await requestVulndbUpdateNow(deps.db);
      // M4: a new interval counts from the last check, not from the run already waiting.
      else if (before.intervalHours !== after.intervalHours) await rescheduleVulndbUpdate(deps.db);
      return readDto();
    },
  );
  app.post(
    '/system/vulnerability-db/update',
    {
      schema: {
        tags: ['system'],
        summary:
          'Check for a new vulnerability database now (instance admins); the check runs in the background; pressed during a check, it queues one more check after it. After a failed re-check, every tracked target is re-checked too',
        response: { 202: settingsDto },
      },
    },
    async (request, reply) => {
      const principal = requireInstanceAdmin(request);
      const queued = await requestVulndbUpdateNow(deps.db);
      // R19: a failed re-check is tried again too, whatever the source: an unchanged download
      // queues none, and an uploaded file is never downloaded.
      if ((await readVulndbState(deps.db)).lastRecheckError !== null) {
        await enqueueRecheck(deps.db, { all: true });
      }
      await deps.audit.record(deps.db, actorOf(request), [
        {
          action: 'vulndb.update_requested',
          target: { type: 'vulndb_settings', id: 'vulndb' },
          details: {},
        },
      ]);
      request.log.info({ userId: principal.user.id, queued }, 'vulndb update requested');
      return reply.code(202).send(await readDto());
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
      // Before any body is read (and without a 100 Continue): only an instance admin sending one
      // of the two raw-stream types gets as far as the parser. Any other type has a buffering
      // parser, which the route-wide bodyLimit would not stop.
      preParsing: async (request, reply, payload) => {
        requireInstanceAdmin(request);
        const mime = request.headers['content-type']?.split(';')[0]?.trim().toLowerCase();
        if (!UPLOAD_TYPES.some((type) => type === mime)) {
          throw new ProblemError(
            415,
            'UNSUPPORTED_MEDIA_TYPE',
            'Send the database file as application/gzip or application/octet-stream',
          );
        }
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
      await enqueueRecheck(deps.db, { all: true });
      // After the re-check is queued, and never a 500: an old dataset left now goes with the next.
      try {
        await pruneDatasets(deps.db);
      } catch (err) {
        request.log.warn(
          { errorClass: err instanceof Error ? err.constructor.name : typeof err },
          'old vulnerability datasets were not pruned',
        );
      }
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

  const priorityTypeMessage = 'Send the file as application/gzip or application/octet-stream';
  // One factory for both routes. The routes themselves are written out below, so that the route
  // sweep (test/route-source.ts) finds each with its rule.
  const priorityUpload = (dataset: PriorityDataset) => {
    const maxBytes = PRIORITY_FILE_MAX_BYTES;
    const label = dataset === 'kev' ? 'CISA KEV catalog' : 'FIRST EPSS scores';
    const tooLarge = () =>
      new ProblemError(413, 'TOO_LARGE', 'The file is too large', {
        detail: `The file is larger than ${maxBytes} bytes`,
      });
    const options = {
      bodyLimit: Number.MAX_SAFE_INTEGER,
      config: {
        deferContinue: true,
        openapi: {
          problems: [403, 413, 415, 422],
          problemDescriptions: {
            403: `FEATURE_NOT_LICENSED (the enterprise feature ${PRIORITY_FEATURE} is not active), FORBIDDEN or INSUFFICIENT_SCOPE`,
            413: `TOO_LARGE: the body is over ${maxBytes} bytes, or the unpacked file is over its cap or has too many entries; \`detail\` says which`,
            422: 'INVALID_DATA: the file is not a usable catalog or score file; `detail` says why',
          },
          requestBody: {
            required: true,
            description: `The ${label} (${PRIORITY_FILES[dataset]}) as downloaded, gzipped or plain, at most 32 MiB. Needs the ${PRIORITY_FEATURE} feature.`,
            content: Object.fromEntries(
              UPLOAD_TYPES.map((type) => [type, { schema: { type: 'string', format: 'binary' } }]),
            ),
          },
        },
      },
      schema: {
        tags: ['system'],
        summary: `Upload the ${label}, ${PRIORITY_FILES[dataset]} (instance admins); needs vuln.priority`,
        response: { 200: settingsDto },
      },
      // Admin, then the feature, then the type: all before any body is read.
      preParsing: async (request: FastifyRequest, _reply: FastifyReply, payload: Readable) => {
        requireInstanceAdmin(request);
        if (!deps.edition.limits().vulnerabilities.priority) throw priorityNotLicensed();
        const mime = request.headers['content-type']?.split(';')[0]?.trim().toLowerCase();
        if (!UPLOAD_TYPES.some((type) => type === mime)) {
          throw new ProblemError(415, 'UNSUPPORTED_MEDIA_TYPE', priorityTypeMessage);
        }
        return payload;
      },
      onSend: async (request: FastifyRequest, reply: FastifyReply, payload: unknown) => {
        closeAfterRefusal(request, reply, maxBytes);
        return payload;
      },
    };
    const handle = async (request: FastifyRequest, reply: FastifyReply, userId: string) => {
      if (!deps.edition.limits().vulnerabilities.priority) throw priorityNotLicensed();
      if (!(request.body instanceof Readable)) {
        throw new ProblemError(415, 'UNSUPPORTED_MEDIA_TYPE', priorityTypeMessage);
      }
      const declared = Number(request.headers['content-length']);
      if (Number.isFinite(declared) && declared > maxBytes) throw tooLarge();
      sendContinue(request, reply);
      const chunks: Buffer[] = [];
      let total = 0;
      for await (const chunk of request.body as AsyncIterable<Buffer>) {
        total += chunk.length;
        if (total > maxBytes) throw tooLarge();
        chunks.push(chunk);
      }
      const stored = await storePriorityFile(
        deps.db,
        dataset,
        Buffer.concat(chunks),
        'upload',
        { etag: null, lastModified: null, url: null },
        new Date(),
        request.log,
      );
      if ('problem' in stored) {
        // The body fit; the parser refused its inflated size or its entry count, and says which.
        const [status, code, title] =
          stored.problem.code === 'TOO_LARGE'
            ? ([413, 'TOO_LARGE', 'The file is too large'] as const)
            : ([422, 'INVALID_DATA', 'The file is not usable'] as const);
        throw new ProblemError(status, code, title, { detail: stored.problem.message });
      }
      request.log.info({ userId, dataset, sizeBytes: total }, 'vulndb priority file uploaded');
      return { dataset, sizeBytes: stored.sizeBytes ?? total, builtAt: stored.dataDate };
    };
    return { options, handle };
  };

  const audit = (
    request: FastifyRequest,
    details: { dataset: PriorityDataset; sizeBytes: number; builtAt: string | null },
  ) =>
    deps.audit.record(deps.db, actorOf(request), [
      {
        action: 'vulndb.file_uploaded',
        target: { type: 'vulndb_settings', id: 'vulndb' },
        details,
      },
    ]);

  app.put(
    '/system/vulnerability-db/file/kev',
    priorityUpload('kev').options,
    async (request, reply) => {
      const principal = requireInstanceAdmin(request);
      await audit(request, await priorityUpload('kev').handle(request, reply, principal.user.id));
      return readDto();
    },
  );
  app.put(
    '/system/vulnerability-db/file/epss',
    priorityUpload('epss').options,
    async (request, reply) => {
      const principal = requireInstanceAdmin(request);
      await audit(request, await priorityUpload('epss').handle(request, reply, principal.user.id));
      return readDto();
    },
  );
};
