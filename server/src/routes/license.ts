import { eq } from 'drizzle-orm';
import type { FastifyRequest } from 'fastify';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { actorOf } from '../audit/recorder';
import { requireInstanceAdmin } from '../auth/access';
import { instanceSettings } from '../db/schema';
import { conflict, ProblemError } from '../http/problem';
import { INVALID_REASON_TEXT } from '../license/reasons';
import {
  LICENSE_SETTING_KEY,
  MAX_LICENSE_FILE_BYTES,
  readStoredLicense,
  type StoredLicense,
} from '../license/source';
import { licenseState, type LicenseState } from '../license/state';
import { keyHash, normaliseKey } from '../license/token';
import { verifyLicenseKey, type InvalidReason } from '../license/verify';

/**
 * The route's own body limit: `{ "key": "<16 KiB>" }` plus room for JSON escapes of whitespace.
 * A larger body is refused with 413 before it is parsed; up to it, the schema says 422.
 */
const LICENSE_BODY_LIMIT = MAX_LICENSE_FILE_BYTES + 1024;

const MANAGED_BY_ENVIRONMENT =
  'LICENSE_MANAGED_BY_ENVIRONMENT: the key comes from QUALOR_LICENSE or QUALOR_LICENSE_FILE';

const INVALID_REASONS = [
  'malformed',
  'unknown-key',
  'bad-signature',
  'bad-payload',
  'revoked',
  'not-yet-valid',
] as const satisfies readonly InvalidReason[];

const statusSchema = z.object({
  edition: z.enum(['community', 'enterprise']),
  state: z.enum(['none', 'invalid', 'active', 'grace', 'expired']),
  /** Why the boot key was rejected (state `invalid`); the UI has a label for each. */
  reason: z.enum(INVALID_REASONS).nullable(),
  /** Where the boot key came from; fixed for the life of the process (enterprise.md §6). */
  source: z.enum(['environment', 'file', 'uploaded']).nullable(),
  license: z
    .object({
      id: z.string(),
      keyId: z.string(),
      customer: z.string(),
      issued: z.string(),
      expires: z.string(),
      graceEndsAt: z.string(),
      features: z.array(z.string()),
      /** Signed with a `test-` key id: never accepted by a release build. */
      test: z.boolean(),
    })
    .nullable(),
  expiresSoon: z.boolean(),
  /** The stored key differs from the boot key: a saved or removed key applies at the next start. */
  restartRequired: z.boolean(),
  activeFeatures: z.array(z.string()),
  plugins: z.array(
    z.object({
      name: z.string(),
      state: z.enum(['loaded', 'failed']),
      features: z.array(z.string()),
      error: z.string().nullable(),
    }),
  ),
});
type Status = z.infer<typeof statusSchema>;

/**
 * enterprise.md §9.1: `license` is shown once the payload is trusted (a verified signature), so
 * also for `revoked` and `not-yet-valid`, never for `malformed`, `unknown-key`, `bad-signature`
 * or `bad-payload`. Never the key text or its hash.
 */
function licenseDto(state: LicenseState): Status['license'] {
  if (!state.license || !state.kid || !state.graceEndsAt) return null;
  return {
    id: state.license.id,
    keyId: state.kid,
    customer: state.license.customer,
    issued: new Date(state.license.issued).toISOString(),
    expires: new Date(state.license.expires).toISOString(),
    graceEndsAt: state.graceEndsAt.toISOString(),
    features: [...state.license.features],
    test: state.kid.startsWith('test-'),
  };
}

const keyBody = z.strictObject({
  key: z
    .string()
    .min(1)
    .max(MAX_LICENSE_FILE_BYTES)
    .meta({ description: 'Write-only: the licence key text; line breaks and spaces are ignored' }),
});

export const licenseRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (app, { deps }) => {
  const fromEnvironment = (): boolean =>
    deps.edition.bootSource === 'environment' || deps.edition.bootSource === 'file';

  /** enterprise.md §9: an environment or file key wins at every start, so an upload would never apply. */
  const refuseWhenManagedByEnvironment = (request: FastifyRequest, userId: string): void => {
    if (fromEnvironment()) {
      request.log.warn(
        { userId, source: deps.edition.bootSource },
        'licence change refused: the key comes from the environment',
      );
      throw conflict(
        'LICENSE_MANAGED_BY_ENVIRONMENT',
        'The licence key comes from QUALOR_LICENSE or QUALOR_LICENSE_FILE; change it there',
      );
    }
  };

  async function status(): Promise<Status> {
    const edition = deps.edition;
    const state = edition.state();
    const stored = await readStoredLicense(deps.db);
    const storedHash = stored ? keyHash(stored.key) : null;
    return {
      edition: edition.edition(),
      state: state.state,
      reason: state.reason,
      source: edition.bootSource,
      license: licenseDto(state),
      expiresSoon: state.expiresSoon,
      // An environment or file key ignores the stored row, so nothing waits for a restart.
      restartRequired: !fromEnvironment() && storedHash !== edition.bootKeyHash,
      activeFeatures: edition.activeFeatures(),
      plugins: edition.plugins().map((p) => ({
        name: p.name,
        state: p.state,
        features: [...p.features],
        error: p.error,
      })),
    };
  }

  app.get(
    '/license',
    {
      schema: {
        tags: ['system'],
        summary: 'The licence status (instance admins)',
        response: { 200: statusSchema },
      },
    },
    async (request) => {
      requireInstanceAdmin(request);
      return status();
    },
  );

  app.put(
    '/license',
    {
      bodyLimit: LICENSE_BODY_LIMIT,
      config: {
        openapi: {
          problems: [409, 413, 422],
          problemDescriptions: {
            409: MANAGED_BY_ENVIRONMENT,
            413: 'BODY_TOO_LARGE: the body is larger than 17 KiB',
            422: 'VALIDATION_FAILED: the body is not { key } with 1 to 16 KiB of text (checked first); LICENSE_INVALID: the key failed verification, `reason` says why; LICENSE_EXPIRED: the key is past its grace period',
          },
        },
      },
      schema: {
        tags: ['system'],
        summary: 'Save a licence key (instance admins); it takes effect at the next start',
        body: keyBody,
        response: { 200: statusSchema },
      },
    },
    async (request) => {
      const principal = requireInstanceAdmin(request);
      refuseWhenManagedByEnvironment(request, principal.user.id);
      const now = deps.edition.now();
      const key = normaliseKey(request.body.key);
      // Verified before it is stored (enterprise.md §9): a row never holds a key that fails.
      const verification = verifyLicenseKey(key, deps.edition.verifyOptions(now));
      if (!verification.ok) {
        request.log.warn(
          { userId: principal.user.id, reason: verification.reason },
          'licence key upload refused',
        );
        throw new ProblemError(422, 'LICENSE_INVALID', 'The licence key was rejected', {
          // Clients map the reason code, never the English text (enterprise.md §9).
          extensions: { reason: verification.reason },
          errors: [{ path: 'body.key', message: INVALID_REASON_TEXT[verification.reason] }],
        });
      }
      if (licenseState(verification, now).state === 'expired') {
        request.log.warn(
          { userId: principal.user.id, reason: 'expired' },
          'licence key upload refused',
        );
        throw new ProblemError(422, 'LICENSE_EXPIRED', 'This licence is past its grace period', {
          errors: [{ path: 'body.key', message: 'This licence has expired' }],
        });
      }
      const value: StoredLicense = {
        key,
        savedAt: now.toISOString(),
        savedBy: principal.user.id,
      };
      const license = verification.license;
      await deps.db.transaction(async (tx) => {
        await tx
          .insert(instanceSettings)
          .values({ key: LICENSE_SETTING_KEY, value })
          .onConflictDoUpdate({ target: instanceSettings.key, set: { value, updatedAt: now } });
        // rbac-audit.md §8: from the verified payload, never the key text or its hash. While
        // audit-log is inactive nothing is recorded, even for a key that lists it: the key
        // applies at the next start (enterprise.md §6).
        await deps.audit.record(tx, actorOf(request), [
          {
            action: 'license.uploaded',
            target: { type: 'license', id: license.id, label: license.customer },
            details: {
              licenseId: license.id,
              keyId: verification.kid,
              expires: new Date(license.expires).toISOString(),
              features: [...license.features],
            },
          },
        ]);
      });
      // Audit line: who and which licence, never the key text or its hash.
      request.log.info(
        { userId: principal.user.id, licenceId: verification.license.id, keyId: verification.kid },
        'licence key saved; it applies at the next start',
      );
      return status();
    },
  );

  app.delete(
    '/license',
    {
      config: {
        openapi: { problems: [409], problemDescriptions: { 409: MANAGED_BY_ENVIRONMENT } },
      },
      schema: {
        tags: ['system'],
        summary: 'Remove the saved licence key (instance admins); it applies at the next start',
        response: { 200: statusSchema },
      },
    },
    async (request) => {
      const principal = requireInstanceAdmin(request);
      refuseWhenManagedByEnvironment(request, principal.user.id);
      const removed = await deps.db.transaction(async (tx) => {
        const rows = await tx
          .delete(instanceSettings)
          .where(eq(instanceSettings.key, LICENSE_SETTING_KEY))
          .returning({ key: instanceSettings.key });
        if (rows.length > 0) {
          await deps.audit.record(tx, actorOf(request), [
            {
              action: 'license.removed',
              target: { type: 'license', id: LICENSE_SETTING_KEY },
              details: {},
            },
          ]);
        }
        return rows;
      });
      request.log.info(
        { userId: principal.user.id, removed: removed.length > 0 },
        'licence key removed; the change applies at the next start',
      );
      return status();
    },
  );
};
