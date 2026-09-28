import type { FastifyBaseLogger } from 'fastify';
import { z } from 'zod';
import type { AuditRecorder } from '../audit/recorder';
import { requireSession } from '../auth/access';
import type { Config } from '../config';
import type { Db } from '../db/client';
import { notFound, ProblemError, validationFailed } from '../http/problem';
import type { Edition } from '../license/edition';
import type { PluginScim, PluginSso } from '../plugins/contract';
import { handleScim } from '../scim/handle';
import { createScimToken, listScimTokens, revokeScimToken } from '../scim/tokens';
import { unlinkIdentity, userIdentities } from './accounts';
import type { FlowDeps } from './complete';
import {
  createConnection,
  deleteConnection,
  getConnection,
  isConnectionInEffect,
  listConnections,
  loadConnection,
  testConnection,
  updateConnection,
  type ConnectionDeps,
  type LoadedConnection,
  type SsoCertificateView,
} from './connections';
import { failSsoFlow, SsoFailure, ssoDetail } from './errors';
import { listMappings, replaceMappings } from './groups';
import { oidcCallback, startOidc } from './oidc';
import { forgetOidcConfiguration } from './oidc-config';
import { safeReturnTo } from './return-to';
import { finishSaml, readSamlMetadata, samlAcs, spMetadata, startSaml } from './saml';
import {
  readSignInSettings,
  updateSignInSettings,
  usableBreakGlass,
  type SignInSettings,
} from './sign-in-policy';

/** `POST /ee/sso/connections/{id}/saml/metadata` (spec §4.3): what the admin reviews; not saved. */
export interface SamlMetadataPreview {
  idpEntityId: string;
  idpSsoUrl: string;
  certificates: SsoCertificateView[];
}

/** `PUT /ee/sso/settings` (spec §10.1). */
export type SignInSettingsInput = SignInSettings;

/** `GET /ee/sso/settings` (spec §17.2): the stored row, the variable, and the listed admins. */
export interface SignInSettingsView extends SignInSettings {
  /** QUALOR_FORCE_PASSWORD_SIGN_IN is set (§10.4). */
  forced: boolean;
  /** The listed users that exist, in list order; `usable`: active, instance admin, a password. */
  breakGlass: { userId: string; username: string; usable: boolean }[];
}

/** `POST /ee/scim/tokens` (spec §17.2): `expiresAt` an ISO 8601 time with its offset, or none. */
export interface ScimTokenInput {
  connectionId: string;
  name: string;
  expiresAt?: string | null;
}

export interface SsoServiceDeps {
  db: Db;
  config: Config;
  /** A getter: bootEnterprise builds the edition after the services. */
  edition: () => Edition;
  audit: AuditRecorder;
  log: FastifyBaseLogger;
}

/** Where a link flow comes back to (the Linked accounts screen, spec §18). */
const LINKED_ACCOUNTS = '/settings/ee/linked-accounts';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EXPIRES_AT = z.iso.datetime({ offset: true });

/**
 * Ruling SS1: core checks the feature itself, whatever the plugin's route guard did, with the
 * guard's own answer (403 FEATURE_NOT_LICENSED), so no call through the plugin writes or reads
 * SSO or SCIM state while its feature is inactive.
 */
function requireFeature(edition: () => Edition, feature: 'sso' | 'scim'): void {
  if (!edition().isFeatureActive(feature)) {
    throw new ProblemError(
      403,
      'FEATURE_NOT_LICENSED',
      `The enterprise feature "${feature}" is not licensed`,
    );
  }
}

/** A connection id in a path: anything but a UUID is an unknown connection (never a 500). */
function connectionId(id: string): string {
  if (typeof id !== 'string' || !UUID.test(id)) throw notFound('SSO connection');
  return id;
}

/**
 * sso-scim.md §17.1: `ctx.sso`, built from the core functions. The admin members check nothing
 * about the caller (the plugin's route calls `ctx.access.requireInstanceAdmin` first, or, for a
 * user's own identities, `ctx.access.requireUser`); the browser flows carry their own checks (the
 * binding cookie, the session for linking). Every member checks `sso` first (SS1).
 */
export function createSsoService(deps: SsoServiceDeps): PluginSso {
  const sso = (): void => {
    requireFeature(deps.edition, 'sso');
  };
  const connectionDeps = (): ConnectionDeps => ({
    db: deps.db,
    config: deps.config,
    audit: deps.audit,
    edition: deps.edition(),
  });
  const flow = (): FlowDeps => ({
    db: deps.db,
    config: deps.config,
    edition: deps.edition(),
    audit: deps.audit,
    log: deps.log,
  });
  /** A connection in effect (spec §4.4) whose config parses, or null. */
  const enabled = async (id: string): Promise<LoadedConnection | null> => {
    const c = await loadConnection(deps.db, id, deps.config.secretKey);
    if (!c?.row.enabled) return null;
    return (await isConnectionInEffect(deps.db, deps.edition(), c.row.id)) ? c : null;
  };
  const signInView = async (): Promise<SignInSettingsView> => {
    const stored = await readSignInSettings(deps.db, deps.log);
    return {
      passwordSignIn: stored.passwordSignIn,
      breakGlassUserIds: stored.breakGlassUserIds,
      forced: deps.config.forcePasswordSignIn,
      breakGlass: await usableBreakGlass(deps.db, stored.breakGlassUserIds),
    };
  };

  return Object.freeze({
    listConnections: async () => {
      sso();
      return listConnections(connectionDeps());
    },
    getConnection: async (id) => {
      sso();
      return getConnection(connectionDeps(), id);
    },
    createConnection: async (actor, input) => {
      sso();
      return createConnection(connectionDeps(), actor, input);
    },
    updateConnection: async (actor, id, input) => {
      sso();
      const view = await updateConnection(connectionDeps(), actor, id, input);
      forgetOidcConfiguration(id);
      return view;
    },
    deleteConnection: async (actor, id) => {
      sso();
      await deleteConnection(connectionDeps(), actor, id);
      forgetOidcConfiguration(id);
    },
    testConnection: async (id) => {
      sso();
      return testConnection(connectionDeps(), id);
    },
    readSamlMetadata: async (id) => {
      sso();
      const c = await loadConnection(deps.db, connectionId(id), deps.config.secretKey);
      if (!c) {
        await getConnection(connectionDeps(), id); // 404 when unknown
        throw validationFailed([
          { path: 'saml.metadataUrl', message: 'The stored configuration is not valid' },
        ]);
      }
      return readSamlMetadata(c, { config: deps.config });
    },
    mappings: async (id) => {
      sso();
      await getConnection(connectionDeps(), id); // 404 when unknown
      return listMappings(deps.db, id);
    },
    replaceMappings: async (actor, id, input) => {
      sso();
      return replaceMappings({ db: deps.db, audit: deps.audit }, actor, connectionId(id), input);
    },
    signInSettings: async () => {
      sso();
      return signInView();
    },
    updateSignInSettings: async (actor, input) => {
      sso();
      await updateSignInSettings({ db: deps.db, audit: deps.audit }, actor, input);
      return signInView();
    },
    userIdentities: async (userId) => {
      sso();
      return userIdentities(deps.db, userId);
    },
    unlinkIdentity: async (actor, userId, identityId, byAdmin) => {
      sso();
      await unlinkIdentity(
        { db: deps.db, audit: deps.audit, edition: deps.edition(), log: deps.log },
        actor,
        userId,
        identityId,
        byAdmin === true,
      );
    },
    spMetadata: async (id) => {
      sso();
      const c = await loadConnection(deps.db, connectionId(id), deps.config.secretKey);
      if (!c || c.parsed.protocol !== 'saml' || !deps.config.publicUrl) {
        throw notFound('SSO connection');
      }
      return spMetadata(c, deps.config.publicUrl);
    },
    // spec §7.3: an unknown or disabled connection is 303 to the login page; a flow that cannot
    // start (the IdP's discovery down) ends there too, through failSsoFlow.
    start: async (request, reply, id) => {
      sso();
      const c = await enabled(id);
      if (!c) return reply.code(303).header('location', '/login?sso_error=unavailable').send();
      const query = request.query as { returnTo?: unknown } | undefined;
      const returnTo = safeReturnTo(query?.returnTo);
      try {
        const intent = { returnTo, link: null };
        const url =
          c.parsed.protocol === 'oidc'
            ? await startOidc(flow(), request, reply, c, intent)
            : await startSaml(flow(), request, reply, c, intent);
        return await reply.code(302).header('location', url).send();
      } catch (err) {
        return failSsoFlow(flow(), request, reply, {
          connectionId: c.row.id,
          protocol: c.parsed.protocol,
          failure: err instanceof SsoFailure ? err : new SsoFailure('unavailable', 'start.other'),
        });
      }
    },
    // spec §7.3: a browser session only (403 SESSION_REQUIRED with a token).
    startLink: async (request, reply, id) => {
      sso();
      const principal = requireSession(request);
      const c = await enabled(id);
      if (!c) throw notFound('SSO connection');
      const intent = { returnTo: LINKED_ACCOUNTS, link: { userId: principal.user.id } };
      try {
        const url =
          c.parsed.protocol === 'oidc'
            ? await startOidc(flow(), request, reply, c, intent)
            : await startSaml(flow(), request, reply, c, intent);
        return { url };
      } catch (err) {
        const failure =
          err instanceof SsoFailure ? err : new SsoFailure('unavailable', 'start.other');
        deps.log.warn(
          {
            component: 'sso',
            connectionId: c.row.id,
            reason: failure.code,
            detail: ssoDetail(failure.detail),
          },
          'single sign-on linking could not start',
        );
        throw new ProblemError(
          503,
          'SSO_UNAVAILABLE',
          'The identity provider cannot be used now; try again later',
        );
      }
    },
    oidcCallback: async (request, reply, id) => {
      sso();
      return oidcCallback(flow(), request, reply, id);
    },
    samlAcs: async (request, reply, id) => {
      sso();
      return samlAcs(flow(), request, reply, id);
    },
    finish: async (request, reply) => {
      sso();
      return finishSaml(flow(), request, reply);
    },
  } satisfies PluginSso);
}

/** `expiresAt` of a token body: an ISO 8601 time with its offset, or none (422 otherwise). */
function expiryOf(raw: unknown): Date | null {
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== 'string' || !EXPIRES_AT.safeParse(raw).success) {
    throw validationFailed([
      { path: 'body.expiresAt', message: 'Give an ISO 8601 time with its offset, or none' },
    ]);
  }
  return new Date(raw);
}

/**
 * sso-scim.md §17.1: `ctx.scim`. `handle` authenticates the SCIM token itself and answers in SCIM
 * (it checks `scim` with a SCIM error, SS7); the token members check `scim` first (SS1) and nothing
 * about the caller (the plugin's route calls `ctx.access.requireInstanceAdmin` first).
 */
export function createScimService(deps: SsoServiceDeps): PluginScim {
  const scim = (): void => {
    requireFeature(deps.edition, 'scim');
  };
  const tokenDeps = { db: deps.db, audit: deps.audit };
  return Object.freeze({
    handle: (request, reply) =>
      handleScim(
        {
          db: deps.db,
          secretKey: deps.config.secretKey,
          config: deps.config,
          edition: deps.edition(),
          audit: deps.audit,
          log: deps.log,
        },
        request,
        reply,
      ),
    listTokens: async (id) => {
      scim();
      return listScimTokens(deps.db, id);
    },
    createToken: async (actor, input) => {
      scim();
      return createScimToken(tokenDeps, actor, {
        connectionId: input.connectionId,
        name: input.name,
        expiresAt: expiryOf(input.expiresAt),
      });
    },
    revokeToken: async (actor, id) => {
      scim();
      await revokeScimToken(tokenDeps, actor, id);
    },
  } satisfies PluginScim);
}
