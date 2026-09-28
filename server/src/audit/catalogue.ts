import { ENGINE_ID_PATTERN } from '@qualor/shared';
import { z } from 'zod';
import { ORGANIZATION_KEY_PATTERN, PROJECT_KEY_PATTERN } from '../patterns';
import type { AuditJson } from './canonical';
import { auditHashString, auditSeqString } from './settings';

/** rbac-audit.md §8: what an event may name as its target. */
export const AUDIT_TARGET_TYPES = [
  'user',
  'token',
  'organization',
  'project',
  'branch',
  'quality_gate',
  'quality_profile',
  'issue',
  'scm_connection',
  'webhook',
  'license',
  'ai_settings',
  'audit_settings',
  'sso_connection',
  'scim_token',
  'scim_group',
  'sign_in_settings',
] as const;
export type AuditTargetType = (typeof AUDIT_TARGET_TYPES)[number];

const str = z.string().max(1000);
/**
 * A stored webhook or SCM base URL is at most 2 048 characters (webhooks/url.ts
 * `MAX_WEBHOOK_URL_LENGTH`, checked on the normalised form), and so is its origin.
 */
const url = z.string().max(2_048);
const id = z.uuid();
const nullableId = id.nullable();
const iso = z.string().max(40);
const json: z.ZodType<AuditJson> = z.lazy(() =>
  z.union([
    z.string().max(1000),
    z.number().int().refine(Number.isSafeInteger),
    z.boolean(),
    z.null(),
    z.array(json).max(100),
    z.record(z.string().max(64), json),
  ]),
);
/** A change of one of `fields` (spec §8 names them), so a free field name can never carry a secret. */
function changesOf<const F extends readonly [string, ...string[]]>(fields: F, max: number) {
  return z.array(z.strictObject({ field: z.enum(fields), from: json, to: json })).max(max);
}
/** spec §8: the fields of each `changes` list. */
export const USER_CHANGE_FIELDS = ['displayName', 'email', 'active', 'isInstanceAdmin'] as const;
export const PROJECT_CHANGE_FIELDS = [
  'name',
  'mainBranchName',
  'newCodeDefinition',
  'qualityGateId',
  'scmConnectionId',
  'scmProjectRef',
] as const;
export const QUALITY_PROFILE_CHANGE_FIELDS = ['name', 'unknownRules'] as const;
/** spec §8: the names `scm_connection.updated` may list (names only, never values). */
export const SCM_CONNECTION_CHANGED_FIELDS = [
  'baseUrl',
  'token',
  'appId',
  'privateKey',
  'webhookSecret',
] as const;
/** sso-scim.md §7.7: the SSO flow failure codes, reused by `sso.sign_in_failed` and Task 12's errors.ts. */
export const SSO_ERROR_REASONS = [
  'unavailable',
  'flow_expired',
  'flow_mismatch',
  'idp_error',
  'invalid_response',
  'replayed',
  'required_claim',
  'no_account',
  'inactive_user',
  'email_in_use',
  'username_unavailable',
  'identity_in_use',
  'already_linked',
  'rate_limited',
] as const;
/** sso-scim.md §15: the names `sso.connection_updated` may list (names only, never values). */
export const SSO_CONNECTION_CHANGED_FIELDS = [
  'name',
  'enabled',
  'jit',
  'linkByEmail',
  'groupSource',
  'requiredClaims',
  'claims',
  'issuer',
  'clientId',
  'clientSecret',
  'clientAuth',
  'scopes',
  'userinfo',
  'idpEntityId',
  'idpSsoUrl',
  'idpCertificates',
  'metadataUrl',
  'nameIdFormat',
  'emailVerified',
  'wantResponseSigned',
  'spKey',
  'spCertificate',
] as const;
/** sso-scim.md §15: the fields `scim.user_updated`'s `changes` list may name. */
export const SCIM_USER_CHANGE_FIELDS = ['userName', 'displayName', 'email', 'externalId'] as const;
const changed = z.strictObject({ changed: z.array(z.string().max(64)).max(20) });
const organizationKey = z.string().regex(ORGANIZATION_KEY_PATTERN);
const projectKey = z.string().regex(PROJECT_KEY_PATTERN);
/** `<engine>:<rule id>`, as `PUT /quality-profiles/:id/rules/:ruleKey` accepts it. */
export const AUDIT_RULE_KEY_PATTERN = new RegExp(
  String.raw`${ENGINE_ID_PATTERN.source.slice(0, -1)}:[\s\S]{1,512}$`,
);
const ruleKey = z.string().regex(AUDIT_RULE_KEY_PATTERN);
const orgRole = z.enum(['admin', 'project_admin', 'member', 'viewer']);
const roleChange = { from: orgRole, to: orgRole };
const gateName = z.strictObject({ name: str });
const condition = z.strictObject({
  conditionId: id,
  metric: z.string().max(100),
  operator: z.enum(['gt', 'lt']),
  threshold: json,
});
const profileRef = z.strictObject({ name: str, language: z.string().max(32) });
const empty = z.strictObject({});
const provider = z.enum(['gitlab', 'github']);
const webhookRef = z.strictObject({
  origin: url,
  projectId: nullableId,
  events: z.array(z.string().max(64)).max(10),
  active: z.boolean(),
});
const tokenRef = z.strictObject({ name: str, prefix: z.string().max(16) });
/** sso-scim.md §12.8: every SCIM event names the token and the connection that made it. */
const scim = { scimTokenId: id, connectionId: id };
/** sso-scim.md §15: a bounded count (members, mappings changed, sessions ended, …). */
const count = z.number().int().min(0).max(1_000_000);

/**
 * rbac-audit.md §8: every audited action, its target type and a strict schema of its `details`.
 * The schemas list only the spec's fields, so a secret can never be passed through by accident.
 */
export const AUDIT_CATALOGUE = {
  'auth.sign_in': {
    target: 'user',
    details: z.strictObject({
      method: z.enum(['password', 'oidc', 'saml']),
      connectionId: id.optional(),
      forced: z.literal(true).optional(),
    }),
  },
  'auth.sign_in_failed': {
    target: 'user',
    details: z.strictObject({
      reason: z.enum(['invalid_credentials', 'inactive_user', 'rate_limited', 'password_disabled']),
      knownUser: z.boolean(),
    }),
  },
  'auth.sign_out': { target: 'user', details: empty },
  'auth.password_changed': { target: 'user', details: empty },
  'auth.password_sign_in_forced': {
    target: null,
    details: z.strictObject({ storedPolicy: z.enum(['everyone', 'break_glass_only']) }),
  },
  'sso.sign_in_failed': {
    target: 'user',
    details: z.strictObject({
      connectionId: id,
      protocol: z.enum(['oidc', 'saml']),
      reason: z.enum(SSO_ERROR_REASONS),
    }),
  },
  'sso.user_provisioned': {
    target: 'user',
    details: z.strictObject({ connectionId: id, emailSet: z.boolean() }),
  },
  'sso.identity_linked': {
    target: 'user',
    details: z.strictObject({
      connectionId: id,
      method: z.enum(['verified_email', 'user', 'scim_match']),
    }),
  },
  'sso.identity_unlinked': {
    target: 'user',
    details: z.strictObject({ connectionId: id, byAdmin: z.boolean() }),
  },
  'sso.connection_created': {
    target: 'sso_connection',
    details: z.strictObject({
      name: str,
      protocol: z.enum(['oidc', 'saml']),
      host: z.string().max(255),
    }),
  },
  'sso.connection_updated': {
    target: 'sso_connection',
    details: z.strictObject({
      changed: z.array(z.enum(SSO_CONNECTION_CHANGED_FIELDS)).max(32),
    }),
  },
  'sso.connection_deleted': {
    target: 'sso_connection',
    details: z.strictObject({
      name: str,
      protocol: z.enum(['oidc', 'saml']),
      identities: count,
      managedMemberships: count,
    }),
  },
  'sso.group_mappings_replaced': {
    target: 'sso_connection',
    details: z.strictObject({ count, added: count, removed: count }),
  },
  'sso.sign_in_settings_updated': {
    target: 'sign_in_settings',
    details: z.strictObject({
      passwordSignIn: z.enum(['everyone', 'break_glass_only']),
      breakGlassUserIds: z.array(id).max(10),
    }),
  },
  'scim_token.created': {
    target: 'scim_token',
    details: z.strictObject({
      connectionId: id,
      name: str,
      prefix: z.string().max(16),
      expiresAt: iso.nullable(),
    }),
  },
  'scim_token.revoked': {
    target: 'scim_token',
    details: z.strictObject({ connectionId: id, name: str, prefix: z.string().max(16) }),
  },
  'scim.user_created': {
    target: 'user',
    details: z.strictObject({ ...scim, linkedExisting: z.boolean() }),
  },
  'scim.user_updated': {
    target: 'user',
    details: z.strictObject({ ...scim, changes: changesOf(SCIM_USER_CHANGE_FIELDS, 4) }),
  },
  'scim.user_deactivated': {
    target: 'user',
    details: z.strictObject({ ...scim, sessionsEnded: count, tokensRevoked: count }),
  },
  'scim.user_reactivated': { target: 'user', details: z.strictObject(scim) },
  'scim.user_deleted': {
    target: 'user',
    details: z.strictObject({ ...scim, sessionsEnded: count, tokensRevoked: count }),
  },
  'scim.group_created': {
    target: 'scim_group',
    details: z.strictObject({ ...scim, displayName: str, members: count, unknownMembers: count }),
  },
  'scim.group_updated': {
    target: 'scim_group',
    details: z.strictObject({
      ...scim,
      displayName: str,
      membersAdded: count,
      membersRemoved: count,
      unknownMembers: count,
      renamed: z.boolean(),
    }),
  },
  'scim.group_deleted': {
    target: 'scim_group',
    details: z.strictObject({ ...scim, displayName: str, members: count }),
  },
  'user.created': {
    target: 'user',
    details: z.strictObject({ instanceAdmin: z.boolean(), passwordChangeRequired: z.boolean() }),
  },
  'user.updated': {
    target: 'user',
    details: z.strictObject({
      changes: changesOf(USER_CHANGE_FIELDS, 10),
      passwordReset: z.boolean(),
    }),
  },
  'token.created': {
    target: 'token',
    details: z.strictObject({
      name: str,
      prefix: z.string().max(16),
      scopes: z.array(z.string().max(32)).max(8),
      expiresAt: iso.nullable(),
    }),
  },
  'token.revoked': { target: 'token', details: tokenRef },
  'project_token.created': {
    target: 'token',
    details: z.strictObject({ name: str, prefix: z.string().max(16), expiresAt: iso.nullable() }),
  },
  'project_token.revoked': { target: 'token', details: tokenRef },
  'organization.created': {
    target: 'organization',
    details: z.strictObject({ key: organizationKey, name: str }),
  },
  'member.added': {
    target: 'user',
    details: z.strictObject({ role: orgRole, managedBy: id.optional() }),
  },
  'member.role_changed': {
    target: 'user',
    details: z.strictObject({ ...roleChange, managedBy: id.optional() }),
  },
  'member.removed': {
    target: 'user',
    details: z.strictObject({ role: orgRole, managedBy: id.optional() }),
  },
  'project_member.added': {
    target: 'user',
    details: z.strictObject({ role: orgRole, managedBy: id.optional() }),
  },
  'project_member.role_changed': {
    target: 'user',
    details: z.strictObject({ ...roleChange, managedBy: id.optional() }),
  },
  'project_member.removed': {
    target: 'user',
    details: z.strictObject({ role: orgRole, managedBy: id.optional() }),
  },
  'project.created': {
    target: 'project',
    details: z.strictObject({ key: projectKey, name: str, mainBranchName: str }),
  },
  'project.updated': {
    target: 'project',
    details: z.strictObject({ changes: changesOf(PROJECT_CHANGE_FIELDS, 20) }),
  },
  'project.deleted': { target: 'project', details: z.strictObject({ key: projectKey }) },
  'project.profile_assigned': {
    target: 'project',
    details: z.strictObject({ language: z.string().max(32), from: nullableId, to: nullableId }),
  },
  'branch.deleted': {
    target: 'branch',
    details: z.strictObject({ kind: z.enum(['branch', 'merge_request']), name: str }),
  },
  'quality_gate.created': { target: 'quality_gate', details: gateName },
  'quality_gate.updated': {
    target: 'quality_gate',
    details: z.strictObject({ from: str, to: str }),
  },
  'quality_gate.deleted': { target: 'quality_gate', details: gateName },
  'quality_gate.copied': {
    target: 'quality_gate',
    details: z.strictObject({ sourceId: id, name: str }),
  },
  'quality_gate.default_set': { target: 'quality_gate', details: gateName },
  'quality_gate.condition_added': { target: 'quality_gate', details: condition },
  'quality_gate.condition_updated': {
    target: 'quality_gate',
    details: z.strictObject({
      conditionId: id,
      metric: z.string().max(100),
      from: json,
      to: json,
    }),
  },
  'quality_gate.condition_removed': { target: 'quality_gate', details: condition },
  'quality_profile.created': { target: 'quality_profile', details: profileRef },
  'quality_profile.updated': {
    target: 'quality_profile',
    details: z.strictObject({ changes: changesOf(QUALITY_PROFILE_CHANGE_FIELDS, 20) }),
  },
  'quality_profile.deleted': { target: 'quality_profile', details: profileRef },
  'quality_profile.copied': {
    target: 'quality_profile',
    details: z.strictObject({ sourceId: id, name: str, language: z.string().max(32) }),
  },
  'quality_profile.default_set': { target: 'quality_profile', details: profileRef },
  'quality_profile.rule_set': {
    target: 'quality_profile',
    details: z.strictObject({
      ruleKey,
      active: z.boolean(),
      severityOverride: z.string().max(16).nullable(),
    }),
  },
  'quality_profile.rule_reset': {
    target: 'quality_profile',
    details: z.strictObject({ ruleKey }),
  },
  'issue.status_changed': {
    target: 'issue',
    details: z.strictObject({
      from: z.string().max(16),
      to: z.string().max(16),
      bulk: z.boolean(),
      mirrored: z.boolean(),
      commented: z.boolean(),
      suggestionId: nullableId,
    }),
  },
  'issue.severity_changed': {
    target: 'issue',
    details: z.strictObject({ from: z.string().max(16), to: z.string().max(16) }),
  },
  'issue.statuses_imported': {
    target: 'project',
    details: z.strictObject({
      items: z.number().int(),
      applied: z.number().int(),
      alreadySet: z.number().int(),
      conflicts: z.number().int(),
      unmatched: z.number().int(),
      ambiguous: z.number().int(),
      competitorsUnknown: z.number().int(),
    }),
  },
  'scm_connection.created': {
    target: 'scm_connection',
    details: z.strictObject({ provider, baseUrl: url }),
  },
  'scm_connection.updated': {
    target: 'scm_connection',
    details: z.strictObject({
      changed: z
        .array(z.enum(SCM_CONNECTION_CHANGED_FIELDS))
        .max(SCM_CONNECTION_CHANGED_FIELDS.length),
    }),
  },
  'scm_connection.deleted': {
    target: 'scm_connection',
    details: z.strictObject({ provider, baseUrl: url }),
  },
  'webhook.created': { target: 'webhook', details: webhookRef },
  'webhook.updated': { target: 'webhook', details: changed },
  'webhook.deleted': { target: 'webhook', details: webhookRef },
  'webhook.secret_regenerated': { target: 'webhook', details: empty },
  'webhook.redelivered': {
    target: 'webhook',
    details: z.strictObject({ deliveryId: id, event: z.string().max(64) }),
  },
  'license.uploaded': {
    target: 'license',
    details: z.strictObject({
      licenseId: id,
      keyId: z.string().max(32),
      expires: iso,
      features: z.array(z.string().max(64)).max(64),
    }),
  },
  'license.removed': { target: 'license', details: empty },
  'ai.settings_updated': {
    target: 'ai_settings',
    details: z.strictObject({
      changed: z.array(z.string().max(64)).max(30),
      apiKey: z.enum(['set', 'removed', 'kept']),
    }),
  },
  'ai.requested': {
    target: 'issue',
    details: z.strictObject({
      requestId: id,
      feature: z.enum(['explain', 'triage', 'fix']),
      providerHost: str,
      model: str,
    }),
  },
  'ai.fix_posted': { target: 'issue', details: z.strictObject({ requestId: id }) },
  'audit.settings_updated': {
    target: 'audit_settings',
    details: z.strictObject({
      changed: z.array(z.string().max(64)).max(10),
      retentionDays: z.number().int(),
      streamOrigin: str.nullable(),
      streamActive: z.boolean(),
    }),
  },
  'audit.stream_secret_regenerated': { target: 'audit_settings', details: empty },
  'audit.exported': {
    target: null,
    details: z.strictObject({ from: iso, to: iso, filters: z.record(z.string().max(32), json) }),
  },
  'audit.pruned': {
    target: null,
    details: z.strictObject({
      throughSeq: auditSeqString,
      throughHash: auditHashString,
      deleted: z.number().int(),
      cutoff: iso,
    }),
  },
} as const satisfies Record<string, { target: AuditTargetType | null; details: z.ZodType }>;

export type AuditAction = keyof typeof AUDIT_CATALOGUE;
export type AuditDetails<A extends AuditAction> = z.input<(typeof AUDIT_CATALOGUE)[A]['details']>;
export const AUDIT_ACTIONS = Object.freeze(Object.keys(AUDIT_CATALOGUE)) as readonly AuditAction[];

/** Whether `action` names a catalogue entry (an own key, never an inherited property). */
export function isAuditAction(action: string): action is AuditAction {
  return Object.hasOwn(AUDIT_CATALOGUE, action);
}

/**
 * a webhook or stream URL is recorded as its origin only (a path, a query or credentials
 * may hold a secret).
 */
export function urlOrigin(url: string): string {
  return new URL(url).origin;
}
