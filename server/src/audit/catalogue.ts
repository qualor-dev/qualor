import {
  ENGINE_ID_PATTERN,
  LICENSE_GROUPS,
  RULE_SCOPES,
  SEVERITIES,
  type LicenseGroupId,
} from '@qualor/shared';
import { z } from 'zod';
import { ORGANIZATION_KEY_PATTERN, PROJECT_KEY_PATTERN } from '../patterns';
import { REVIEW_SCOPES } from '../review/schema';
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
  'mail_settings',
  'compliance_report',
  'oauth_client',
  'oauth_grant',
  'mcp_settings',
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
/** 6M §5: a stored licence policy (`licensePolicySchema`'s bounds), or none. */
const licensePolicyList = z.array(z.string().max(256)).max(500);
const licensePolicy = z
  .strictObject({
    mode: z.enum(['denylist', 'allowlist']),
    forbiddenGroups: z
      .array(z.enum(LICENSE_GROUPS.map((g) => g.id) as [LicenseGroupId, ...LicenseGroupId[]]))
      .max(LICENSE_GROUPS.length),
    forbidden: licensePolicyList,
    allowed: licensePolicyList,
    warnUnknown: z.boolean(),
  })
  .nullable();
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
/** E1 spec: the names `mail.settings_updated` may list (names only, never a value). */
export const MAIL_SETTINGS_CHANGED_FIELDS = [
  'server',
  'server.host',
  'server.port',
  'server.security',
  'server.username',
  'server.password',
  'server.fromName',
  'server.fromAddress',
  'server.replyTo',
  'alerts.licenseExpiry',
  'alerts.webhookFailures',
] as const;
export type MailSettingsChangedField = (typeof MAIL_SETTINGS_CHANGED_FIELDS)[number];
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
  /** 6G: the webhook's kind. */
  kind: z.enum(['generic', 'slack', 'teams']),
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
      method: z.enum(['password', 'oidc', 'saml', 'demo']),
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
  /** Mail E2: a reset link was sent; the actor is anonymous, never the name or address typed. */
  'auth.password_reset_requested': { target: 'user', details: empty },
  /** Mail E2: a password set through a reset link; the actor is the account itself. */
  'auth.password_reset': { target: 'user', details: empty },
  /** Mail E2: a first password chosen through an invitation link; the actor is the account itself. */
  'auth.invitation_accepted': { target: 'user', details: empty },
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
    details: z.strictObject({
      instanceAdmin: z.boolean(),
      passwordChangeRequired: z.boolean(),
      invited: z.boolean(),
    }),
  },
  'user.updated': {
    target: 'user',
    details: z.strictObject({
      changes: changesOf(USER_CHANGE_FIELDS, 10),
      passwordReset: z.boolean(),
    }),
  },
  /** Mail E2 A8: an invitation sent (or sent again, `resend`). */
  'user.invited': { target: 'user', details: z.strictObject({ resend: z.boolean() }) },
  'user.invitation_revoked': { target: 'user', details: empty },
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
  /** 6N: an MCP client registered itself (RFC 7591). */
  'oauth.client_registered': {
    target: 'oauth_client',
    details: z.strictObject({ clientId: url, name: str, source: z.enum(['dcr']) }),
  },
  'oauth.grant_created': {
    target: 'oauth_grant',
    details: z.strictObject({
      clientId: url,
      clientName: str,
      scopes: z.array(z.enum(['mcp:read', 'mcp:write'])).max(2),
    }),
  },
  'oauth.grant_revoked': {
    target: 'oauth_grant',
    details: z.strictObject({
      clientId: url,
      reason: z.enum(['user', 'admin', 'refresh_reuse', 'code_reuse']),
    }),
  },
  'oauth.settings_changed': {
    target: 'mcp_settings',
    details: z.strictObject({
      dcr: z.boolean(),
      cimd: z.boolean(),
      allowedClients: z.number().int().min(0).max(100),
    }),
  },
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
      /** The profile's own scope override after the change (0.13; older events lack it). */
      scopeOverride: z.enum(RULE_SCOPES).nullable(),
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
      mcpClientId: url.nullable().optional(),
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
  'mail.settings_updated': {
    target: 'mail_settings',
    details: z.strictObject({
      changed: z
        .array(z.enum(MAIL_SETTINGS_CHANGED_FIELDS))
        .max(MAIL_SETTINGS_CHANGED_FIELDS.length),
    }),
  },
  'mail.test_sent': {
    target: 'mail_settings',
    details: z.strictObject({ messageId: id, delivered: z.boolean() }),
  },
  'organization.auto_fix_changed': {
    target: 'organization',
    details: z.strictObject({
      enabled: z.boolean(),
      minSeverity: z.enum(SEVERITIES),
      // 4E-3a §2: 1–25, as llm/settings.ts MAX_AUTO_FIX_PER_ANALYSIS.
      maxPerAnalysis: z.number().int().min(1).max(25),
    }),
  },
  'project.auto_fix_changed': {
    target: 'project',
    details: z.strictObject({ enabled: z.boolean() }),
  },
  // 6I-2 (D4, C1): PUT /organizations/:id/ai/review changed the organisation's AI review.
  // `consentGiven`: the change recorded the data-sharing acknowledgement; the provider is the one
  // configured when it was made (null without one).
  'organization.ai_review_changed': {
    target: 'organization',
    details: z.strictObject({
      enabled: z.boolean(),
      scope: z.enum(REVIEW_SCOPES),
      // The projects listed (llm.md §3.3: at most 1 000).
      projects: z.number().int().min(0).max(1_000),
      consentGiven: z.boolean(),
      providerHost: str.nullable(),
      model: str.nullable(),
    }),
  },
  // 6M §5: PUT /organizations/:id/license-policy changed the policy; `null` is no policy.
  'organization.license_policy_changed': {
    target: 'organization',
    details: z.strictObject({ before: licensePolicy, after: licensePolicy }),
  },
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
  'compliance.report.created': {
    target: 'compliance_report',
    details: z.strictObject({ scope: z.enum(['project', 'organization']), branch: str.nullable() }),
  },
  'compliance.report.downloaded': {
    target: 'compliance_report',
    details: z.strictObject({
      format: z.enum(['json', 'csv', 'pdf']),
      sha256: z.string().regex(/^[0-9a-f]{64}$/),
    }),
  },
  'compliance.report.deleted': {
    target: 'compliance_report',
    details: z.strictObject({ scope: z.enum(['project', 'organization']) }),
  },
  // 4E-3b §4: an instance admin downloaded the support bundle; it names no target.
  'support.bundle_downloaded': {
    target: null,
    details: z.strictObject({
      source: z.literal('ui'),
      bytes: z.number().int().min(0).refine(Number.isSafeInteger),
    }),
  },
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
