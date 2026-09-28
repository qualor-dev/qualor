import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { z } from 'zod';
import { AUDIT_ACTIONS, AUDIT_CATALOGUE, urlOrigin, type AuditAction } from './catalogue';

/** A sample id for every id field of the samples below. */
const ID = '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e5f';

const SSO_SAMPLES: Record<string, unknown> = {
  'auth.sign_in': { method: 'oidc', connectionId: ID },
  'auth.password_sign_in_forced': { storedPolicy: 'break_glass_only' },
  'sso.sign_in_failed': { connectionId: ID, protocol: 'saml', reason: 'replayed' },
  'sso.user_provisioned': { connectionId: ID, emailSet: true },
  'sso.identity_linked': { connectionId: ID, method: 'verified_email' },
  'sso.identity_unlinked': { connectionId: ID, byAdmin: false },
  'sso.connection_created': { name: 'Acme', protocol: 'oidc', host: 'idp.example' },
  'sso.connection_updated': { changed: ['clientSecret', 'enabled'] },
  'sso.connection_deleted': {
    name: 'Acme',
    protocol: 'oidc',
    identities: 3,
    managedMemberships: 2,
  },
  'sso.group_mappings_replaced': { count: 4, added: 2, removed: 1 },
  'sso.sign_in_settings_updated': { passwordSignIn: 'break_glass_only', breakGlassUserIds: [ID] },
  'scim_token.created': {
    connectionId: ID,
    name: 'Entra',
    prefix: 'qlr_scim_abc',
    expiresAt: null,
  },
  'scim_token.revoked': { connectionId: ID, name: 'Entra', prefix: 'qlr_scim_abc' },
  'scim.user_created': { scimTokenId: ID, connectionId: ID, linkedExisting: false },
  'scim.user_updated': {
    scimTokenId: ID,
    connectionId: ID,
    changes: [{ field: 'displayName', from: 'A', to: 'B' }],
  },
  'scim.user_deactivated': {
    scimTokenId: ID,
    connectionId: ID,
    sessionsEnded: 2,
    tokensRevoked: 1,
  },
  'scim.user_reactivated': { scimTokenId: ID, connectionId: ID },
  'scim.user_deleted': { scimTokenId: ID, connectionId: ID, sessionsEnded: 0, tokensRevoked: 0 },
  'scim.group_created': {
    scimTokenId: ID,
    connectionId: ID,
    displayName: 'Devs',
    members: 3,
    unknownMembers: 0,
  },
  'scim.group_updated': {
    scimTokenId: ID,
    connectionId: ID,
    displayName: 'Devs',
    membersAdded: 1,
    membersRemoved: 0,
    unknownMembers: 0,
    renamed: false,
  },
  'scim.group_deleted': { scimTokenId: ID, connectionId: ID, displayName: 'Devs', members: 3 },
};

describe('the audit catalogue (rbac-audit.md §8)', () => {
  // The design specs are kept outside the public repository; this parity check runs where they exist.
  it.runIf(existsSync('docs/spec/rbac-audit.md') && existsSync('docs/spec/sso-scim.md'))(
    'names every action of the spec table and no other',
    () => {
      const spec = readFileSync('docs/spec/rbac-audit.md', 'utf8');
      const section = spec.slice(
        spec.indexOf('## 8. The audit catalogue'),
        spec.indexOf('### 8.1 Community'),
      );
      const named = new Set<string>();
      for (const m of section.matchAll(/^\|\s*`([a-z_]+\.[a-z_]+)`((?:, `\.[a-z_]+`)*)/gm)) {
        const base = m[1]!;
        named.add(base);
        const prefix = base.slice(0, base.indexOf('.'));
        for (const tail of m[2]!.matchAll(/`\.([a-z_]+)`/g)) named.add(`${prefix}.${tail[1]}`);
      }
      for (const m of section.matchAll(/`(project_member\.[a-z_]+)`/g)) named.add(m[1]!);

      // sso-scim.md §15 (4D): the SSO and SCIM additions. Every action there is spelled out in full
      // (no `quality_gate.created`, `.updated`, ... abbreviation), so one broad scan is enough; the
      // wildcard rows (`member.*`, `project_member.*`) never match (the `.[a-z_]+` tail requires a
      // letter or underscore right after the dot, never `*`), so they add nothing already covered.
      const ssoSpec = readFileSync('docs/spec/sso-scim.md', 'utf8');
      const ssoSection = ssoSpec.slice(
        ssoSpec.indexOf('## 15. Audit catalogue additions'),
        ssoSpec.indexOf('## 16. Core API changes'),
      );
      for (const m of ssoSection.matchAll(/`([a-z_]+\.[a-z_]+)`/g)) named.add(m[1]!);

      expect([...named].sort()).toEqual([...AUDIT_ACTIONS].sort());
    },
  );

  it.each(Object.entries(SSO_SAMPLES))('accepts the 4D details of %s', (action, details) => {
    expect(AUDIT_CATALOGUE[action as AuditAction].details.safeParse(details).success).toBe(true);
  });

  it('keeps password sign-in details valid, adds forced, refuses a secret-looking field', () => {
    const d = AUDIT_CATALOGUE['auth.sign_in'].details;
    expect(d.safeParse({ method: 'password' }).success).toBe(true);
    expect(d.safeParse({ method: 'password', forced: true }).success).toBe(true);
    expect(d.safeParse({ method: 'oidc', connectionId: ID, idToken: 'x' }).success).toBe(false);
    expect(
      AUDIT_CATALOGUE['auth.sign_in_failed'].details.safeParse({
        reason: 'password_disabled',
        knownUser: true,
      }).success,
    ).toBe(true);
    expect(
      AUDIT_CATALOGUE['member.added'].details.safeParse({ role: 'member', managedBy: ID }).success,
    ).toBe(true);
    expect(
      AUDIT_CATALOGUE['sso.connection_updated'].details.safeParse({ changed: ['issuer?'] }).success,
    ).toBe(false);
  });

  /** The secret-looking field names the check below catches. */
  const SECRET_NAME = /secret|password|token$|key$|apiKey|cookie|comment$|prompt/i;
  const isIdentifier = (valid: string) => (s: z.ZodType) =>
    s.safeParse(valid).success &&
    !s.safeParse('not an identifier!').success &&
    !s.safeParse('').success &&
    !s.safeParse('x'.repeat(2000)).success;
  /*
   * The (action, field) pairs spec §8 names that match the pattern but cannot hold a secret, each
   * pinned to a schema that proves it: flags, a three-value enum, and public identifiers bound to
   * their formats (an organisation or project key, a rule key). Any other matching pair fails.
   */
  const ALLOWED: Record<string, (schema: z.ZodType) => boolean> = {
    'organization.created.key': isIdentifier('acme'),
    'project.created.key': isIdentifier('acme:web'),
    'project.deleted.key': isIdentifier('acme:web'),
    'quality_profile.rule_set.ruleKey': isIdentifier('eslint:no-eval'),
    'quality_profile.rule_reset.ruleKey': isIdentifier('eslint:no-eval'),
    'user.created.passwordChangeRequired': (s) => s instanceof z.ZodBoolean,
    'user.updated.passwordReset': (s) => s instanceof z.ZodBoolean,
    'ai.settings_updated.apiKey': (s) =>
      s instanceof z.ZodEnum && [...s.options].sort().join() === 'kept,removed,set',
    // sso-scim.md §10.1: the stored policy name, never a password itself.
    'sso.sign_in_settings_updated.passwordSignIn': (s) =>
      s instanceof z.ZodEnum && [...s.options].sort().join() === 'break_glass_only,everyone',
  };

  function secretNameViolations(catalogue: Record<string, { details: z.ZodType }>): string[] {
    const found: string[] = [];
    for (const [action, entry] of Object.entries(catalogue)) {
      const shape = (entry.details as unknown as { shape?: Record<string, z.ZodType> }).shape ?? {};
      for (const [field, schema] of Object.entries(shape)) {
        if (!SECRET_NAME.test(field)) continue;
        const pair = `${action}.${field}`;
        if (ALLOWED[pair]?.(schema) !== true) found.push(pair);
      }
    }
    return found;
  }

  it('refuses a secret-looking field in any details schema', () => {
    expect(secretNameViolations(AUDIT_CATALOGUE)).toEqual([]);
  });

  it('fails the secret-name check for a new action or a free-text key', () => {
    expect(
      secretNameViolations({
        'thing.created': { details: z.strictObject({ key: z.string() }) },
        'organization.created': { details: z.strictObject({ key: z.string(), name: z.string() }) },
        'user.created': { details: z.strictObject({ passwordChangeRequired: z.string() }) },
      }),
    ).toEqual([
      'thing.created.key',
      'organization.created.key',
      'user.created.passwordChangeRequired',
    ]);
  });

  it.each([
    [
      'user.updated',
      { changes: [{ field: 'password', from: null, to: 'hunter2' }], passwordReset: true },
    ],
    ['project.updated', { changes: [{ field: 'password', from: null, to: 'hunter2' }] }],
    ['quality_profile.updated', { changes: [{ field: 'password', from: null, to: 'hunter2' }] }],
    ['scm_connection.updated', { changed: ['password'] }],
  ] as const)('%s refuses a field outside the spec list (password)', (action, details) => {
    expect(AUDIT_CATALOGUE[action].details.safeParse(details).success).toBe(false);
  });

  it('accepts the spec fields of each change list', () => {
    const one = (field: string) => ({ changes: [{ field, from: 'a', to: 'b' }] });
    for (const field of ['displayName', 'email', 'active', 'isInstanceAdmin'])
      expect(
        AUDIT_CATALOGUE['user.updated'].details.safeParse({ ...one(field), passwordReset: false })
          .success,
      ).toBe(true);
    for (const field of [
      'name',
      'mainBranchName',
      'newCodeDefinition',
      'qualityGateId',
      'scmConnectionId',
      'scmProjectRef',
    ])
      expect(AUDIT_CATALOGUE['project.updated'].details.safeParse(one(field)).success).toBe(true);
    for (const field of ['name', 'unknownRules'])
      expect(AUDIT_CATALOGUE['quality_profile.updated'].details.safeParse(one(field)).success).toBe(
        true,
      );
    expect(
      AUDIT_CATALOGUE['scm_connection.updated'].details.safeParse({
        changed: ['baseUrl', 'token', 'appId', 'privateKey', 'webhookSecret'],
      }).success,
    ).toBe(true);
  });

  it('bounds an anchor seq to MAX_SAFE_INTEGER', () => {
    const pruned = (throughSeq: string) =>
      AUDIT_CATALOGUE['audit.pruned'].details.safeParse({
        throughSeq,
        throughHash: 'a'.repeat(64),
        deleted: 1,
        cutoff: '2026-01-01T00:00:00.000Z',
      }).success;
    expect(pruned(String(Number.MAX_SAFE_INTEGER))).toBe(true);
    expect(pruned('9007199254740992')).toBe(false);
    expect(pruned('9999999999999999999')).toBe(false);
    expect(pruned('007')).toBe(false);
  });

  it('refuses unknown fields in every details schema (strict objects)', () => {
    for (const action of AUDIT_ACTIONS) {
      const schema = AUDIT_CATALOGUE[action].details;
      expect(schema.safeParse({ password: 'hunter2' }).success, action).toBe(false);
    }
  });

  it('keeps only the origin of a URL', () => {
    expect(urlOrigin('https://hooks.slack.com/services/T0/B0/SECRET?x=1')).toBe(
      'https://hooks.slack.com',
    );
    expect(urlOrigin('https://siem.example:8443/in')).toBe('https://siem.example:8443');
    expect(urlOrigin('https://user:pass@siem.example/in')).toBe('https://siem.example');
  });
});
