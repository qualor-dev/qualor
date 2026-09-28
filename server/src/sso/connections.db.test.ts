import { asc, eq, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestContext, type TestContext } from '../../test/app';
import { BUSINESS_FEATURES, ENTERPRISE_FEATURES } from '../../test/license';
import { TEST_IDP, TEST_SP } from '../../test/saml';
import { licensedEdition } from '../../test/sso';
import { createAuditRecorder, SYSTEM_ACTOR } from '../audit/recorder';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import { createDatabase } from '../db/client';
import { LOCKS } from '../db/locks';
import {
  auditEvents,
  identities,
  memberships,
  organizations,
  scimTokens,
  ssoConnections,
  ssoGroupMappings,
  users,
} from '../db/schema';
import {
  connectionsInEffect,
  createConnection,
  deleteConnection,
  getConnection,
  inEffectConnectionIds,
  listConnections,
  loadConnection,
  updateConnection,
  type ConnectionDeps,
} from './connections';
import { createScimToken } from '../scim/tokens';
import { SP_KEY_AAD } from './connection-config';
import { updateSignInSettings } from './sign-in-policy';

/** Built at run time, so the source holds no such character. */
const NUL = String.fromCharCode(0);
const LONE = String.fromCharCode(0xd800);
const TAB = String.fromCharCode(9);
/** U+202E RIGHT-TO-LEFT OVERRIDE, a bidi format character. */
const RLO = String.fromCharCode(0x202e);
const OIDC = { issuer: 'https://t.example', clientId: 'q', clientSecret: 's' };
const SAML = {
  idpEntityId: 'https://idp.example/saml',
  idpSsoUrl: 'https://idp.example/sso',
  idpCertificates: [TEST_IDP.certPem],
};

describe('SSO connections (sso-scim.md §4, §13)', () => {
  let ctx: TestContext;
  let deps: ConnectionDeps;
  beforeAll(async () => {
    ctx = await createTestContext({ config: { publicUrl: 'https://q.example' } });
    deps = {
      db: ctx.db,
      config: {
        secretKey: ctx.config.secretKey,
        publicUrl: 'https://q.example',
        ssoInternalHosts: new Set(),
      },
      audit: createAuditRecorder({ isActive: () => false, log: { error() {} } }),
      // Several connections are enabled at once below: sso.multi (sso-scim.md §4.4).
      edition: licensedEdition(ENTERPRISE_FEATURES),
    };
  });
  afterAll(async () => ctx.close());

  it('stores the client secret encrypted, never returns it, and decrypts it for the flow', async () => {
    const view = await createConnection(deps, SYSTEM_ACTOR, {
      name: 'Acme',
      protocol: 'oidc',
      oidc: {
        issuer: 'https://idp.example/realms/acme',
        clientId: 'q',
        clientSecret: 'shh-client-secret',
      },
    });
    expect(view.oidc).toMatchObject({ clientSecretSet: true, clientAuth: 'client_secret_basic' });
    expect(JSON.stringify(view)).not.toContain('shh-client-secret');
    const [row] = await ctx.db.select().from(ssoConnections).where(eq(ssoConnections.id, view.id));
    expect(JSON.stringify(row)).not.toContain('shh-client-secret');
    const loaded = await loadConnection(ctx.db, view.id, ctx.config.secretKey);
    expect(loaded?.clientSecret).toBe('shh-client-secret');
    expect(view.urls?.redirectUri).toBe(`https://q.example/api/v0/ee/sso/oidc/${view.id}/callback`);
  });

  it('refuses an http issuer unless listed, and a private address', async () => {
    await expect(
      createConnection(deps, SYSTEM_ACTOR, {
        name: 'Http',
        protocol: 'oidc',
        oidc: { issuer: 'http://idp.example', clientId: 'q', clientSecret: 's' },
      }),
    ).rejects.toMatchObject({ status: 422, errors: [{ path: 'body.oidc.issuer' }] });
    await expect(
      createConnection(deps, SYSTEM_ACTOR, {
        name: 'Private',
        protocol: 'oidc',
        oidc: { issuer: 'https://10.0.0.5', clientId: 'q', clientSecret: 's' },
      }),
    ).rejects.toMatchObject({ status: 422 });
    const listed = {
      ...deps,
      config: { ...deps.config, ssoInternalHosts: new Set(['127.0.0.1:18080']) },
    };
    await expect(
      createConnection(listed, SYSTEM_ACTOR, {
        name: 'Local',
        protocol: 'oidc',
        oidc: { issuer: 'http://127.0.0.1:18080/realms/q', clientId: 'q', clientSecret: 's' },
      }),
    ).resolves.toMatchObject({ name: 'Local' });
  });

  it('needs the client secret again when the issuer changes', async () => {
    const view = await createConnection(deps, SYSTEM_ACTOR, {
      name: 'Moves',
      protocol: 'oidc',
      oidc: { issuer: 'https://a.example', clientId: 'q', clientSecret: 's' },
    });
    await expect(
      updateConnection(deps, SYSTEM_ACTOR, view.id, { oidc: { issuer: 'https://b.example' } }),
    ).rejects.toMatchObject({ status: 422, errors: [{ path: 'body.oidc.clientSecret' }] });
    const moved = await updateConnection(deps, SYSTEM_ACTOR, view.id, {
      oidc: { issuer: 'https://b.example/', clientSecret: 'new-secret' },
      claims: { groups: 'roles' },
    });
    // spec §4.2: the issuer is kept as given, trailing slash included (discovery matches exactly).
    expect(moved.oidc).toMatchObject({ issuer: 'https://b.example/', clientId: 'q' });
    expect(moved.claims).toEqual({
      username: 'preferred_username',
      email: 'email',
      displayName: 'name',
      groups: 'roles',
    });
    const loaded = await loadConnection(ctx.db, view.id, ctx.config.secretKey);
    expect(loaded?.clientSecret).toBe('new-secret');
  });

  it('stores a SAML connection with its certificate fingerprints', async () => {
    const view = await createConnection(deps, SYSTEM_ACTOR, {
      name: 'Saml',
      protocol: 'saml',
      saml: {
        idpEntityId: 'https://idp.example/saml',
        idpSsoUrl: 'https://idp.example/sso',
        idpCertificates: [TEST_IDP.certPem],
      },
    });
    expect(view.saml?.idpCertificates[0]).toMatchObject({
      sha256: expect.stringMatching(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/),
      expired: false,
    });
    expect(view.saml).toMatchObject({ spKeySet: false, spCertificate: null });
    expect(view.oidc).toBeNull();
    expect(view.urls?.acsUrl).toBe(`https://q.example/api/v0/ee/sso/saml/${view.id}/acs`);
  });

  it('accepts SAML URLs with a query (Google, Entra ID), never with a fragment or credentials', async () => {
    const saml = {
      idpEntityId: 'https://accounts.google.com/o/saml2?idpid=C0abc',
      idpSsoUrl: 'https://accounts.google.com/o/saml2/idp?idpid=C0abc123',
      idpCertificates: [TEST_IDP.certPem],
      metadataUrl:
        'https://login.microsoftonline.com/t1/federationmetadata/2007-06/federationmetadata.xml?appid=a1b2',
    };
    const view = await createConnection(deps, SYSTEM_ACTOR, {
      name: 'Google',
      protocol: 'saml',
      saml,
    });
    expect(view.saml).toMatchObject({ idpSsoUrl: saml.idpSsoUrl, metadataUrl: saml.metadataUrl });
    await expect(
      updateConnection(deps, SYSTEM_ACTOR, view.id, {
        saml: { idpSsoUrl: 'https://idp.example/sso#frag' },
      }),
    ).rejects.toMatchObject({ status: 422, errors: [{ path: 'body.saml.idpSsoUrl' }] });
    await expect(
      updateConnection(deps, SYSTEM_ACTOR, view.id, {
        saml: { metadataUrl: 'https://user:pass@idp.example/metadata?appid=1' },
      }),
    ).rejects.toMatchObject({ status: 422, errors: [{ path: 'body.saml.metadataUrl' }] });
    await deleteConnection(deps, SYSTEM_ACTOR, view.id);
  });

  it('refuses a certificate that is not X.509, or an RSA key under 2048 bits', async () => {
    await expect(
      createConnection(deps, SYSTEM_ACTOR, {
        name: 'Bad',
        protocol: 'saml',
        saml: {
          idpEntityId: 'x',
          idpSsoUrl: 'https://idp.example/sso',
          idpCertificates: ['not a cert'],
        },
      }),
    ).rejects.toMatchObject({ status: 422, errors: [{ path: 'body.saml.idpCertificates.0' }] });
  });

  it('stores an SP key encrypted with its certificate, and refuses a key without one', async () => {
    const saml = {
      idpEntityId: 'https://idp.example/saml',
      idpSsoUrl: 'https://idp.example/sso',
      idpCertificates: [TEST_IDP.certPem],
    };
    await expect(
      createConnection(deps, SYSTEM_ACTOR, {
        name: 'NoCert',
        protocol: 'saml',
        saml: { ...saml, spKey: TEST_SP.keyPem },
      }),
    ).rejects.toMatchObject({ status: 422, errors: [{ path: 'body.saml.spCertificate' }] });
    await expect(
      createConnection(deps, SYSTEM_ACTOR, {
        name: 'Mismatch',
        protocol: 'saml',
        saml: { ...saml, spKey: TEST_SP.keyPem, spCertificate: TEST_IDP.certPem },
      }),
    ).rejects.toMatchObject({ status: 422, errors: [{ path: 'body.saml.spCertificate' }] });
    const view = await createConnection(deps, SYSTEM_ACTOR, {
      name: 'Signed',
      protocol: 'saml',
      saml: { ...saml, spKey: TEST_SP.keyPem, spCertificate: TEST_SP.certPem },
    });
    expect(view.saml).toMatchObject({ spKeySet: true });
    expect(JSON.stringify(view)).not.toContain('PRIVATE KEY');
    const [row] = await ctx.db.select().from(ssoConnections).where(eq(ssoConnections.id, view.id));
    expect(JSON.stringify(row)).not.toContain('PRIVATE KEY');
    const loaded = await loadConnection(ctx.db, view.id, ctx.config.secretKey);
    expect(loaded?.spKey).toContain('PRIVATE KEY');
    expect(loaded?.clientSecret).toBeNull();
  });

  it('refuses fields of the other protocol and a missing client secret', async () => {
    await expect(
      createConnection(deps, SYSTEM_ACTOR, {
        name: 'Mixed',
        protocol: 'oidc',
        oidc: { issuer: 'https://m.example', clientId: 'q', clientSecret: 's' },
        saml: {
          idpEntityId: 'x',
          idpSsoUrl: 'https://idp.example/sso',
          idpCertificates: [TEST_IDP.certPem],
        },
      }),
    ).rejects.toMatchObject({ status: 422, errors: [{ path: 'body.saml' }] });
    await expect(
      createConnection(deps, SYSTEM_ACTOR, {
        name: 'NoSecret',
        protocol: 'oidc',
        oidc: { issuer: 'https://m.example', clientId: 'q' },
      }),
    ).rejects.toMatchObject({ status: 422, errors: [{ path: 'body.oidc.clientSecret' }] });
    await expect(
      createConnection(deps, SYSTEM_ACTOR, {
        name: 'Bad\u0007name',
        protocol: 'oidc',
        oidc: { issuer: 'https://m.example', clientId: 'q', clientSecret: 's' },
      }),
    ).rejects.toMatchObject({ status: 422, errors: [{ path: 'body.name' }] });
  });

  it('reads a stored config that no longer parses as unusable, never as a 500', async () => {
    const view = await createConnection(deps, SYSTEM_ACTOR, {
      name: 'Broken',
      protocol: 'oidc',
      oidc: { issuer: 'https://broken.example', clientId: 'q', clientSecret: 's' },
    });
    await ctx.db
      .update(ssoConnections)
      .set({ config: { issuer: 42 } })
      .where(eq(ssoConnections.id, view.id));
    expect(await loadConnection(ctx.db, view.id, ctx.config.secretKey)).toBeNull();
    expect(
      await loadConnection(ctx.db, view.id, 'another-secret-key-of-32-characters!!'),
    ).toBeNull();
    await expect(getConnection(deps, view.id)).resolves.toMatchObject({ oidc: null, saml: null });
    await deleteConnection(deps, SYSTEM_ACTOR, view.id);
  });

  it.each([
    ['oidc.clientId', (bad: string) => ({ oidc: { ...OIDC, clientId: `q${bad}` } })],
    ['oidc.clientSecret', (bad: string) => ({ oidc: { ...OIDC, clientSecret: `s${bad}` } })],
    ['oidc.issuer', (bad: string) => ({ oidc: { ...OIDC, issuer: `https://t.example/${bad}` } })],
    [
      'requiredClaims.0.value',
      (bad: string) => ({ oidc: OIDC, requiredClaims: [{ claim: 'hd', value: `x${bad}` }] }),
    ],
    ['saml.idpEntityId', (bad: string) => ({ saml: { ...SAML, idpEntityId: `e${bad}` } })],
    [
      'saml.idpSsoUrl',
      (bad: string) => ({ saml: { ...SAML, idpSsoUrl: `https://idp.example/${bad}` } }),
    ],
    [
      'saml.metadataUrl',
      (bad: string) => ({ saml: { ...SAML, metadataUrl: `https://idp.example/${bad}` } }),
    ],
    [
      'saml.idpCertificates.0',
      (bad: string) => ({ saml: { ...SAML, idpCertificates: [`${TEST_IDP.certPem}${bad}`] } }),
    ],
    [
      'saml.spCertificate',
      (bad: string) => ({
        saml: { ...SAML, spKey: TEST_SP.keyPem, spCertificate: `${TEST_SP.certPem}${bad}` },
      }),
    ],
    [
      'saml.spKey',
      (bad: string) => ({
        saml: { ...SAML, spKey: `${TEST_SP.keyPem}${bad}`, spCertificate: TEST_SP.certPem },
      }),
    ],
  ] as const)(
    'refuses NUL and a lone surrogate in %s with a 422 on its path',
    async (path, body) => {
      for (const bad of [NUL, LONE]) {
        const fields = body(bad);
        await expect(
          createConnection(deps, SYSTEM_ACTOR, {
            name: 'Unstorable',
            protocol: 'oidc' in fields ? 'oidc' : 'saml',
            ...fields,
          }),
        ).rejects.toMatchObject({ status: 422, errors: [{ path: `body.${path}` }] });
      }
    },
  );

  it('refuses URLs with tabs, line breaks or spaces at either end, instead of dropping them', async () => {
    for (const issuer of [
      ' https://t.example',
      'https://t.example ',
      `https://t.exa${TAB}mple`,
      'https://t.example/a\nb',
    ]) {
      await expect(
        createConnection(deps, SYSTEM_ACTOR, {
          name: 'Blank',
          protocol: 'oidc',
          oidc: { ...OIDC, issuer },
        }),
      ).rejects.toMatchObject({ status: 422, errors: [{ path: 'body.oidc.issuer' }] });
    }
    await expect(
      createConnection(deps, SYSTEM_ACTOR, {
        name: 'Blank',
        protocol: 'saml',
        saml: { ...SAML, idpSsoUrl: `https://idp.example/sso?a=1${TAB}` },
      }),
    ).rejects.toMatchObject({ status: 422, errors: [{ path: 'body.saml.idpSsoUrl' }] });
  });

  it('trims the name, and refuses an empty one or one with a bidi or control character', async () => {
    await expect(
      createConnection(deps, SYSTEM_ACTOR, { name: '  acme  ', protocol: 'oidc', oidc: OIDC }),
    ).rejects.toMatchObject({ status: 409, code: 'SSO_CONNECTION_NAME_TAKEN' });
    for (const name of ['   ', `Ac${RLO}me`, `Ac${TAB}me`, `Ac${LONE}me`]) {
      await expect(
        createConnection(deps, SYSTEM_ACTOR, { name, protocol: 'oidc', oidc: OIDC }),
      ).rejects.toMatchObject({ status: 422, errors: [{ path: 'body.name' }] });
    }
    const view = await createConnection(deps, SYSTEM_ACTOR, {
      name: ' Trimmed ',
      protocol: 'oidc',
      oidc: OIDC,
    });
    expect(view.name).toBe('Trimmed');
    await deleteConnection(deps, SYSTEM_ACTOR, view.id);
  });

  it('reads a valid row under another QUALOR_SECRET_KEY with no client secret', async () => {
    const acme = (await listConnections(deps)).find((c) => c.name === 'Acme')!;
    const loaded = await loadConnection(ctx.db, acme.id, 'another-secret-key-of-32-characters!!');
    expect(loaded).toMatchObject({ parsed: { protocol: 'oidc' }, clientSecret: null });
  });

  it('keeps an SP key that no longer decrypts through changes that do not touch it', async () => {
    const view = await createConnection(deps, SYSTEM_ACTOR, {
      name: 'Rotated',
      protocol: 'saml',
      saml: { ...SAML, spKey: TEST_SP.keyPem, spCertificate: TEST_SP.certPem },
    });
    const foreign = encryptSecret(
      encryptionKey('another-secret-key-of-32-characters!!'),
      'x',
      SP_KEY_AAD,
    );
    await ctx.db
      .update(ssoConnections)
      .set({ spKeyEnc: foreign })
      .where(eq(ssoConnections.id, view.id));
    await expect(
      updateConnection(deps, SYSTEM_ACTOR, view.id, { enabled: false }),
    ).resolves.toMatchObject({ saml: { spKeySet: true } });
    await expect(
      updateConnection(deps, SYSTEM_ACTOR, view.id, {
        name: 'Rotated again',
        saml: { emailVerified: true },
      }),
    ).resolves.toMatchObject({
      name: 'Rotated again',
      saml: { emailVerified: true, spKeySet: true },
    });
    // Touching the pair needs the key again.
    await expect(
      updateConnection(deps, SYSTEM_ACTOR, view.id, { saml: { spCertificate: TEST_SP.certPem } }),
    ).rejects.toMatchObject({ status: 422, errors: [{ path: 'body.saml.spKey' }] });
    await deleteConnection(deps, SYSTEM_ACTOR, view.id);
  });

  it('refuses a duplicate name in another case, and an 11th connection', async () => {
    await expect(
      createConnection(deps, SYSTEM_ACTOR, {
        name: 'ACME',
        protocol: 'oidc',
        oidc: { issuer: 'https://c.example', clientId: 'q', clientSecret: 's' },
      }),
    ).rejects.toMatchObject({ status: 409, code: 'SSO_CONNECTION_NAME_TAKEN' });
    const existing = (await listConnections(deps)).length;
    for (let i = existing; i < 10; i += 1) {
      await createConnection(deps, SYSTEM_ACTOR, {
        name: `n${i}`,
        protocol: 'oidc',
        oidc: { issuer: `https://n${i}.example`, clientId: 'q', clientSecret: 's' },
      });
    }
    await expect(
      createConnection(deps, SYSTEM_ACTOR, {
        name: 'eleven',
        protocol: 'oidc',
        oidc: { issuer: 'https://eleven.example', clientId: 'q', clientSecret: 's' },
      }),
    ).rejects.toMatchObject({ status: 409, code: 'SSO_CONNECTION_LIMIT_REACHED' });
  });

  it('refuses to enable a connection without QUALOR_PUBLIC_URL', async () => {
    const noUrl = { ...deps, config: { ...deps.config, publicUrl: null } };
    const [first] = await listConnections(deps);
    await expect(
      updateConnection(noUrl, SYSTEM_ACTOR, first!.id, { enabled: true }),
    ).rejects.toMatchObject({
      status: 409,
      code: 'PUBLIC_URL_REQUIRED',
    });
    expect((await getConnection(noUrl, first!.id)).urls).toBeNull();
  });

  it('lists only the enabled connections for the sign-in page, by name', async () => {
    const all = await listConnections(deps);
    const saml = all.find((c) => c.name === 'Saml')!;
    const acme = all.find((c) => c.name === 'Acme')!;
    await updateConnection(deps, SYSTEM_ACTOR, saml.id, { enabled: true });
    await updateConnection(deps, SYSTEM_ACTOR, acme.id, { enabled: true });
    expect(await connectionsInEffect(ctx.db, deps.edition)).toEqual([
      { id: acme.id, name: 'Acme', protocol: 'oidc' },
      { id: saml.id, name: 'Saml', protocol: 'saml' },
    ]);
  });

  it('deletes, then answers 404', async () => {
    const [first] = await listConnections(deps);
    await deleteConnection(deps, SYSTEM_ACTOR, first!.id);
    await expect(getConnection(deps, first!.id)).rejects.toMatchObject({ status: 404 });
    await expect(deleteConnection(deps, SYSTEM_ACTOR, first!.id)).rejects.toMatchObject({
      status: 404,
    });
  });

  it('records created, updated (field names only) and deleted, never a secret', async () => {
    const audited = {
      ...deps,
      audit: createAuditRecorder({ isActive: () => true, log: { error() {} } }),
    };
    const view = await createConnection(audited, SYSTEM_ACTOR, {
      name: 'Audited',
      protocol: 'oidc',
      oidc: {
        issuer: 'https://idp.audited.example/realms/a',
        clientId: 'q',
        clientSecret: 'first-secret',
      },
    });
    await updateConnection(audited, SYSTEM_ACTOR, view.id, {
      enabled: true,
      jit: false,
      oidc: { clientId: 'q2', clientSecret: 'second-secret' },
    });
    await ctx.db.insert(identities).values({
      connectionId: view.id,
      userId: ctx.adminId,
      subject: 'sub-admin',
      linkedBy: 'user',
    });
    await ctx.db
      .update(memberships)
      .set({ managedByConnectionId: view.id })
      .where(eq(memberships.userId, ctx.adminId));
    await deleteConnection(audited, SYSTEM_ACTOR, view.id);
    // The memberships it managed stay, as manual ones (spec §13: SET NULL).
    const kept = await ctx.db.select().from(memberships).where(eq(memberships.userId, ctx.adminId));
    expect(kept.length).toBeGreaterThan(0);
    expect(kept.every((m) => m.managedByConnectionId === null)).toBe(true);
    const events = await ctx.db
      .select()
      .from(auditEvents)
      .where(eq(auditEvents.targetId, view.id))
      .orderBy(asc(auditEvents.seq));
    expect(events.map((e) => [e.action, e.targetType, e.details])).toEqual([
      [
        'sso.connection_created',
        'sso_connection',
        { name: 'Audited', protocol: 'oidc', host: 'idp.audited.example' },
      ],
      [
        'sso.connection_updated',
        'sso_connection',
        { changed: ['enabled', 'jit', 'clientId', 'clientSecret'] },
      ],
      [
        'sso.connection_deleted',
        'sso_connection',
        { name: 'Audited', protocol: 'oidc', identities: 1, managedMemberships: 1 },
      ],
    ]);
    expect(JSON.stringify(events)).not.toMatch(/first-secret|second-secret/);
  });
});

describe('the last enabled connection while password sign-in is limited', () => {
  let ctx: TestContext;
  let deps: ConnectionDeps;
  const make = async (name: string) =>
    (
      await createConnection(deps, SYSTEM_ACTOR, {
        name,
        protocol: 'oidc',
        enabled: true,
        oidc: { issuer: `https://${name.toLowerCase()}.example`, clientId: 'q', clientSecret: 's' },
      })
    ).id;
  const policy = (passwordSignIn: 'everyone' | 'break_glass_only') =>
    updateSignInSettings({ db: ctx.db, audit: deps.audit }, SYSTEM_ACTOR, {
      passwordSignIn,
      breakGlassUserIds: [ctx.adminId],
    });
  const refused = { status: 409, code: 'LAST_SSO_CONNECTION' };
  const enabled = async (id: string) =>
    (await ctx.db.select().from(ssoConnections).where(eq(ssoConnections.id, id)))[0]?.enabled;

  beforeAll(async () => {
    ctx = await createTestContext({ config: { publicUrl: 'https://q.example' } });
    deps = {
      db: ctx.db,
      config: {
        secretKey: ctx.config.secretKey,
        publicUrl: 'https://q.example',
        ssoInternalHosts: new Set(),
      },
      audit: createAuditRecorder({ isActive: () => false, log: { error() {} } }),
      // Several connections are enabled at once below: sso.multi (sso-scim.md §4.4).
      edition: licensedEdition(ENTERPRISE_FEATURES),
    };
  });
  afterAll(async () => ctx.close());

  it('refuses to disable or delete the last enabled connection (409), allows any other', async () => {
    const a = await make('Last-A');
    await policy('break_glass_only');
    await expect(updateConnection(deps, SYSTEM_ACTOR, a, { enabled: false })).rejects.toMatchObject(
      refused,
    );
    await expect(deleteConnection(deps, SYSTEM_ACTOR, a)).rejects.toMatchObject(refused);
    expect(await enabled(a)).toBe(true);
    // Other changes to it stay allowed.
    await updateConnection(deps, SYSTEM_ACTOR, a, { name: 'Last-A2', enabled: true });

    const b = await make('Last-B');
    await updateConnection(deps, SYSTEM_ACTOR, a, { enabled: false });
    // A disabled connection may go; b is now the last enabled one.
    await expect(deleteConnection(deps, SYSTEM_ACTOR, b)).rejects.toMatchObject(refused);
    await deleteConnection(deps, SYSTEM_ACTOR, a);

    // Password sign-in for everyone again: nothing is refused.
    await policy('everyone');
    await updateConnection(deps, SYSTEM_ACTOR, b, { enabled: false });
    await deleteConnection(deps, SYSTEM_ACTOR, b);
  });

  it('waits for a concurrent save of the setting (the instance-admin lock), then refuses', async () => {
    const c = await make('Last-C');
    await policy('everyone');
    const other = createDatabase(ctx.database.url, { max: 1 });
    let commit!: () => void;
    const release = new Promise<void>((resolve) => {
      commit = resolve;
    });
    try {
      let saved!: () => void;
      const written = new Promise<void>((resolve) => {
        saved = resolve;
      });
      // As updateSignInSettings does: the lock, then the row, committed later.
      const save = other.db.transaction(async (tx) => {
        await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.instanceAdmins})`);
        await tx.execute(
          sql`UPDATE instance_settings SET value = jsonb_set(value, '{passwordSignIn}', '"break_glass_only"') WHERE key = 'sign-in'`,
        );
        saved();
        await release;
      });
      await written;
      let settled = false;
      const disable = updateConnection(deps, SYSTEM_ACTOR, c, { enabled: false }).finally(() => {
        settled = true;
      });
      await new Promise((resolve) => setTimeout(resolve, 300));
      expect(settled).toBe(false);
      commit();
      await save;
      await expect(disable).rejects.toMatchObject(refused);
      expect(await enabled(c)).toBe(true);
    } finally {
      commit();
      await other.close();
    }
  });
});

describe('one connection in effect without sso.multi (sso-scim.md §4.4)', () => {
  const MULTI_REFUSED = {
    status: 409,
    code: 'SSO_MULTI_NOT_LICENSED',
    message:
      'Your plan allows one enabled single sign-on connection. Disable the enabled one first, or keep this one disabled; several enabled connections need the Enterprise plan.',
  };
  const LAST_REFUSED = { status: 409, code: 'LAST_SSO_CONNECTION' };
  let ctx: TestContext;
  /** Real signed keys on one database: an Enterprise key's edition and a Business key's. */
  let enterprise: ConnectionDeps;
  let business: ConnectionDeps;
  let counter = 0;

  const input = (name: string, enabled?: boolean) => ({
    name,
    protocol: 'oidc' as const,
    ...(enabled === undefined ? {} : { enabled }),
    oidc: { issuer: `https://${name.toLowerCase()}.example`, clientId: 'q', clientSecret: 's' },
  });
  const make = async (deps: ConnectionDeps, enabled?: boolean) => {
    counter += 1;
    return (await createConnection(deps, SYSTEM_ACTOR, input(`Conn-${counter}`, enabled))).id;
  };
  const stored = async () =>
    ctx.db
      .select({ id: ssoConnections.id, name: ssoConnections.name, enabled: ssoConnections.enabled })
      .from(ssoConnections)
      .orderBy(asc(ssoConnections.createdAt), asc(ssoConnections.id));
  const inEffect = async (deps: ConnectionDeps) =>
    Object.fromEntries((await listConnections(deps)).map((c) => [c.id, c.inEffect]));
  const inEffectIds = async (deps: ConnectionDeps) => [
    ...(await inEffectConnectionIds(ctx.db, deps.edition)),
  ];
  const policy = (passwordSignIn: 'everyone' | 'break_glass_only') =>
    updateSignInSettings({ db: ctx.db, audit: business.audit }, SYSTEM_ACTOR, {
      passwordSignIn,
      breakGlassUserIds: [ctx.adminId],
    });
  const eventCount = async () => (await ctx.db.select().from(auditEvents)).length;
  const defaultOrg = async () =>
    (
      await ctx.db
        .select({ id: organizations.id })
        .from(organizations)
        .where(eq(organizations.key, 'default'))
    )[0]!.id;
  const newUser = async (username: string) =>
    (await ctx.db.insert(users).values({ username }).returning({ id: users.id }))[0]!.id;

  beforeEach(async () => {
    ctx = await createTestContext({ config: { publicUrl: 'https://q.example' } });
    const base = {
      db: ctx.db,
      config: {
        secretKey: ctx.config.secretKey,
        publicUrl: 'https://q.example',
        ssoInternalHosts: new Set<string>(),
      },
      audit: createAuditRecorder({ isActive: () => true, log: { error() {} } }),
    };
    enterprise = { ...base, edition: licensedEdition(ENTERPRISE_FEATURES) };
    business = { ...base, edition: licensedEdition(BUSINESS_FEATURES) };
    expect(business.edition.isFeatureActive('sso')).toBe(true);
    expect(business.edition.isFeatureActive('sso.multi')).toBe(false);
    expect(enterprise.edition.isFeatureActive('sso.multi')).toBe(true);
  });
  afterEach(async () => ctx.close());

  it('without sso.multi only one connection can be enabled (409 SSO_MULTI_NOT_LICENSED)', async () => {
    // Review Focus 4. The first connection is created, then enabled: no other is enabled yet.
    const a = await make(business);
    await expect(
      updateConnection(business, SYSTEM_ACTOR, a, { enabled: true }),
    ).resolves.toMatchObject({ enabled: true, inEffect: true });

    // A second one created enabled is refused, and adds no row and no event.
    const events = await eventCount();
    await expect(
      createConnection(business, SYSTEM_ACTOR, input('Second', true)),
    ).rejects.toMatchObject(MULTI_REFUSED);
    expect(await stored()).toHaveLength(1);
    expect(await eventCount()).toBe(events);

    // Without `enabled`, or with false, it is created disabled, to be prepared.
    const b = await createConnection(business, SYSTEM_ACTOR, input('Second'));
    expect(b).toMatchObject({ enabled: false, inEffect: false });
    await expect(
      createConnection(business, SYSTEM_ACTOR, input('Third', false)),
    ).resolves.toMatchObject({ enabled: false, inEffect: false });

    // Enabling it while the first is enabled is refused; nothing in the patch is saved.
    const before = await stored();
    const events2 = await eventCount();
    await expect(
      updateConnection(business, SYSTEM_ACTOR, b.id, { enabled: true, name: 'Renamed' }),
    ).rejects.toMatchObject(MULTI_REFUSED);
    expect(await stored()).toEqual(before);
    expect(await eventCount()).toBe(events2);

    // Any other patch of it, and `enabled: true` on the one already enabled, are allowed.
    await expect(
      updateConnection(business, SYSTEM_ACTOR, b.id, { name: 'Second prepared', jit: false }),
    ).resolves.toMatchObject({ name: 'Second prepared', enabled: false, inEffect: false });
    await expect(
      updateConnection(business, SYSTEM_ACTOR, a, { enabled: true, name: 'First' }),
    ).resolves.toMatchObject({ name: 'First', enabled: true, inEffect: true });
    await expect(
      updateConnection(business, SYSTEM_ACTOR, b.id, { enabled: false }),
    ).resolves.toMatchObject({ enabled: false });

    // The bound of 10 stored connections still holds, and is checked first.
    for (let i = (await stored()).length; i < 10; i += 1) await make(business);
    for (const enabled of [undefined, true]) {
      await expect(
        createConnection(business, SYSTEM_ACTOR, input('Eleventh', enabled)),
      ).rejects.toMatchObject({ status: 409, code: 'SSO_CONNECTION_LIMIT_REACHED' });
    }
    expect((await stored()).filter((r) => r.enabled).map((r) => r.id)).toEqual([a]);
  });

  it('allows an enabled create while every stored connection is disabled', async () => {
    const a = await make(business);
    const b = await createConnection(business, SYSTEM_ACTOR, input('Enabled', true));
    expect(b).toMatchObject({ enabled: true, inEffect: true });
    expect(await inEffect(business)).toEqual({ [a]: false, [b.id]: true });
  });

  it('two concurrent enables without sso.multi leave one connection enabled (the connections lock)', async () => {
    const a = await make(business);
    const b = await make(business);
    // Another session holds the lock, so all three requests wait on it together.
    const other = createDatabase(ctx.database.url, { max: 1 });
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    try {
      let locked!: () => void;
      const hasLock = new Promise<void>((resolve) => {
        locked = resolve;
      });
      const holder = other.db.transaction(async (tx) => {
        await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.ssoConnections})`);
        locked();
        await held;
      });
      await hasLock;
      const results = Promise.allSettled([
        updateConnection(business, SYSTEM_ACTOR, a, { enabled: true }),
        updateConnection(business, SYSTEM_ACTOR, b, { enabled: true }),
        createConnection(business, SYSTEM_ACTOR, input('Racing', true)),
      ]);
      await new Promise((resolve) => setTimeout(resolve, 300));
      release();
      await holder;
      const settled = await results;
      expect(settled.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
      for (const r of settled) {
        if (r.status === 'rejected') expect(r.reason).toMatchObject(MULTI_REFUSED);
      }
      expect((await stored()).filter((r) => r.enabled)).toHaveLength(1);
    } finally {
      release();
      await other.close();
    }
  });

  it('a Business admin switches provider without deleting anything', async () => {
    // Review Focus 4: the old connection has an identity and a mapping.
    const old = await make(business, true);
    const next = await make(business);
    await ctx.db.insert(identities).values({
      connectionId: old,
      userId: await newUser('switcher'),
      subject: 'sub-switcher',
      linkedBy: 'user',
    });
    await ctx.db.insert(ssoGroupMappings).values({
      connectionId: old,
      groupValue: 'devs',
      organizationId: await defaultOrg(),
      role: 'member',
    });

    // Under break_glass_only the only enabled connection may not be disabled.
    await policy('break_glass_only');
    await expect(
      updateConnection(business, SYSTEM_ACTOR, old, { enabled: false }),
    ).rejects.toMatchObject(LAST_REFUSED);
    await policy('everyone');

    await expect(
      updateConnection(business, SYSTEM_ACTOR, old, { enabled: false }),
    ).resolves.toMatchObject({ enabled: false, inEffect: false });
    await expect(
      updateConnection(business, SYSTEM_ACTOR, next, { enabled: true }),
    ).resolves.toMatchObject({ enabled: true, inEffect: true });
    expect((await connectionsInEffect(ctx.db, business.edition)).map((c) => c.id)).toEqual([next]);
    // Nothing of the old connection went: switching back needs nothing new.
    expect(await stored()).toHaveLength(2);
    expect(
      await ctx.db.select().from(identities).where(eq(identities.connectionId, old)),
    ).toHaveLength(1);
    expect(
      await ctx.db.select().from(ssoGroupMappings).where(eq(ssoGroupMappings.connectionId, old)),
    ).toHaveLength(1);
  });

  it('after sso.multi goes, only the oldest enabled connection is in effect and nothing changes', async () => {
    // Review Focus 5: three enabled under Enterprise, each with an identity, a mapping, a token.
    const ids: string[] = [];
    for (let i = 0; i < 3; i += 1) ids.push(await make(enterprise, true));
    const org = await defaultOrg();
    for (const [i, id] of ids.entries()) {
      await ctx.db.insert(identities).values({
        connectionId: id,
        userId: await newUser(`kept-${i}`),
        subject: `sub-${i}`,
        linkedBy: 'user',
      });
      await ctx.db
        .insert(ssoGroupMappings)
        .values({ connectionId: id, groupValue: `g-${i}`, organizationId: org, role: 'member' });
      await createScimToken({ db: ctx.db, audit: enterprise.audit }, SYSTEM_ACTOR, {
        connectionId: id,
        name: `t-${i}`,
        expiresAt: null,
      });
    }
    const snapshot = async () => ({
      connections: await ctx.db.select().from(ssoConnections).orderBy(asc(ssoConnections.id)),
      identities: (await ctx.db.select().from(identities)).length,
      scimTokens: (await ctx.db.select().from(scimTokens)).length,
      mappings: (await ctx.db.select().from(ssoGroupMappings)).length,
    });
    const before = await snapshot();
    expect(before.connections.every((c) => c.enabled)).toBe(true);
    const all = Object.fromEntries(ids.map((id) => [id, true]));
    expect(await inEffect(enterprise)).toEqual(all);

    // A Business key: the oldest is in effect, the others not; not a row is written.
    expect(await inEffect(business)).toEqual({
      [ids[0]!]: true,
      [ids[1]!]: false,
      [ids[2]!]: false,
    });
    expect(await inEffectIds(business)).toEqual([ids[0]]);
    expect((await getConnection(business, ids[1]!)).inEffect).toBe(false);
    expect((await connectionsInEffect(ctx.db, business.edition)).map((c) => c.id)).toEqual([
      ids[0],
    ]);
    expect(await snapshot()).toEqual(before);

    // Enterprise again: every enabled connection is in effect at once.
    expect(await inEffect(enterprise)).toEqual(all);
    expect(await snapshot()).toEqual(before);
    // Without sso nothing is in effect.
    expect((await inEffectConnectionIds(ctx.db, licensedEdition(['audit-log']))).size).toBe(0);
  });

  it('disabling the one in effect hands over to the next oldest', async () => {
    const ids: string[] = [];
    for (let i = 0; i < 3; i += 1) ids.push(await make(enterprise, true));
    expect(await inEffectIds(business)).toEqual([ids[0]]);
    await updateConnection(business, SYSTEM_ACTOR, ids[0]!, { enabled: false });
    expect(await inEffectIds(business)).toEqual([ids[1]]);
    expect((await connectionsInEffect(ctx.db, business.edition)).map((c) => c.id)).toEqual([
      ids[1],
    ]);
    // It cannot be enabled again while another connection is enabled.
    await expect(
      updateConnection(business, SYSTEM_ACTOR, ids[0]!, { enabled: true }),
    ).rejects.toMatchObject(MULTI_REFUSED);
  });

  it('LAST_SSO_CONNECTION still guards the last enabled connection with sso.multi off', async () => {
    // Review Focus 6.
    const a = await make(enterprise, true);
    const b = await make(enterprise, true);
    await policy('break_glass_only');
    // Disabling the one in effect is allowed while another is enabled: that one takes over.
    await expect(
      updateConnection(business, SYSTEM_ACTOR, a, { enabled: false }),
    ).resolves.toMatchObject({ enabled: false });
    expect(await inEffectIds(business)).toEqual([b]);
    // The last enabled one is kept.
    await expect(
      updateConnection(business, SYSTEM_ACTOR, b, { enabled: false }),
    ).rejects.toMatchObject(LAST_REFUSED);
    await expect(deleteConnection(business, SYSTEM_ACTOR, b)).rejects.toMatchObject(LAST_REFUSED);
    // A disabled one may go.
    await deleteConnection(business, SYSTEM_ACTOR, a);
    expect((await stored()).map((r) => [r.id, r.enabled])).toEqual([[b, true]]);
  });
});
