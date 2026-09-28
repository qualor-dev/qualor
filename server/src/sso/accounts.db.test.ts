import { and, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createUser, type TestContext } from '../../test/app';
import { ENTERPRISE_FEATURES } from '../../test/license';
import {
  auditRows,
  licensedEdition,
  ONE_CONNECTION_FEATURES,
  oidcConnection,
  samlConnection,
  ssoContext,
} from '../../test/sso';
import { createAuditRecorder, SYSTEM_ACTOR } from '../audit/recorder';
import { createDatabase, type Database, type Db } from '../db/client';
import { identities, ssoConnections, users } from '../db/schema';
import type { Edition } from '../license/edition';
import { linkIdentity, resolveAccount, unlinkIdentity, type SignInClaims } from './accounts';
import { loadConnection } from './connections';

const claims = (over: Partial<SignInClaims> = {}): SignInClaims => ({
  subject: 'sub-alice',
  username: 'alice',
  email: 'alice@acme.example',
  emailVerified: true,
  displayName: 'Alice A',
  groups: [],
  ...over,
});

describe('account resolution (sso-scim.md §8)', () => {
  let ctx: TestContext;
  let conn: string;
  let linking: string;
  const audit = () => createAuditRecorder({ isActive: () => true, log: { error() {} } });
  const runOn = async (db: Db, connectionId: string, c: SignInClaims) => {
    const loaded = (await loadConnection(db, connectionId, ctx.config.secretKey))!;
    return db.transaction((tx) =>
      resolveAccount(tx, {
        connectionId,
        config: loaded.parsed,
        claims: c,
        audit: audit(),
        actor: SYSTEM_ACTOR,
      }),
    );
  };
  const run = (connectionId: string, c: SignInClaims) => runOn(ctx.db, connectionId, c);
  /** Removes a test's own connections again (at most 10 may exist, spec §4.1). */
  const drop = async (...ids: string[]) => {
    for (const id of ids) await ctx.db.delete(ssoConnections).where(eq(ssoConnections.id, id));
  };

  beforeAll(async () => {
    ctx = await ssoContext({});
    conn = await oidcConnection(ctx, { jit: true, linkByEmail: false });
    linking = await oidcConnection(ctx, { name: 'Linking', jit: false, linkByEmail: true });
  });
  afterAll(async () => ctx.close());

  it('runs licensed: ssoContext without `now` is inside the test licence', () => {
    for (const feature of ['sso', 'scim', 'audit-log']) {
      expect(ctx.edition?.isFeatureActive(feature), feature).toBe(true);
    }
  });

  it('JIT-creates a user without a password, then signs the same subject in again', async () => {
    const first = await run(conn, claims());
    expect(first).toMatchObject({
      ok: true,
      created: true,
      user: {
        username: 'alice',
        passwordHash: null,
        passwordChangeRequired: false,
        isInstanceAdmin: false,
        active: true,
        email: 'alice@acme.example',
        displayName: 'Alice A',
      },
      identity: { connectionId: conn, subject: 'sub-alice', linkedBy: 'jit' },
    });
    expect((await auditRows(ctx)).at(-1)).toMatchObject({
      action: 'sso.user_provisioned',
      details: { connectionId: conn, emailSet: true },
    });
    const again = await run(conn, claims({ displayName: 'Alice B' }));
    expect(again).toMatchObject({
      ok: true,
      created: false,
      user: { id: first.ok && first.user.id, displayName: 'Alice B' },
    });
    // last_sign_in_at is the session's to set (issueSsoSession, §7.5), not resolution's.
    expect(again.ok && again.identity.lastSignInAt).toBeNull();
  });

  it('never links by username: a local "carol" gets a new "carol-2"', async () => {
    const carol = await createUser(ctx, { username: 'carol' });
    const r = await run(
      conn,
      claims({ subject: 'sub-carol', username: 'carol', email: null, emailVerified: false }),
    );
    expect(r).toMatchObject({ ok: true, created: true, user: { username: 'carol-2' } });
    expect(r.ok && r.user.id).not.toBe(carol.id);
  });

  it('refuses a verified email another account has when linking is off', async () => {
    await createUser(ctx, { username: 'dave', email: 'dave@acme.example' });
    expect(
      await run(
        conn,
        claims({ subject: 'sub-dave', username: 'dave', email: 'dave@acme.example' }),
      ),
    ).toMatchObject({ ok: false, reason: 'email_in_use' });
    const rows = await ctx.db.select().from(identities).where(eq(identities.subject, 'sub-dave'));
    expect(rows).toEqual([]);
  });

  it('stores no unverified email', async () => {
    const r = await run(
      conn,
      claims({
        subject: 'sub-erin',
        username: 'erin',
        email: 'erin@acme.example',
        emailVerified: false,
      }),
    );
    expect(r).toMatchObject({ ok: true, user: { email: null } });
  });

  it('links by an IdP-verified email when the connection allows it', async () => {
    const frank = await createUser(ctx, { username: 'frank', email: 'Frank@Acme.example' });
    const r = await run(
      linking,
      claims({ subject: 'sub-frank', username: 'whatever', email: 'frank@acme.example' }),
    );
    expect(r).toMatchObject({
      ok: true,
      created: false,
      user: { id: frank.id, username: 'frank' },
      identity: { linkedBy: 'verified_email' },
    });
    expect((await auditRows(ctx)).at(-1)).toMatchObject({
      action: 'sso.identity_linked',
      targetId: frank.id,
      details: { connectionId: linking, method: 'verified_email' },
    });
  });

  it('never links by email to an instance admin, nor by an unverified email', async () => {
    const admin = await createUser(ctx, {
      username: 'gina',
      email: 'gina@acme.example',
      isInstanceAdmin: true,
    });
    expect(
      await run(linking, claims({ subject: 'sub-gina', email: 'gina@acme.example' })),
    ).toMatchObject({ ok: false, reason: 'no_account' });
    const hank = await createUser(ctx, { username: 'hank', email: 'hank@acme.example' });
    expect(
      await run(
        linking,
        claims({ subject: 'sub-hank', email: 'hank@acme.example', emailVerified: false }),
      ),
    ).toMatchObject({ ok: false, reason: 'no_account' });
    for (const id of [admin.id, hank.id]) {
      const rows = await ctx.db.select().from(identities).where(eq(identities.userId, id));
      expect(rows).toEqual([]);
    }
  });

  it('never links by email to an inactive user', async () => {
    const olga = await createUser(ctx, {
      username: 'olga',
      email: 'olga@acme.example',
      active: false,
    });
    expect(
      await run(linking, claims({ subject: 'sub-olga', email: 'olga@acme.example' })),
    ).toMatchObject({ ok: false, reason: 'no_account' });
    const rows = await ctx.db.select().from(identities).where(eq(identities.userId, olga.id));
    expect(rows).toEqual([]);
  });

  it('a SAML connection links by email only when it marks emails as verified', async () => {
    const unverified = await samlConnection(ctx, { jit: false, linkByEmail: true });
    const pia = await createUser(ctx, { username: 'pia', email: 'pia@acme.example' });
    // Even if a caller passed emailVerified, the connection's setting decides for SAML (§8.3).
    expect(
      await run(unverified, claims({ subject: 'sub-pia', email: 'pia@acme.example' })),
    ).toMatchObject({ ok: false, reason: 'no_account' });
    const verified = await samlConnection(ctx, {
      jit: false,
      linkByEmail: true,
      emailVerified: true,
    });
    expect(
      await run(verified, claims({ subject: 'sub-pia', email: 'pia@acme.example' })),
    ).toMatchObject({ ok: true, user: { id: pia.id } });
  });

  it('refuses an inactive user', async () => {
    const r = await run(
      conn,
      claims({ subject: 'sub-ivy', username: 'ivy', email: null, emailVerified: false }),
    );
    await ctx.db
      .update(users)
      .set({ active: false })
      .where(eq(users.id, r.ok ? r.user.id : ''));
    expect(await run(conn, claims({ subject: 'sub-ivy' }))).toMatchObject({
      ok: false,
      reason: 'inactive_user',
      userId: r.ok && r.user.id,
    });
  });

  it('matches a SCIM record of the same connection by its userName', async () => {
    const jane = await createUser(ctx, { username: 'jane' });
    await ctx.db.insert(identities).values({
      connectionId: conn,
      userId: jane.id,
      linkedBy: 'scim',
      scimUserName: 'Jane@Acme.example',
    });
    const r = await run(
      conn,
      claims({
        subject: 'sub-jane',
        username: 'jane@acme.example',
        email: null,
        emailVerified: false,
      }),
    );
    expect(r).toMatchObject({
      ok: true,
      created: false,
      user: { id: jane.id },
      identity: { subject: 'sub-jane', linkedBy: 'scim_match' },
    });
    expect((await auditRows(ctx)).at(-1)).toMatchObject({
      action: 'sso.identity_linked',
      details: { method: 'scim_match' },
    });
  });

  it('OIDC: the SCIM match falls back to the email only when the IdP verified it', async () => {
    const strict = await oidcConnection(ctx, { jit: false, linkByEmail: false });
    const victim = await createUser(ctx, { username: 'victim' });
    await ctx.db.insert(identities).values({
      connectionId: strict,
      userId: victim.id,
      linkedBy: 'scim',
      scimUserName: 'victim@acme.example',
    });
    // No username claim and an unverified email equal to the SCIM userName: no match.
    expect(
      await run(
        strict,
        claims({
          subject: 'sub-attacker',
          username: null,
          email: 'victim@acme.example',
          emailVerified: false,
        }),
      ),
    ).toEqual({ ok: false, reason: 'no_account', userId: null });
    const [untouched] = await ctx.db
      .select()
      .from(identities)
      .where(eq(identities.userId, victim.id));
    expect(untouched).toMatchObject({ subject: null, linkedBy: 'scim' });
    // The same email, verified: the SCIM record is the person's.
    expect(
      await run(
        strict,
        claims({ subject: 'sub-victim', username: null, email: 'victim@acme.example' }),
      ),
    ).toMatchObject({
      ok: true,
      user: { id: victim.id },
      identity: { subject: 'sub-victim', linkedBy: 'scim_match' },
    });
  });

  it('OIDC: a username claim that is the email claim matches only when the email is verified', async () => {
    const same = await oidcConnection(ctx, {
      jit: false,
      linkByEmail: false,
      claims: { username: 'email', email: 'email' },
    });
    const yara = await createUser(ctx, { username: 'yara' });
    await ctx.db.insert(identities).values({
      connectionId: same,
      userId: yara.id,
      linkedBy: 'scim',
      scimUserName: 'yara@acme.example',
    });
    const asEmail = (emailVerified: boolean, subject: string) =>
      claims({
        subject,
        username: 'yara@acme.example',
        email: 'yara@acme.example',
        emailVerified,
      });
    expect(await run(same, asEmail(false, 'sub-yara-attacker'))).toEqual({
      ok: false,
      reason: 'no_account',
      userId: null,
    });
    expect(await run(same, asEmail(true, 'sub-yara'))).toMatchObject({
      ok: true,
      user: { id: yara.id },
      identity: { subject: 'sub-yara', linkedBy: 'scim_match' },
    });
    await drop(same);
  });

  it('SAML: a username attribute that is the email attribute needs the connection to verify emails', async () => {
    const scimRecord = async (connectionId: string, username: string, scimUserName: string) => {
      const user = await createUser(ctx, { username });
      await ctx.db
        .insert(identities)
        .values({ connectionId, userId: user.id, linkedBy: 'scim', scimUserName });
      return user;
    };
    const unverified = await samlConnection(ctx, {
      jit: false,
      claims: { username: 'mail', email: 'mail' },
    });
    await scimRecord(unverified, 'zed', 'zed@acme.example');
    expect(
      await run(
        unverified,
        claims({
          subject: 'sub-zed',
          username: 'zed@acme.example',
          email: 'zed@acme.example',
          nameId: null,
        }),
      ),
    ).toEqual({ ok: false, reason: 'no_account', userId: null });
    const verified = await samlConnection(ctx, {
      jit: false,
      emailVerified: true,
      claims: { username: 'mail', email: 'mail' },
    });
    const zoe = await scimRecord(verified, 'zoe', 'zoe@acme.example');
    expect(
      await run(
        verified,
        claims({
          subject: 'sub-zoe',
          username: 'zoe@acme.example',
          email: 'zoe@acme.example',
          nameId: null,
        }),
      ),
    ).toMatchObject({ ok: true, user: { id: zoe.id } });
    await drop(unverified, verified);
  });

  it('SAML: an emailAddress NameID is a match key only when the connection verifies emails', async () => {
    const EMAIL_FORMAT = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
    const unverified = await samlConnection(ctx, { jit: false, nameIdFormat: EMAIL_FORMAT });
    const una = await createUser(ctx, { username: 'una' });
    await ctx.db.insert(identities).values({
      connectionId: unverified,
      userId: una.id,
      linkedBy: 'scim',
      scimUserName: 'una@acme.example',
    });
    const byNameId = (subject: string) =>
      claims({ subject, username: null, email: null, nameId: 'una@acme.example' });
    expect(await run(unverified, byNameId('sub-una'))).toEqual({
      ok: false,
      reason: 'no_account',
      userId: null,
    });
    const verified = await samlConnection(ctx, {
      jit: false,
      emailVerified: true,
      nameIdFormat: EMAIL_FORMAT,
    });
    const val = await createUser(ctx, { username: 'val' });
    await ctx.db.insert(identities).values({
      connectionId: verified,
      userId: val.id,
      linkedBy: 'scim',
      scimUserName: 'una@acme.example',
    });
    expect(await run(verified, byNameId('sub-val'))).toMatchObject({
      ok: true,
      user: { id: val.id },
    });
    await drop(unverified, verified);
  });

  it('never matches the SCIM record of an instance admin (they link with Link)', async () => {
    const strict = await oidcConnection(ctx, { jit: false, linkByEmail: false });
    const boss = await createUser(ctx, { username: 'boss', isInstanceAdmin: true });
    await ctx.db.insert(identities).values({
      connectionId: strict,
      userId: boss.id,
      linkedBy: 'scim',
      scimUserName: 'boss@acme.example',
    });
    expect(
      await run(strict, claims({ subject: 'sub-boss', username: 'boss@acme.example' })),
    ).toEqual({ ok: false, reason: 'no_account', userId: null });
    const [row] = await ctx.db.select().from(identities).where(eq(identities.userId, boss.id));
    expect(row).toMatchObject({ subject: null, linkedBy: 'scim' });
  });

  it('refuses a deactivated SCIM record without storing the subject on it', async () => {
    const quinn = await createUser(ctx, { username: 'quinn', active: false });
    await ctx.db.insert(identities).values({
      connectionId: conn,
      userId: quinn.id,
      linkedBy: 'scim',
      scimUserName: 'quinn@acme.example',
    });
    expect(
      await run(
        conn,
        claims({ subject: 'sub-quinn', username: 'quinn@acme.example', email: null }),
      ),
    ).toMatchObject({ ok: false, reason: 'inactive_user', userId: quinn.id });
    const [row] = await ctx.db.select().from(identities).where(eq(identities.userId, quinn.id));
    expect(row).toMatchObject({ subject: null, linkedBy: 'scim' });
  });

  it('does not match a SCIM record of another connection', async () => {
    const rose = await createUser(ctx, { username: 'rose' });
    await ctx.db.insert(identities).values({
      connectionId: linking,
      userId: rose.id,
      linkedBy: 'scim',
      scimUserName: 'rose',
    });
    const r = await run(
      conn,
      claims({ subject: 'sub-rose', username: 'rose', email: null, emailVerified: false }),
    );
    expect(r).toMatchObject({ ok: true, created: true, user: { username: 'rose-2' } });
  });

  it('updates a verified email only when nobody else has it', async () => {
    const r = await run(
      conn,
      claims({ subject: 'sub-sam', username: 'sam', email: null, emailVerified: false }),
    );
    expect(r).toMatchObject({ ok: true, user: { email: null } });
    const moved = await run(conn, claims({ subject: 'sub-sam', email: 'sam@acme.example' }));
    expect(moved).toMatchObject({ ok: true, user: { email: 'sam@acme.example' } });
    const kept = await run(conn, claims({ subject: 'sub-sam', email: 'dave@acme.example' }));
    expect(kept).toMatchObject({ ok: true, user: { email: 'sam@acme.example' } });
    const unverified = await run(
      conn,
      claims({ subject: 'sub-sam', email: 'other@acme.example', emailVerified: false }),
    );
    expect(unverified).toMatchObject({ ok: true, user: { email: 'sam@acme.example' } });
  });

  it('refuses when JIT is off and nothing matches', async () => {
    expect(
      await run(linking, claims({ subject: 'sub-nobody', email: null, emailVerified: false })),
    ).toEqual({ ok: false, reason: 'no_account', userId: null });
  });

  it('gives up after -20: username_unavailable', async () => {
    await createUser(ctx, { username: 'taken' });
    for (let n = 2; n <= 20; n += 1) await createUser(ctx, { username: `taken-${n}` });
    expect(
      await run(
        conn,
        claims({ subject: 'sub-taken', username: 'taken', email: null, emailVerified: false }),
      ),
    ).toEqual({ ok: false, reason: 'username_unavailable', userId: null });
  });

  it('strips control characters from the display name and keeps at most 255', async () => {
    const r = await run(
      conn,
      claims({
        subject: 'sub-uma',
        username: 'uma',
        email: null,
        emailVerified: false,
        displayName: `Uma${String.fromCharCode(0)}${String.fromCharCode(10)} ${'x'.repeat(300)}`,
      }),
    );
    expect(r.ok && r.user.displayName).toBe(`Uma ${'x'.repeat(251)}`);
  });

  it('links a signed-in user, and refuses a subject already in use or a second identity', async () => {
    const kim = await createUser(ctx, { username: 'kim' });
    const link = (subject: string, userId: string) =>
      ctx.db.transaction((tx) =>
        linkIdentity(tx, {
          connectionId: conn,
          userId,
          subject,
          audit: audit(),
          actor: SYSTEM_ACTOR,
        }),
      );
    expect(await link('sub-kim', kim.id)).toMatchObject({
      ok: true,
      identity: { subject: 'sub-kim', linkedBy: 'user' },
    });
    expect((await auditRows(ctx)).at(-1)).toMatchObject({
      action: 'sso.identity_linked',
      details: { method: 'user' },
    });
    expect(await link('sub-kim', kim.id)).toMatchObject({ ok: true });
    expect(await link('sub-kim-2', kim.id)).toEqual({ ok: false, reason: 'already_linked' });
    const lee = await createUser(ctx, { username: 'lee' });
    expect(await link('sub-alice', lee.id)).toEqual({ ok: false, reason: 'identity_in_use' });
  });

  it('SAML: the SCIM match falls back to the NameID, never to the email (§8.2)', async () => {
    const saml = await samlConnection(ctx, { jit: false, emailVerified: true });
    const vera = await createUser(ctx, { username: 'vera' });
    await ctx.db.insert(identities).values({
      connectionId: saml,
      userId: vera.id,
      linkedBy: 'scim',
      scimUserName: 'vera@acme.example',
    });
    // The email equals the SCIM userName, but there is no NameID: no match.
    expect(
      await run(
        saml,
        claims({ subject: 'sub-vera', username: null, email: 'vera@acme.example', nameId: null }),
      ),
    ).toEqual({ ok: false, reason: 'no_account', userId: null });
    const r = await run(
      saml,
      claims({
        subject: 'sub-vera',
        username: null,
        email: 'other@acme.example',
        nameId: 'Vera@Acme.example',
      }),
    );
    expect(r).toMatchObject({
      ok: true,
      created: false,
      user: { id: vera.id },
      identity: { subject: 'sub-vera', linkedBy: 'scim_match' },
    });
  });

  it('a second subject with the email of a user already linked on the connection takes nothing', async () => {
    const first = await run(
      conn,
      claims({ subject: 'sub-wes-a', username: 'wes', email: 'wes@acme.example' }),
    );
    expect(first).toMatchObject({ ok: true, created: true });
    const wesId = first.ok ? first.user.id : '';
    // JIT on, linking off: the verified email is someone else's.
    expect(
      await run(conn, claims({ subject: 'sub-wes-b', username: 'wes', email: 'wes@acme.example' })),
    ).toEqual({ ok: false, reason: 'email_in_use', userId: null });
    // Linking on: the user already has an identity on this connection, so no second one.
    const onLinking = await run(
      linking,
      claims({ subject: 'sub-wes-a', username: 'wes', email: 'wes@acme.example' }),
    );
    expect(onLinking).toMatchObject({ ok: true, user: { id: wesId } });
    expect(
      await run(
        linking,
        claims({ subject: 'sub-wes-b', username: 'wes', email: 'wes@acme.example' }),
      ),
    ).toEqual({ ok: false, reason: 'no_account', userId: null });
    for (const connectionId of [conn, linking]) {
      const rows = await ctx.db
        .select()
        .from(identities)
        .where(and(eq(identities.connectionId, connectionId), eq(identities.userId, wesId)));
      expect(rows.map((i) => i.subject)).toEqual(['sub-wes-a']);
    }
    const bySubjectB = await ctx.db
      .select()
      .from(identities)
      .where(eq(identities.subject, 'sub-wes-b'));
    expect(bySubjectB).toEqual([]);
  });

  describe('concurrency (two pools)', () => {
    let second: Database;
    beforeAll(() => {
      second = createDatabase(ctx.database.url, { max: 2 });
    });
    afterAll(async () => second.close());

    it('two first sign-ins of one subject make one user, even when one waits on the other', async () => {
      const c = claims({ subject: 'sub-race', username: 'race', email: 'race@acme.example' });
      const loaded = (await loadConnection(ctx.db, conn, ctx.config.secretKey))!;
      let release!: () => void;
      const held = new Promise<void>((resolve) => {
        release = resolve;
      });
      let resolvedFirst!: () => void;
      const firstDone = new Promise<void>((resolve) => {
        resolvedFirst = resolve;
      });
      const a = ctx.db.transaction(async (tx) => {
        const r = await resolveAccount(tx, {
          connectionId: conn,
          config: loaded.parsed,
          claims: c,
          audit: audit(),
          actor: SYSTEM_ACTOR,
        });
        resolvedFirst();
        await held;
        return r;
      });
      await firstDone;
      let bSettled = false;
      const b = runOn(second.db, conn, c).finally(() => {
        bSettled = true;
      });
      await new Promise((resolve) => setTimeout(resolve, 300));
      expect(bSettled).toBe(false);
      release();
      const [ra, rb] = await Promise.all([a, b]);
      expect(ra).toMatchObject({ ok: true, created: true });
      expect(rb).toMatchObject({ ok: true, created: false, user: { id: ra.ok && ra.user.id } });
      const made = await ctx.db.select().from(users).where(eq(users.username, 'race'));
      expect(made).toHaveLength(1);
      const suffixed = await ctx.db.select().from(users).where(eq(users.username, 'race-2'));
      expect(suffixed).toEqual([]);
    });

    it('locks the identity before the user, as SCIM does: a concurrent SCIM write does not deadlock', async () => {
      const first = await run(
        conn,
        claims({ subject: 'sub-order', username: 'order', email: null }),
      );
      expect(first).toMatchObject({ ok: true });
      const userId = first.ok ? first.user.id : '';
      let lockUser!: () => void;
      const userTurn = new Promise<void>((resolve) => {
        lockUser = resolve;
      });
      let identityHeld!: () => void;
      const held = new Promise<void>((resolve) => {
        identityHeld = resolve;
      });
      // SCIM's order (scim/users.ts): the identity row, then the user row.
      const scim = second.db.transaction(async (tx) => {
        await tx.execute(
          sql`SELECT id FROM identities WHERE subject = 'sub-order' FOR NO KEY UPDATE`,
        );
        identityHeld();
        await userTurn;
        await tx.execute(sql`SELECT id FROM users WHERE id = ${userId} FOR NO KEY UPDATE`);
      });
      await held;
      // A new display name and email: the sign-in writes the user row.
      const signIn = run(
        conn,
        claims({ subject: 'sub-order', displayName: 'Order Two', email: 'order@acme.example' }),
      );
      await new Promise((resolve) => setTimeout(resolve, 300));
      lockUser();
      await scim;
      expect(await signIn).toMatchObject({
        ok: true,
        user: { id: userId, displayName: 'Order Two', email: 'order@acme.example' },
      });
    });

    it('many simultaneous first sign-ins of one subject make one user and one identity', async () => {
      const c = claims({ subject: 'sub-burst', username: 'burst', email: null });
      const results = await Promise.all([
        run(conn, c),
        runOn(second.db, conn, c),
        run(conn, c),
        runOn(second.db, conn, c),
      ]);
      expect(results.every((r) => r.ok)).toBe(true);
      expect(results.filter((r) => r.ok && r.created)).toHaveLength(1);
      expect(new Set(results.map((r) => r.ok && r.user.id)).size).toBe(1);
      const rows = await ctx.db
        .select()
        .from(identities)
        .where(and(eq(identities.connectionId, conn), eq(identities.subject, 'sub-burst')));
      expect(rows).toHaveLength(1);
    });
  });
});

describe('unlinking without sso.multi (sso-scim.md §4.4)', () => {
  let ctx: TestContext;
  /** Created and enabled under an Enterprise key: `older` first, so it stays in effect. */
  let older: string;
  let newer: string;
  const enterprise = licensedEdition(ENTERPRISE_FEATURES);
  const business = licensedEdition(ONE_CONNECTION_FEATURES);
  const audit = createAuditRecorder({ isActive: () => true, log: { error() {} } });
  const unlink = (edition: Edition, userId: string, identityId: string) =>
    unlinkIdentity(
      { db: ctx.db, audit, edition, log: { warn() {} } },
      SYSTEM_ACTOR,
      userId,
      identityId,
      true,
    );
  /** A user without a password, with an identity on each connection; the identities' ids. */
  const ssoOnlyUser = async (username: string) => {
    const [user] = await ctx.db.insert(users).values({ username }).returning({ id: users.id });
    const onOlder = await ctx.db
      .insert(identities)
      .values({ connectionId: older, userId: user!.id, subject: `${username}-a`, linkedBy: 'user' })
      .returning({ id: identities.id });
    const onNewer = await ctx.db
      .insert(identities)
      .values({ connectionId: newer, userId: user!.id, subject: `${username}-b`, linkedBy: 'user' })
      .returning({ id: identities.id });
    return { userId: user!.id, older: onOlder[0]!.id, newer: onNewer[0]!.id };
  };

  beforeAll(async () => {
    ctx = await ssoContext({ features: ONE_CONNECTION_FEATURES });
    older = await oidcConnection(ctx, { enabled: true, edition: enterprise });
    newer = await oidcConnection(ctx, { enabled: true, edition: enterprise });
  });
  afterAll(async () => ctx.close());

  it('unlink counts only identities on connections in effect (LAST_SIGN_IN_METHOD)', async () => {
    const u = await ssoOnlyUser('two-idps');
    // Only the older connection is in effect: the identity on it is the last way in.
    await expect(unlink(business, u.userId, u.older)).rejects.toMatchObject({
      status: 409,
      code: 'LAST_SIGN_IN_METHOD',
    });
    expect(
      await ctx.db.select().from(identities).where(eq(identities.userId, u.userId)),
    ).toHaveLength(2);
    // The identity on the connection not in effect may go: the one in effect remains.
    await unlink(business, u.userId, u.newer);
    expect(
      (await ctx.db.select().from(identities).where(eq(identities.userId, u.userId))).map(
        (i) => i.connectionId,
      ),
    ).toEqual([older]);
  });

  it('with sso.multi an identity on any enabled connection counts', async () => {
    const u = await ssoOnlyUser('multi-idps');
    await unlink(enterprise, u.userId, u.older);
    expect(
      (await ctx.db.select().from(identities).where(eq(identities.userId, u.userId))).map(
        (i) => i.connectionId,
      ),
    ).toEqual([newer]);
  });
});
