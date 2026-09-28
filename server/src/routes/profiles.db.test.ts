import { and, eq, sql } from 'drizzle-orm';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { addMember, bearer, createUser, login, type Session } from '../../test/app';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { mainBranchId, seedIssue, seedRule } from '../../test/issues';
import {
  branches,
  organizations,
  profileRules,
  projects,
  qualityProfiles,
  rules,
} from '../db/schema';
import type { Db } from '../db/client';

/** Polls until `n` backends of this file's own database wait on a lock (never a fixed sleep). */
async function waitForLockWaiters(db: Db, n: number, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const result = await db.execute(sql`
      SELECT count(*)::int AS n FROM pg_stat_activity
       WHERE wait_event_type = 'Lock' AND datname = current_database()`);
    if (Number(result.rows[0]?.n) >= n) return;
    if (Date.now() > deadline) throw new Error(`Timed out waiting for ${n} lock waiter(s)`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

interface Profile {
  id: string;
  name: string;
  language: string;
  parentId: string | null;
  isDefault: boolean;
  isBuiltin: boolean;
  unknownRules: string;
}

describe('rule catalog and quality profiles API (api.md §3, server step 13)', () => {
  let h: IngestHarness;
  let member: Session;
  let outsider: Session;
  let builtinTs: Profile;
  let otherOrgId: string;
  const call = (
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
    url: string,
    session: Session | Record<string, string> = h.orgAdmin,
    payload?: unknown,
  ) =>
    h.ctx.app.inject({
      method,
      url: `/api/v0${url}`,
      headers: 'headers' in session ? (session as Session).headers : session,
      ...(payload === undefined ? {} : { payload: payload as object }),
    });
  const create = async (body: Record<string, unknown>): Promise<Profile> => {
    const res = await call('POST', '/quality-profiles', h.orgAdmin, {
      organizationId: h.organizationId,
      language: 'typescript',
      ...body,
    });
    expect(res.statusCode, res.body).toBe(201);
    return res.json() as Profile;
  };
  const org = () => `organizationId=${h.organizationId}`;

  beforeAll(async () => {
    h = await createIngestHarness();
    const m = await createUser(h.ctx, { username: 'profile-member' });
    await addMember(h.ctx, h.organizationId, m.id, 'member');
    member = await login(h.ctx, m.username, m.password);
    const o = await createUser(h.ctx, { username: 'profile-outsider' });
    outsider = await login(h.ctx, o.username, o.password);
    const list = await call(
      'GET',
      `/quality-profiles?organizationId=${h.organizationId}&language=typescript`,
      member,
    );
    builtinTs = (list.json() as { items: Profile[] }).items.find((p) => p.isBuiltin)!;
    const seeded = [
      await seedRule(h.ctx.db, {
        key: 'eslint:no-console',
        name: 'Disallow console',
        languages: ['typescript', 'javascript'],
      }),
      await seedRule(h.ctx.db, {
        key: 'eslint:no-eval',
        name: 'Disallow eval()',
        languages: ['javascript'],
        quality: 'security',
        defaultSeverity: 'high',
        cwe: [95],
      }),
      await seedRule(h.ctx.db, { key: 'gitleaks:aws-access-token', quality: 'security' }),
      await seedRule(h.ctx.db, { key: 'external:scope/rule:with:colons' }),
    ];
    // Ruling X2: the catalog lists the rules the organisation has seen — here, through issues.
    const project = await h.project('acme/rules-catalog');
    const branchId = await mainBranchId(h.ctx.db, project.id);
    for (const ruleId of seeded)
      await seedIssue(h.ctx.db, { projectId: project.id, branchId, ruleId });
    // Another organisation's project reports a rule this organisation never saw.
    const [other] = await h.ctx.db
      .insert(organizations)
      .values({ key: 'profile-other', name: 'Other' })
      .returning();
    otherOrgId = other!.id;
    const [otherProject] = await h.ctx.db
      .insert(projects)
      .values({ organizationId: otherOrgId, key: 'other/secret', name: 'Secret' })
      .returning();
    const [otherBranch] = await h.ctx.db
      .insert(branches)
      .values({ projectId: otherProject!.id, kind: 'branch', name: 'main', isMain: true })
      .returning();
    const secret = await seedRule(h.ctx.db, { key: 'semgrep:other-org-secret-rule' });
    await seedIssue(h.ctx.db, {
      projectId: otherProject!.id,
      branchId: otherBranch!.id,
      ruleId: secret,
    });
  });
  afterAll(async () => {
    await h.close();
  });

  describe('GET /rules', () => {
    it('lists the catalog by key, filtered and keyset-paginated', async () => {
      const keys = async (query: string) =>
        (
          (await call('GET', `/rules?${org()}&${query}`, member)).json() as {
            items: { key: string }[];
          }
        ).items.map((r) => r.key);
      expect(await keys('')).toEqual([
        'eslint:no-console',
        'eslint:no-eval',
        'external:scope/rule:with:colons',
        'gitleaks:aws-access-token',
      ]);
      expect(await keys('engine=eslint&language=javascript&quality=security')).toEqual([
        'eslint:no-eval',
      ]);
      expect(await keys('q=EVAL')).toEqual(['eslint:no-eval']);
      expect(await keys('q=100%25')).toEqual([]);
      expect(await keys('severity=high')).toEqual(['eslint:no-eval']);
      const first = (await call('GET', `/rules?${org()}&limit=3`, member)).json() as {
        nextCursor: string;
      };
      expect(await keys(`limit=3&cursor=${encodeURIComponent(first.nextCursor)}`)).toEqual([
        'gitleaks:aws-access-token',
      ]);
      expect((await call('GET', `/rules?${org()}&limit=501`, member)).statusCode).toBe(422);
      expect((await call('GET', `/rules?${org()}&cursor=bogus`, member)).statusCode).toBe(422);
      const nul = await call('GET', `/rules?${org()}&q=a%00b`, member);
      expect([nul.statusCode, nul.json().errors[0].path]).toEqual([422, 'query.q']);
      expect((await call('GET', '/rules', member)).statusCode).toBe(422);
      expect((await call('GET', `/rules?${org()}`, {})).statusCode).toBe(401);
    });

    it('reads one rule by its URL-encoded key', async () => {
      const res = await call(
        'GET',
        `/rules/${encodeURIComponent('external:scope/rule:with:colons')}?${org()}`,
        member,
      );
      expect(res.statusCode, res.body).toBe(200);
      expect(res.json()).toMatchObject({
        key: 'external:scope/rule:with:colons',
        origin: 'reported',
      });
      const evalRule = await call('GET', `/rules/eslint%3Ano-eval?${org()}`, member);
      expect(evalRule.json()).toMatchObject({
        engine: 'eslint',
        engineRuleId: 'no-eval',
        defaultSeverity: 'high',
        cwe: [95],
      });
      expect((await call('GET', `/rules/eslint%3Anope?${org()}`, member)).statusCode).toBe(404);
      expect((await call('GET', `/rules/eslint%3Ano-eval`, member)).statusCode).toBe(422);
    });

    it('hides the rules only other organisations reported (ruling X2)', async () => {
      const listed = async (session: Session, organizationId: string) => {
        const res = await call('GET', `/rules?organizationId=${organizationId}&limit=500`, session);
        return res.statusCode === 200
          ? (res.json() as { items: { key: string }[] }).items.map((r) => r.key)
          : res.statusCode;
      };
      expect(await listed(member, h.organizationId)).not.toContain('semgrep:other-org-secret-rule');
      const one = `/rules/${encodeURIComponent('semgrep:other-org-secret-rule')}`;
      expect((await call('GET', `${one}?${org()}`, member)).statusCode).toBe(404);
      // Another organisation's catalog is not the caller's to read, even for a rule it can see.
      expect(await listed(member, otherOrgId)).toBe(404);
      expect(
        (await call('GET', `/rules/eslint%3Ano-eval?organizationId=${otherOrgId}`, member))
          .statusCode,
      ).toBe(404);
      expect(await listed(outsider, h.organizationId)).toBe(404);
      expect((await call('GET', `/rules/eslint%3Ano-eval?${org()}`, outsider)).statusCode).toBe(
        404,
      );

      // A built-in rule is visible to every organisation.
      const builtin = await seedRule(h.ctx.db, { key: 'pmd:BuiltinCatalogRule' });
      await h.ctx.db.update(rules).set({ origin: 'builtin' }).where(eq(rules.id, builtin));
      expect(await listed(member, h.organizationId)).toContain('pmd:BuiltinCatalogRule');

      // A rule one of the organisation's profiles has a row for is visible too.
      const viaProfile = await seedRule(h.ctx.db, { key: 'semgrep:profiled-only' });
      expect(await listed(member, h.organizationId)).not.toContain('semgrep:profiled-only');
      const [star] = await h.ctx.db
        .select()
        .from(qualityProfiles)
        .where(
          and(
            eq(qualityProfiles.organizationId, h.organizationId),
            eq(qualityProfiles.language, '*'),
          ),
        );
      await h.ctx.db
        .insert(profileRules)
        .values({ profileId: star!.id, ruleId: viaProfile, active: false });
      expect(await listed(member, h.organizationId)).toContain('semgrep:profiled-only');
      expect(
        (
          await call(
            'GET',
            `/rules/${encodeURIComponent('semgrep:profiled-only')}?${org()}`,
            member,
          )
        ).statusCode,
      ).toBe(200);
      expect(await listed(h.orgAdmin, h.organizationId)).not.toContain(
        'semgrep:other-org-secret-rule',
      );
    });
  });

  describe('quality profiles', () => {
    it('lists the built-in "Qualor way" profiles to members; hides the organisation from outsiders', async () => {
      const res = await call('GET', `/quality-profiles?organizationId=${h.organizationId}`, member);
      const items = (res.json() as { items: Profile[] }).items;
      expect(
        items.filter((p) => p.isBuiltin).map((p) => [p.language, p.name, p.isDefault]),
      ).toEqual(
        expect.arrayContaining([
          ['typescript', 'Qualor way', true],
          ['javascript', 'Qualor way', true],
          ['java', 'Qualor way', true],
          ['*', 'Qualor way', true],
        ]),
      );
      expect(
        (await call('GET', `/quality-profiles?organizationId=${h.organizationId}`, outsider))
          .statusCode,
      ).toBe(404);
      expect((await call('GET', `/quality-profiles/${builtinTs.id}`, outsider)).statusCode).toBe(
        404,
      );
      expect((await call('GET', `/quality-profiles/${builtinTs.id}`, member)).json()).toMatchObject(
        { id: builtinTs.id, unknownRules: 'activate', parentId: null },
      );
    });

    it('reserves the name "Qualor way" in any case and spacing (422 body.name)', async () => {
      for (const name of [
        'Qualor way',
        ' qualor  WAY ',
        'QUALOR WAY',
        'QualorWay',
        'Qualor way',
        'Qualor​way',
        'Ｑualor way',
        'Qualor-way',
        'Qualor_way',
        'Qualor.way',
        '"Qualor way!"',
      ]) {
        const res = await call('POST', '/quality-profiles', h.orgAdmin, {
          organizationId: h.organizationId,
          name,
          language: 'java',
        });
        expect(res.statusCode, name).toBe(422);
        expect(res.json().errors).toEqual([
          { path: 'body.name', message: '"Qualor way" is reserved for the built-in profiles' },
        ]);
      }
      const custom = await create({ name: 'Reserved check' });
      const rename = await call('PATCH', `/quality-profiles/${custom.id}`, h.orgAdmin, {
        name: 'qualor way',
      });
      expect(rename.statusCode).toBe(422);
      const copy = await call('POST', `/quality-profiles/${builtinTs.id}/copy`, h.orgAdmin, {
        name: 'Qualor Way',
      });
      expect(copy.statusCode).toBe(422);
      const nul = await call('POST', '/quality-profiles', h.orgAdmin, {
        organizationId: h.organizationId,
        name: 'a\u0000b',
        language: 'java',
      });
      expect([nul.statusCode, nul.json().errors[0].path]).toEqual([422, 'body.name']);
    });

    it('keeps the built-ins read-only (409 BUILTIN_READ_ONLY)', async () => {
      const patch = await call('PATCH', `/quality-profiles/${builtinTs.id}`, h.orgAdmin, {
        unknownRules: 'ignore',
      });
      expect([patch.statusCode, patch.json().code]).toEqual([409, 'BUILTIN_READ_ONLY']);
      const del = await call('DELETE', `/quality-profiles/${builtinTs.id}`, h.orgAdmin);
      expect([del.statusCode, del.json().code]).toEqual([409, 'BUILTIN_READ_ONLY']);
    });

    it('creates, renames and refuses a duplicate name per language (409 PROFILE_NAME_TAKEN)', async () => {
      const profile = await create({ name: 'Strict TS' });
      expect(profile).toMatchObject({
        name: 'Strict TS',
        language: 'typescript',
        isDefault: false,
        isBuiltin: false,
        unknownRules: 'activate',
        parentId: null,
      });
      const again = await call('POST', '/quality-profiles', h.orgAdmin, {
        organizationId: h.organizationId,
        name: 'Strict TS',
        language: 'typescript',
      });
      expect([again.statusCode, again.json().code]).toEqual([409, 'PROFILE_NAME_TAKEN']);
      // The same name in another language is fine.
      await create({ name: 'Strict TS', language: 'javascript' });
      const renamed = await call('PATCH', `/quality-profiles/${profile.id}`, h.orgAdmin, {
        name: 'Strict TypeScript',
        unknownRules: 'ignore',
      });
      expect(renamed.json()).toMatchObject({ name: 'Strict TypeScript', unknownRules: 'ignore' });
      const empty = await call('PATCH', `/quality-profiles/${profile.id}`, h.orgAdmin, {});
      expect(empty.statusCode).toBe(422);
      // The parent is fixed at creation, so no PATCH can make a cycle.
      const reparent = await call('PATCH', `/quality-profiles/${profile.id}`, h.orgAdmin, {
        parentId: builtinTs.id,
      });
      expect(reparent.statusCode).toBe(422);
      const taken = await call('PATCH', `/quality-profiles/${profile.id}`, h.orgAdmin, {
        name: 'Reserved check',
      });
      expect([taken.statusCode, taken.json().code]).toEqual([409, 'PROFILE_NAME_TAKEN']);
    });

    it('resolves concurrent creates of one name through the unique index (one 201, one 409)', async () => {
      const results = await Promise.all(
        Array.from({ length: 4 }, () =>
          call('POST', '/quality-profiles', h.orgAdmin, {
            organizationId: h.organizationId,
            name: 'Raced name',
            language: 'java',
          }),
        ),
      );
      const codes = results.map((r) => r.statusCode).sort();
      expect(codes).toEqual([201, 409, 409, 409]);
      for (const r of results.filter((x) => x.statusCode === 409)) {
        expect(r.json().code).toBe('PROFILE_NAME_TAKEN');
      }
    });

    it('inherits at most three levels, from a parent of the same language (422 body.parentId)', async () => {
      const level1 = await create({ name: 'Level 1', parentId: builtinTs.id });
      const level2 = await create({ name: 'Level 2', parentId: level1.id });
      expect(level2.parentId).toBe(level1.id);
      const tooDeep = await call('POST', '/quality-profiles', h.orgAdmin, {
        organizationId: h.organizationId,
        name: 'Level 3',
        language: 'typescript',
        parentId: level2.id,
      });
      expect(tooDeep.statusCode).toBe(422);
      expect(tooDeep.json().errors[0].path).toBe('body.parentId');
      const otherLanguage = await call('POST', '/quality-profiles', h.orgAdmin, {
        organizationId: h.organizationId,
        name: 'Java child',
        language: 'java',
        parentId: level1.id,
      });
      expect(otherLanguage.statusCode).toBe(422);
      const hasChildren = await call('DELETE', `/quality-profiles/${level1.id}`, h.orgAdmin);
      expect([hasChildren.statusCode, hasChildren.json().code]).toEqual([
        409,
        'PROFILE_HAS_CHILDREN',
      ]);
      // A copy keeps its source's parent, so it stays within the limit too.
      const copy = await call('POST', `/quality-profiles/${level2.id}/copy`, h.orgAdmin, {
        name: 'Level 2 copy',
      });
      expect(copy.json()).toMatchObject({ parentId: level1.id });
    });

    it('copies a profile with its rule settings and parent', async () => {
      const source = await create({ name: 'Copy source', parentId: builtinTs.id });
      const ruleId = await seedRule(h.ctx.db, { key: 'eslint:no-alert' });
      await h.ctx.db
        .insert(profileRules)
        .values({ profileId: source.id, ruleId, active: false, severityOverride: 'low' });
      const res = await call('POST', `/quality-profiles/${source.id}/copy`, h.orgAdmin, {
        name: 'Copy target',
      });
      expect(res.statusCode).toBe(201);
      const copy = res.json() as Profile;
      expect(copy).toMatchObject({ parentId: builtinTs.id, isDefault: false, isBuiltin: false });
      expect(
        await h.ctx.db.select().from(profileRules).where(eq(profileRules.profileId, copy.id)),
      ).toEqual([expect.objectContaining({ ruleId, active: false, severityOverride: 'low' })]);
      const builtinCopy = await call('POST', `/quality-profiles/${builtinTs.id}/copy`, h.orgAdmin, {
        name: 'Editable Qualor way',
      });
      expect(builtinCopy.json()).toMatchObject({ isBuiltin: false, parentId: null });
      const taken = await call('POST', `/quality-profiles/${source.id}/copy`, h.orgAdmin, {
        name: 'Copy target',
      });
      expect([taken.statusCode, taken.json().code]).toEqual([409, 'PROFILE_NAME_TAKEN']);
    });

    it('answers 409 PROFILE_HAS_CHILDREN when a child is created while the DELETE waits for the lock', async () => {
      const parent = await create({ name: 'Race parent', language: 'java' });
      const holder = new pg.Client({ connectionString: h.ctx.database.url });
      await holder.connect();
      try {
        // A concurrent create-with-parent: it holds the language's row locks and has inserted
        // the child, not yet committed, when the DELETE starts waiting.
        await holder.query('BEGIN');
        await holder.query(
          'SELECT id FROM quality_profiles WHERE organization_id = $1 AND language = $2 ORDER BY id FOR UPDATE',
          [h.organizationId, 'java'],
        );
        await holder.query(
          `INSERT INTO quality_profiles (id, organization_id, name, language, parent_id)
           VALUES (gen_random_uuid(), $1, 'Race child', 'java', $2)`,
          [h.organizationId, parent.id],
        );
        const pending = call('DELETE', `/quality-profiles/${parent.id}`);
        await waitForLockWaiters(h.ctx.db, 1);
        await holder.query('COMMIT');
        const res = await pending;
        expect([res.statusCode, res.json().code]).toEqual([409, 'PROFILE_HAS_CHILDREN']);
      } finally {
        await holder.end();
      }
      const [still] = await h.ctx.db
        .select()
        .from(qualityProfiles)
        .where(eq(qualityProfiles.id, parent.id));
      expect(still).toBeDefined();
    });

    it('sets the default per language; deleting the default hands it back to the built-in', async () => {
      const profile = await create({ name: 'Team default', language: 'java' });
      const res = await call('POST', `/quality-profiles/${profile.id}/set-default`, h.orgAdmin);
      expect(res.json()).toMatchObject({ id: profile.id, isDefault: true });
      const defaults = async () =>
        h.ctx.db
          .select()
          .from(qualityProfiles)
          .where(
            and(
              eq(qualityProfiles.organizationId, h.organizationId),
              eq(qualityProfiles.language, 'java'),
              eq(qualityProfiles.isDefault, true),
            ),
          );
      expect((await defaults()).map((p) => p.id)).toEqual([profile.id]);
      expect((await call('DELETE', `/quality-profiles/${profile.id}`, h.orgAdmin)).statusCode).toBe(
        204,
      );
      expect(await defaults()).toEqual([
        expect.objectContaining({ isBuiltin: true, name: 'Qualor way' }),
      ]);
    });

    it('serialises concurrent set-default calls: exactly one default per language', async () => {
      const a = await create({ name: 'Race A', language: 'javascript' });
      const b = await create({ name: 'Race B', language: 'javascript' });
      const results = await Promise.all(
        [a, b, a, b, a, b].map((p) =>
          call('POST', `/quality-profiles/${p.id}/set-default`, h.orgAdmin),
        ),
      );
      expect(results.map((r) => r.statusCode)).toEqual([200, 200, 200, 200, 200, 200]);
      const defaults = await h.ctx.db
        .select()
        .from(qualityProfiles)
        .where(
          and(
            eq(qualityProfiles.organizationId, h.organizationId),
            eq(qualityProfiles.language, 'javascript'),
            eq(qualityProfiles.isDefault, true),
          ),
        );
      expect(defaults).toHaveLength(1);
      expect([a.id, b.id]).toContain(defaults[0]!.id);
    });

    it('lets only org admins change profiles (403 for members and admin-less tokens)', async () => {
      const profile = await create({ name: 'Admins only' });
      const denied = await call('PATCH', `/quality-profiles/${profile.id}`, member, {
        name: 'Nope',
      });
      expect([denied.statusCode, denied.json().code]).toEqual([403, 'FORBIDDEN']);
      const create403 = await call('POST', '/quality-profiles', member, {
        organizationId: h.organizationId,
        name: 'Nope',
        language: 'java',
      });
      expect(create403.statusCode).toBe(403);
      for (const [method, url, body] of [
        ['DELETE', `/quality-profiles/${profile.id}`, undefined],
        ['POST', `/quality-profiles/${profile.id}/copy`, { name: 'Nope' }],
        ['POST', `/quality-profiles/${profile.id}/set-default`, undefined],
      ] as const) {
        const res = await call(method, url, member, body);
        expect([res.statusCode, res.json().code], url).toEqual([403, 'FORBIDDEN']);
      }
      const tokenRes = await call('POST', '/tokens', h.orgAdmin, { name: 'w', scopes: ['write'] });
      const writeToken = bearer((tokenRes.json() as { token: string }).token);
      const scoped = await call('POST', `/quality-profiles/${profile.id}/set-default`, writeToken);
      expect([scoped.statusCode, scoped.json().code]).toEqual([403, 'INSUFFICIENT_SCOPE']);
      expect((await call('DELETE', `/quality-profiles/${profile.id}`, outsider)).statusCode).toBe(
        404,
      );
    });

    it('scopes profiles to their organisation', async () => {
      const res = await call('POST', '/quality-profiles', h.orgAdmin, {
        organizationId: otherOrgId,
        name: 'Elsewhere',
        language: 'java',
      });
      expect(res.statusCode).toBe(404);
      const parentElsewhere = await call('POST', '/quality-profiles', h.orgAdmin, {
        organizationId: h.organizationId,
        name: 'Foreign parent',
        language: 'typescript',
        parentId: '019a0000-0000-7000-8000-000000000000',
      });
      expect(parentElsewhere.statusCode).toBe(422);
      const [foreign] = await h.ctx.db
        .insert(qualityProfiles)
        .values({ organizationId: otherOrgId, name: 'Foreign', language: 'typescript' })
        .returning();
      const foreignParent = await call('POST', '/quality-profiles', h.orgAdmin, {
        organizationId: h.organizationId,
        name: 'Foreign parent 2',
        language: 'typescript',
        parentId: foreign!.id,
      });
      expect(foreignParent.statusCode).toBe(422);
      expect((await call('GET', `/quality-profiles/${foreign!.id}`, member)).statusCode).toBe(404);
    });
  });
});
