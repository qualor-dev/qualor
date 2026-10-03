import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { addMember, bearer, createUser, login, type Session } from '../../test/app';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { mainBranchId, seedIssue, seedRule } from '../../test/issues';
import { engine, file, finding, reportWith } from '../../test/reports';
import {
  analyses,
  branches,
  issues,
  organizations,
  projects,
  qualityProfiles,
  rules,
} from '../db/schema';
import { PROFILE_LANGUAGES } from '../orgs/builtins';

interface Entry {
  rule: { key: string };
  active: boolean;
  severityOverride: string | null;
  source: 'profile' | 'inherited' | 'default';
  sourceProfileId: string | null;
}

describe('profile rule activation and per-project profiles (api.md Â§3, server step 13)', () => {
  let h: IngestHarness;
  let member: Session;
  let outsider: Session;
  let builtinTs: string;
  const call = (
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
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
  const createProfile = async (name: string, extra: Record<string, unknown> = {}) => {
    const res = await call('POST', '/quality-profiles', h.orgAdmin, {
      organizationId: h.organizationId,
      name,
      language: 'typescript',
      ...extra,
    });
    expect(res.statusCode, res.body).toBe(201);
    return (res.json() as { id: string }).id;
  };
  const setRule = (profileId: string, key: string, body: unknown, session = h.orgAdmin) =>
    call('PUT', `/quality-profiles/${profileId}/rules/${encodeURIComponent(key)}`, session, body);
  const entries = async (profileId: string, query = '') => {
    const res = await call('GET', `/quality-profiles/${profileId}/rules?limit=500${query}`, member);
    expect(res.statusCode, res.body).toBe(200);
    return (res.json() as { items: Entry[] }).items;
  };
  const builtinOf = async (language: string) => {
    const [row] = await h.ctx.db
      .select()
      .from(qualityProfiles)
      .where(
        and(
          eq(qualityProfiles.organizationId, h.organizationId),
          eq(qualityProfiles.language, language),
          eq(qualityProfiles.isBuiltin, true),
        ),
      );
    return row!.id;
  };

  beforeAll(async () => {
    h = await createIngestHarness();
    const m = await createUser(h.ctx, { username: 'rules-member' });
    await addMember(h.ctx, h.organizationId, m.id, 'member');
    member = await login(h.ctx, m.username, m.password);
    const o = await createUser(h.ctx, { username: 'rules-outsider' });
    outsider = await login(h.ctx, o.username, o.password);
    builtinTs = await builtinOf('typescript');
    const seeded = [
      await seedRule(h.ctx.db, {
        key: 'eslint:no-console',
        languages: ['typescript', 'javascript'],
      }),
      await seedRule(h.ctx.db, { key: 'eslint:no-debugger' }),
      await seedRule(h.ctx.db, { key: 'eslint:no-with', languages: ['javascript'] }),
      await seedRule(h.ctx.db, { key: 'pmd:UnusedLocalVariable', languages: ['java'] }),
      await seedRule(h.ctx.db, { key: 'gitleaks:aws-access-token', quality: 'security' }),
      await seedRule(h.ctx.db, { key: 'semgrep:eval-detected', quality: 'security' }),
    ];
    // Ruling X2: the organisation has met these rules (its issues reference them).
    const seen = await h.project('acme/seen-rules');
    const branchId = await mainBranchId(h.ctx.db, seen.id);
    for (const ruleId of seeded)
      await seedIssue(h.ctx.db, { projectId: seen.id, branchId, ruleId });
    // Rules only another organisation reported: never listed here (a PUT by key sees only bare data).
    const [other] = await h.ctx.db
      .insert(organizations)
      .values({ key: 'rules-other', name: 'Other' })
      .returning();
    const [otherProject] = await h.ctx.db
      .insert(projects)
      .values({ organizationId: other!.id, key: 'rules-other/app', name: 'App' })
      .returning();
    const [otherBranch] = await h.ctx.db
      .insert(branches)
      .values({ projectId: otherProject!.id, kind: 'branch', name: 'main', isMain: true })
      .returning();
    for (const key of ['eslint:other-org-only', 'semgrep:other-org-only']) {
      await seedIssue(h.ctx.db, {
        projectId: otherProject!.id,
        branchId: otherBranch!.id,
        // Metadata a leak would show: nothing a bare row derives from the key.
        ruleId: await seedRule(h.ctx.db, {
          key,
          name: 'Secret rule of another organisation',
          languages: ['typescript'],
          quality: 'security',
          defaultSeverity: 'high',
        }),
      });
    }
  });
  afterAll(async () => {
    await h.close();
  });

  it('lists the rules a profile governs: a language profile the bound engines, `*` the rest', async () => {
    const keys = (list: Entry[]) => list.map((e) => e.rule.key);
    expect(keys(await entries(builtinTs))).toEqual(['eslint:no-console', 'eslint:no-debugger']);
    const star = await builtinOf('*');
    expect(keys(await entries(star))).toEqual([
      'gitleaks:aws-access-token',
      'semgrep:eval-detected',
    ]);
    expect(await entries(builtinTs)).toEqual([
      expect.objectContaining({ active: true, source: 'default', sourceProfileId: null }),
      expect.objectContaining({ active: true, source: 'default', sourceProfileId: null }),
    ]);
    // Ruling X4: `scope=all` lists everything a finding could route to the profile.
    expect(keys(await entries(builtinTs, '&scope=all'))).toEqual([
      'eslint:no-console',
      'eslint:no-debugger',
      'eslint:no-with',
      'pmd:UnusedLocalVariable',
    ]);
    expect(keys(await entries(star, '&scope=all'))).toEqual([
      'eslint:no-console',
      'eslint:no-debugger',
      'eslint:no-with',
      'gitleaks:aws-access-token',
      'pmd:UnusedLocalVariable',
      'semgrep:eval-detected',
    ]);
    expect(
      (await call('GET', `/quality-profiles/${star}/rules?scope=everything`, member)).statusCode,
    ).toBe(422);
  });

  it('activates, deactivates and re-grades rules, with inheritance resolved', async () => {
    const parent = await createProfile('Parent', { parentId: builtinTs });
    const child = await createProfile('Child', { parentId: parent });
    const off = await setRule(parent, 'eslint:no-console', { active: false });
    expect(off.statusCode, off.body).toBe(200);
    expect(off.json()).toMatchObject({ active: false, source: 'profile', sourceProfileId: parent });
    await setRule(parent, 'eslint:no-debugger', { active: true, severityOverride: 'blocker' });
    const inherited = await entries(child);
    expect(inherited).toEqual([
      expect.objectContaining({
        rule: expect.objectContaining({ key: 'eslint:no-console' }),
        active: false,
        source: 'inherited',
        sourceProfileId: parent,
      }),
      expect.objectContaining({
        rule: expect.objectContaining({ key: 'eslint:no-debugger' }),
        active: true,
        severityOverride: 'blocker',
        source: 'inherited',
      }),
    ]);
    // The child overrides its parent, then drops its own row and inherits again.
    await setRule(child, 'eslint:no-console', { active: true });
    expect((await entries(child, '&active=true')).map((e) => e.rule.key)).toEqual([
      'eslint:no-console',
      'eslint:no-debugger',
    ]);
    const del = await call(
      'DELETE',
      `/quality-profiles/${child}/rules/${encodeURIComponent('eslint:no-console')}`,
    );
    expect(del.statusCode).toBe(204);
    expect((await entries(child, '&active=false')).map((e) => e.rule.key)).toEqual([
      'eslint:no-console',
    ]);
    // A profile that ignores unknown rules lists a rule without any row as inactive.
    const strict = await createProfile('Ignore unknown');
    await call('PATCH', `/quality-profiles/${strict}`, h.orgAdmin, { unknownRules: 'ignore' });
    expect((await entries(strict, '&active=true')).map((e) => e.rule.key)).toEqual([]);
    expect((await entries(strict, '&q=DEBUG')).map((e) => e.rule.key)).toEqual([
      'eslint:no-debugger',
    ]);
    const nul = await call('GET', `/quality-profiles/${strict}/rules?q=a%00b`, member);
    expect([nul.statusCode, nul.json().errors[0].path]).toEqual([422, 'query.q']);
  });

  it('pages the rule list by key', async () => {
    const first = await call('GET', `/quality-profiles/${builtinTs}/rules?limit=1`, member);
    const body = first.json() as { items: Entry[]; nextCursor: string };
    expect(body.items.map((e) => e.rule.key)).toEqual(['eslint:no-console']);
    const second = await call(
      'GET',
      `/quality-profiles/${builtinTs}/rules?limit=1&cursor=${encodeURIComponent(body.nextCursor)}`,
      member,
    );
    expect((second.json() as { items: Entry[]; nextCursor: string | null }).items).toHaveLength(1);
    expect(
      (await call('GET', `/quality-profiles/${builtinTs}/rules?cursor=bogus`, member)).statusCode,
    ).toBe(422);
    expect((await call('GET', `/quality-profiles/${builtinTs}/rules`, outsider)).statusCode).toBe(
      404,
    );
  });

  it('validates rule changes: built-in 409, an engine the profile does not decide 422, bad body 422', async () => {
    const custom = await createProfile('Validation');
    const builtin = await setRule(builtinTs, 'eslint:no-console', { active: false });
    expect([builtin.statusCode, builtin.json().code]).toEqual([409, 'BUILTIN_READ_ONLY']);
    // Ruling X4: only the engine prefix decides; a language profile takes any ESLint, PMD or
    // SpotBugs rule (a finding of those engines in one of its files is routed to it).
    for (const key of ['semgrep:eval-detected', 'gitleaks:aws-access-token', 'semgrep:unknown']) {
      const res = await setRule(custom, key, { active: false });
      expect([res.statusCode, res.json().errors[0].path], key).toEqual([422, 'params.ruleKey']);
      const del = await call(
        'DELETE',
        `/quality-profiles/${custom}/rules/${encodeURIComponent(key)}`,
      );
      expect(del.statusCode, key).toBe(422);
    }
    for (const key of ['no-colon', 'Eslint:upper', ':empty-engine', 'eslint:']) {
      const res = await setRule(custom, key, { active: false });
      expect([res.statusCode, res.json().errors[0].path], key).toEqual([422, 'params.ruleKey']);
    }
    expect((await setRule(custom, 'pmd:UnusedLocalVariable', { active: false })).statusCode).toBe(
      200,
    );
    expect((await setRule(custom, 'eslint:no-with', { active: false })).statusCode).toBe(200);
    const javaStar = await createProfile('Validation star', { language: '*' });
    expect((await setRule(javaStar, 'pmd:UnusedLocalVariable', { active: false })).statusCode).toBe(
      200,
    );
    const badSeverity = await setRule(custom, 'eslint:no-console', {
      active: true,
      severityOverride: 'urgent',
    });
    expect(badSeverity.json().errors[0].path).toBe('body.severityOverride');
    expect((await setRule(custom, 'eslint:no-console', {})).statusCode).toBe(422);
    const byMember = await setRule(custom, 'eslint:no-console', { active: false }, member);
    expect([byMember.statusCode, byMember.json().code]).toEqual([403, 'FORBIDDEN']);
    const delByMember = await call(
      'DELETE',
      `/quality-profiles/${custom}/rules/${encodeURIComponent('eslint:no-console')}`,
      member,
    );
    expect([delByMember.statusCode, delByMember.json().code]).toEqual([403, 'FORBIDDEN']);
    expect(
      (await setRule(custom, 'eslint:no-console', { active: false }, outsider)).statusCode,
    ).toBe(404);
  });

  it('assigns a profile to one language of a project, and ingestion then filters by it', async () => {
    const project = await h.project('acme/profiled');
    const list = await call('GET', `/projects/${project.id}/quality-profiles`, member);
    expect(list.statusCode).toBe(200);
    expect(
      (list.json() as { language: string; source: string }[]).map((e) => [e.language, e.source]),
    ).toEqual(PROFILE_LANGUAGES.map((language) => [language, 'default']));
    const quiet = await createProfile('No console');
    await setRule(quiet, 'eslint:no-console', { active: false });
    const assign = await call(
      'PUT',
      `/projects/${project.id}/quality-profiles/typescript`,
      h.orgAdmin,
      {
        profileId: quiet,
      },
    );
    expect(assign.statusCode, assign.body).toBe(200);
    expect(assign.json()).toMatchObject({
      language: 'typescript',
      source: 'project',
      profile: { id: quiet, name: 'No console' },
    });
    const report = reportWith({
      projectKey: project.key,
      engines: [engine('eslint', [{ id: 'no-console' }, { id: 'no-debugger' }])],
      files: [file('src/a.ts')],
      findings: [
        finding({ ruleId: 'no-console', line: 1 }),
        finding({ ruleId: 'no-debugger', line: 2 }),
      ],
    });
    const analysisId = await project.ingestOk(report);
    const branch = await mainBranchId(h.ctx.db, project.id);
    const stored = await h.ctx.db.select().from(issues).where(eq(issues.branchId, branch));
    expect(stored).toHaveLength(1);
    const [analysis] = await h.ctx.db.select().from(analyses).where(eq(analyses.id, analysisId));
    expect(analysis!.warnings).toContainEqual(
      expect.objectContaining({ code: 'FINDINGS_FILTERED_BY_PROFILE', count: 1 }),
    );
    const reset = await call(
      'PUT',
      `/projects/${project.id}/quality-profiles/typescript`,
      h.orgAdmin,
      {
        profileId: null,
      },
    );
    expect(reset.json()).toMatchObject({ source: 'default', profile: { name: 'Qualor way' } });
  });

  it('the next analysis follows every profile change: default, rule rows, unknownRules, deletion', async () => {
    const project = await h.project('acme/follows');
    const branch = await mainBranchId(h.ctx.db, project.id);
    const report = reportWith({
      projectKey: project.key,
      engines: [engine('eslint', [{ id: 'no-console' }, { id: 'no-debugger' }])],
      files: [file('src/a.ts')],
      findings: [
        finding({ ruleId: 'no-console', line: 1 }),
        finding({ ruleId: 'no-debugger', line: 2 }),
      ],
    });
    const openAfterIngest = async () => {
      await project.ingestOk(report);
      const rows = await h.ctx.db
        .select({ key: rules.key, severity: issues.severity })
        .from(issues)
        .innerJoin(rules, eq(rules.id, issues.ruleId))
        .where(and(eq(issues.branchId, branch), eq(issues.status, 'open')))
        .orderBy(rules.key);
      return rows.map((r) => `${r.key}/${r.severity}`);
    };
    expect(await openAfterIngest()).toEqual([
      'eslint:no-console/medium',
      'eslint:no-debugger/medium',
    ]);

    // A new organisation default for the language (the project has no override).
    const team = await createProfile('Team TS');
    await setRule(team, 'eslint:no-debugger', { active: false });
    expect((await call('POST', `/quality-profiles/${team}/set-default`)).statusCode).toBe(200);
    expect(await openAfterIngest()).toEqual(['eslint:no-console/medium']);

    // A rule row changed in the default profile: re-activated and re-graded.
    await setRule(team, 'eslint:no-debugger', { active: true, severityOverride: 'blocker' });
    expect(await openAfterIngest()).toEqual([
      'eslint:no-console/medium',
      'eslint:no-debugger/blocker',
    ]);

    // Its own row dropped and unknown rules ignored: nothing is active any more.
    await call(
      'DELETE',
      `/quality-profiles/${team}/rules/${encodeURIComponent('eslint:no-debugger')}`,
    );
    await call('PATCH', `/quality-profiles/${team}`, h.orgAdmin, { unknownRules: 'ignore' });
    expect(await openAfterIngest()).toEqual([]);

    // A child of the default, assigned to the project: its own row wins over the chain, and its
    // own unknownRules ('activate') decides a rule no profile of the chain has a row for â€” the
    // listing says exactly what the analysis then does.
    const child = await createProfile('Team TS child', { parentId: team });
    await setRule(team, 'eslint:no-console', { active: true, severityOverride: 'low' });
    await setRule(child, 'eslint:no-console', { active: false });
    await call('PUT', `/projects/${project.id}/quality-profiles/typescript`, h.orgAdmin, {
      profileId: child,
    });
    expect(
      (await entries(child)).map((e) => [e.rule.key, e.active, e.source, e.severityOverride]),
    ).toEqual([
      ['eslint:no-console', false, 'profile', null],
      ['eslint:no-debugger', true, 'default', null],
    ]);
    expect(await openAfterIngest()).toEqual(['eslint:no-debugger/medium']);
    await call(
      'DELETE',
      `/quality-profiles/${child}/rules/${encodeURIComponent('eslint:no-console')}`,
    );
    expect(await openAfterIngest()).toEqual(['eslint:no-console/low', 'eslint:no-debugger/medium']);

    // Deleting the assigned profile returns the project to the default; deleting the default
    // hands it back to the built-in, which activates every rule.
    expect((await call('DELETE', `/quality-profiles/${child}`)).statusCode).toBe(204);
    expect(await openAfterIngest()).toEqual(['eslint:no-console/low']);
    expect((await call('DELETE', `/quality-profiles/${team}`)).statusCode).toBe(204);
    expect(await openAfterIngest()).toEqual([
      'eslint:no-console/medium',
      'eslint:no-debugger/medium',
    ]);
  });

  it('validates project assignments: same organisation and language, admins only', async () => {
    const project = await h.project('acme/assign-checks');
    const javaProfile = await createProfile('Java team', { language: 'java' });
    const wrongLanguage = await call(
      'PUT',
      `/projects/${project.id}/quality-profiles/typescript`,
      h.orgAdmin,
      { profileId: javaProfile },
    );
    expect(wrongLanguage.statusCode).toBe(422);
    expect(wrongLanguage.json().errors[0].path).toBe('body.profileId');
    const [other] = await h.ctx.db
      .insert(organizations)
      .values({ key: 'assign-other', name: 'Other' })
      .returning();
    const [foreign] = await h.ctx.db
      .insert(qualityProfiles)
      .values({ organizationId: other!.id, name: 'Foreign', language: 'java' })
      .returning();
    const foreignRes = await call(
      'PUT',
      `/projects/${project.id}/quality-profiles/java`,
      h.orgAdmin,
      {
        profileId: foreign!.id,
      },
    );
    expect(foreignRes.statusCode).toBe(422);
    const star = await call('PUT', `/projects/${project.id}/quality-profiles/*`, h.orgAdmin, {
      profileId: null,
    });
    expect(star.statusCode).toBe(200);
    expect(
      (
        await call('PUT', `/projects/${project.id}/quality-profiles/cobol`, h.orgAdmin, {
          profileId: null,
        })
      ).statusCode,
    ).toBe(422);
    const byMember = await call('PUT', `/projects/${project.id}/quality-profiles/java`, member, {
      profileId: javaProfile,
    });
    expect(byMember.statusCode).toBe(403);
    expect(
      (await call('GET', `/projects/${project.id}/quality-profiles`, outsider)).statusCode,
    ).toBe(404);
    expect(
      (
        await call('PUT', `/projects/${project.id}/quality-profiles/java`, outsider, {
          profileId: javaProfile,
        })
      ).statusCode,
    ).toBe(404);
  });

  it('refuses project analysis tokens on the profile and rule routes (403 TOKEN_NOT_ALLOWED)', async () => {
    const project = await h.project('acme/token-check');
    const token = bearer(project.token);
    const org = `organizationId=${h.organizationId}`;
    for (const [method, url, body] of [
      ['GET', `/rules?${org}`, undefined],
      ['GET', `/rules/eslint%3Ano-console?${org}`, undefined],
      ['GET', `/quality-profiles?${org}`, undefined],
      ['GET', `/quality-profiles/${builtinTs}`, undefined],
      ['GET', `/quality-profiles/${builtinTs}/rules`, undefined],
      [
        'POST',
        '/quality-profiles',
        { organizationId: h.organizationId, name: 'By token', language: 'java' },
      ],
      ['PUT', `/quality-profiles/${builtinTs}/rules/eslint%3Ano-console`, { active: false }],
      ['DELETE', `/quality-profiles/${builtinTs}/rules/eslint%3Ano-console`, undefined],
      ['POST', `/quality-profiles/${builtinTs}/set-default`, undefined],
      ['GET', `/projects/${project.id}/quality-profiles`, undefined],
      ['PUT', `/projects/${project.id}/quality-profiles/typescript`, { profileId: null }],
    ] as const) {
      const res = await call(method, url, token, body);
      expect([res.statusCode, res.json().code], `${method} ${url}`).toEqual([
        403,
        'TOKEN_NOT_ALLOWED',
      ]);
    }
  });

  // The two tests below make rules visible to the organisation (profile rows), so they run last.

  it('decides every rule ingestion routes to the profile (ruling X4): JavaScript-only ESLint on TypeScript, PMD on pom.xml and file-less SpotBugs on *', async () => {
    const project = await h.project('acme/routing');
    const branch = await mainBranchId(h.ctx.db, project.id);
    const report = reportWith({
      projectKey: project.key,
      engines: [
        engine('eslint', [{ id: 'no-with', languages: ['javascript'] }]),
        engine('pmd'),
        engine('spotbugs'),
      ],
      files: [file('src/a.ts'), file('pom.xml', { language: 'other' })],
      findings: [
        finding({ ruleId: 'no-with', line: 1 }),
        finding({ ruleId: 'no-console', line: 2 }),
        finding({ engineId: 'pmd', ruleId: 'PomRule', path: 'pom.xml', line: 3 }),
        finding({ engineId: 'spotbugs', ruleId: 'FileLessBug', path: null }),
      ],
    });
    const openAfterIngest = async () => {
      const analysisId = await project.ingestOk(report);
      const rows = await h.ctx.db
        .select({ key: rules.key })
        .from(issues)
        .innerJoin(rules, eq(rules.id, issues.ruleId))
        .where(and(eq(issues.branchId, branch), eq(issues.status, 'open')))
        .orderBy(rules.key);
      const [analysis] = await h.ctx.db.select().from(analyses).where(eq(analyses.id, analysisId));
      return { keys: rows.map((r) => r.key), warnings: analysis!.warnings };
    };
    expect((await openAfterIngest()).keys).toEqual([
      'eslint:no-console',
      'eslint:no-with',
      'pmd:PomRule',
      'spotbugs:FileLessBug',
    ]);

    const ts = await createProfile('Routing TS');
    const star = await createProfile('Routing star', { language: '*' });
    // A JavaScript-only ESLint rule fires on a .ts file, so the TypeScript profile decides it.
    expect((await setRule(ts, 'eslint:no-with', { active: false })).statusCode).toBe(200);
    // pom.xml is a file of language `other`, and a file-less finding has no language: `*`.
    expect((await setRule(star, 'pmd:PomRule', { active: false })).statusCode).toBe(200);
    expect((await setRule(star, 'spotbugs:FileLessBug', { active: false })).statusCode).toBe(200);
    for (const [language, profileId] of [
      ['typescript', ts],
      ['*', star],
    ] as const) {
      const res = await call(
        'PUT',
        `/projects/${project.id}/quality-profiles/${language}`,
        h.orgAdmin,
        { profileId },
      );
      expect(res.statusCode, res.body).toBe(200);
    }
    // A rule that was set is always listed, although P4's default view would leave it out.
    const listed = async (profileId: string) =>
      (await entries(profileId))
        .filter((e) => e.source === 'profile')
        .map((e) => [e.rule.key, e.active]);
    expect(await listed(ts)).toEqual([['eslint:no-with', false]]);
    expect(await listed(star)).toEqual([
      ['pmd:PomRule', false],
      ['spotbugs:FileLessBug', false],
    ]);

    const after = await openAfterIngest();
    expect(after.keys).toEqual(['eslint:no-console']);
    expect(after.warnings).toContainEqual(
      expect.objectContaining({ code: 'FINDINGS_FILTERED_BY_PROFILE', count: 3 }),
    );
  });

  it("decides Qualor's security rules in the language profiles, keys with a slash included (plan 6B-1)", async () => {
    const java = await createProfile('Qualor rules java', { language: 'java' });
    expect((await setRule(java, 'qualor:java/sql-injection', { active: false })).statusCode).toBe(
      200,
    );
    const ts = await createProfile('Qualor rules ts');
    expect((await setRule(ts, 'qualor:js/sql-injection', { active: false })).statusCode).toBe(200);
    expect(
      (await entries(java)).find((e) => e.rule.key === 'qualor:java/sql-injection'),
    ).toMatchObject({
      active: false,
    });
  });

  it('hides other organisationsâ€™ rules; a PUT by key answers alike for them and for new keys (rulings X2, X5)', async () => {
    const custom = await createProfile('X2 check');
    const star = await createProfile('X2 star', { language: '*' });
    const org = `organizationId=${h.organizationId}`;
    expect((await entries(custom, '&scope=all')).map((e) => e.rule.key)).not.toContain(
      'eslint:other-org-only',
    );
    expect((await entries(star, '&scope=all')).map((e) => e.rule.key)).not.toContain(
      'semgrep:other-org-only',
    );
    expect((await call('GET', `/rules/eslint%3Aother-org-only?${org}`, member)).statusCode).toBe(
      404,
    );

    // Another organisation's rule and a key nobody reported answer the same way: 200, with only
    // what the key itself says (ingestion's bare defaults), never the stored metadata.
    const foreign = await setRule(custom, 'eslint:other-org-only', { active: false });
    const fresh = await setRule(custom, 'eslint:never-reported', { active: false });
    expect([foreign.statusCode, fresh.statusCode]).toEqual([200, 200]);
    const bare = (ruleId: string) => ({
      key: `eslint:${ruleId}`,
      name: ruleId,
      engine: 'eslint',
      languages: [],
      defaultSeverity: 'medium',
      quality: 'maintainability',
      kind: 'issue',
    });
    const rest = {
      active: false,
      severityOverride: null,
      source: 'profile',
      sourceProfileId: custom,
    };
    expect(foreign.json()).toEqual({ rule: bare('other-org-only'), ...rest });
    expect(fresh.json()).toEqual({ rule: bare('never-reported'), ...rest });
    const [created] = await h.ctx.db
      .select()
      .from(rules)
      .where(eq(rules.key, 'eslint:never-reported'));
    expect(created).toMatchObject({
      origin: 'reported',
      engineId: 'eslint',
      name: 'never-reported',
    });
    // Gitleaks' bare defaults, as ingestion writes them (report-format.md Â§7.1).
    const secret = await setRule(star, 'gitleaks:new-token-kind', { active: true });
    expect(secret.json().rule).toMatchObject({ defaultSeverity: 'blocker', quality: 'security' });

    // DELETE is 204 for another organisation's rule and for a key that does not exist.
    for (const key of ['semgrep:other-org-only', 'semgrep:nobody-ever']) {
      const del = await call(
        'DELETE',
        `/quality-profiles/${star}/rules/${encodeURIComponent(key)}`,
      );
      expect(del.statusCode, key).toBe(204);
    }
    expect(
      (await h.ctx.db.select().from(rules).where(eq(rules.key, 'semgrep:nobody-ever'))).length,
    ).toBe(0);

    // Once one of its profiles has a row, the organisation has met the rule; its metadata is the
    // shared global row.
    const seen = await call('GET', `/rules/eslint%3Aother-org-only?${org}`, member);
    expect(seen.json()).toMatchObject({ name: 'Secret rule of another organisation' });
  });
});
