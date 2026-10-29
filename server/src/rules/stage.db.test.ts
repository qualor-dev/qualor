import { and, eq, sql } from 'drizzle-orm';
import { computeFingerprints } from '@qualor/shared';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { engine, file, finding, reportWith } from '../../test/reports';
import { analyses, profileRules, projectProfiles, qualityProfiles, rules } from '../db/schema';
import type { IngestionStage } from '../ingest/process';
import type { IngestionState } from '../ingest/state';
import { upsertReportedRules } from './catalog';
import { rulesStage } from './stage';

describe('rules stage (server step 7)', () => {
  let h: IngestHarness;
  let seen: IngestionState = {};
  const probe: IngestionStage = {
    name: 'probe',
    run: async (ctx) => {
      seen = ctx.state;
    },
  };
  const stages = [rulesStage, probe];
  const ruleRow = async (key: string) =>
    (await h.ctx.db.select().from(rules).where(eq(rules.key, key)))[0];
  const tsDefault = async () =>
    (
      await h.ctx.db
        .select()
        .from(qualityProfiles)
        .where(
          and(
            eq(qualityProfiles.organizationId, h.organizationId),
            eq(qualityProfiles.language, 'typescript'),
            eq(qualityProfiles.isDefault, true),
          ),
        )
    )[0]!;

  beforeAll(async () => {
    h = await createIngestHarness();
  });
  afterAll(async () => {
    await h.close();
  });

  it('creates reported rules from metadata, and bare rules from findings with engine defaults', async () => {
    const p = await h.project('rules/create');
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        engines: [
          engine('eslint', [
            {
              id: 'eqeqeq',
              name: 'Require ===',
              helpUri: 'https://eslint.org/docs/latest/rules/eqeqeq',
              defaultSeverity: 'high',
              quality: 'maintainability',
              tags: ['style'],
              cwe: [],
              languages: ['typescript'],
            },
            // The schema does not forbid a duplicate id; the first entry wins.
            { id: 'eqeqeq', name: 'Duplicate entry' },
          ]),
          engine('gitleaks'),
          engine('my-tool'),
        ],
        files: [file('src/a.ts')],
        findings: [
          finding({ ruleId: 'eqeqeq', line: 1 }),
          finding({ engineId: 'gitleaks', ruleId: 'generic-api-key', line: 2 }),
          finding({ engineId: 'my-tool', ruleId: 'R1', line: 3, severity: 'low' }),
          finding({ engineId: 'my-tool', ruleId: 'R2', path: null }),
        ],
      }),
      stages,
    );
    expect(await ruleRow('eslint:eqeqeq')).toMatchObject({
      engineId: 'eslint',
      engineRuleId: 'eqeqeq',
      name: 'Require ===',
      helpUri: 'https://eslint.org/docs/latest/rules/eqeqeq',
      defaultSeverity: 'high',
      quality: 'maintainability',
      kind: 'issue',
      tags: ['style'],
      languages: ['typescript'],
      origin: 'reported',
      status: 'ready',
    });
    expect(await ruleRow('gitleaks:generic-api-key')).toMatchObject({
      name: 'generic-api-key',
      defaultSeverity: 'blocker',
      quality: 'security',
      origin: 'reported',
    });
    expect(await ruleRow('my-tool:R1')).toMatchObject({
      defaultSeverity: 'low',
      quality: 'maintainability',
    });
    expect(await ruleRow('my-tool:R2')).toMatchObject({ defaultSeverity: 'medium' });
    // Metadata without a scope and a bare rule both apply to all code (0.13).
    expect((await ruleRow('eslint:eqeqeq'))!.scope).toBe('all');
    expect((await ruleRow('my-tool:R2'))!.scope).toBe('all');
    expect(seen.findings?.map((f) => [f.rule.key, f.severity])).toEqual([
      ['eslint:eqeqeq', 'high'],
      ['gitleaks:generic-api-key', 'blocker'],
      ['my-tool:R1', 'low'],
      ['my-tool:R2', 'medium'],
    ]);
  });

  it('refreshes reported metadata, keeps it when a later report has none, and never touches a builtin rule', async () => {
    const p = await h.project('rules/refresh');
    await h.ctx.db.insert(rules).values({
      key: 'eslint:no-eval',
      engineId: 'eslint',
      engineRuleId: 'no-eval',
      name: 'Built-in name',
      defaultSeverity: 'high',
      quality: 'security',
      kind: 'issue',
      origin: 'builtin',
    });
    const withMeta = (name: string) =>
      reportWith({
        projectKey: p.key,
        engines: [
          engine('eslint', [
            { id: 'no-var', name, defaultSeverity: 'low' },
            { id: 'no-eval', name: 'Reported name', defaultSeverity: 'info' },
          ]),
        ],
        files: [file('src/a.ts')],
        findings: [finding({ ruleId: 'no-var' }), finding({ ruleId: 'no-eval', line: 2 })],
      });
    await p.ingestOk(withMeta('Old name'), stages);
    const created = await ruleRow('eslint:no-var');
    await p.ingestOk({ ...withMeta('New name'), analysisDate: '2026-09-22T11:00:00Z' }, stages);
    const refreshed = await ruleRow('eslint:no-var');
    expect(refreshed).toMatchObject({ id: created!.id, name: 'New name' });
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        analysisDate: '2026-09-22T12:00:00Z',
        files: [file('src/a.ts')],
        findings: [finding({ ruleId: 'no-var' })],
      }),
      stages,
    );
    expect(await ruleRow('eslint:no-var')).toMatchObject({
      name: 'New name',
      defaultSeverity: 'low',
    });
    expect(await ruleRow('eslint:no-eval')).toMatchObject({
      name: 'Built-in name',
      defaultSeverity: 'high',
      origin: 'builtin',
    });
    // A finding without its own severity takes its rule's default.
    expect(seen.findings?.map((f) => f.severity)).toEqual(['low']);
  });

  it('never locks an unchanged rule row, and locks changed ones in key order', async () => {
    // Rules are global: an ingestion that merely re-sends the same metadata must not hold a row
    // lock on them until it commits, or every other organisation's ingestion of those rules
    // would queue behind it.
    const p = await h.project('rules/no-lock');
    const meta = (name: string, scope?: 'main') => ({
      id: 'no-lock-rule',
      name,
      defaultSeverity: 'high' as const,
      quality: 'maintainability' as const,
      ...(scope ? { scope } : {}),
    });
    const reportOf = (name: string, scope?: 'main') =>
      reportWith({
        projectKey: p.key,
        engines: [engine('eslint', [meta(name, scope)])],
        files: [file('src/a.ts')],
        findings: [finding({ ruleId: 'no-lock-rule' })],
      });
    await p.ingestOk(reportOf('Same name'));
    const lockedElsewhere = async (strength: 'NO KEY UPDATE' | 'UPDATE'): Promise<boolean> => {
      try {
        await h.ctx.db.transaction(async (other) => {
          await other.execute(sql`SET LOCAL lock_timeout = '100ms'`);
          await other.execute(
            sql`SELECT 1 FROM rules WHERE key = 'eslint:no-lock-rule' FOR ${sql.raw(strength)}`,
          );
        });
        return false;
      } catch {
        return true;
      }
    };
    const whileUpserting = (name: string, strength: 'NO KEY UPDATE' | 'UPDATE') =>
      h.ctx.db.transaction(async (tx) => {
        await upsertReportedRules(tx, reportOf(name));
        return lockedElsewhere(strength);
      });
    // Another ingestion changing the metadata (NO KEY UPDATE) never waits on an unchanged rule...
    expect(await whileUpserting('Same name', 'NO KEY UPDATE')).toBe(false);
    // ...though the rules the findings reference are held FOR KEY SHARE, so a cleanup deleting a
    // bare rule (FOR UPDATE) cannot remove one this ingestion is about to use.
    expect(await whileUpserting('Same name', 'UPDATE')).toBe(true);
    // (0.13) Once a report has given the rule a scope, a report without one (an older scanner)
    // leaves it: no write and no lock, however the two scanner versions alternate.
    await h.ctx.db.transaction((tx) => upsertReportedRules(tx, reportOf('Same name', 'main')));
    expect(await whileUpserting('Same name', 'NO KEY UPDATE')).toBe(false);
    expect((await ruleRow('eslint:no-lock-rule'))!.scope).toBe('main');
    // A real change takes the stronger lock (and writes), and still keeps the stored scope.
    expect(await whileUpserting('New name', 'NO KEY UPDATE')).toBe(true);
    expect(await ruleRow('eslint:no-lock-rule')).toMatchObject({ name: 'New name', scope: 'main' });
  });

  it('filters and re-grades findings by the effective profile, with inheritance and a project override', async () => {
    const p = await h.project('rules/profiles');
    const report = reportWith({
      projectKey: p.key,
      engines: [
        engine('eslint', [{ id: 'keep' }, { id: 'drop' }, { id: 'other' }]),
        engine('gitleaks'),
      ],
      files: [file('src/a.ts'), file('Main.java', { language: 'java' })],
      findings: [
        finding({ ruleId: 'keep', line: 1 }),
        finding({ ruleId: 'drop', line: 2 }),
        finding({ ruleId: 'other', line: 3 }),
        finding({ engineId: 'gitleaks', ruleId: 'aws-access-token', line: 4 }),
        finding({ ruleId: 'keep', path: 'Main.java', line: 5 }),
      ],
    });
    // Seed the rules, then build: parent (ignore unknown) activates `keep` and `drop`; the
    // project's child profile turns `drop` off and re-grades `keep` to blocker.
    await p.ingestOk(report, stages);
    const id = async (key: string) => (await ruleRow(key))!.id;
    const [parent] = await h.ctx.db
      .insert(qualityProfiles)
      .values({
        organizationId: h.organizationId,
        name: 'Team TS',
        language: 'typescript',
        unknownRules: 'ignore',
      })
      .returning();
    const [child] = await h.ctx.db
      .insert(qualityProfiles)
      .values({
        organizationId: h.organizationId,
        name: 'Payments TS',
        language: 'typescript',
        parentId: parent!.id,
        unknownRules: 'ignore',
      })
      .returning();
    await h.ctx.db.insert(profileRules).values([
      { profileId: parent!.id, ruleId: await id('eslint:keep'), active: true },
      { profileId: parent!.id, ruleId: await id('eslint:drop'), active: true },
      { profileId: child!.id, ruleId: await id('eslint:drop'), active: false },
      {
        profileId: child!.id,
        ruleId: await id('eslint:keep'),
        active: true,
        severityOverride: 'blocker',
      },
    ]);
    await h.ctx.db
      .insert(projectProfiles)
      .values({ projectId: p.id, language: 'typescript', profileId: child!.id });

    const analysisId = await p.ingestOk(
      { ...report, analysisDate: '2026-09-22T11:00:00Z' },
      stages,
    );
    expect(seen.findings?.map((f) => [f.rule.key, f.finding.location?.path, f.severity])).toEqual([
      ['eslint:keep', 'src/a.ts', 'blocker'],
      // Gitleaks is not language-bound: the `*` built-in (activate unknown) governs it.
      ['gitleaks:aws-access-token', 'src/a.ts', 'blocker'],
      // A Java file uses the Java built-in, untouched by the TS override.
      ['eslint:keep', 'Main.java', 'medium'],
    ]);
    const [row] = await h.ctx.db.select().from(analyses).where(eq(analyses.id, analysisId));
    expect(row!.warnings).toContainEqual({
      code: 'FINDINGS_FILTERED_BY_PROFILE',
      message: '2 finding(s) were dropped because their rule is not active in the quality profile',
      count: 2,
    });
    // The organisation default is still the built-in: other projects are unaffected.
    expect((await tsDefault()).isBuiltin).toBe(true);
  });

  it("drops a finding its rule's scope leaves out: a main rule on test code, a test rule on main code (0.13)", async () => {
    const p = await h.project('rules/scope');
    const report = reportWith({
      projectKey: p.key,
      engines: [
        engine('sonarjs', [
          { id: 'S2004', scope: 'main' },
          { id: 'S2699', scope: 'test' },
          // No scope: `all`, as every report before 0.13.
          { id: 'S1481' },
        ]),
      ],
      files: [file('src/a.ts'), file('src/a.test.ts', { kind: 'test' })],
      findings: [
        finding({ engineId: 'sonarjs', ruleId: 'S2004', line: 1 }),
        finding({ engineId: 'sonarjs', ruleId: 'S2004', path: 'src/a.test.ts', line: 2 }),
        finding({ engineId: 'sonarjs', ruleId: 'S2004', path: 'src/a.test.ts', line: 3 }),
        finding({ engineId: 'sonarjs', ruleId: 'S2699', line: 4 }),
        finding({ engineId: 'sonarjs', ruleId: 'S2699', path: 'src/a.test.ts', line: 5 }),
        finding({ engineId: 'sonarjs', ruleId: 'S1481', path: 'src/a.test.ts', line: 6 }),
        // A file-less finding has no kind: its scope never drops it.
        finding({ engineId: 'sonarjs', ruleId: 'S2004', path: null }),
      ],
    });
    const analysisId = await p.ingestOk(report, stages);
    expect(seen.findings?.map((f) => [f.rule.key, f.finding.location?.path ?? null])).toEqual([
      ['sonarjs:S2004', 'src/a.ts'],
      ['sonarjs:S2699', 'src/a.test.ts'],
      ['sonarjs:S1481', 'src/a.test.ts'],
      ['sonarjs:S2004', null],
    ]);
    expect((await ruleRow('sonarjs:S2004'))!.scope).toBe('main');
    expect((await ruleRow('sonarjs:S2699'))!.scope).toBe('test');
    expect((await ruleRow('sonarjs:S1481'))!.scope).toBe('all');
    const [row] = await h.ctx.db.select().from(analyses).where(eq(analyses.id, analysisId));
    expect(row!.warnings).toEqual([
      {
        code: 'FINDINGS_FILTERED_BY_SCOPE',
        message: '2 finding(s) were dropped because their rule does not apply to test code',
        count: 2,
      },
      {
        code: 'FINDINGS_FILTERED_BY_SCOPE',
        message: '1 finding(s) were dropped because their rule does not apply to main code',
        count: 1,
      },
    ]);
  });

  it('never drops a finding on a file the report does not list, whatever its scope (0.13)', async () => {
    const p = await h.project('rules/scope-unlisted');
    // The report schema refuses such a finding; the stage still never guesses the file's kind.
    const unlisted: IngestionStage = {
      name: 'rules',
      run: (ctx) =>
        rulesStage.run({
          ...ctx,
          report: { ...ctx.report, files: ctx.report.files.filter((f) => f.kind !== 'test') },
        }),
    };
    const analysisId = await p.ingestOk(
      reportWith({
        projectKey: p.key,
        engines: [engine('sonarjs', [{ id: 'S2004', scope: 'main' }])],
        files: [file('src/a.ts'), file('src/a.test.ts', { kind: 'test' })],
        findings: [finding({ engineId: 'sonarjs', ruleId: 'S2004', path: 'src/a.test.ts' })],
      }),
      [unlisted, probe],
    );
    expect(seen.findings?.map((f) => f.finding.location?.path)).toEqual(['src/a.test.ts']);
    const [row] = await h.ctx.db.select().from(analyses).where(eq(analyses.id, analysisId));
    expect(row!.warnings).toEqual([]);
  });

  it('stores the scope a report carries; a report without one keeps the stored scope and is judged as all code (0.13)', async () => {
    const p = await h.project('rules/scope-refresh');
    let minute = 0;
    const withScope = (scope?: 'main' | 'test') =>
      reportWith({
        projectKey: p.key,
        analysisDate: new Date(Date.UTC(2026, 8, 22, 10, minute++)).toISOString(),
        engines: [engine('sonarjs', [{ id: 'S3776', ...(scope ? { scope } : {}) }])],
        files: [file('src/a.ts'), file('src/a.test.ts', { kind: 'test' })],
        findings: [
          finding({ engineId: 'sonarjs', ruleId: 'S3776', line: 1 }),
          finding({ engineId: 'sonarjs', ruleId: 'S3776', path: 'src/a.test.ts', line: 2 }),
        ],
      });
    const kept = () => seen.findings?.map((f) => f.finding.location?.path);
    await p.ingestOk(withScope('main'), stages);
    const created = await ruleRow('sonarjs:S3776');
    expect(created!.scope).toBe('main');
    expect(kept()).toEqual(['src/a.ts']);
    await p.ingestOk(withScope('test'), stages);
    const refreshed = await ruleRow('sonarjs:S3776');
    expect(refreshed).toMatchObject({ id: created!.id, scope: 'test' });
    expect(kept()).toEqual(['src/a.test.ts']);
    // An older scanner sends no scope: its report is judged as in 0.12, and the stored scope stays.
    await p.ingestOk(withScope(), stages);
    expect(await ruleRow('sonarjs:S3776')).toMatchObject({
      scope: 'test',
      updatedAt: refreshed!.updatedAt,
    });
    expect(kept()).toEqual(['src/a.ts', 'src/a.test.ts']);
  });

  it('judges a finding by its own report: a stored main scope never drops a rule the report gives no scope (0.13)', async () => {
    const p = await h.project('rules/scope-own-report');
    let minute = 0;
    const reportOf = (rules: Parameters<typeof engine>[1]) =>
      reportWith({
        projectKey: p.key,
        analysisDate: new Date(Date.UTC(2026, 8, 22, 10, minute++)).toISOString(),
        engines: [engine('sonarjs', rules)],
        files: [file('src/a.test.ts', { kind: 'test' })],
        findings: [finding({ engineId: 'sonarjs', ruleId: 'S138', path: 'src/a.test.ts' })],
      });
    // A 0.13 scanner stores `main`...
    await p.ingestOk(reportOf([{ id: 'S138', scope: 'main' }]), stages);
    expect((await ruleRow('sonarjs:S138'))!.scope).toBe('main');
    expect(seen.findings).toEqual([]);
    // ...and an external SARIF names the rule only in its finding: kept, as in 0.12.
    await p.ingestOk(reportOf([]), stages);
    expect(seen.findings?.map((f) => f.finding.location?.path)).toEqual(['src/a.test.ts']);
  });

  it('drops a test-file finding of a rule its report says is main, whatever the stored scope (0.13)', async () => {
    const p = await h.project('rules/scope-builtin');
    // A built-in rule is never refreshed by a report, so its stored scope stays `all`.
    await h.ctx.db.insert(rules).values({
      key: 'sonarjs:S1541',
      engineId: 'sonarjs',
      engineRuleId: 'S1541',
      name: 'Built-in S1541',
      defaultSeverity: 'medium',
      quality: 'maintainability',
      kind: 'issue',
      origin: 'builtin',
    });
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        engines: [engine('sonarjs', [{ id: 'S1541', scope: 'main' }])],
        files: [file('src/a.ts'), file('src/a.test.ts', { kind: 'test' })],
        findings: [
          finding({ engineId: 'sonarjs', ruleId: 'S1541', line: 1 }),
          finding({ engineId: 'sonarjs', ruleId: 'S1541', path: 'src/a.test.ts', line: 2 }),
        ],
      }),
      stages,
    );
    expect((await ruleRow('sonarjs:S1541'))!.scope).toBe('all');
    expect(seen.findings?.map((f) => f.finding.location?.path)).toEqual(['src/a.ts']);
  });

  it("applies a profile's scope override: the nearest override of the chain beats the rule's scope (0.13)", async () => {
    const p = await h.project('rules/scope-profiles');
    const report = reportWith({
      projectKey: p.key,
      engines: [
        engine('sonarjs', [
          { id: 'S107', scope: 'main' },
          { id: 'S2187', scope: 'test' },
          { id: 'S1186' },
        ]),
      ],
      files: [file('src/a.ts'), file('src/a.spec.ts', { kind: 'test' })],
      findings: [
        finding({ engineId: 'sonarjs', ruleId: 'S107', path: 'src/a.spec.ts', line: 1 }),
        finding({ engineId: 'sonarjs', ruleId: 'S2187', line: 2 }),
        finding({ engineId: 'sonarjs', ruleId: 'S2187', path: 'src/a.spec.ts', line: 3 }),
        finding({ engineId: 'sonarjs', ruleId: 'S1186', path: 'src/a.spec.ts', line: 4 }),
        finding({ engineId: 'sonarjs', ruleId: 'S1186', line: 5 }),
      ],
    });
    await p.ingestOk(report, stages);
    const id = async (key: string) => (await ruleRow(key))!.id;
    const [parent] = await h.ctx.db
      .insert(qualityProfiles)
      .values({ organizationId: h.organizationId, name: 'Scope parent', language: 'typescript' })
      .returning();
    const [child] = await h.ctx.db
      .insert(qualityProfiles)
      .values({
        organizationId: h.organizationId,
        name: 'Scope child',
        language: 'typescript',
        parentId: parent!.id,
      })
      .returning();
    await h.ctx.db.insert(profileRules).values([
      // The parent lets the main rule report on tests too, and the test rule on main code.
      {
        profileId: parent!.id,
        ruleId: await id('sonarjs:S107'),
        active: true,
        scopeOverride: 'all',
      },
      {
        profileId: parent!.id,
        ruleId: await id('sonarjs:S2187'),
        active: true,
        scopeOverride: 'all',
      },
      // The child's own row without an override keeps the parent's override...
      { profileId: child!.id, ruleId: await id('sonarjs:S107'), active: true },
      // ...and its own override beats the parent's.
      {
        profileId: child!.id,
        ruleId: await id('sonarjs:S2187'),
        active: true,
        scopeOverride: 'test',
      },
      {
        profileId: child!.id,
        ruleId: await id('sonarjs:S1186'),
        active: true,
        scopeOverride: 'main',
      },
    ]);
    await h.ctx.db
      .insert(projectProfiles)
      .values({ projectId: p.id, language: 'typescript', profileId: child!.id });

    await p.ingestOk({ ...report, analysisDate: '2026-09-22T11:00:00Z' }, stages);
    expect(seen.findings?.map((f) => [f.rule.key, f.finding.location?.path])).toEqual([
      ['sonarjs:S107', 'src/a.spec.ts'],
      ['sonarjs:S2187', 'src/a.spec.ts'],
      ['sonarjs:S1186', 'src/a.ts'],
    ]);
  });

  it('fingerprints with the occurrence index over all findings, identical ones included', async () => {
    const p = await h.project('rules/fingerprints');
    const same = finding({ line: 7 });
    const report = reportWith({
      projectKey: p.key,
      files: [file('src/a.ts')],
      findings: [same, { ...same, location: { path: 'src/a.ts', startLine: 9 } }, same],
    });
    await p.ingestOk(report, stages);
    const expected = computeFingerprints(
      report.findings.map((f) => ({
        ruleKey: `${f.engineId}:${f.ruleId}`,
        path: f.location?.path ?? null,
        lineHash: f.lineHash,
        contextHash: f.contextHash,
        startLine: f.location?.startLine ?? 0,
        startColumn: f.location?.startColumn ?? 0,
      })),
    );
    expect(seen.findings?.map((f) => f.fingerprint)).toEqual(expected);
    expect(new Set(expected).size).toBe(3);
  });

  it('ingests a report whose ruleId, rule metadata and message carry U+0000 without wedging (ruling U4)', async () => {
    const p = await h.project('rules/nul');
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        engines: [engine('eslint', [{ id: 'a\u0000b', name: 'Rule\u0000Name' }])],
        files: [file('src/a.ts')],
        findings: [{ ...finding({ ruleId: 'a\u0000b', line: 1 }), message: 'bad\u0000 message' }],
      }),
      stages,
    );
    // decode.ts strips U+0000 before any stage runs, so the engine metadata's rule id and the
    // finding's ruleId agree on the same NUL-free key: the row is created, not left dangling.
    expect(await ruleRow('eslint:ab')).toMatchObject({ engineRuleId: 'ab', name: 'RuleName' });
    expect(seen.findings?.map((f) => [f.rule.key, f.finding.ruleId, f.finding.message])).toEqual([
      ['eslint:ab', 'ab', 'bad message'],
    ]);
  });
});
