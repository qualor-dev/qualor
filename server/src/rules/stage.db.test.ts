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
    const meta = (name: string) => ({
      id: 'no-lock-rule',
      name,
      defaultSeverity: 'high' as const,
      quality: 'maintainability' as const,
    });
    const reportOf = (name: string) =>
      reportWith({
        projectKey: p.key,
        engines: [engine('eslint', [meta(name)])],
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
    // A real change takes the stronger lock (and writes).
    expect(await whileUpserting('New name', 'NO KEY UPDATE')).toBe(true);
    expect(await ruleRow('eslint:no-lock-rule')).toMatchObject({ name: 'New name' });
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
