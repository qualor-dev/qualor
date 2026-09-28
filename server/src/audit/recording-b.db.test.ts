import { asc, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestContext, login, ADMIN_PASSWORD, organizationId } from '../../test/app';
import { createFakeGitLab, type FakeGitLab } from '../../test/fake-gitlab';
import { createFakeLlm, type FakeLlm } from '../../test/fake-llm';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { mainBranchId, seedIssue, seedRule } from '../../test/issues';
import { configureLlm, llmJobDeps, runLlmJobs } from '../../test/llm';
import { rbacContext, rbacPlugins } from '../../test/rbac';
import { engine, file, finding, reportWith } from '../../test/reports';
import { mappedProject, mergeRequestReport } from '../../test/scm';
import { auditEvents, instanceSettings, issues, qualityGates } from '../db/schema';
import { parseInternalHosts } from '../scm/url';
import { createDelivery } from '../webhooks/deliveries';
import { ProblemError } from '../http/problem';
import { DEFAULT_BUDGETS } from '../llm/settings';
import { parseRuleKey } from '../routes/profiles';
import { AUDIT_RULE_KEY_PATTERN } from './catalogue';
import { AUDIT_CHAIN_KEY } from './settings';
import { verifyAuditChain } from './verify';

const NOW = new Date('2027-01-01T00:00:00Z');
const LINES = ['const a = 1;', 'if (a == 1) {}', 'if (a == 2) {}', 'export {};'];
const HEAD = 'a'.repeat(40);
const BASE = 'b'.repeat(40);
const DIFF = '@@ -1,1 +1,4 @@\n const a = 1;\n+if (a == 1) {}\n+if (a == 2) {}\n+export {};';

type Event = typeof auditEvents.$inferSelect;

describe('audit recording B (rbac-audit.md §8, §9): gates, profiles, issues, SCM, webhooks, AI', () => {
  let h: IngestHarness;
  let llm: FakeLlm;
  let gitlab: FakeGitLab;
  let org: string;
  let p: IngestProject;
  const call = (
    method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE',
    url: string,
    payload?: object,
  ) =>
    h.ctx.app.inject({
      method,
      url: `/api/v0${url}`,
      headers: h.orgAdmin.headers,
      ...(payload === undefined ? {} : { payload }),
    });
  const events = (action: string): Promise<Event[]> =>
    h.ctx.db
      .select()
      .from(auditEvents)
      .where(eq(auditEvents.action, action))
      .orderBy(asc(auditEvents.seq));
  const latest = async (action: string): Promise<Event> => {
    const all = await events(action);
    const last = all.at(-1);
    if (!last) throw new Error(`no ${action} event`);
    return last;
  };
  const count = async (action: string) => (await events(action)).length;

  beforeAll(async () => {
    llm = await createFakeLlm();
    gitlab = await createFakeGitLab();
    h = await createIngestHarness({
      config: {
        scmInternalHosts: parseInternalHosts(new URL(gitlab.url).host),
        llmInternalHosts: parseInternalHosts(llm.host),
      },
      pluginsFor: rbacPlugins({ now: () => NOW }),
    });
    org = h.organizationId;
    await configureLlm(h.ctx.db, h.ctx.config.secretKey, llm, org, {
      budgets: { ...DEFAULT_BUDGETS, perUserPerHour: 1_000 },
    });
    p = await h.project('acme/audit');
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        engines: [engine('eslint')],
        files: [file('src/a.ts', { lines: LINES.length })],
        findings: [
          finding({ ruleId: 'eqeqeq', line: 2, snippet: { startLine: 1, lines: LINES } }),
          finding({ ruleId: 'eqeqeq', line: 3, snippet: { startLine: 1, lines: LINES } }),
        ],
      }),
    );
  });
  afterAll(async () => {
    // Every event of this file forms one chain that verifies.
    expect(await verifyAuditChain(h.ctx.db)).toMatchObject({ ok: true });
    await h.close();
    await Promise.all([llm.close(), gitlab.close()]);
  });

  it('records the gate routes, a rename only when the name changed', async () => {
    const created = await call('POST', '/quality-gates', { organizationId: org, name: 'Strict' });
    expect(created.statusCode, created.body).toBe(201);
    const gate = (created.json() as { id: string }).id;
    const e = await latest('quality_gate.created');
    expect(e).toMatchObject({
      organizationId: org,
      organizationKey: 'default',
      projectId: null,
      targetType: 'quality_gate',
      targetId: gate,
      targetLabel: 'Strict',
      actorType: 'user',
      details: { name: 'Strict' },
    });

    expect((await call('PATCH', `/quality-gates/${gate}`, { name: 'Stricter' })).statusCode).toBe(
      200,
    );
    expect((await call('PATCH', `/quality-gates/${gate}`, { name: 'Stricter' })).statusCode).toBe(
      200,
    );
    expect((await events('quality_gate.updated')).map((x) => x.details)).toEqual([
      { from: 'Strict', to: 'Stricter' },
    ]);

    const cond = await call('POST', `/quality-gates/${gate}/conditions`, {
      metric: 'new_coverage',
      operator: 'lt',
      threshold: 80.5,
    });
    expect(cond.statusCode, cond.body).toBe(201);
    const condId = (cond.json() as { id: string }).id;
    expect((await latest('quality_gate.condition_added')).details).toEqual({
      conditionId: condId,
      metric: 'new_coverage',
      operator: 'lt',
      threshold: '80.5',
    });
    // A refused change (a second condition on the metric) records nothing.
    const again = await call('POST', `/quality-gates/${gate}/conditions`, {
      metric: 'new_coverage',
      operator: 'lt',
      threshold: 70,
    });
    expect(again.statusCode).toBe(409);
    expect(await count('quality_gate.condition_added')).toBe(1);

    const changed = await call('PATCH', `/quality-gates/${gate}/conditions/${condId}`, {
      threshold: 90,
    });
    expect(changed.statusCode, changed.body).toBe(200);
    expect((await latest('quality_gate.condition_updated')).details).toEqual({
      conditionId: condId,
      metric: 'new_coverage',
      from: { metric: 'new_coverage', operator: 'lt', threshold: '80.5' },
      to: { metric: 'new_coverage', operator: 'lt', threshold: '90' },
    });
    expect((await call('DELETE', `/quality-gates/${gate}/conditions/${condId}`)).statusCode).toBe(
      204,
    );
    expect((await latest('quality_gate.condition_removed')).details).toEqual({
      conditionId: condId,
      metric: 'new_coverage',
      operator: 'lt',
      threshold: '90',
    });

    const copy = await call('POST', `/quality-gates/${gate}/copy`, { name: 'Copy' });
    expect(copy.statusCode).toBe(201);
    const copyId = (copy.json() as { id: string }).id;
    expect(await latest('quality_gate.copied')).toMatchObject({
      targetId: copyId,
      details: { sourceId: gate, name: 'Copy' },
    });
    expect((await call('POST', `/quality-gates/${copyId}/set-default`)).statusCode).toBe(200);
    expect(await latest('quality_gate.default_set')).toMatchObject({
      targetId: copyId,
      details: { name: 'Copy' },
    });
    expect((await call('DELETE', `/quality-gates/${gate}`)).statusCode).toBe(204);
    expect(await latest('quality_gate.deleted')).toMatchObject({
      organizationId: org,
      targetId: gate,
      details: { name: 'Stricter' },
    });
  });

  it('records the profile routes and a project profile assignment only when it changed', async () => {
    const created = await call('POST', '/quality-profiles', {
      organizationId: org,
      name: 'Team',
      language: 'typescript',
    });
    expect(created.statusCode, created.body).toBe(201);
    const profile = (created.json() as { id: string }).id;
    expect(await latest('quality_profile.created')).toMatchObject({
      organizationId: org,
      targetType: 'quality_profile',
      targetId: profile,
      details: { name: 'Team', language: 'typescript' },
    });
    const patched = await call('PATCH', `/quality-profiles/${profile}`, {
      name: 'Team TS',
      unknownRules: 'ignore',
    });
    expect(patched.statusCode).toBe(200);
    expect((await latest('quality_profile.updated')).details).toEqual({
      changes: [
        { field: 'name', from: 'Team', to: 'Team TS' },
        { field: 'unknownRules', from: 'activate', to: 'ignore' },
      ],
    });
    await call('PATCH', `/quality-profiles/${profile}`, { unknownRules: 'ignore' });
    expect(await count('quality_profile.updated')).toBe(1);

    const set = await call('PUT', `/quality-profiles/${profile}/rules/eslint:no-eval`, {
      active: false,
      severityOverride: 'high',
    });
    expect(set.statusCode, set.body).toBe(200);
    expect((await latest('quality_profile.rule_set')).details).toEqual({
      ruleKey: 'eslint:no-eval',
      active: false,
      severityOverride: 'high',
    });
    expect(
      (await call('DELETE', `/quality-profiles/${profile}/rules/eslint:no-eval`)).statusCode,
    ).toBe(204);
    expect(
      (await call('DELETE', `/quality-profiles/${profile}/rules/eslint:no-eval`)).statusCode,
    ).toBe(204);
    expect((await events('quality_profile.rule_reset')).map((x) => x.details)).toEqual([
      { ruleKey: 'eslint:no-eval' },
    ]);

    // Every rule key the route accepts fits the audit schema. The router takes a path parameter
    // of at most 100 characters (Fastify's maxParamLength), and the key's own check bounds the
    // rule id at 512 like a report's (tested on parseRuleKey below), so neither can pass a key
    // the audit event would refuse.
    const longest = `eslint:${'r'.repeat(93)}`;
    const ok = await call('PUT', `/quality-profiles/${profile}/rules/${longest}`, { active: true });
    expect(ok.statusCode, ok.body).toBe(200);
    expect((await latest('quality_profile.rule_set')).details).toMatchObject({ ruleKey: longest });
    const over = await call('PUT', `/quality-profiles/${profile}/rules/${longest}r`, {
      active: true,
    });
    expect(over.statusCode).toBe(414);
    expect(parseRuleKey(`eslint:${'r'.repeat(512)}`).engineRuleId).toHaveLength(512);
    expect(AUDIT_RULE_KEY_PATTERN.test(`eslint:${'r'.repeat(512)}`)).toBe(true);
    expect(() => parseRuleKey(`eslint:${'r'.repeat(513)}`)).toThrow(ProblemError);
    try {
      parseRuleKey(`eslint:${'r'.repeat(513)}`);
    } catch (err) {
      expect([(err as ProblemError).status, (err as ProblemError).code]).toEqual([
        422,
        'VALIDATION_FAILED',
      ]);
    }

    const copy = await call('POST', `/quality-profiles/${profile}/copy`, { name: 'Team copy' });
    expect(copy.statusCode).toBe(201);
    const copyId = (copy.json() as { id: string }).id;
    expect(await latest('quality_profile.copied')).toMatchObject({
      targetId: copyId,
      details: { sourceId: profile, name: 'Team copy', language: 'typescript' },
    });
    expect((await call('POST', `/quality-profiles/${copyId}/set-default`)).statusCode).toBe(200);
    expect(await latest('quality_profile.default_set')).toMatchObject({
      targetId: copyId,
      details: { name: 'Team copy', language: 'typescript' },
    });

    const assign = (profileId: string | null) =>
      call('PUT', `/projects/${p.id}/quality-profiles/typescript`, { profileId });
    expect((await assign(profile)).statusCode).toBe(200);
    expect((await assign(profile)).statusCode).toBe(200);
    expect((await assign(null)).statusCode).toBe(200);
    expect((await assign(null)).statusCode).toBe(200);
    const assigned = await events('project.profile_assigned');
    expect(assigned.map((x) => [x.projectId, x.projectKey, x.targetId, x.details])).toEqual([
      [p.id, p.key, p.id, { language: 'typescript', from: null, to: profile }],
      [p.id, p.key, p.id, { language: 'typescript', from: profile, to: null }],
    ]);

    expect((await call('DELETE', `/quality-profiles/${profile}`)).statusCode).toBe(204);
    expect(await latest('quality_profile.deleted')).toMatchObject({
      targetId: profile,
      details: { name: 'Team TS', language: 'typescript' },
    });
    // The default goes back to the built-in profile (ruling F2), which the later cases rely on.
    expect((await call('DELETE', `/quality-profiles/${copyId}`)).statusCode).toBe(204);
    expect(await count('quality_profile.deleted')).toBe(2);
  });

  it('records one status event per changed issue, mirrored duplicates marked', async () => {
    const branchId = await mainBranchId(h.ctx.db, p.id);
    const ruleId = await seedRule(h.ctx.db, { key: 'eslint:no-console' });
    const primary = await seedIssue(h.ctx.db, { projectId: p.id, branchId, ruleId });
    const duplicate = await seedIssue(h.ctx.db, {
      projectId: p.id,
      branchId,
      ruleId,
      duplicateOfIssueId: primary,
    });
    const res = await call('POST', '/issues/bulk-transition', {
      ids: [primary],
      to: 'false_positive',
      comment: 'not reachable in production',
    });
    expect(res.statusCode, res.body).toBe(200);
    const status = await events('issue.status_changed');
    expect(status.map((e) => [e.targetId, e.projectId, e.organizationId, e.details])).toEqual([
      [
        primary,
        p.id,
        org,
        {
          from: 'open',
          to: 'false_positive',
          bulk: true,
          mirrored: false,
          commented: true,
          suggestionId: null,
        },
      ],
      [
        duplicate,
        p.id,
        org,
        {
          from: 'open',
          to: 'false_positive',
          bulk: true,
          mirrored: true,
          commented: true,
          suggestionId: null,
        },
      ],
    ]);
    expect(JSON.stringify(status)).not.toContain('not reachable in production');

    // A single transition; an invalid one (already open) records nothing.
    const single = await call('POST', `/issues/${primary}/transition`, { to: 'open' });
    expect(single.statusCode, single.body).toBe(200);
    expect(
      (await events('issue.status_changed')).slice(2).map((e) => [e.targetId, e.details]),
    ).toEqual([
      [
        primary,
        {
          from: 'false_positive',
          to: 'open',
          bulk: false,
          mirrored: false,
          commented: false,
          suggestionId: null,
        },
      ],
      [
        duplicate,
        {
          from: 'false_positive',
          to: 'open',
          bulk: false,
          mirrored: true,
          commented: false,
          suggestionId: null,
        },
      ],
    ]);
    expect((await call('POST', `/issues/${primary}/transition`, { to: 'open' })).statusCode).toBe(
      409,
    );
    expect(await count('issue.status_changed')).toBe(4);

    expect((await call('PATCH', `/issues/${primary}`, { severity: 'low' })).statusCode).toBe(200);
    expect((await call('PATCH', `/issues/${primary}`, { severity: 'low' })).statusCode).toBe(200);
    expect(
      (await events('issue.severity_changed')).map((e) => [e.targetId, e.projectId, e.details]),
    ).toEqual([[primary, p.id, { from: 'medium', to: 'low' }]]);
  });

  it('records one summary event per status import, none for a dry run', async () => {
    const item = (over: Record<string, unknown>) => ({
      ref: 'AYi-1',
      ruleKeys: ['eslint:eqeqeq'],
      path: 'src/a.ts',
      line: 2,
      sonarLineHash: null,
      message: null,
      status: 'false_positive',
      comment: 'Imported from SonarQube: a secret-free comment',
      ...over,
    });
    const items = [item({}), item({ ref: 'AYi-2', ruleKeys: ['eslint:nothing-here'] })];
    const dry = await call('POST', `/projects/${p.id}/issue-status-import`, {
      dryRun: true,
      items,
    });
    expect(dry.statusCode, dry.body).toBe(200);
    expect(await count('issue.statuses_imported')).toBe(0);
    const res = await call('POST', `/projects/${p.id}/issue-status-import`, {
      dryRun: false,
      items,
    });
    expect(res.statusCode, res.body).toBe(200);
    expect(
      (res.json() as { results: { outcome: string }[] }).results.map((r) => r.outcome),
    ).toEqual(['applied', 'unmatched']);
    const imported = await events('issue.statuses_imported');
    expect(imported.map((e) => [e.projectId, e.targetType, e.targetId, e.details])).toEqual([
      [
        p.id,
        'project',
        p.id,
        {
          items: 2,
          applied: 1,
          alreadySet: 0,
          conflicts: 0,
          unmatched: 1,
          ambiguous: 0,
          competitorsUnknown: 0,
        },
      ],
    ]);
    // The import's own transitions are summarised, not recorded one by one.
    expect(await count('issue.status_changed')).toBe(4);
    expect(JSON.stringify(imported)).not.toContain('secret-free comment');
  });

  it('records SCM connections without their credentials', async () => {
    const token = `glpat-${'x'.repeat(10)}${'SCMTOKEN'}`;
    const created = await call('POST', '/scm-connections', {
      organizationId: org,
      provider: 'gitlab',
      baseUrl: gitlab.url,
      token,
    });
    expect(created.statusCode, created.body).toBe(201);
    const id = (created.json() as { id: string; baseUrl: string }).id;
    const baseUrl = (created.json() as { baseUrl: string }).baseUrl;
    expect(await latest('scm_connection.created')).toMatchObject({
      organizationId: org,
      targetType: 'scm_connection',
      targetId: id,
      details: { provider: 'gitlab', baseUrl },
    });
    const newToken = `glpat-${'y'.repeat(10)}${'SCMTOKEN'}`;
    expect((await call('PATCH', `/scm-connections/${id}`, { token: newToken })).statusCode).toBe(
      200,
    );
    expect(await latest('scm_connection.updated')).toMatchObject({
      targetId: id,
      details: { changed: ['token'] },
    });
    expect((await call('DELETE', `/scm-connections/${id}`)).statusCode).toBe(204);
    expect(await latest('scm_connection.deleted')).toMatchObject({
      targetId: id,
      details: { provider: 'gitlab', baseUrl },
    });
    const all = JSON.stringify(await h.ctx.db.select().from(auditEvents));
    expect(all).not.toContain('SCMTOKEN');
  });

  it('records a webhook by its origin only, never its secret', async () => {
    await h.ctx.db
      .insert(instanceSettings)
      .values({ key: 'webhooks', value: { allowInternalHosts: true } })
      .onConflictDoUpdate({
        target: instanceSettings.key,
        set: { value: { allowInternalHosts: true } },
      });
    const res = await call('POST', '/webhooks', {
      organizationId: org,
      projectId: p.id,
      url: 'https://127.0.0.1:8443/services/T0/B0/PATHSECRET?token=QUERYSECRET',
      events: ['analysis.completed'],
    });
    expect(res.statusCode, res.body).toBe(201);
    const { id, secret } = res.json() as { id: string; secret: string };
    const e = await latest('webhook.created');
    expect(e).toMatchObject({
      organizationId: org,
      projectId: p.id,
      projectKey: p.key,
      targetType: 'webhook',
      targetId: id,
      details: {
        origin: 'https://127.0.0.1:8443',
        projectId: p.id,
        events: ['analysis.completed'],
        active: true,
      },
    });

    const patched = await call('PATCH', `/webhooks/${id}`, {
      secret: 'a-provided-secret-VALUESECRET',
      active: false,
      events: ['analysis.completed'],
    });
    expect(patched.statusCode, patched.body).toBe(200);
    expect((await latest('webhook.updated')).details).toEqual({ changed: ['secret', 'active'] });

    const regenerated = await call('POST', `/webhooks/${id}/regenerate-secret`);
    expect(regenerated.statusCode).toBe(200);
    expect(await latest('webhook.secret_regenerated')).toMatchObject({ targetId: id, details: {} });

    const deliveryId = await createDelivery(h.ctx.db, {
      subscriptionId: id,
      event: 'analysis.completed',
      payload: { finishedAt: '2026-09-01T00:00:00Z' },
    });
    const redelivered = await call('POST', `/webhooks/${id}/deliveries/${deliveryId}/redeliver`);
    expect(redelivered.statusCode, redelivered.body).toBe(202);
    expect(await latest('webhook.redelivered')).toMatchObject({
      targetId: id,
      details: { deliveryId, event: 'analysis.completed' },
    });

    expect((await call('DELETE', `/webhooks/${id}`)).statusCode).toBe(204);
    expect(await latest('webhook.deleted')).toMatchObject({
      targetId: id,
      details: { origin: 'https://127.0.0.1:8443', active: false },
    });

    const all = JSON.stringify(await h.ctx.db.select().from(auditEvents));
    for (const hidden of [
      'PATHSECRET',
      'QUERYSECRET',
      'VALUESECRET',
      secret,
      (regenerated.json() as { secret: string }).secret,
    ]) {
      expect(all).not.toContain(hidden);
    }
  });

  it('records an AI request sent to the provider (not a cached answer) and a queued fix post', async () => {
    gitlab.addProject({ id: 501, path: 'acme/ai-audit' });
    gitlab.addMergeRequest(501, {
      iid: 7,
      title: 'Fix',
      state: 'opened',
      sourceBranch: 'feature/x',
      targetBranch: 'main',
      headSha: HEAD,
      baseSha: BASE,
      startSha: BASE,
      diffs: [{ oldPath: 'src/a.ts', newPath: 'src/a.ts', diff: DIFF }],
    });
    const project = await mappedProject(h, gitlab, 'acme/ai-audit', 501);
    await project.ingestOk(
      mergeRequestReport(7, HEAD, {
        projectKey: project.key,
        gitlab: { projectId: '501' },
        engines: [engine('eslint')],
        files: [file('src/a.ts', { lines: 4, newLines: [[2, 4]] })],
        findings: [
          finding({
            ruleId: 'eqeqeq',
            path: 'src/a.ts',
            line: 2,
            snippet: { startLine: 1, lines: LINES },
          }),
        ],
      }),
    );
    const [row] = await h.ctx.db
      .select({ id: issues.id })
      .from(issues)
      .where(eq(issues.projectId, project.id));
    const issueId = row?.id;
    expect(issueId).toBeDefined();

    const asked = await call('POST', `/issues/${issueId}/ai/fix`, {});
    expect(asked.statusCode, asked.body).toBe(202);
    const requestId = (asked.json() as { id: string }).id;
    const e = await latest('ai.requested');
    expect(e).toMatchObject({
      organizationId: org,
      projectId: project.id,
      targetType: 'issue',
      targetId: issueId,
      details: { requestId, feature: 'fix', providerHost: llm.host, model: 'fake-model' },
    });
    await runLlmJobs(h, llmJobDeps(h));
    // The succeeded answer is reused: nothing is sent, nothing recorded.
    const cached = await call('POST', `/issues/${issueId}/ai/fix`, {});
    expect(cached.statusCode).toBe(200);
    expect(await count('ai.requested')).toBe(1);

    const posted = await call('POST', `/ai-requests/${requestId}/post`, {});
    expect(posted.statusCode, posted.body).toBe(202);
    expect(await latest('ai.fix_posted')).toMatchObject({
      organizationId: org,
      projectId: project.id,
      targetId: issueId,
      details: { requestId },
    });
    const refused = await call('POST', `/ai-requests/${requestId}/post`, {});
    expect(refused.statusCode).toBe(409);
    expect(await count('ai.fix_posted')).toBe(1);

    // No prompt, answer or API key in any event.
    const all = JSON.stringify(await h.ctx.db.select().from(auditEvents));
    expect(all).not.toContain('if (a == 1)');
    expect(all).not.toContain('if (a === 1)');
    if (llm.apiKey !== '') expect(all).not.toContain(llm.apiKey);
  });
});

describe('audit recording B without the feature, and with a failing append', () => {
  it('records nothing without audit-log', async () => {
    const ctx = await createTestContext();
    try {
      const root = await login(ctx, 'admin', ADMIN_PASSWORD);
      const org = await organizationId(ctx, 'default');
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/api/v0/quality-gates',
        headers: root.headers,
        payload: { organizationId: org, name: 'Community' },
      });
      expect(res.statusCode).toBe(201);
      expect(await ctx.db.select().from(auditEvents)).toEqual([]);
    } finally {
      await ctx.close();
    }
  });

  it('rolls the change back when its event cannot be written (one transaction)', async () => {
    const ctx = await rbacContext({ now: () => NOW });
    try {
      const root = await login(ctx, 'admin', ADMIN_PASSWORD);
      const org = await organizationId(ctx, 'default');
      // A malformed anchor row makes an append to an empty table throw (fail closed,
      // audit/settings.ts). The sign-in's own event is removed first, as retention would.
      await ctx.db.transaction(async (tx) => {
        await tx.execute(sql`SELECT set_config('qualor.audit_prune', txid_current()::text, true)`);
        await tx.delete(auditEvents);
      });
      await ctx.db.insert(instanceSettings).values({ key: AUDIT_CHAIN_KEY, value: { bad: true } });
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/api/v0/quality-gates',
        headers: root.headers,
        payload: { organizationId: org, name: 'Rolled back' },
      });
      // The central error handler maps it to its problem (api.md §2.1), not a 500.
      expect([res.statusCode, res.json().code]).toEqual([409, 'AUDIT_CHAIN_ANCHOR_MALFORMED']);
      const gates = await ctx.db
        .select()
        .from(qualityGates)
        .where(eq(qualityGates.name, 'Rolled back'));
      expect(gates).toEqual([]);
      expect(await ctx.db.select().from(auditEvents)).toEqual([]);
    } finally {
      await ctx.close();
    }
  });
});
