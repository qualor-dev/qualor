import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  addMember,
  createProject,
  createTestContext,
  createUser,
  login,
  organizationId,
  type Session,
  type TestContext,
} from '../../test/app';
import { mainBranchId, seedIssue, seedRule } from '../../test/issues';
import { callTool, mcpCall, sdkClient } from '../../test/mcp';
import { oauthTokens as runOAuth } from '../../test/oauth';
import { issueChanges, issues, oauthClients, vulnerabilityDecisions } from '../db/schema';
import { MCP_VIA_LINE } from './tools/transition';

describe('qualor_transition_issue (spec §5, ruling R2)', () => {
  let ctx: TestContext;
  let writer: string;
  let reader: string;
  let viewer: string;
  let maint: Session;
  let projectId: string;
  let issueId: string;
  beforeAll(async () => {
    ctx = await createTestContext({ config: { publicUrl: 'https://q.example' } });
    const admin = await login(ctx, 'admin', 'correct horse battery staple');
    const org = await organizationId(ctx, 'default');
    const m = await createUser(ctx, { username: 'maint' });
    const v = await createUser(ctx, { username: 'view' });
    await addMember(ctx, org, m.id, 'member');
    await addMember(ctx, org, v.id, 'viewer');
    projectId = (await createProject(ctx, admin, { organizationId: org, key: 'shop' })).id;
    const ruleId = await seedRule(ctx.db, { key: 'eslint:no-eval' });
    issueId = await seedIssue(ctx.db, {
      projectId,
      branchId: await mainBranchId(ctx.db, projectId),
      ruleId,
    });
    maint = await login(ctx, m.username, m.password);
    const view = await login(ctx, v.username, v.password);
    writer = (await runOAuth(ctx, maint, ['mcp:read', 'mcp:write'])).accessToken;
    reader = (await runOAuth(ctx, maint, ['mcp:read'])).accessToken;
    viewer = (await runOAuth(ctx, view, ['mcp:read', 'mcp:write'])).accessToken;
  });
  afterAll(async () => {
    await ctx.close();
  });

  it('marks a false positive with the comment and the via-MCP line', async () => {
    const r = await callTool(ctx, writer, 'qualor_transition_issue', {
      issueId,
      to: 'false_positive',
      comment: 'Input is a compile-time constant',
    });
    expect(r.isError).toBe(false);
    const [row] = await ctx.db.select().from(issues).where(eq(issues.id, issueId));
    expect(row?.status).toBe('false_positive');
    const changes = await ctx.db
      .select()
      .from(issueChanges)
      .where(eq(issueChanges.issueId, issueId));
    expect(changes.at(-1)?.comment).toBe(
      'Input is a compile-time constant\n\nvia MCP · Test agent',
    );
  });

  it('passes the reason on: a Trivy issue on main writes it into the project decision', async () => {
    const trivy = await seedIssue(ctx.db, {
      projectId,
      branchId: await mainBranchId(ctx.db, projectId),
      ruleId: await seedRule(ctx.db, { key: 'trivy:CVE-2026-0001', quality: 'security' }),
      packageName: 'lodash',
    });
    const r = await callTool(ctx, writer, 'qualor_transition_issue', {
      issueId: trivy,
      to: 'false_positive',
      reason: 'vulnerable_code_not_in_execute_path',
      comment: 'The vulnerable function is never called',
    });
    expect(r.isError, r.text).toBe(false);
    const [decision] = await ctx.db
      .select()
      .from(vulnerabilityDecisions)
      .where(eq(vulnerabilityDecisions.projectId, projectId));
    expect(decision).toMatchObject({
      packageName: 'lodash',
      status: 'false_positive',
      reason: 'vulnerable_code_not_in_execute_path',
    });
  });

  it('needs a comment', async () => {
    const r = await callTool(ctx, writer, 'qualor_transition_issue', {
      issueId,
      to: 'open',
      comment: '',
    });
    expect(r.error ?? r.isError).toBeTruthy();
  });

  it('refuses a comment too long to fit the route limit with the via line', async () => {
    const r = await callTool(ctx, writer, 'qualor_transition_issue', {
      issueId,
      to: 'open',
      comment: 'x'.repeat(1_950),
    });
    expect(r.error ?? r.isError).toBeTruthy();
  });

  it('refuses a whitespace-only comment', async () => {
    const r = await callTool(ctx, writer, 'qualor_transition_issue', {
      issueId,
      to: 'open',
      comment: '   \n\t ',
    });
    expect(r.error ?? r.isError).toBeTruthy();
  });

  it('stores at most 2000 characters for a longest comment and a longest client name', async () => {
    const t = await runOAuth(ctx, maint, ['mcp:read', 'mcp:write']);
    // 70 code points of 2 UTF-16 units each: cut to 64 without splitting a pair.
    await ctx.db
      .update(oauthClients)
      .set({ name: '\u{1F600}'.repeat(70) })
      .where(eq(oauthClients.clientId, t.clientId));
    const r = await callTool(ctx, t.accessToken, 'qualor_transition_issue', {
      issueId,
      to: 'open',
      comment: 'x'.repeat(1_850),
    });
    expect(r.isError).toBe(false);
    const changes = await ctx.db
      .select()
      .from(issueChanges)
      .where(eq(issueChanges.issueId, issueId));
    const stored = changes.at(-1)?.comment ?? '';
    expect(stored.length).toBeLessThanOrEqual(2_000);
    expect(stored.endsWith(`via MCP · ${'\u{1F600}'.repeat(64)}`)).toBe(true);
  });

  it('answers 403 insufficient_scope with only mcp:read (Review Focus 3)', async () => {
    const res = await mcpCall(ctx, reader, 'tools/call', {
      name: 'qualor_transition_issue',
      arguments: { issueId, to: 'open', comment: 'x' },
    });
    expect(res.status).toBe(403);
    expect(res.headers['www-authenticate']).toContain('error="insufficient_scope"');
  });

  it('leaves the role to decide: a viewer is refused by the REST rules', async () => {
    const r = await callTool(ctx, viewer, 'qualor_transition_issue', {
      issueId,
      to: 'open',
      comment: 'reopen',
    });
    expect(r.isError).toBe(true);
    expect(r.text).toContain('FORBIDDEN');
  });

  for (const mode of ['legacy', { pin: '2026-07-28' }] as const) {
    it(`offers the fix_quality_gate prompt in the ${typeof mode === 'string' ? '2025' : mode.pin} era`, async () => {
      const { client } = await sdkClient(ctx.app, reader, mode);
      try {
        const { prompts } = await client.listPrompts();
        expect(prompts.map((p) => p.name)).toContain('fix_quality_gate');
        const got = await client.getPrompt({
          name: 'fix_quality_gate',
          arguments: { project: 'shop', branch: 'main' },
        });
        const first = got.messages[0]?.content;
        const text = first?.type === 'text' ? first.text : '';
        expect(text).toContain('qualor_gate_status');
        expect(text).toContain('commit SHA');
        expect(text).toContain('branch main');
      } finally {
        await client.close();
      }
    });
  }
});

describe('MCP_VIA_LINE', () => {
  it('strips control characters and caps a long client name', () => {
    expect(MCP_VIA_LINE('Bad\r\nname\u0000')).toBe('via MCP · Badname');
    expect(MCP_VIA_LINE('n'.repeat(500)).length).toBe('via MCP · '.length + 64);
  });

  it('drops format and separator characters, keeps surrogate pairs whole, names an empty client', () => {
    expect(MCP_VIA_LINE('a‮b​c d e')).toBe('via MCP · abcde');
    expect(MCP_VIA_LINE('\u{1F600}'.repeat(65))).toBe(`via MCP · ${'\u{1F600}'.repeat(64)}`);
    expect(MCP_VIA_LINE(' ​\u0000 ')).toBe('via MCP · unnamed client');
  });
});
