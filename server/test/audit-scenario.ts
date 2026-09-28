import { createHash, generateKeyPairSync } from 'node:crypto';
import { asc, eq, sql } from 'drizzle-orm';
import type { Report } from '@qualor/shared';
import type { Config } from '../src/config';
import { analyses, branches, instanceSettings, issues, jobs } from '../src/db/schema';
import { gateHandlers } from '../src/gates/reevaluate';
import { jobHandlers } from '../src/ingest/handlers';
import { createEdition } from '../src/license/edition';
import { licenseState } from '../src/license/state';
import { verifyLicenseKey } from '../src/license/verify';
import { createLlmRuntime, llmHandlers } from '../src/llm/job';
import { LLM_QUEUE } from '../src/llm/service';
import { DEFAULT_BUDGETS } from '../src/llm/settings';
import { loadPlugins } from '../src/plugins/loader';
import { runUntilIdle } from '../src/queue/worker';
import { parseInternalHosts } from '../src/scm/url';
import { createDelivery } from '../src/webhooks/deliveries';
import {
  ADMIN_PASSWORD,
  bearer,
  createProject,
  createTestContext,
  login,
  nextIp,
  organizationId,
  type Session,
  type TestContext,
} from './app';
import { createFakeGitLab, type FakeGitLab } from './fake-gitlab';
import { createFakeLlm, type FakeLlm } from './fake-llm';
import { signTest, testPayload, testSigner, verifyWith, type TestSigner } from './license';
import { RBAC_FIXTURE } from './rbac';
import { engine, file, finding, gzipJson, reportWith, uploadReport } from './reports';
import { mergeRequestReport, silentLogger } from './scm';

/**
 * The secrets the scenario uses. Each is distinctive (no false match on an id or a date) and
 * built from parts, so no scanner mistakes a test value for a real credential.
 */
const S = {
  typedName: ['my', 'password', 'typed', 'as', 'the', 'name', '7Q'].join('-'),
  wrongPassword: ['wrong', 'admin', 'password', '8R'].join('-'),
  userPassword: ['first', 'user', 'passphrase', '1A'].join('-'),
  resetPassword: ['reset', 'user', 'passphrase', '2B'].join('-'),
  changedPassword: ['changed', 'user', 'passphrase', '3C'].join('-'),
  llmKey: ['sk', 'scenario', 'llm', 'key', '4D5E6F'].join('-'),
  gitlabToken: ['glpat', 'scenario', 'mapped', '9Z8Y'].join('-'),
  scmToken: ['glpat', 'scenario', 'created', '5G6H'].join('-'),
  scmTokenUpdated: ['glpat', 'scenario', 'updated', '7J8K'].join('-'),
  githubWebhookSecret: ['github', 'webhook', 'secret', 'CREATED61'].join('-'),
  githubWebhookSecretUpdated: ['github', 'webhook', 'secret', 'UPDATED72'].join('-'),
  webhookPath: ['WHPATH', 'SECRET', '31'].join(''),
  webhookQuery: ['WHQUERY', 'SECRET', '42'].join(''),
  webhookGiven: ['given', 'webhook', 'secret', 'VALUE53'].join('-'),
  transitionComment: 'scenario comment: single transition 64',
  bulkComment: 'scenario comment: bulk transition 75',
  importComment: 'scenario comment: imported from SonarQube 86',
} as const;

/** A prompt line: the AI request sends it to the provider; no event may hold it. */
const LINES = ['const a = 1;', 'if (a == 1) {}', 'if (a == 2) {}', 'export {};'];
const HEAD = 'a'.repeat(40);
const BASE = 'b'.repeat(40);
const DIFF = '@@ -1,1 +1,4 @@\n const a = 1;\n+if (a == 1) {}\n+if (a == 2) {}\n+export {};';
/** Inside the test licence (issued 2026-10-01, expires 2027-10-01). */
export const SCENARIO_NOW = new Date('2027-01-01T00:00:00Z');

/** The fakes and the licence signer a scenario runs against; the server's config must list them. */
export interface AuditScenarioEnv {
  llm: FakeLlm;
  gitlab: FakeGitLab;
  /** Trusted by the scenario's `PUT /license` when the context's edition trusts it. */
  signer: TestSigner;
  /** createTestContext's `config`: the fakes are internal hosts the server may call. */
  config: Partial<Config>;
  close(): Promise<void>;
}

export async function startAuditScenarioEnv(): Promise<AuditScenarioEnv> {
  const llm = await createFakeLlm({ apiKey: S.llmKey });
  const gitlab = await createFakeGitLab({ token: S.gitlabToken });
  return {
    llm,
    gitlab,
    signer: testSigner(),
    config: {
      scmInternalHosts: parseInternalHosts(new URL(gitlab.url).host),
      llmInternalHosts: parseInternalHosts(llm.host),
    },
    close: async () => {
      await Promise.all([llm.close(), gitlab.close()]);
    },
  };
}

function quietLogger(): never {
  const l = { debug() {}, info() {}, warn() {}, error() {}, child: () => l };
  return l as never;
}

/**
 * A server for the scenario. `features` lists the licensed features (the fixture plugin
 * implements `rbac` and `audit-log`); `null` is the community edition: no licence and no plugin.
 * Both trust `env.signer` for `PUT /license` (the boot key is `uploaded`, so the licence routes
 * run), so the same scenario runs on both.
 */
export async function auditScenarioContext(
  env: AuditScenarioEnv,
  features: string[] | null,
  now: () => Date = () => SCENARIO_NOW,
): Promise<TestContext> {
  const verifyOptions = (at: Date) => verifyWith(env.signer, at);
  if (features === null) {
    return createTestContext({
      config: env.config,
      edition: createEdition({
        boot: { source: null, keyHash: null, verification: null },
        now,
        verifyOptions,
      }),
    });
  }
  const verification = verifyLicenseKey(
    signTest(env.signer, testPayload({ features })),
    verifyOptions(now()),
  );
  const boot = { source: 'uploaded' as const, keyHash: 'h', verification };
  return createTestContext({
    config: env.config,
    pluginsFor: async (db) => ({
      plugins: await loadPlugins({
        paths: ['/virtual/rbac-fixture.js'],
        state: licenseState(verification, now()),
        base: { serverVersion: '0.0.0', db, logger: quietLogger() },
        checkFile: async (path) => ({ ok: true, realPath: path }),
        importModule: async () => ({ default: RBAC_FIXTURE }),
      }),
      edition: (frozen) => createEdition({ boot, plugins: frozen, now, verifyOptions }),
    }),
  });
}

/** A throwaway 2 048-bit RSA key in PKCS#8 PEM, made at run time and never stored. */
function rsaPrivateKeyPem(): string {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
}

/** A PEM's base64 lines, each alone, and joined: a key could be stored reflowed or unwrapped. */
function pemBodyLines(pem: string): string[] {
  const body = pem.split('\n').filter((l) => l.length > 0 && !l.startsWith('-----'));
  return [...body.filter((l) => l.length >= 16), body.join('')];
}

/** The ways a hashed secret could be spelled in a row: hex, base64 and base64url of SHA-256. */
function hashForms(secret: string): string[] {
  const digest = createHash('sha256').update(secret, 'utf8').digest();
  return [digest.toString('hex'), digest.toString('base64'), digest.toString('base64url')];
}

/**
 * Drives every core route of the audit catalogue (rbac-audit.md §8) once, as the bootstrap admin
 * and one user, with known secret values, and returns every secret it used (the values, and the
 * SHA-256 forms of the ones Qualor stores hashed). It ends with `DELETE /projects/:id`, after
 * every other step on that project (ruling P-B1), so `project.deleted` is recorded last.
 *
 * The context must be built with `env.config` (auditScenarioContext does it). The licence steps
 * run only when the edition trusts `env.signer`; a context that does not (a key the server cannot
 * verify would be refused) skips them, and a coverage test on it then lists `license.*` missing.
 */
export async function runAuditScenario(
  ctx: TestContext,
  env: AuditScenarioEnv,
): Promise<{ secrets: string[] }> {
  const secrets: string[] = [...Object.values(S), ADMIN_PASSWORD, ...LINES.slice(1, 3)];
  const keep = (...values: string[]) => {
    for (const v of values) secrets.push(v, ...hashForms(v));
  };
  const { llm, gitlab } = env;

  const expectStatus = (
    res: { statusCode: number; body: string },
    status: number,
    what: string,
  ) => {
    if (res.statusCode !== status) {
      throw new Error(`${what}: expected ${status}, got ${res.statusCode} ${res.body}`);
    }
  };
  const loginAs = (username: string, password: string) =>
    ctx.app.inject({
      method: 'POST',
      url: '/api/v0/auth/login',
      payload: { username, password },
      remoteAddress: nextIp(),
    });

  // auth.sign_in
  const root = await login(ctx, 'admin', ADMIN_PASSWORD);
  keep(root.cookie, root.csrf);
  const call = async (
    method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE',
    url: string,
    status: number,
    payload?: object,
    session: Session = root,
  ) => {
    const res = await ctx.app.inject({
      method,
      url: `/api/v0${url}`,
      headers: session.headers,
      ...(payload === undefined ? {} : { payload }),
    });
    expectStatus(res, status, `${method} ${url}`);
    return res;
  };
  const org = await organizationId(ctx, 'default');

  // auth.sign_in_failed: a password typed into the name field, and a known name's wrong password.
  expectStatus(await loginAs(S.typedName, S.wrongPassword), 401, 'unknown name');
  expectStatus(await loginAs('admin', S.wrongPassword), 401, 'wrong password');

  // user.created, user.updated (with a password reset)
  const created = await call('POST', '/users', 201, {
    username: 'scenario-user',
    password: S.userPassword,
    isInstanceAdmin: false,
  });
  const userId = (created.json() as { id: string }).id;
  await call('PATCH', `/users/${userId}`, 200, {
    displayName: 'Scenario User',
    password: S.resetPassword,
  });

  // auth.password_changed and auth.sign_out, as that user
  const user = await login(ctx, 'scenario-user', S.resetPassword);
  keep(user.cookie, user.csrf);
  await call(
    'PUT',
    '/auth/me/password',
    204,
    { currentPassword: S.resetPassword, newPassword: S.changedPassword },
    user,
  );
  await call('POST', '/auth/logout', 204, undefined, user);

  // token.created, token.revoked
  const personal = (
    await call('POST', '/tokens', 201, {
      name: 'scenario laptop',
      scopes: ['read'],
      expiresInDays: 30,
    })
  ).json() as { id: string; token: string };
  keep(personal.token);
  await call('DELETE', `/tokens/${personal.id}`, 204);

  // organization.created
  await call('POST', '/organizations', 201, { key: 'scenario-org', name: 'Scenario' });

  // member.added, member.role_changed, member.removed (roles the community edition assigns)
  await call('PUT', `/organizations/${org}/members/${userId}`, 200, { role: 'member' });
  await call('PUT', `/organizations/${org}/members/${userId}`, 200, { role: 'admin' });
  await call('DELETE', `/organizations/${org}/members/${userId}`, 204);

  // quality_gate.*
  const gate = (
    (
      await call('POST', '/quality-gates', 201, { organizationId: org, name: 'Scenario gate' })
    ).json() as {
      id: string;
    }
  ).id;
  await call('PATCH', `/quality-gates/${gate}`, 200, { name: 'Scenario gate 2' });
  const condition = (
    (
      await call('POST', `/quality-gates/${gate}/conditions`, 201, {
        metric: 'new_coverage',
        operator: 'lt',
        threshold: 80.5,
      })
    ).json() as { id: string }
  ).id;
  await call('PATCH', `/quality-gates/${gate}/conditions/${condition}`, 200, { threshold: 90 });
  await call('DELETE', `/quality-gates/${gate}/conditions/${condition}`, 204);
  const gateCopy = (
    (
      await call('POST', `/quality-gates/${gate}/copy`, 201, { name: 'Scenario gate copy' })
    ).json() as {
      id: string;
    }
  ).id;
  await call('POST', `/quality-gates/${gateCopy}/set-default`, 200);
  await call('DELETE', `/quality-gates/${gate}`, 204);

  // project.created, project_token.created: the project the issue steps use and that is deleted
  // last, and a project mapped to the fake GitLab for the AI steps (project.updated).
  const main = await createProject(ctx, root, { organizationId: org, key: 'scenario/main' });
  const mainToken = (
    await call('POST', `/projects/${main.id}/tokens`, 201, { name: 'ci' })
  ).json() as { id: string; token: string };
  keep(mainToken.token);

  // project_member.added, .role_changed, .removed: the core grant routes (rbac-audit.md §16)
  await call('PUT', `/projects/${main.id}/members/${userId}`, 200, { role: 'member' });
  await call('PUT', `/projects/${main.id}/members/${userId}`, 200, { role: 'viewer' });
  await call('DELETE', `/projects/${main.id}/members/${userId}`, 204);

  const ingest = async (token: string, key: string, report: Report) => {
    const analysisId = await uploadReport(ctx, bearer(token), key, gzipJson(report));
    await runUntilIdle(
      ctx.db,
      {
        ...jobHandlers({ db: ctx.db, upload: ctx.config.upload, logger: ctx.app.log }),
        ...gateHandlers({ db: ctx.db }),
      },
      ctx.app.log,
    );
    const [row] = await ctx.db.select().from(analyses).where(eq(analyses.id, analysisId));
    if (row?.status !== 'succeeded') throw new Error(`analysis ${analysisId} ended ${row?.status}`);
  };
  await ingest(
    mainToken.token,
    main.key,
    reportWith({
      projectKey: main.key,
      engines: [engine('eslint')],
      files: [file('src/a.ts', { lines: LINES.length })],
      findings: [
        finding({ ruleId: 'eqeqeq', line: 2, snippet: { startLine: 1, lines: LINES } }),
        finding({ ruleId: 'eqeqeq', line: 3, snippet: { startLine: 1, lines: LINES } }),
      ],
    }),
  );

  // branch.deleted: a merge request branch seeded in the database
  const [branch] = await ctx.db
    .insert(branches)
    .values({ projectId: main.id, kind: 'merge_request', name: '42', isMain: false })
    .returning();
  if (!branch) throw new Error('no branch seeded');
  await call('DELETE', `/branches/${branch.id}`, 204);

  // issue.statuses_imported: one applied item (line 2), one unmatched
  const item = (over: Record<string, unknown>) => ({
    ref: 'AYi-1',
    ruleKeys: ['eslint:eqeqeq'],
    path: 'src/a.ts',
    line: 2,
    sonarLineHash: null,
    message: null,
    status: 'false_positive',
    comment: S.importComment,
    ...over,
  });
  const imported = await call('POST', `/projects/${main.id}/issue-status-import`, 200, {
    dryRun: false,
    items: [item({}), item({ ref: 'AYi-2', ruleKeys: ['eslint:nothing-here'] })],
  });
  const outcomes = (imported.json() as { results: { outcome: string }[] }).results;
  if (outcomes[0]?.outcome !== 'applied') throw new Error(`import: ${imported.body}`);

  // issue.status_changed (single and bulk), issue.severity_changed, on the line 3 issue
  const [open] = await ctx.db
    .select({ id: issues.id })
    .from(issues)
    .where(sql`${issues.projectId} = ${main.id} AND ${issues.status} = 'open'`)
    .orderBy(asc(issues.startLine));
  if (!open) throw new Error('no open issue');
  await call('POST', `/issues/${open.id}/transition`, 200, {
    to: 'wont_fix',
    comment: S.transitionComment,
  });
  await call('POST', '/issues/bulk-transition', 200, {
    ids: [open.id],
    to: 'open',
    comment: S.bulkComment,
  });
  await call('PATCH', `/issues/${open.id}`, 200, { severity: 'low' });

  // quality_profile.*, project.profile_assigned
  const profile = (
    (
      await call('POST', '/quality-profiles', 201, {
        organizationId: org,
        name: 'Scenario profile',
        language: 'typescript',
      })
    ).json() as { id: string }
  ).id;
  await call('PATCH', `/quality-profiles/${profile}`, 200, { name: 'Scenario profile 2' });
  await call('PUT', `/quality-profiles/${profile}/rules/eslint:no-eval`, 200, {
    active: false,
    severityOverride: 'high',
  });
  await call('DELETE', `/quality-profiles/${profile}/rules/eslint:no-eval`, 204);
  const profileCopy = (
    (
      await call('POST', `/quality-profiles/${profile}/copy`, 201, {
        name: 'Scenario profile copy',
      })
    ).json() as { id: string }
  ).id;
  await call('POST', `/quality-profiles/${profileCopy}/set-default`, 200);
  await call('PUT', `/projects/${main.id}/quality-profiles/typescript`, 200, {
    profileId: profile,
  });
  await call('PUT', `/projects/${main.id}/quality-profiles/typescript`, 200, { profileId: null });
  await call('DELETE', `/quality-profiles/${profile}`, 204);
  // The default goes back to the built-in profile.
  await call('DELETE', `/quality-profiles/${profileCopy}`, 204);

  // scm_connection.created, .updated (a new token), .deleted
  const scm = (
    (
      await call('POST', '/scm-connections', 201, {
        organizationId: org,
        provider: 'gitlab',
        baseUrl: gitlab.url,
        token: S.scmToken,
      })
    ).json() as { id: string }
  ).id;
  await call('PATCH', `/scm-connections/${scm}`, 200, { token: S.scmTokenUpdated });
  await call('DELETE', `/scm-connections/${scm}`, 204);

  // scm_connection.created, .updated (App id, private key and webhook secret), .deleted for a
  // GitHub App. Creating and changing one calls nothing (only the connection test does).
  const githubKeys = [rsaPrivateKeyPem(), rsaPrivateKeyPem()] as const;
  keep(...githubKeys, ...githubKeys.flatMap(pemBodyLines));
  const github = (
    (
      await call('POST', '/scm-connections', 201, {
        organizationId: org,
        provider: 'github',
        baseUrl: 'https://api.github.com',
        appId: '123456',
        privateKey: githubKeys[0],
        webhookSecret: S.githubWebhookSecret,
      })
    ).json() as { id: string }
  ).id;
  await call('PATCH', `/scm-connections/${github}`, 200, {
    appId: '654321',
    privateKey: githubKeys[1],
    webhookSecret: S.githubWebhookSecretUpdated,
  });
  await call('DELETE', `/scm-connections/${github}`, 204);

  // webhook.*: a URL whose path and query hold secrets, on the internal fake address
  await ctx.db
    .insert(instanceSettings)
    .values({ key: 'webhooks', value: { allowInternalHosts: true } })
    .onConflictDoUpdate({
      target: instanceSettings.key,
      set: { value: { allowInternalHosts: true } },
    });
  const hook = (
    await call('POST', '/webhooks', 201, {
      organizationId: org,
      projectId: main.id,
      url: `https://127.0.0.1:8443/services/${S.webhookPath}?token=${S.webhookQuery}`,
      events: ['analysis.completed'],
    })
  ).json() as { id: string; secret: string };
  keep(hook.secret);
  await call('PATCH', `/webhooks/${hook.id}`, 200, { secret: S.webhookGiven, active: false });
  const regenerated = (
    await call('POST', `/webhooks/${hook.id}/regenerate-secret`, 200)
  ).json() as { secret: string };
  keep(regenerated.secret);
  const deliveryId = await createDelivery(ctx.db, {
    subscriptionId: hook.id,
    event: 'analysis.completed',
    payload: { finishedAt: '2026-09-01T00:00:00Z' },
  });
  await call('POST', `/webhooks/${hook.id}/deliveries/${deliveryId}/redeliver`, 202);
  await call('DELETE', `/webhooks/${hook.id}`, 204);

  // license.uploaded, license.removed: only where the edition trusts the scenario's signer
  const trusted =
    ctx.edition?.verifyOptions(ctx.edition.now()).publicKeys[env.signer.kid] === env.signer.x;
  if (trusted) {
    const key = signTest(env.signer, testPayload({ features: ['audit-log'] }));
    keep(key, ...key.split('.').filter((part) => part.length >= 16));
    await call('PUT', '/license', 200, { key });
    await call('DELETE', '/license', 200);
  }

  // ai.settings_updated (with an API key): the fake provider, every feature on
  await call('PUT', '/system/llm', 200, {
    provider: {
      kind: 'openai',
      baseUrl: llm.openAiBaseUrl,
      model: 'fake-model',
      timeoutSeconds: 5,
      apiKey: S.llmKey,
    },
    organizations: {
      [org]: {
        enabled: true,
        features: { explain: true, triage: true, fix: true },
        excludedProjectIds: [],
      },
    },
    excludePaths: [],
    budgets: { ...DEFAULT_BUDGETS, perUserPerHour: 1_000 },
    pricing: null,
    storePrompts: false,
    promptRetentionDays: 7,
  });

  // ai.requested and ai.fix_posted on a merge request of a project mapped to the fake GitLab
  gitlab.addProject({ id: 501, path: 'scenario/ai' });
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
  const mapping = (
    (
      await call('POST', '/scm-connections', 201, {
        organizationId: org,
        provider: 'gitlab',
        baseUrl: gitlab.url,
        token: S.gitlabToken,
      })
    ).json() as { id: string }
  ).id;
  const ai = await createProject(ctx, root, { organizationId: org, key: 'scenario/ai' });
  // A grant the run leaves in place (the community run shows it needs no licence).
  await call('PUT', `/projects/${ai.id}/members/${userId}`, 200, { role: 'viewer' });
  await call('PATCH', `/projects/${ai.id}`, 200, {
    scmConnectionId: mapping,
    scmProjectRef: '501',
  });
  const aiToken = (await call('POST', `/projects/${ai.id}/tokens`, 201, { name: 'ci' })).json() as {
    token: string;
  };
  keep(aiToken.token);
  await ingest(
    aiToken.token,
    ai.key,
    mergeRequestReport(7, HEAD, {
      projectKey: ai.key,
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
  const [aiIssue] = await ctx.db
    .select({ id: issues.id })
    .from(issues)
    .where(eq(issues.projectId, ai.id));
  if (!aiIssue) throw new Error('no issue on the AI project');
  const requestId = (
    (await call('POST', `/issues/${aiIssue.id}/ai/fix`, 202, {})).json() as { id: string }
  ).id;
  await ctx.db
    .update(jobs)
    .set({ runAt: sql`now()` })
    .where(eq(jobs.queue, LLM_QUEUE));
  await runUntilIdle(
    ctx.db,
    llmHandlers({
      db: ctx.db,
      secretKey: ctx.config.secretKey,
      internalHosts: ctx.config.llmInternalHosts,
      runtime: createLlmRuntime(),
      logger: ctx.app.log,
      version: '0.0.0',
    }),
    silentLogger,
  );
  await call('POST', `/ai-requests/${requestId}/post`, 202, {});

  // project_token.revoked, then project.deleted last (ruling P-B1)
  await call('DELETE', `/projects/${main.id}/tokens/${mainToken.id}`, 204);
  await call('DELETE', `/projects/${main.id}?confirm=${encodeURIComponent(main.key)}`, 204);

  return { secrets: [...new Set(secrets)] };
}
