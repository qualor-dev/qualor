import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { sql } from 'drizzle-orm';
import type { Pool, PoolClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { TestContext } from '../../test/app';
import {
  auditScenarioContext,
  runAuditScenario,
  startAuditScenarioEnv,
  type AuditScenarioEnv,
} from '../../test/audit-scenario';
import { LOCKS } from '../db/locks';
import { AUDIT_ACTIONS, isAuditAction } from './catalogue';
import type * as Refs from './refs';
import { createAuditRecorder, SYSTEM_ACTOR } from './recorder';
import { exportAuditLines } from './query';
import {
  AUDIT_CHAIN_KEY,
  AUDIT_SETTINGS_KEY,
  AUDIT_STREAM_KEY,
  regenerateStreamSecret,
  updateAuditSettings,
} from './settings';
import { streamAuditEvents } from './stream';
import { verifyAuditChain } from './verify';
import { QUIET_AUDIT_LOG } from '../../test/audit-log';

/**
 * The audit-only reads (an event's organisation and project keys): counted, so the community run
 * can show it never makes them (rbac-audit.md §8.1).
 */
const refCalls = vi.hoisted(() => ({ n: 0 }));
vi.mock('./refs', async (importOriginal) => {
  const actual = await importOriginal<typeof Refs>();
  return {
    ...actual,
    organizationRef: (...args: Parameters<typeof actual.organizationRef>) => {
      refCalls.n += 1;
      return actual.organizationRef(...args);
    },
    projectRefs: (...args: Parameters<typeof actual.projectRefs>) => {
      refCalls.n += 1;
      return actual.projectRefs(...args);
    },
  };
});

/**
 * The catalogue actions the scenario's core routes cannot produce, each with its reason. Every
 * other action must be produced, so a new action without a recording site fails this test.
 */
const NOT_FROM_CORE_ROUTES = new Map<string, string>([
  ['audit.settings_updated', 'recorded by the enterprise audit settings route (Task 14)'],
  ['audit.stream_secret_regenerated', 'recorded by the enterprise audit settings route (Task 14)'],
  ['audit.exported', 'recorded by the enterprise export route (Task 14)'],
  ['audit.pruned', 'recorded by retention in housekeeping (Task 11), not by a request'],
  // Plan 4D: the SSO and SCIM actions of sso-scim.md §15. None is recorded by a core route; each is produced by its flow, the
  // enterprise plugin's routes or the SCIM service, and covered by that code's own db tests.
  [
    'auth.password_sign_in_forced',
    'recorded at boot when QUALOR_FORCE_PASSWORD_SIGN_IN=true (4D Task 12, main.ts), not by a request; covered by its own boot test',
  ],
  [
    'sso.sign_in_failed',
    'recorded by failSsoFlow (4D Task 12) when the OIDC (4D Task 13) or SAML (4D Task 14) flow fails; covered by their own tests',
  ],
  [
    'sso.user_provisioned',
    'recorded by resolveAccount (4D Task 10) during just-in-time sign-in, reached through the enterprise SSO routes (4D Task 19); covered by their own tests',
  ],
  [
    'sso.identity_linked',
    'recorded by resolveAccount/linkIdentity (4D Task 10) during sign-in or linking, reached through the enterprise SSO routes (4D Task 19); covered by their own tests',
  ],
  [
    'sso.identity_unlinked',
    'recorded by unlinkIdentity (4D Task 18, accounts.ts), reached through the enterprise identity routes (4D Task 19); covered by their own tests',
  ],
  [
    'sso.connection_created',
    'recorded by createConnection (4D Task 5), reached through the enterprise connection routes (4D Task 19); covered by their own tests',
  ],
  [
    'sso.connection_updated',
    'recorded by updateConnection (4D Task 5), reached through the enterprise connection routes (4D Task 19); covered by their own tests',
  ],
  [
    'sso.connection_deleted',
    'recorded by deleteConnection (4D Task 5), reached through the enterprise connection routes (4D Task 19); covered by their own tests',
  ],
  [
    'sso.group_mappings_replaced',
    'recorded by replaceMappings (4D Task 11), reached through the enterprise mappings route (4D Task 19); covered by their own tests',
  ],
  [
    'sso.sign_in_settings_updated',
    'recorded by updateSignInSettings (4D Task 12), reached through the enterprise sign-in settings route (4D Task 19); covered by their own tests',
  ],
  [
    'scim_token.created',
    'recorded by createScimToken (4D Task 16), reached through the enterprise SCIM token routes (4D Task 19); covered by their own tests',
  ],
  [
    'scim_token.revoked',
    'recorded by revokeScimToken (4D Task 16), reached through the enterprise SCIM token routes (4D Task 19); covered by their own tests',
  ],
  [
    'scim.user_created',
    'recorded by the SCIM Users resource (4D Task 17) via handleScim, mounted by the enterprise plugin (4D Task 19); covered by their own tests',
  ],
  [
    'scim.user_updated',
    'recorded by the SCIM Users resource (4D Task 17) via handleScim, mounted by the enterprise plugin (4D Task 19); covered by their own tests',
  ],
  [
    'scim.user_deactivated',
    'recorded by the SCIM Users resource (4D Task 17) via handleScim, mounted by the enterprise plugin (4D Task 19); covered by their own tests',
  ],
  [
    'scim.user_reactivated',
    'recorded by the SCIM Users resource (4D Task 17) via handleScim, mounted by the enterprise plugin (4D Task 19); covered by their own tests',
  ],
  [
    'scim.user_deleted',
    'recorded by the SCIM Users resource (4D Task 17) via handleScim, mounted by the enterprise plugin (4D Task 19); covered by their own tests',
  ],
  [
    'scim.group_created',
    'recorded by the SCIM Groups resource (4D Task 17) via handleScim, mounted by the enterprise plugin (4D Task 19); covered by their own tests',
  ],
  [
    'scim.group_updated',
    'recorded by the SCIM Groups resource (4D Task 17) via handleScim, mounted by the enterprise plugin (4D Task 19); covered by their own tests',
  ],
  [
    'scim.group_deleted',
    'recorded by the SCIM Groups resource (4D Task 17) via handleScim, mounted by the enterprise plugin (4D Task 19); covered by their own tests',
  ],
]);

/** The SQL a pool's clients send, captured at checkout (pool.query and transactions alike). */
function captureQueries(pool: Pool): { text: string; values: unknown[] }[] {
  const seen: { text: string; values: unknown[] }[] = [];
  const wrapped = new WeakSet<PoolClient>();
  pool.on('acquire', (client) => {
    if (wrapped.has(client)) return;
    wrapped.add(client);
    const original = client.query.bind(client) as (...args: unknown[]) => unknown;
    const query = (...args: unknown[]): unknown => {
      const [first, second] = args;
      if (typeof first === 'string') {
        seen.push({ text: first, values: Array.isArray(second) ? second : [] });
      } else if (first !== null && typeof first === 'object' && 'text' in first) {
        const config = first as { text: string; values?: unknown[] };
        seen.push({ text: config.text, values: config.values ?? [] });
      }
      return original(...args);
    };
    client.query = query as never;
  });
  return seen;
}

/** A statement that exists only for the audit log: its table, its chain lock, its settings rows. */
function isAuditQuery(q: { text: string; values: unknown[] }): boolean {
  const lock = String(LOCKS.auditChain);
  return (
    /\baudit_events\b/i.test(q.text) ||
    q.values.some((v) => String(v) === lock) ||
    q.values.some((v) =>
      [AUDIT_SETTINGS_KEY, AUDIT_CHAIN_KEY, AUDIT_STREAM_KEY].includes(String(v)),
    )
  );
}

/** A SIEM receiver on the loopback address: every batch body it was sent. */
async function startReceiver(): Promise<{ server: Server; port: number; bodies: string[] }> {
  const bodies: string[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      bodies.push(Buffer.concat(chunks).toString());
      res.statusCode = 204;
      res.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, port: (server.address() as AddressInfo).port, bodies };
}

const allowLoopbackReceivers = (ctx: TestContext) =>
  ctx.db.execute(sql`
    INSERT INTO instance_settings (key, value)
    VALUES ('webhooks', ${JSON.stringify({ allowHttp: true, allowInternalHosts: true })}::jsonb)
    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`);

describe('the audit catalogue end to end (rbac-audit.md §19 criteria 7–8)', () => {
  let env: AuditScenarioEnv;
  let ctx: TestContext;
  let secrets: string[];
  let queries: { text: string; values: unknown[] }[];
  let receiver: Awaited<ReturnType<typeof startReceiver>>;
  const streamSecrets = [
    ['stream', 'given', 'secret', 'Q1W2E3R4'].join('-'),
    ['STREAMPATH', 'SECRET', '97'].join(''),
    ['STREAMQUERY', 'SECRET', '08'].join(''),
  ];

  beforeAll(async () => {
    env = await startAuditScenarioEnv();
    receiver = await startReceiver();
    ctx = await auditScenarioContext(env, ['audit-log']);
    queries = captureQueries(ctx.database.pool);
    refCalls.n = 0;
    // A stream set up first starts at the head, so it carries every event of the scenario.
    await allowLoopbackReceivers(ctx);
    const recorder = createAuditRecorder({ log: QUIET_AUDIT_LOG, isActive: () => true });
    const deps = { secretKey: ctx.config.secretKey, recorder };
    await updateAuditSettings(ctx.db, deps, SYSTEM_ACTOR, {
      stream: {
        url: `http://127.0.0.1:${receiver.port}/siem/${streamSecrets[1]}?key=${streamSecrets[2]}`,
        secret: streamSecrets[0],
      },
    });
    ({ secrets } = await runAuditScenario(ctx, env));
    const regenerated = await regenerateStreamSecret(ctx.db, deps, SYSTEM_ACTOR);
    secrets.push(...streamSecrets, regenerated);
    // The scenario's webhook step rewrote the row; the receiver needs both settings again.
    await allowLoopbackReceivers(ctx);
    const sent = await streamAuditEvents(
      { db: ctx.db, secretKey: ctx.config.secretKey, version: '0.0.0', active: () => true },
      new AbortController().signal,
    );
    expect(sent.failed).toBe(false);
  }, 180_000);
  afterAll(async () => {
    receiver.server.closeAllConnections();
    await new Promise<void>((resolve) => receiver.server.close(() => resolve()));
    await ctx.close();
    await env.close();
  });

  it('lists only catalogue actions as exempt', () => {
    expect([...NOT_FROM_CORE_ROUTES.keys()].filter((a) => !isAuditAction(a))).toEqual([]);
  });

  it('produces every core action of the catalogue', async () => {
    const rows = await ctx.db.execute<{ action: string }>(
      sql`SELECT DISTINCT action FROM audit_events`,
    );
    const seen = new Set(rows.rows.map((r) => r.action));
    const expected = AUDIT_ACTIONS.filter((a) => !NOT_FROM_CORE_ROUTES.has(a));
    expect(expected.filter((a) => !seen.has(a))).toEqual([]);
  });

  it('ends with project.deleted, after every other event of that project (ruling P-B1)', async () => {
    const rows = await ctx.db.execute<{ action: string; project_key: string | null }>(
      sql`SELECT action, project_key FROM audit_events ORDER BY seq`,
    );
    const ofMain = rows.rows.filter((r) => r.project_key === 'scenario/main');
    expect(ofMain.at(-1)?.action).toBe('project.deleted');
  });

  it('holds no secret in any column, in the export or in a stream batch', async () => {
    const rows = await ctx.db.execute<{ row: string }>(
      sql`SELECT row_to_json(a)::text AS row FROM audit_events a ORDER BY seq`,
    );
    const columns = rows.rows.map((r) => r.row).join('\n');
    const day = 86_400_000;
    const lines: string[] = [];
    for await (const line of exportAuditLines(ctx.db, {
      from: new Date(Date.now() - day),
      to: new Date(Date.now() + day),
    })) {
      lines.push(line);
    }
    expect(lines).toHaveLength(rows.rows.length);
    const batches = receiver.bodies.join('\n');
    const streamed = receiver.bodies.flatMap(
      (b) => (JSON.parse(b) as { events: unknown[] }).events,
    );
    expect(streamed).toHaveLength(rows.rows.length);

    expect(secrets.length).toBeGreaterThan(8);
    for (const [where, text] of [
      ['a column', columns],
      ['the export', lines.join('\n')],
      ['a stream batch', batches],
    ] as const) {
      for (const secret of secrets) {
        expect(text.includes(secret), `a secret of length ${secret.length} is in ${where}`).toBe(
          false,
        );
      }
    }
    // The URLs are there as their origins only.
    expect(columns).toContain('https://127.0.0.1:8443');
    expect(columns).toContain(`http://127.0.0.1:${receiver.port}`);
  });

  it('names every changed SCM credential field, GitHub App ones included', async () => {
    const rows = await ctx.db.execute<{ changed: string[] }>(
      sql`SELECT details->'changed' AS changed FROM audit_events
          WHERE action = 'scm_connection.updated' ORDER BY seq`,
    );
    expect(rows.rows.map((r) => r.changed)).toEqual([
      ['token'],
      ['appId', 'privateKey', 'webhookSecret'],
    ]);
  });

  it('is one valid chain', async () => {
    expect(await verifyAuditChain(ctx.db)).toMatchObject({ ok: true, break: null });
  });

  it('the probes of the community run see the audit work here (they are live)', () => {
    expect(queries.filter(isAuditQuery).length).toBeGreaterThan(0);
    expect(refCalls.n).toBeGreaterThan(0);
  });
});

describe('community records nothing (rbac-audit.md §8.1)', () => {
  it('writes no row and runs no audit query for the whole scenario', async () => {
    const env = await startAuditScenarioEnv();
    const ctx = await auditScenarioContext(env, null);
    try {
      const queries = captureQueries(ctx.database.pool);
      refCalls.n = 0;
      await runAuditScenario(ctx, env);
      const scenarioQueries = [...queries];
      // §19 criterion 1: audit_events stays empty after a community boot and this run; since 5B
      // project_memberships holds the one grant the run leaves (on scenario/ai), made through the
      // core grant routes with no licence.
      const [row] = (
        await ctx.db.execute<{ n: number; grants: number }>(
          sql`SELECT (SELECT count(*)::int FROM audit_events) AS n,
                     (SELECT count(*)::int FROM project_memberships) AS grants`,
        )
      ).rows;
      expect(row).toEqual({ n: 0, grants: 1 });
      expect(scenarioQueries.length).toBeGreaterThan(100);
      expect(scenarioQueries.filter(isAuditQuery).map((q) => q.text)).toEqual([]);
      expect(refCalls.n, 'audit-only reads of organisation and project keys').toBe(0);
    } finally {
      await ctx.close();
      await env.close();
    }
  }, 180_000);
});
