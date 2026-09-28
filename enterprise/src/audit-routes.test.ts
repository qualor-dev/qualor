// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, describe, expect, it } from 'vitest';
import type { PluginContext } from '@qualor/server/plugin-contract';
import { auditRoutes, eventsQuery, exportQuery } from './audit-routes';

/** A gate a test opens by hand. */
function gate(): { wait: Promise<void>; open: () => void } {
  let open = () => {};
  const wait = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { wait, open };
}

const PERIOD = 'from=2027-01-01T00:00:00Z&to=2027-01-02T00:00:00Z';

/**
 * The routes over a fake context: every caller is the instance admin `x-user` names, every
 * problem is an error with its status, and the audit service records what it was asked.
 */
function harness(audit: Partial<PluginContext['audit']>): {
  app: FastifyInstance;
  calls: string[];
} {
  const calls: string[] = [];
  const principal = (request: { headers: Record<string, unknown> }) => ({
    user: { id: String(request.headers['x-user'] ?? 'u1'), isInstanceAdmin: true },
  });
  const ctx = {
    access: {
      requireUser: principal,
      requireInstanceAdmin: principal,
      actor: () => ({ actor: { type: 'system' }, ip: null, userAgent: null }),
      problem: (status: number, code: string, title: string) =>
        Object.assign(new Error(title), { statusCode: status, code }),
    },
    audit: {
      record: async (_actor: unknown, event: { action: string }) => {
        calls.push(`record ${event.action}`);
      },
      ...audit,
    },
  } as unknown as PluginContext;
  const app = Fastify({ logger: false });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  void app.register(auditRoutes(ctx));
  return { app, calls };
}

let app: FastifyInstance | undefined;
afterEach(async () => {
  await app?.close();
  app = undefined;
});

describe('the audit export (rbac-audit.md §12)', () => {
  it('records audit.exported before the first line, then streams the lines', async () => {
    const h = harness({
      exportLines: async function* () {
        h.calls.push('first line');
        yield '{"seq":"1"}';
        yield '{"seq":"2"}';
      },
    });
    app = h.app;
    const res = await app.inject({ url: `/audit/export?${PERIOD}` });
    expect(res.statusCode).toBe(200);
    expect(res.body).toBe('{"seq":"1"}\n{"seq":"2"}\n');
    expect(h.calls).toEqual(['record audit.exported', 'first line']);
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it('runs one export per user at a time (429 RATE_LIMITED), and frees it when it ends', async () => {
    const entered = gate();
    const release = gate();
    const h = harness({
      exportLines: async function* () {
        entered.open();
        await release.wait;
        yield '{"seq":"1"}';
      },
    });
    app = h.app;
    const first = app.inject({ url: `/audit/export?${PERIOD}` });
    await entered.wait;
    const second = await app.inject({ url: `/audit/export?${PERIOD}` });
    expect(second.statusCode).toBe(429);
    expect(second.json()).toMatchObject({ code: 'RATE_LIMITED' });
    // Another user is not held up.
    const other = app.inject({ url: `/audit/export?${PERIOD}`, headers: { 'x-user': 'u2' } });
    release.open();
    expect((await first).statusCode).toBe(200);
    expect((await other).statusCode).toBe(200);
    expect((await app.inject({ url: `/audit/export?${PERIOD}` })).statusCode).toBe(200);
  });

  it('frees the user when recording the export fails, and sends no line', async () => {
    let fail = true;
    let read = 0;
    const h = harness({
      record: async () => {
        if (fail) throw Object.assign(new Error('refused'), { statusCode: 409 });
      },
      exportLines: async function* () {
        read += 1;
        yield '{"seq":"1"}';
      },
    });
    app = h.app;
    expect((await app.inject({ url: `/audit/export?${PERIOD}` })).statusCode).toBe(409);
    expect(read).toBe(0);
    fail = false;
    expect((await app.inject({ url: `/audit/export?${PERIOD}` })).statusCode).toBe(200);
  });

  it('frees the user when the lines fail midway', async () => {
    let fail = true;
    const h = harness({
      exportLines: async function* () {
        yield '{"seq":"1"}';
        if (fail) throw new Error('the database went away');
      },
    });
    app = h.app;
    await app.inject({ url: `/audit/export?${PERIOD}` }).catch(() => undefined);
    fail = false;
    expect((await app.inject({ url: `/audit/export?${PERIOD}` })).statusCode).toBe(200);
  });

  it('refuses a match-all action filter', async () => {
    app = harness({}).app;
    for (const action of ['.*', '*', '%25', '_.*']) {
      const res = await app.inject({ url: `/audit/export?${PERIOD}&action=${action}` });
      expect(res.statusCode, action).toBe(400);
    }
  });
});

describe('the verification (rbac-audit.md §13)', () => {
  it('runs one at a time (429 RATE_LIMITED)', async () => {
    const entered = gate();
    const release = gate();
    const result = {
      ok: true,
      checked: 0,
      firstSeq: null,
      lastSeq: null,
      anchor: null,
      break: null,
    };
    const h = harness({
      verify: async () => {
        entered.open();
        await release.wait;
        return result;
      },
    });
    app = h.app;
    const first = app.inject({ url: '/audit/verify' });
    await entered.wait;
    const second = await app.inject({ url: '/audit/verify', headers: { 'x-user': 'u2' } });
    expect(second.statusCode).toBe(429);
    release.open();
    expect((await first).json()).toEqual(result);
    expect((await app.inject({ url: '/audit/verify' })).statusCode).toBe(200);
  });
});

describe('the free-text filters (rbac-audit.md §13, api.md §2.1)', () => {
  const PERIOD_QUERY = { from: '2027-01-01T00:00:00Z', to: '2027-01-02T00:00:00Z' };
  const issuesOf = (result: { success: boolean; error?: { issues: unknown[] } }) =>
    result.success ? [] : result.error!.issues;

  it.each([
    ['a\u0000b', 'Must not contain NUL characters'],
    ['a\ud800b', 'Must be well-formed Unicode (no lone surrogate)'],
    ['a\udc00', 'Must be well-formed Unicode (no lone surrogate)'],
    ['\u0000\ud800', 'Must not contain NUL characters'],
  ])('refuses %j in targetType and targetId, one error on the field', (value, message) => {
    for (const field of ['targetType', 'targetId']) {
      for (const schema of [eventsQuery, exportQuery]) {
        const input = { ...(schema === exportQuery ? PERIOD_QUERY : {}), [field]: value };
        expect(issuesOf(schema.safeParse(input))).toMatchObject([{ path: [field], message }]);
      }
    }
  });

  it('accepts a surrogate pair (an emoji)', () => {
    expect(eventsQuery.safeParse({ targetId: 'a\u{1f600}b' }).success).toBe(true);
    expect(exportQuery.safeParse({ ...PERIOD_QUERY, targetType: 'a\u{1f600}' }).success).toBe(true);
  });
});
