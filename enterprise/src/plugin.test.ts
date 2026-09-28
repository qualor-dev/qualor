// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import type { PluginContext } from '@qualor/server/plugin-contract';
import plugin from './plugin';

describe('qualor-enterprise', () => {
  it('declares its six features, lifts the fix ceiling, and registers the audit-log, audit-log.stream, sso and scim API (rbac is retired in 5B)', async () => {
    const limits: unknown[] = [];
    const routes: string[] = [];
    const jobs: [string, string[]][] = [];
    const schedules: unknown[] = [];
    const ui: unknown[] = [];
    const logged: unknown[] = [];
    const log = (...args: unknown[]) => logged.push(args);
    const ctx = {
      apiVersion: 1,
      license: { customer: 'Acme Corporation', id: '6f1c2a9e-8d4b-4c1e-9f3a-2b7d5e8c1a40' },
      logger: { debug: log, info: log, warn: log, error: log },
      limits: (feature: string, override: unknown) => limits.push([feature, override]),
      routes: (feature: string, fn: unknown) => {
        expect(typeof fn).toBe('function');
        routes.push(feature);
      },
      jobs: (feature: string, handlers: Record<string, unknown>) =>
        jobs.push([feature, Object.keys(handlers)]),
      schedule: (...args: unknown[]) => schedules.push(args),
      ui: (feature: string, extension: unknown) => ui.push([feature, extension]),
    } as unknown as PluginContext;
    expect(plugin).toMatchObject({
      name: 'qualor-enterprise',
      apiVersion: 1,
      features: ['llm.fix-quota', 'audit-log', 'audit-log.stream', 'sso', 'sso.multi', 'scim'],
    });
    await plugin.register(ctx);
    expect(limits).toEqual([['llm.fix-quota', { llm: { maxFixPerOrganizationPerDay: 100_000 } }]]);
    expect(routes).toEqual(['audit-log', 'audit-log.stream', 'sso', 'scim']);
    // rbac-audit.md §14.2, §14.4: the stream, every 10 seconds, only while audit-log.stream is active.
    expect(jobs).toEqual([['audit-log.stream', ['ee.audit.stream']]]);
    expect(schedules).toEqual([['audit-log.stream', 'ee.audit.stream', 10]]);
    expect(ui).toEqual([
      [
        'audit-log',
        {
          point: 'settings.nav',
          id: 'audit-log',
          label: 'Audit log',
          path: '/settings/ee/audit-log',
        },
      ],
      [
        'audit-log',
        {
          point: 'settings.nav',
          id: 'audit-settings',
          label: 'Audit settings',
          path: '/settings/ee/audit-settings',
        },
      ],
      // sso-scim.md §18: the ids the UI knows.
      [
        'sso',
        { point: 'settings.nav', id: 'sso', label: 'Single sign-on', path: '/settings/ee/sso' },
      ],
      [
        'sso',
        { point: 'settings.nav', id: 'sign-in', label: 'Sign-in', path: '/settings/ee/sign-in' },
      ],
      [
        'sso',
        {
          point: 'settings.nav',
          id: 'linked-accounts',
          label: 'Linked accounts',
          path: '/settings/ee/linked-accounts',
        },
      ],
      ['scim', { point: 'settings.nav', id: 'scim', label: 'SCIM', path: '/settings/ee/scim' }],
    ]);
    // enterprise.md §6: the licensee is not logged (the boot line leaves it out, and so does the plugin).
    expect(logged).toEqual([['Qualor Enterprise registered']]);
    expect(JSON.stringify(logged)).not.toMatch(/Acme|6f1c2a9e/);
  });

  it('declares llm.fix-quota, audit-log, audit-log.stream, sso, sso.multi and scim, and never a retired feature (enterprise.md §1.4, §1.7)', () => {
    // RETIRED_FEATURES lives in server/src/license/token.ts; enterprise/src imports core as types
    // only (tools/boundaries.test.ts), so the retired list is inlined here, kept in sync by hand.
    const RETIRED_FEATURES: readonly string[] = ['rbac'];
    expect(plugin.features).toEqual([
      'llm.fix-quota',
      'audit-log',
      'audit-log.stream',
      'sso',
      'sso.multi',
      'scim',
    ]);
    for (const feature of RETIRED_FEATURES) expect(plugin.features).not.toContain(feature);
  });

  it('runs the stream through the audit service, with the job signal', async () => {
    let handler: ((job: { signal: AbortSignal }) => Promise<void>) | undefined;
    const signals: AbortSignal[] = [];
    const ctx = {
      logger: { debug() {}, info() {}, warn() {}, error() {} },
      limits() {},
      routes() {},
      schedule() {},
      ui() {},
      jobs: (_feature: string, handlers: Record<string, typeof handler>) => {
        handler = handlers['ee.audit.stream'];
      },
      audit: { streamOnce: async (signal: AbortSignal) => void signals.push(signal) },
    } as unknown as PluginContext;
    await plugin.register(ctx);
    const signal = new AbortController().signal;
    await handler!({ signal });
    expect(signals).toEqual([signal]);
  });

  it('has only runtime dependencies the server image already carries, at the same ranges', () => {
    const read = (p: string) =>
      JSON.parse(readFileSync(new URL(p, import.meta.url), 'utf8')) as {
        dependencies?: Record<string, string>;
      };
    const ee = read('../package.json').dependencies ?? {};
    const server = read('../../server/package.json').dependencies ?? {};
    // rbac-audit.md (Global Constraints): zod is the one runtime dependency, external in the bundle.
    expect(Object.keys(ee)).toEqual(['zod']);
    for (const [name, range] of Object.entries(ee)) expect(server[name], name).toBe(range);
  });
});
