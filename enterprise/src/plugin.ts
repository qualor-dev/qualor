// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
/**
 * Qualor Enterprise (enterprise.md §13). Source-available under enterprise/LICENSE,
 * not MIT. Core loads this module only while a licence is active or in its grace period, and
 * checks every registration; this file imports core for types only.
 */
import type { QualorPlugin } from '@qualor/server/plugin-contract';
import { auditRoutes, auditStreamRoutes } from './audit-routes';
import { scimRoutes } from './scim-routes';
import { ssoRoutes } from './sso-routes';

/** The admin's budget maximum (server/src/llm/settings.ts); core refuses more. */
const MAX_FIX_PER_DAY = 100_000;
/** rbac-audit.md §14.2: the SIEM stream runs every 10 seconds. */
const STREAM_EVERY_SECONDS = 10;

const plugin: QualorPlugin = {
  name: 'qualor-enterprise',
  apiVersion: 1,
  // enterprise.md §1.4, §7.1: rbac is retired in 5B; roles and project grants are community.
  // 5D (§1.7): audit-log.stream needs audit-log, sso.multi needs sso (core's prerequisite table).
  features: ['llm.fix-quota', 'audit-log', 'audit-log.stream', 'sso', 'sso.multi', 'scim'],
  register(ctx) {
    ctx.limits('llm.fix-quota', { llm: { maxFixPerOrganizationPerDay: MAX_FIX_PER_DAY } });
    // rbac-audit.md §13: mounted under /api/v0/ee, 403 while the feature is inactive. The grant
    // routes are core routes since 5B (§16).
    ctx.routes('audit-log', auditRoutes(ctx));
    // rbac-audit.md §14.4: the stream's two routes, 403 while audit-log.stream is inactive.
    ctx.routes('audit-log.stream', auditStreamRoutes(ctx));
    // sso-scim.md §17.2: /ee/sso and /ee/scim, 403 while their feature is inactive (§11).
    ctx.routes('sso', ssoRoutes(ctx));
    ctx.routes('scim', scimRoutes(ctx));
    // §14.2, §14.4: core's scheduler runs it one at a time, and skips it while audit-log.stream
    // is inactive; the next run is still scheduled.
    ctx.jobs('audit-log.stream', {
      'ee.audit.stream': async (job) => {
        await ctx.audit.streamOnce(job.signal);
      },
    });
    ctx.schedule('audit-log.stream', 'ee.audit.stream', STREAM_EVERY_SECONDS);
    ctx.ui('audit-log', {
      point: 'settings.nav',
      id: 'audit-log',
      label: 'Audit log',
      path: '/settings/ee/audit-log',
    });
    ctx.ui('audit-log', {
      point: 'settings.nav',
      id: 'audit-settings',
      label: 'Audit settings',
      path: '/settings/ee/audit-settings',
    });
    // sso-scim.md §18: the 4D screens; single sign-on, sign-in and SCIM for instance admins,
    // linked accounts for every user.
    ctx.ui('sso', {
      point: 'settings.nav',
      id: 'sso',
      label: 'Single sign-on',
      path: '/settings/ee/sso',
    });
    ctx.ui('sso', {
      point: 'settings.nav',
      id: 'sign-in',
      label: 'Sign-in',
      path: '/settings/ee/sign-in',
    });
    ctx.ui('sso', {
      point: 'settings.nav',
      id: 'linked-accounts',
      label: 'Linked accounts',
      path: '/settings/ee/linked-accounts',
    });
    ctx.ui('scim', { point: 'settings.nav', id: 'scim', label: 'SCIM', path: '/settings/ee/scim' });
    // No licensee name or licence id: the boot line leaves them out too (enterprise.md §6).
    ctx.logger.info('Qualor Enterprise registered');
  },
};

export default plugin;
