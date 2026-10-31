// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
/**
 * Qualor Enterprise (enterprise.md §13). Source-available under enterprise/LICENSE,
 * not MIT. Core loads this module only while a licence is active or in its grace period, and
 * checks every registration; this file imports core for types only.
 */
import type { QualorPlugin } from '@qualor/server/plugin-contract';
import { auditRoutes, auditStreamRoutes } from './audit-routes';
import { complianceJobs, complianceRoutes, HOUSEKEEPING_QUEUE } from './compliance-routes';
import { portfolioRoutes } from './portfolio-routes';
import { scimRoutes } from './scim-routes';
import { ssoRoutes } from './sso-routes';
import { supportRoutes } from './support-routes';

/** rbac-audit.md §14.2: the SIEM stream runs every 10 seconds. */
const STREAM_EVERY_SECONDS = 10;
/** 4E-1 §2.4 step 5: the compliance housekeeping runs hourly. */
const COMPLIANCE_HOUSEKEEPING_SECONDS = 3_600;

const plugin: QualorPlugin = {
  name: 'qualor-enterprise',
  apiVersion: 1,
  // enterprise.md §1.4, §7.1: rbac is retired in 5B; roles and project grants are community.
  // 5D (§1.7): audit-log.stream needs audit-log, sso.multi needs sso (core's prerequisite table).
  // 4E-1: compliance-export has no prerequisite; neither has 4E-2's portfolio.
  // 4E-3a: llm.auto-fix is Enterprise only and has no prerequisite.
  // 4E-3b: support-bundle is Business and Enterprise, with no prerequisite.
  // 6M: license-policy is Business and Enterprise, with no prerequisite.
  // 0.15: vuln.priority, vuln.alerts and sbom are Business and Enterprise, with no prerequisite.
  // 6I (D10): llm.fix-quota is kept, so a licence already issued that lists it stays active (and
  // the deploy probe, tools/deploy/checks.ts, still finds it), but it sets no limit: the community
  // edition has no ceiling on AI fix suggestions.
  features: [
    'llm.fix-quota',
    'audit-log',
    'audit-log.stream',
    'sso',
    'sso.multi',
    'scim',
    'compliance-export',
    'portfolio',
    'llm.auto-fix',
    'support-bundle',
    'license-policy',
    'vuln.priority',
    'vuln.alerts',
    'sbom',
  ],
  register(ctx) {
    // 4E-3a: the seam core reads for automatic fix suggestions; the routes and the opt-out are core's.
    ctx.limits('llm.auto-fix', { llm: { automaticFixSuggestions: true } });
    // 6M: the seam core reads for the organisation licence policy; the routes, the ingest stage and
    // the permission are core's.
    ctx.limits('license-policy', { licenses: { policy: true } });
    // 0.15: the seams core reads for KEV and EPSS, vulnerability alert rules and the SBOM export.
    ctx.limits('vuln.priority', { vulnerabilities: { priority: true } });
    ctx.limits('vuln.alerts', { vulnerabilities: { alerts: true } });
    ctx.limits('sbom', { vulnerabilities: { sbom: true } });
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
    // 4E-1: compliance exports, Enterprise; the database work is core's ctx.compliance.
    ctx.routes('compliance-export', complianceRoutes(ctx));
    ctx.jobs('compliance-export', complianceJobs(ctx));
    ctx.schedule('compliance-export', HOUSEKEEPING_QUEUE, COMPLIANCE_HOUSEKEEPING_SECONDS);
    // 4E-2: portfolio reports, Enterprise; the numbers are core's ctx.portfolio.
    ctx.routes('portfolio', portfolioRoutes(ctx));
    // 4E-3b: the support bundle for instance admins; the data is core's ctx.support.
    ctx.routes('support-bundle', supportRoutes(ctx));
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
    // 4E-1 §4: the project's Compliance tab, and the organisation reports under Settings. Both
    // use the id `compliance`; the UI tells them apart by point.
    ctx.ui('compliance-export', {
      point: 'project.tab',
      id: 'compliance',
      label: 'Compliance',
      path: 'compliance',
    });
    ctx.ui('compliance-export', {
      point: 'settings.nav',
      id: 'compliance',
      label: 'Compliance reports',
      path: '/settings/ee/compliance',
    });
    // 4E-2 §4: the Portfolio entry of the main menu, after Quality gates.
    ctx.ui('portfolio', {
      point: 'main.nav',
      id: 'portfolio',
      label: 'Portfolio',
      path: '/portfolio',
    });
    ctx.ui('support-bundle', {
      point: 'settings.nav',
      id: 'support',
      label: 'Support',
      path: '/settings/ee/support',
    });
    // No licensee name or licence id: the boot line leaves them out too (enterprise.md §6).
    ctx.logger.info('Qualor Enterprise registered');
  },
};

export default plugin;
