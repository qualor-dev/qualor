import type { GateResult } from '@qualor/shared';
import type { RenderedMail } from '../payload';
import { renderAnalysisFailed } from './notify-analysis-failed';
import {
  orgAdminFooterLinks,
  orgAdminReason,
  type AnalysisFailedMailInput,
  type GateMailInput,
  type NotifyLinks,
} from './notify-common';
import { renderExploitedAlert } from './notify-exploited';
import { renderGateFailed } from './notify-gate-failed';
import { renderGateRecovered } from './notify-gate-recovered';
import { renderVulnerabilityDigest } from './notify-vulnerabilities';
import type {
  VulnerabilityMailLinks,
  VulnerabilityMailProject,
} from './notify-vulnerability-common';
import { instanceHost, publicLink } from './text';
import { renderWebhookFailed } from './webhook-failed';

/** A sample's links, built from a public URL the way notifications/links.ts builds them. */
export function sampleLinks(publicUrl: string | null): NotifyLinks {
  return {
    publicUrl,
    instanceHost: instanceHost(publicUrl),
    unsubscribeUrl: publicLink(publicUrl, '/unsubscribe#t=sample.token'),
    settingsUrl: publicLink(publicUrl, '/settings/notifications'),
  };
}

/** A vulnerability email's sample links: its stop page is its own. */
export function sampleVulnerabilityLinks(publicUrl: string | null): VulnerabilityMailLinks {
  return {
    ...sampleLinks(publicUrl),
    unsubscribeUrl: publicLink(publicUrl, '/unsubscribe/vulnerabilities#t=sample.token'),
  };
}

export const SAMPLE_LINKS: NotifyLinks = sampleLinks('https://qualor.example.com');
export const NO_LINKS: NotifyLinks = sampleLinks(null);
export const SAMPLE_VULNERABILITY_LINKS = sampleVulnerabilityLinks('https://qualor.example.com');
export const NO_VULNERABILITY_LINKS = sampleVulnerabilityLinks(null);

const FAILED_GATE: GateResult = {
  status: 'failed',
  gate: { id: 'builtin:qualor-way', name: 'Qualor way' },
  conditions: [
    { metric: 'new_issues', operator: 'gt', threshold: 0, value: 3, status: 'failed' },
    { metric: 'new_coverage', operator: 'lt', threshold: 80, value: 45.5, status: 'failed' },
    {
      metric: 'new_duplicated_lines_density',
      operator: 'gt',
      threshold: 3,
      value: 1.2,
      status: 'passed',
    },
    { metric: 'security_rating', operator: 'gt', threshold: 1, value: 4, status: 'failed' },
  ],
  ignoredConditions: [],
  warnings: [],
};

const PROJECT = { id: '0190a6c2-0000-7000-8000-0000000000b1', name: 'Payments API' };

export const SAMPLE_GATE_FAILED: GateMailInput = {
  project: PROJECT,
  branch: {
    id: '0190a6c2-0000-7000-8000-0000000000c1',
    name: 'main',
    kind: 'branch',
    mrTitle: null,
    mrTargetBranch: null,
  },
  revision: 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678',
  gate: FAILED_GATE,
  measures: {
    new_blocker_issues: 0,
    new_high_issues: 1,
    new_medium_issues: 2,
    new_low_issues: null,
    new_info_issues: 0,
  },
  cause: 'analysis',
  links: SAMPLE_LINKS,
};

export const SAMPLE_GATE_FAILED_MR: GateMailInput = {
  ...SAMPLE_GATE_FAILED,
  branch: {
    id: '0190a6c2-0000-7000-8000-0000000000c2',
    name: '42',
    kind: 'merge_request',
    mrTitle: 'Refund limits',
    mrTargetBranch: 'main',
  },
  cause: 'reevaluation',
};

export const SAMPLE_GATE_RECOVERED: GateMailInput = {
  ...SAMPLE_GATE_FAILED,
  gate: {
    ...FAILED_GATE,
    status: 'passed',
    conditions: FAILED_GATE.conditions.map((c) => ({ ...c, status: 'passed' as const })),
  },
};

export const SAMPLE_ANALYSIS_FAILED: AnalysisFailedMailInput = {
  project: PROJECT,
  branch: { name: 'feature/refunds', kind: 'branch' },
  revision: 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678',
  scannerVersion: '0.7.1',
  error: {
    code: 'REPORT_INVALID',
    message: 'findings.0.location.path: location.path is not listed in files[]',
  },
  links: SAMPLE_LINKS,
};

export const SAMPLE_VULNERABILITY_PROJECTS: VulnerabilityMailProject[] = [
  {
    ...PROJECT,
    rows: [
      {
        vulnerabilityId: 'CVE-2026-1111',
        severity: 'critical',
        title: 'Prototype pollution in merge',
        exploited: { dateAdded: '2026-10-30' },
        packageName: 'lodash',
        installedVersions: ['4.17.20', '4.17.21'],
        fixedVersion: '4.17.22',
        targets: ['main', '2.3.4'],
      },
      {
        vulnerabilityId: 'GHSA-xxxx-yyyy-zzzz',
        severity: 'high',
        title: null,
        exploited: null,
        packageName: 'express',
        installedVersions: ['4.18.0'],
        fixedVersion: null,
        targets: ['main'],
      },
    ],
    more: 0,
  },
];

/**
 * Mail E3's samples for E1's sampleMails(), named after their kind: the three notifications (and
 * the merge request variant), and E1's failing-webhook alert as organisation administrators get it.
 */
export function notifySamples(publicUrl: string | null): { name: string; mail: RenderedMail }[] {
  const links = sampleLinks(publicUrl);
  return [
    { name: 'notify.gate-failed', mail: renderGateFailed({ ...SAMPLE_GATE_FAILED, links }) },
    { name: 'notify.gate-failed-mr', mail: renderGateFailed({ ...SAMPLE_GATE_FAILED_MR, links }) },
    {
      name: 'notify.gate-recovered',
      mail: renderGateRecovered({ ...SAMPLE_GATE_RECOVERED, links }),
    },
    {
      name: 'notify.analysis-failed',
      mail: renderAnalysisFailed({ ...SAMPLE_ANALYSIS_FAILED, links }),
    },
    {
      name: 'notify.vulnerabilities',
      mail: renderVulnerabilityDigest({
        projects: SAMPLE_VULNERABILITY_PROJECTS,
        databaseDate: new Date('2026-11-02T03:00:00Z'),
        links: sampleVulnerabilityLinks(publicUrl),
      }),
    },
    {
      name: 'notify.exploited',
      mail: renderExploitedAlert({
        projects: SAMPLE_VULNERABILITY_PROJECTS,
        links: sampleVulnerabilityLinks(publicUrl),
      }),
    },
    {
      name: 'webhook.failed-organization',
      mail: renderWebhookFailed({
        organization: 'Acme',
        project: 'Payments API',
        receiverHost: 'hooks.example.com',
        lastResponse: 503,
        attempts: 7,
        publicUrl,
        reason: orgAdminReason('Acme'),
        footerLinks: orgAdminFooterLinks(links.settingsUrl),
      }),
    },
  ];
}
