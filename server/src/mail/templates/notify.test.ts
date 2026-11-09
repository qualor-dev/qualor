import { allMetricKeys } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { renderAnalysisFailed } from './notify-analysis-failed';
import { metricLabel } from './notify-common';
import { renderGateFailed } from './notify-gate-failed';
import { renderExploitedAlert } from './notify-exploited';
import { renderGateRecovered } from './notify-gate-recovered';
import { renderVulnerabilityDigest } from './notify-vulnerabilities';
import { capRows, type VulnerabilityMailProject } from './notify-vulnerability-common';
import {
  NO_LINKS,
  SAMPLE_ANALYSIS_FAILED,
  SAMPLE_GATE_FAILED,
  SAMPLE_GATE_FAILED_MR,
  SAMPLE_GATE_RECOVERED,
  SAMPLE_VULNERABILITY_PROJECTS,
  SAMPLE_VULNERABILITY_LINKS,
  NO_VULNERABILITY_LINKS,
} from './notify-samples';

const BRANCH_URL =
  'https://qualor.example.com/projects/0190a6c2-0000-7000-8000-0000000000b1/branches/0190a6c2-0000-7000-8000-0000000000c1';
// E1 wraps the text part at 76 columns: sentences are asserted on the unwrapped text.
const flat = (text: string) => text.replace(/\s+/g, ' ');

describe('project notification templates (mail E3)', () => {
  it.each([
    ['gate failed', () => renderGateFailed(SAMPLE_GATE_FAILED)],
    ['gate failed on a merge request', () => renderGateFailed(SAMPLE_GATE_FAILED_MR)],
    ['gate recovered', () => renderGateRecovered(SAMPLE_GATE_RECOVERED)],
    ['analysis failed', () => renderAnalysisFailed(SAMPLE_ANALYSIS_FAILED)],
  ])(
    '%s: HTML and text under 90 KB, with the watch reason and both footer links',
    (_name, render) => {
      const mail = render();
      expect(Buffer.byteLength(mail.html)).toBeLessThan(90 * 1024);
      for (const part of [mail.html, mail.text]) {
        expect(flat(part)).toContain('You get this because you watch Payments API in Qualor.');
        expect(part).toContain('https://qualor.example.com/unsubscribe#t=sample.token');
        expect(part).toContain('https://qualor.example.com/settings/notifications');
      }
      // E1's footer links: escaped cobalt links in the HTML, `Label: URL` lines in the text part.
      expect(mail.html).toContain('>Stop watching this project</a> · <a ');
      expect(mail.text).toContain(
        'Stop watching this project: https://qualor.example.com/unsubscribe#t=sample.token\nNotification settings: https://qualor.example.com/settings/notifications\n',
      );
      expect(mail.subject).not.toMatch(/[\r\n]/);
      expect(mail.headers).toBeUndefined();
    },
  );

  it('without a public URL: no link to the instance, and the text says where to go', () => {
    for (const mail of [
      renderGateFailed({ ...SAMPLE_GATE_FAILED, links: NO_LINKS }),
      renderGateRecovered({ ...SAMPLE_GATE_RECOVERED, links: NO_LINKS }),
      renderAnalysisFailed({ ...SAMPLE_ANALYSIS_FAILED, links: NO_LINKS }),
    ]) {
      for (const part of [mail.html, mail.text]) {
        expect(part).not.toContain('qualor.example.com');
        expect(part).not.toContain('/unsubscribe');
        expect(part).not.toContain('Stop watching this project');
        expect(part).toContain('in Qualor');
      }
    }
  });

  it('gate failed: subject, badge, facts, the failing conditions in words, and new-code counts', () => {
    const mail = renderGateFailed(SAMPLE_GATE_FAILED);
    expect(mail.subject).toBe('Payments API: quality gate failed on main');
    expect(mail.html).toContain('The quality gate failed on main');
    expect(mail.html).toContain('Failed');
    expect(mail.html).toContain('Qualor way');
    expect(mail.html).toContain('a1b2c3d');
    expect(mail.html).not.toContain('a1b2c3d4');
    expect(mail.html).toContain(BRANCH_URL);
    expect(mail.html).toContain('inNewCode=true');
    for (const part of [mail.html, mail.text]) {
      expect(part).toContain('Failing conditions');
      expect(part).toContain('Issues on new code');
      expect(part).toContain('greater than 0');
      expect(part).toContain('Coverage on new code');
      expect(part).toContain('45.5%');
      expect(part).toContain('less than 80%');
      expect(part).toContain('Security rating');
      expect(part).toContain('worse than A');
      // A condition that passed is not listed.
      expect(part).not.toContain('Duplicated lines (%) on new code');
      // `new_low_issues` is null: left out, the others in severity order.
      expect(part).toContain('Blocker 0 · High 1 · Medium 2 · Info 0');
    }
    // E1's text part keeps table cells apart and a link's URL.
    expect(mail.text).toContain('Coverage on new code · 45.5% · less than 80%');
    const newIssues = `${BRANCH_URL.replace(/\/branches\/.*/, '')}/issues?branch=0190a6c2-0000-7000-8000-0000000000c1&inNewCode=true`;
    expect(mail.text).toContain(`(${newIssues})`);
  });

  it('names a merge request, its title and target, and says a re-evaluation changed issues', () => {
    const mail = renderGateFailed(SAMPLE_GATE_FAILED_MR);
    expect(mail.subject).toBe('Payments API: quality gate failed on !42');
    expect(mail.text).toContain('Merge request');
    expect(mail.text).toContain('Refund limits');
    expect(flat(mail.text)).toContain('targets main');
    expect(flat(mail.text)).toContain('after issues were changed');
    expect(flat(renderGateFailed(SAMPLE_GATE_FAILED).text)).not.toContain(
      'after issues were changed',
    );
  });

  it('says "The quality gate failed" when the gate has no name, never "quality gate quality gate"', () => {
    const gate = { ...SAMPLE_GATE_FAILED.gate, gate: null };
    for (const mail of [
      renderGateFailed({ ...SAMPLE_GATE_FAILED, gate }),
      renderGateRecovered({ ...SAMPLE_GATE_RECOVERED, gate: { ...gate, status: 'passed' } }),
    ]) {
      expect(flat(mail.text)).toMatch(/The quality gate (failed|passes again) on main of Payments/);
      expect(mail.html).toMatch(/The quality gate (failed|passes again) on <strong>main<\/strong>/);
      expect(flat(mail.text)).not.toContain('quality gate quality gate');
    }
  });

  it('leaves the new-code line out when no count is known', () => {
    const mail = renderGateFailed({ ...SAMPLE_GATE_FAILED, measures: {} });
    expect(mail.text).not.toContain('New code:');
  });

  it('gate recovered: ok badge, "passes again", and no conditions table', () => {
    const mail = renderGateRecovered(SAMPLE_GATE_RECOVERED);
    expect(mail.subject).toBe('Payments API: quality gate passes again on main');
    expect(mail.html).toContain('The quality gate passes again on main');
    expect(mail.html).toContain('Passed');
    expect(mail.html).not.toContain('Failing conditions');
    expect(mail.html).toContain(BRANCH_URL);
  });

  it('analysis failed: the branch or Unknown, the scanner, and the error clipped to 500 characters', () => {
    const named = renderAnalysisFailed(SAMPLE_ANALYSIS_FAILED);
    expect(named.subject).toBe('Payments API: an analysis of feature/refunds failed');
    expect(named.html).toContain('An analysis of Payments API failed');
    expect(named.html).toContain('Analysis failed');
    expect(named.text).toContain('feature/refunds');
    expect(named.text).toContain('0.7.1');
    expect(named.text).toContain('REPORT_INVALID');
    expect(named.html).toContain(
      'https://qualor.example.com/projects/0190a6c2-0000-7000-8000-0000000000b1',
    );
    const unknown = renderAnalysisFailed({
      ...SAMPLE_ANALYSIS_FAILED,
      branch: null,
      revision: null,
      error: { code: 'PROCESSING_ERROR', message: 'x'.repeat(2000) },
    });
    expect(unknown.subject).toBe('Payments API: an analysis failed');
    expect(unknown.text).toContain('Unknown');
    expect(unknown.text).toContain('PROCESSING_ERROR');
    expect(unknown.text).not.toContain('x'.repeat(501));
  });

  it('escapes names in HTML, and keeps the subject one line of at most 300 characters', () => {
    const mail = renderGateFailed({
      ...SAMPLE_GATE_FAILED,
      project: {
        ...SAMPLE_GATE_FAILED.project,
        name: '<img src=x onerror=alert(1)>\r\nBcc: x@example.com',
      },
      branch: { ...SAMPLE_GATE_FAILED.branch, name: 'b'.repeat(400) },
    });
    expect(mail.html).not.toContain('<img src=x');
    expect(mail.html).toContain('&lt;img src=x');
    expect(mail.subject).not.toMatch(/[\r\n]/);
    expect(mail.subject.length).toBeLessThanOrEqual(300);
  });

  it('labels every metric a gate condition may use', () => {
    for (const key of allMetricKeys()) expect(metricLabel(key), key).not.toBe(key);
    expect(metricLabel('new_coverage')).toBe('Coverage on new code');
    expect(metricLabel('coverage')).toBe('Coverage');
  });
});

describe('vulnerability emails (4b)', () => {
  const PROJECT_URL =
    'https://qualor.example.com/projects/0190a6c2-0000-7000-8000-0000000000b1/vulnerabilities';
  const digest = (projects = SAMPLE_VULNERABILITY_PROJECTS, links = SAMPLE_VULNERABILITY_LINKS) =>
    renderVulnerabilityDigest({ projects, databaseDate: new Date('2026-11-02T03:00:00Z'), links });
  const project = (n: number, rows = 1): VulnerabilityMailProject => ({
    id: `0190a6c2-0000-7000-8000-00000000010${n}`,
    name: `Project ${n}`,
    rows: Array.from({ length: rows }, (_, i) => ({
      ...SAMPLE_VULNERABILITY_PROJECTS[0]!.rows[0]!,
      vulnerabilityId: `CVE-2026-${String(1000 + i)}`,
    })),
    more: 0,
  });

  it('digest: subject for one project and for three', () => {
    expect(digest().subject).toBe('New vulnerabilities in Payments API');
    expect(digest([project(1), project(2), project(3)]).subject).toBe(
      'New vulnerabilities in 3 projects',
    );
  });

  it('digest: a table per project with the id, severity, package, fix and targets', () => {
    const mail = digest();
    for (const part of [mail.html, mail.text]) {
      expect(part).toContain('CVE-2026-1111');
      expect(part).toContain('Critical');
      expect(part).toContain('Exploited');
      expect(part).toContain('lodash');
      expect(part).toContain('4.17.20, 4.17.21');
      expect(part).toContain('4.17.22');
      expect(part).toContain('No fix yet');
      expect(part).toContain('main, 2.3.4');
      expect(part).toContain('Vulnerability data from 2026-11-02');
    }
    for (const heading of ['Vulnerability', 'Package', 'Fixed in', 'In']) {
      expect(mail.html).toContain(`>${heading}</td>`);
    }
    expect(mail.html).toContain(`href="${PROJECT_URL}"`);
  });

  it('digest: the reason and the two footer links', () => {
    const mail = digest();
    for (const part of [mail.html, mail.text]) {
      expect(flat(part)).toContain(
        'You get this because you watch these projects with New vulnerabilities in tracked versions on.',
      );
    }
    expect(mail.html).toContain('>Stop vulnerability emails</a> · <a ');
    expect(mail.text).toContain(
      'Stop vulnerability emails: https://qualor.example.com/unsubscribe/vulnerabilities#t=sample.token\nNotification settings: https://qualor.example.com/settings/notifications\n',
    );
  });

  it('digest: leaves the data date out when it is unknown', () => {
    const mail = renderVulnerabilityDigest({
      projects: SAMPLE_VULNERABILITY_PROJECTS,
      databaseDate: null,
      links: SAMPLE_VULNERABILITY_LINKS,
    });
    expect(mail.text).not.toContain('Vulnerability data from');
  });

  it('exploited: subject, and each row says when CISA listed it', () => {
    const mail = renderExploitedAlert({
      projects: SAMPLE_VULNERABILITY_PROJECTS,
      links: SAMPLE_VULNERABILITY_LINKS,
    });
    expect(mail.subject).toBe('Exploited vulnerabilities in Payments API');
    expect(
      renderExploitedAlert({
        projects: [project(1), project(2), project(3)],
        links: SAMPLE_VULNERABILITY_LINKS,
      }).subject,
    ).toBe('Exploited vulnerabilities in 3 projects');
    expect(flat(mail.text)).toContain('Added to the CISA KEV catalog on 2026-10-30');
    expect(mail.html).toContain(`href="${PROJECT_URL}"`);
  });

  it('without a public URL: no link anywhere', () => {
    for (const mail of [
      digest(SAMPLE_VULNERABILITY_PROJECTS, NO_VULNERABILITY_LINKS),
      renderExploitedAlert({
        projects: SAMPLE_VULNERABILITY_PROJECTS,
        links: NO_VULNERABILITY_LINKS,
      }),
    ]) {
      expect(mail.html).not.toContain('qualor.example.com');
      expect([...mail.html.matchAll(/href="([^"]+)"/g)].map((m) => m[1])).toEqual([
        'https://qualor.dev',
      ]);
      expect(mail.text).not.toMatch(/https?:\/\//);
      expect(mail.text).not.toContain('Stop vulnerability emails');
    }
  });

  it('caps a project at 20 rows with the rest counted, under 90 KB', () => {
    const big = project(1, 300);
    for (const mail of [
      digest([big]),
      renderExploitedAlert({ projects: [big], links: SAMPLE_VULNERABILITY_LINKS }),
    ]) {
      expect(mail.text.match(/CVE-2026-/g)).toHaveLength(20);
      expect(flat(mail.text)).toContain('And 280 more on the Vulnerabilities tab.');
      expect(Buffer.byteLength(mail.html)).toBeLessThan(90 * 1024);
    }
  });

  it('capRows: 20 per project, 100 per email, later projects stay listed with their count', () => {
    const capped = capRows([1, 2, 3, 4, 5, 6, 7].map((n) => project(n, 30)));
    expect(capped.map((p) => p.rows.length)).toEqual([20, 20, 20, 20, 20, 0, 0]);
    expect(capped.map((p) => p.more)).toEqual([10, 10, 10, 10, 10, 30, 30]);
    expect(capRows(capped)).toEqual(capped);
    expect(capRows([project(1, 3)])[0]).toMatchObject({ more: 0 });
    const mail = digest(capped);
    expect(mail.text).toContain('Project 7');
    expect(flat(mail.text)).toContain('30 more on the Vulnerabilities tab.');
  });

  it('clips advisory text: a full digest and KEV mail stay under 90 KB, the subject within its limit', () => {
    const long = (n: number) => 'x'.repeat(n);
    const full = [1, 2, 3, 4, 5].map((n) => ({
      ...project(n, 20),
      name: long(300),
      rows: Array.from({ length: 20 }, (_, i) => ({
        vulnerabilityId: `CVE-2026-${1000 + i}`,
        severity: 'critical' as const,
        title: long(1000),
        exploited: { dateAdded: '2026-10-30' },
        packageName: long(300),
        installedVersions: Array.from({ length: 30 }, (_, v) => `1.0.${v}${long(20)}`),
        fixedVersion: '1.2.3',
        targets: Array.from({ length: 30 }, (_, v) => `release/${v}${long(30)}`),
      })),
    }));
    for (const mail of [
      digest(full),
      renderExploitedAlert({ projects: full, links: SAMPLE_VULNERABILITY_LINKS }),
    ]) {
      expect(Buffer.byteLength(mail.html, 'utf8')).toBeLessThan(90 * 1024);
      expect(mail.html).not.toContain(long(121));
      expect(mail.text).not.toContain(long(121));
    }
    const one = renderExploitedAlert({
      projects: [{ ...project(1), name: long(300) }],
      links: SAMPLE_VULNERABILITY_LINKS,
    });
    expect(one.subject.length).toBeLessThanOrEqual(300);
    expect(one.subject).toContain('…');
    expect(digest([{ ...project(1), name: long(300) }]).subject.length).toBeLessThanOrEqual(300);
  });

  it('escapes names and titles', () => {
    const row = { ...SAMPLE_VULNERABILITY_PROJECTS[0]!.rows[0]!, title: '<script>x</script>' };
    const mail = digest([{ ...project(1), name: '<b>P</b>', rows: [row] }]);
    expect(mail.html).not.toContain('<script>');
    expect(mail.html).not.toContain('<b>P</b>');
    expect(mail.subject).toBe('New vulnerabilities in <b>P</b>');
  });
});
