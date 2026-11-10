/* eslint-disable @typescript-eslint/no-explicit-any -- walks the built JSON documents */
import { describe, expect, it } from 'vitest';
import { validateAgainst } from '../../../test/export-schemas';
import { VEX_JUSTIFICATIONS } from '../decisions';
import { productId, type ExportDocument } from './types';
import {
  CYCLONEDX_JUSTIFICATION,
  buildCycloneDxVex,
  buildOpenVex,
  type VexEntry,
} from './vex-documents';

const SERIAL = '3e671687-395b-41f5-a30f-a58921a69b79';

const DOC: ExportDocument = {
  project: { key: 'acme-web', name: 'Acme Web' },
  organization: 'Acme',
  target: { kind: 'branch', name: 'release/2.x' },
  generatedAt: new Date('2026-11-10T08:30:15.123Z'),
  serial: SERIAL,
  toolVersion: '0.15.0',
};

const DECIDED = new Date('2026-11-01T10:00:00.000Z');

function entry(overrides: Partial<VexEntry> & { vulnerabilityId: string }): VexEntry {
  return {
    severity: 'high',
    title: null,
    primaryUrl: null,
    fixedVersion: null,
    packageName: 'left-pad',
    purls: ['pkg:npm/left-pad@1.3.0'],
    status: 'open',
    reason: null,
    comment: null,
    decidedAt: null,
    decidedBy: null,
    ...overrides,
  };
}

const ENTRIES: VexEntry[] = [
  entry({
    vulnerabilityId: 'CVE-2026-0001',
    primaryUrl: 'https://avd.aquasec.com/nvd/cve-2026-0001',
    fixedVersion: '1.3.1',
    severity: 'critical',
  }),
  ...VEX_JUSTIFICATIONS.map((reason, i) =>
    entry({
      vulnerabilityId: `CVE-2026-001${i}`,
      packageName: 'lodash',
      purls: ['pkg:npm/lodash@4.17.20', 'pkg:npm/lodash@4.17.21'],
      status: 'false_positive',
      reason,
      comment: i === 0 ? 'Not shipped.' : null,
      decidedAt: DECIDED,
      decidedBy: 'Alice',
    }),
  ),
  entry({
    vulnerabilityId: 'CVE-2026-0020',
    packageName: '@scope/pkg',
    purls: ['pkg:npm/%40scope/pkg@2.0.0'],
    status: 'false_positive',
    comment: 'Migrated decision.',
    decidedAt: DECIDED,
    decidedBy: null,
  }),
  entry({
    vulnerabilityId: 'CVE-2026-0021',
    status: 'false_positive',
    decidedAt: DECIDED,
    decidedBy: 'Bob',
  }),
  entry({
    vulnerabilityId: 'CVE-2026-0030',
    severity: 'low',
    status: 'wont_fix',
    comment: 'Accepted until Q2.',
    decidedAt: DECIDED,
    decidedBy: 'Alice',
  }),
  entry({
    vulnerabilityId: 'CVE-2026-0031',
    severity: 'unknown',
    status: 'wont_fix',
    purls: ['pkg:npm/left-pad'],
    decidedAt: DECIDED,
    decidedBy: 'Alice',
  }),
];

const byId = (list: any[], id: string): any =>
  list.find((v) => (v.id ?? v.vulnerability?.name) === id);

describe('buildCycloneDxVex', () => {
  const out = buildCycloneDxVex(DOC, ENTRIES) as any;

  it('validates against the CycloneDX 1.6 schema', () => {
    expect(validateAgainst('cyclonedx', out)).toEqual([]);
  });

  it('has the BOM envelope', () => {
    expect(out.bomFormat).toBe('CycloneDX');
    expect(out.specVersion).toBe('1.6');
    expect(out.serialNumber).toBe(`urn:uuid:${SERIAL}`);
    expect(out.version).toBe(1);
    expect(out.metadata.timestamp).toBe('2026-11-10T08:30:15.123Z');
    expect(out.metadata.component['bom-ref']).toBe(productId(DOC.project, DOC.target));
  });

  it('lists one component per distinct purl, with name and version', () => {
    const refs = out.components.map((c: any) => c['bom-ref']);
    expect(new Set(refs).size).toBe(refs.length);
    expect(refs).toContain('pkg:npm/lodash@4.17.20');
    expect(refs).toContain('pkg:npm/lodash@4.17.21');
    const scoped = out.components.find((c: any) => c.purl === 'pkg:npm/%40scope/pkg@2.0.0');
    expect(scoped).toMatchObject({ type: 'library', name: '@scope/pkg', version: '2.0.0' });
    const bare = out.components.find((c: any) => c.purl === 'pkg:npm/left-pad');
    expect(bare.version).toBeUndefined();
  });

  it('points every affects ref at a listed component', () => {
    const refs = new Set(out.components.map((c: any) => c['bom-ref']));
    for (const v of out.vulnerabilities) {
      expect(v.affects.length).toBeGreaterThan(0);
      for (const a of v.affects) expect(refs.has(a.ref)).toBe(true);
    }
    expect(byId(out.vulnerabilities, 'CVE-2026-0010').affects).toEqual([
      { ref: 'pkg:npm/lodash@4.17.20' },
      { ref: 'pkg:npm/lodash@4.17.21' },
    ]);
  });

  it('maps an open entry to in_triage with its advisory and recommendation', () => {
    const v = byId(out.vulnerabilities, 'CVE-2026-0001');
    expect(v['bom-ref']).toBe('CVE-2026-0001:left-pad');
    expect(v.source).toEqual({ name: 'Trivy' });
    expect(v.ratings).toEqual([{ severity: 'critical', source: { name: 'Trivy' } }]);
    expect(v.analysis).toEqual({ state: 'in_triage' });
    expect(v.advisories).toEqual([{ url: 'https://avd.aquasec.com/nvd/cve-2026-0001' }]);
    expect(v.recommendation).toBe('Upgrade to 1.3.1.');
    expect(v.properties).toBeUndefined();
  });

  it('omits advisories and recommendation when there is nothing to say', () => {
    const v = byId(out.vulnerabilities, 'CVE-2026-0010');
    expect(v.advisories).toBeUndefined();
    expect(v.recommendation).toBeUndefined();
  });

  it('maps each reason through the justification table', () => {
    VEX_JUSTIFICATIONS.forEach((reason, i) => {
      const v = byId(out.vulnerabilities, `CVE-2026-001${i}`);
      expect(v.analysis.state).toBe('not_affected');
      expect(v.analysis.justification).toBe(CYCLONEDX_JUSTIFICATION[reason]);
      expect(v.analysis.lastUpdated).toBe(DECIDED.toISOString());
      expect(v.analysis.firstIssued).toBe(DECIDED.toISOString());
      expect(v.properties).toEqual([{ name: 'qualor:decided-by', value: 'Alice' }]);
    });
    expect(byId(out.vulnerabilities, 'CVE-2026-0010').analysis.detail).toBe('Not shipped.');
    expect(byId(out.vulnerabilities, 'CVE-2026-0011').analysis.detail).toBeUndefined();
  });

  it('keeps the comment for a not-affected entry with no reason', () => {
    const v = byId(out.vulnerabilities, 'CVE-2026-0020');
    expect(v.analysis.state).toBe('not_affected');
    expect(v.analysis.justification).toBeUndefined();
    expect(v.analysis.detail).toBe('Migrated decision.');
    expect(v.properties).toBeUndefined();
  });

  it('says no reason was recorded when there is neither reason nor comment', () => {
    const v = byId(out.vulnerabilities, 'CVE-2026-0021');
    expect(v.analysis.justification).toBeUndefined();
    expect(v.analysis.detail).toBe('No reason was recorded.');
  });

  it("maps won't fix to exploitable with will_not_fix", () => {
    const v = byId(out.vulnerabilities, 'CVE-2026-0030');
    expect(v.analysis.state).toBe('exploitable');
    expect(v.analysis.response).toEqual(['will_not_fix']);
    expect(v.analysis.detail).toBe('Accepted until Q2.');
    const bare = byId(out.vulnerabilities, 'CVE-2026-0031');
    expect(bare.analysis.detail).toBeUndefined();
    expect(bare.ratings[0].severity).toBe('unknown');
  });
});

describe('buildOpenVex', () => {
  const out = buildOpenVex(DOC, ENTRIES) as any;

  it('validates against the OpenVEX 0.2.0 schema', () => {
    expect(validateAgainst('openvex', out)).toEqual([]);
  });

  it('has the document envelope', () => {
    expect(out['@context']).toBe('https://openvex.dev/ns/v0.2.0');
    expect(out['@id']).toBe(`urn:uuid:${SERIAL}`);
    expect(out.author).toBe('Acme');
    expect(out.tooling).toBe('Qualor 0.15.0');
    expect(out.version).toBe(1);
    expect(out.timestamp).toBe('2026-11-10T08:30:15.123Z');
    expect(out.statements).toHaveLength(ENTRIES.length);
  });

  it('names the vulnerability and the product with its purls', () => {
    const s = byId(out.statements, 'CVE-2026-0010');
    expect(s.vulnerability).toEqual({ name: 'CVE-2026-0010' });
    expect(s.products).toEqual([
      {
        '@id': productId(DOC.project, DOC.target),
        subcomponents: [{ '@id': 'pkg:npm/lodash@4.17.20' }, { '@id': 'pkg:npm/lodash@4.17.21' }],
      },
    ]);
  });

  it('maps an open entry to under_investigation with no timestamp', () => {
    const s = byId(out.statements, 'CVE-2026-0001');
    expect(s.status).toBe('under_investigation');
    expect(s.timestamp).toBeUndefined();
    expect(s.status_notes).toBeUndefined();
    expect(s.justification).toBeUndefined();
  });

  it('keeps the reason as stored, with the comment as impact statement', () => {
    VEX_JUSTIFICATIONS.forEach((reason, i) => {
      const s = byId(out.statements, `CVE-2026-001${i}`);
      expect(s.status).toBe('not_affected');
      expect(s.justification).toBe(reason);
      expect(s.timestamp).toBe(DECIDED.toISOString());
      expect(s.status_notes).toBe('Decided by Alice.');
    });
    expect(byId(out.statements, 'CVE-2026-0010').impact_statement).toBe('Not shipped.');
    expect(byId(out.statements, 'CVE-2026-0011').impact_statement).toBeUndefined();
  });

  it('carries a reasonless decision in the impact statement', () => {
    const s = byId(out.statements, 'CVE-2026-0020');
    expect(s.justification).toBeUndefined();
    expect(s.impact_statement).toBe('Migrated decision.');
    expect(s.status_notes).toBeUndefined();
    const none = byId(out.statements, 'CVE-2026-0021');
    expect(none.impact_statement).toBe('No reason was recorded.');
    expect(none.status_notes).toBe('Decided by Bob.');
  });

  it("maps won't fix to affected with an action statement", () => {
    const s = byId(out.statements, 'CVE-2026-0030');
    expect(s.status).toBe('affected');
    expect(s.action_statement).toBe('Accepted until Q2.');
    expect(byId(out.statements, 'CVE-2026-0031').action_statement).toBe('No action is planned.');
  });
});
