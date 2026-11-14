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
/** The serial of the SBOM the CycloneDX VEX links to, not the VEX's own. */
const SBOM_SERIAL = '9c1f0e2d-4b3a-8c5d-9e6f-7a8b9c0d1e2f';
const link = (purl: string): string => `urn:cdx:${SBOM_SERIAL}/1#${purl}`;

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
    aliases: [],
    ...overrides,
  };
}

/** lodash 4.17.15's CVE-2020-8203, not affected, with the GHSA id Trivy reports for it. */
const LODASH = entry({
  vulnerabilityId: 'CVE-2020-8203',
  packageName: 'lodash',
  purls: ['pkg:npm/lodash@4.17.15'],
  status: 'false_positive',
  reason: 'vulnerable_code_not_present',
  decidedAt: DECIDED,
  decidedBy: 'Alice',
  aliases: ['GHSA-p6mc-m468-83gw'],
});

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
  const out = buildCycloneDxVex(DOC, ENTRIES, SBOM_SERIAL) as any;

  it('validates against the CycloneDX 1.6 schema', () => {
    expect(validateAgainst('cyclonedx', out)).toEqual([]);
  });

  it('has the BOM envelope', () => {
    expect(out.bomFormat).toBe('CycloneDX');
    expect(out.specVersion).toBe('1.6');
    // A15: the VEX keeps a serial of its own; only its links name the SBOM's.
    expect(out.serialNumber).toBe(`urn:uuid:${SERIAL}`);
    expect(out.version).toBe(1);
    expect(out.metadata.timestamp).toBe('2026-11-10T08:30:15.123Z');
    expect(out.metadata.component['bom-ref']).toBe(productId(DOC.project, DOC.target));
    expect(out.metadata.component.purl).toBe(productId(DOC.project, DOC.target));
  });

  it('names the source after the id prefix, so Dependency-Track can match it', () => {
    const doc = buildCycloneDxVex(
      DOC,
      [
        entry({ vulnerabilityId: 'CVE-2026-0001' }),
        entry({ vulnerabilityId: 'GHSA-abcd-1234-wxyz' }),
        entry({ vulnerabilityId: 'GO-2024-1234' }),
      ],
      SBOM_SERIAL,
    ) as any;
    expect(validateAgainst('cyclonedx', doc)).toEqual([]);
    const [cve, ghsa, go] = doc.vulnerabilities;
    expect(cve.source).toEqual({
      name: 'NVD',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0001',
    });
    expect(ghsa.source).toEqual({
      name: 'GITHUB',
      url: 'https://github.com/advisories/GHSA-abcd-1234-wxyz',
    });
    expect(go.source).toEqual({ name: 'OSV', url: 'https://osv.dev/vulnerability/GO-2024-1234' });
    expect(go.ratings[0].source).toEqual({ name: 'Trivy' });
  });

  it('carries the decision of an open entry: detail, dates and author', () => {
    const doc = buildCycloneDxVex(
      DOC,
      [
        entry({
          vulnerabilityId: 'CVE-2026-0040',
          comment: 'Reopened after the fix regressed.',
          decidedAt: DECIDED,
          decidedBy: 'Carol',
        }),
      ],
      SBOM_SERIAL,
    ) as any;
    const v = doc.vulnerabilities[0];
    expect(v.analysis).toEqual({
      state: 'in_triage',
      detail: 'Reopened after the fix regressed.',
      firstIssued: DECIDED.toISOString(),
      lastUpdated: DECIDED.toISOString(),
    });
    expect(v.properties).toEqual([{ name: 'qualor:decided-by', value: 'Carol' }]);
  });

  it('validates an entry with no purls', () => {
    const doc = buildCycloneDxVex(
      DOC,
      [entry({ vulnerabilityId: 'CVE-2026-0050', purls: [] })],
      SBOM_SERIAL,
    );
    expect(validateAgainst('cyclonedx', doc)).toEqual([]);
  });

  it('lists one component per distinct purl, with name and version', () => {
    const refs = out.components.map((c: any) => c['bom-ref']);
    expect(new Set(refs).size).toBe(refs.length);
    expect(refs).toContain(link('pkg:npm/lodash@4.17.20'));
    expect(refs).toContain(link('pkg:npm/lodash@4.17.21'));
    const scoped = out.components.find((c: any) => c.purl === 'pkg:npm/%40scope/pkg@2.0.0');
    expect(scoped).toMatchObject({ type: 'library', name: '@scope/pkg', version: '2.0.0' });
    const bare = out.components.find((c: any) => c.purl === 'pkg:npm/left-pad');
    expect(bare.version).toBeUndefined();
  });

  it('takes the version of a purl before its qualifiers and subpath (D8-2)', () => {
    const doc = buildCycloneDxVex(
      DOC,
      [
        entry({
          vulnerabilityId: 'CVE-2026-0070',
          packageName: 'x',
          purls: ['pkg:npm/x@1.0.0?repository_url=https://u@h', 'pkg:npm/x@2.0.0#lib/a@b'],
        }),
      ],
      SBOM_SERIAL,
    ) as any;
    expect(validateAgainst('cyclonedx', doc)).toEqual([]);
    expect(doc.components.map((c: any) => c.version)).toEqual(['1.0.0', '2.0.0']);
  });

  it('points every affects ref at a listed component, as a BOM-Link into the SBOM', () => {
    const refs = new Set(out.components.map((c: any) => c['bom-ref']));
    for (const c of out.components) expect(c['bom-ref']).toBe(`urn:cdx:${SBOM_SERIAL}/1#${c.purl}`);
    for (const v of out.vulnerabilities) {
      expect(v.affects.length).toBeGreaterThan(0);
      for (const a of v.affects) expect(refs.has(a.ref)).toBe(true);
    }
    expect(byId(out.vulnerabilities, 'CVE-2026-0010').affects).toEqual([
      { ref: `urn:cdx:${SBOM_SERIAL}/1#pkg:npm/lodash@4.17.20` },
      { ref: `urn:cdx:${SBOM_SERIAL}/1#pkg:npm/lodash@4.17.21` },
    ]);
  });

  it('merges entries of one id with the same analysis', () => {
    const notAffected = (packageName: string, purl: string, decidedBy: string) =>
      entry({
        vulnerabilityId: 'CVE-2026-0060',
        packageName,
        purls: [purl],
        status: 'false_positive',
        reason: 'vulnerable_code_not_present',
        decidedAt: DECIDED,
        decidedBy,
      });
    const merged = buildCycloneDxVex(
      DOC,
      [
        notAffected('left-pad', 'pkg:npm/left-pad@1.3.0', 'Alice'),
        notAffected('lodash', 'pkg:npm/lodash@4.17.21', 'Bob'),
      ],
      SBOM_SERIAL,
    ) as any;
    expect(validateAgainst('cyclonedx', merged)).toEqual([]);
    expect(merged.vulnerabilities).toHaveLength(1);
    const [v] = merged.vulnerabilities;
    expect(v.affects).toEqual([
      { ref: link('pkg:npm/left-pad@1.3.0') },
      { ref: link('pkg:npm/lodash@4.17.21') },
    ]);
    expect(v.analysis).toMatchObject({ state: 'not_affected', justification: 'code_not_present' });
    expect(v.properties).toEqual([
      { name: 'qualor:decided-by', value: 'Alice' },
      { name: 'qualor:decided-by', value: 'Bob' },
    ]);

    const split = buildCycloneDxVex(
      DOC,
      [
        notAffected('left-pad', 'pkg:npm/left-pad@1.3.0', 'Alice'),
        entry({
          vulnerabilityId: 'CVE-2026-0060',
          packageName: 'lodash',
          purls: ['pkg:npm/lodash@4.17.21'],
          status: 'wont_fix',
        }),
        notAffected('zod', 'pkg:npm/zod@4.0.0', 'Bob'),
      ],
      SBOM_SERIAL,
    ) as any;
    expect(validateAgainst('cyclonedx', split)).toEqual([]);
    expect(
      split.vulnerabilities.map((x: any) => [x.analysis.state, x.affects.map((a: any) => a.ref)]),
    ).toEqual([
      ['exploitable', [link('pkg:npm/lodash@4.17.21')]],
      ['not_affected', [link('pkg:npm/left-pad@1.3.0'), link('pkg:npm/zod@4.0.0')]],
    ]);
  });

  it('puts the entries Trivy applies last for each id', () => {
    const doc = buildCycloneDxVex(
      DOC,
      [
        entry({ vulnerabilityId: 'CVE-2020-0001', packageName: 'left-pad' }),
        entry({
          vulnerabilityId: 'CVE-2020-8203',
          packageName: 'lodash',
          purls: ['pkg:npm/lodash@4.17.15'],
          status: 'false_positive',
          reason: 'vulnerable_code_not_present',
          decidedAt: DECIDED,
          decidedBy: 'Alice',
        }),
        entry({
          vulnerabilityId: 'CVE-2020-8203',
          packageName: 'lodash-es',
          purls: ['pkg:npm/lodash-es@4.17.15'],
        }),
        entry({
          vulnerabilityId: 'CVE-2020-8203',
          packageName: 'lodash.merge',
          purls: ['pkg:npm/lodash.merge@4.6.1'],
          status: 'wont_fix',
        }),
        entry({
          vulnerabilityId: 'CVE-2020-9999',
          packageName: 'zod',
          purls: ['pkg:npm/zod@4.0.0'],
        }),
      ],
      SBOM_SERIAL,
    ) as any;
    expect(validateAgainst('cyclonedx', doc)).toEqual([]);
    // Trivy keeps the last statement of an id: the not_affected one must not be overridden.
    expect(doc.vulnerabilities.map((v: any) => [v.id, v.analysis.state])).toEqual([
      ['CVE-2020-0001', 'in_triage'],
      ['CVE-2020-8203', 'in_triage'],
      ['CVE-2020-8203', 'exploitable'],
      ['CVE-2020-8203', 'not_affected'],
      ['CVE-2020-9999', 'in_triage'],
    ]);
    const last = doc.vulnerabilities.findLast((v: any) => v.id === 'CVE-2020-8203');
    expect(last.affects).toEqual([{ ref: link('pkg:npm/lodash@4.17.15') }]);
  });

  it('keeps the facts of every merged entry', () => {
    const open = (packageName: string, overrides: Partial<VexEntry>) =>
      entry({
        vulnerabilityId: 'CVE-2026-0061',
        packageName,
        purls: [`pkg:npm/${packageName}@1.0.0`],
        ...overrides,
      });
    const later = new Date('2026-11-05T10:00:00.000Z');
    const doc = buildCycloneDxVex(
      DOC,
      [
        open('a', { severity: 'medium', primaryUrl: 'https://x.test/1', fixedVersion: '1.0.1' }),
        open('b', {
          severity: 'critical',
          primaryUrl: 'https://x.test/1',
          fixedVersion: '2.0.0',
          decidedAt: later,
          decidedBy: 'Carol',
        }),
        open('c', { severity: 'low', primaryUrl: 'https://x.test/2', decidedAt: DECIDED }),
      ],
      SBOM_SERIAL,
    ) as any;
    expect(validateAgainst('cyclonedx', doc)).toEqual([]);
    expect(doc.vulnerabilities).toHaveLength(1);
    const [v] = doc.vulnerabilities;
    expect(v['bom-ref']).toBe('CVE-2026-0061:a');
    expect(v.ratings).toEqual([{ severity: 'critical', source: { name: 'Trivy' } }]);
    expect(v.advisories).toEqual([{ url: 'https://x.test/1' }, { url: 'https://x.test/2' }]);
    expect(v.recommendation).toBe('Upgrade a to 1.0.1. Upgrade b to 2.0.0.');
    expect(v.analysis).toEqual({
      state: 'in_triage',
      firstIssued: DECIDED.toISOString(),
      lastUpdated: later.toISOString(),
    });
    expect(v.properties).toEqual([{ name: 'qualor:decided-by', value: 'Carol' }]);
  });

  it('adds one CycloneDX entry per alias, with the alias source and the same analysis and affects', () => {
    const net = entry({
      vulnerabilityId: 'CVE-2021-33194',
      packageName: 'golang.org/x/net',
      purls: ['pkg:golang/golang.org/x/net@v0.0.0-20210405180319-a5a99cb37ef4'],
      aliases: ['GHSA-83g2-8m93-v3w7', 'GO-2021-0238'],
    });
    const doc = buildCycloneDxVex(DOC, [LODASH, net], SBOM_SERIAL) as any;
    expect(validateAgainst('cyclonedx', doc)).toEqual([]);
    expect(doc.vulnerabilities.map((v: any) => v.id)).toEqual([
      'CVE-2020-8203',
      'GHSA-p6mc-m468-83gw',
      'CVE-2021-33194',
      'GHSA-83g2-8m93-v3w7',
      'GO-2021-0238',
    ]);
    const [cve, ghsa, netCve, netGhsa, go] = doc.vulnerabilities;
    expect(ghsa.source).toEqual({
      name: 'GITHUB',
      url: 'https://github.com/advisories/GHSA-p6mc-m468-83gw',
    });
    expect(ghsa.analysis).toEqual(cve.analysis);
    expect(ghsa.analysis).toMatchObject({
      state: 'not_affected',
      justification: 'code_not_present',
    });
    expect(ghsa.affects).toEqual([{ ref: link('pkg:npm/lodash@4.17.15') }]);
    expect(ghsa.properties).toEqual(cve.properties);
    // The alias points back at the entry it stands for.
    expect(ghsa.references).toEqual([
      {
        id: 'CVE-2020-8203',
        source: { name: 'NVD', url: 'https://nvd.nist.gov/vuln/detail/CVE-2020-8203' },
      },
    ]);
    expect(go.source).toEqual({ name: 'OSV', url: 'https://osv.dev/vulnerability/GO-2021-0238' });
    expect([netGhsa.affects, go.affects]).toEqual([netCve.affects, netCve.affects]);
    expect([netGhsa.analysis, go.analysis]).toEqual([
      { state: 'in_triage' },
      { state: 'in_triage' },
    ]);
    const refs = doc.vulnerabilities.map((v: any) => v['bom-ref']);
    expect(new Set(refs).size).toBe(refs.length);
  });

  it('lists the aliases of the main entry in its references', () => {
    const doc = buildCycloneDxVex(
      DOC,
      [
        entry({
          vulnerabilityId: 'CVE-2021-33194',
          aliases: ['GHSA-83g2-8m93-v3w7', 'GO-2021-0238'],
        }),
        entry({ vulnerabilityId: 'CVE-2026-0001' }),
      ],
      SBOM_SERIAL,
    ) as any;
    expect(byId(doc.vulnerabilities, 'CVE-2021-33194').references).toEqual([
      {
        id: 'GHSA-83g2-8m93-v3w7',
        source: { name: 'GITHUB', url: 'https://github.com/advisories/GHSA-83g2-8m93-v3w7' },
      },
      {
        id: 'GO-2021-0238',
        source: { name: 'OSV', url: 'https://osv.dev/vulnerability/GO-2021-0238' },
      },
    ]);
    expect(byId(doc.vulnerabilities, 'CVE-2026-0001').references).toBeUndefined();
  });

  it('merges alias entries like any other: one alias on two packages with one analysis', () => {
    const doc = buildCycloneDxVex(
      DOC,
      [LODASH, { ...LODASH, packageName: 'lodash-es', purls: ['pkg:npm/lodash-es@4.17.15'] }],
      SBOM_SERIAL,
    ) as any;
    expect(validateAgainst('cyclonedx', doc)).toEqual([]);
    expect(doc.vulnerabilities.map((v: any) => [v.id, v.affects.map((a: any) => a.ref)])).toEqual([
      ['CVE-2020-8203', [link('pkg:npm/lodash@4.17.15'), link('pkg:npm/lodash-es@4.17.15')]],
      ['GHSA-p6mc-m468-83gw', [link('pkg:npm/lodash@4.17.15'), link('pkg:npm/lodash-es@4.17.15')]],
    ]);
  });

  it('gives an alias that two entries of one package share one entry, which no decision of one CVE suppresses', () => {
    const shared = (vulnerabilityId: string, overrides: Partial<VexEntry>) =>
      entry({
        vulnerabilityId,
        packageName: 'lodash',
        aliases: ['GHSA-aaaa-bbbb-cccc'],
        ...overrides,
      });
    const doc = buildCycloneDxVex(
      DOC,
      [
        shared('CVE-2026-0101', {
          purls: ['pkg:npm/lodash@4.17.15', 'pkg:npm/lodash@4.17.20'],
          status: 'false_positive',
          reason: 'vulnerable_code_not_present',
          decidedAt: DECIDED,
          decidedBy: 'Alice',
        }),
        shared('CVE-2026-0102', { purls: ['pkg:npm/lodash@4.17.15'], comment: 'Looking.' }),
      ],
      SBOM_SERIAL,
    ) as any;
    expect(validateAgainst('cyclonedx', doc)).toEqual([]);
    const refs = doc.vulnerabilities.map((v: any) => v['bom-ref']);
    expect(new Set(refs).size).toBe(refs.length);
    const aliases = doc.vulnerabilities.filter((v: any) => v.id === 'GHSA-aaaa-bbbb-cccc');
    expect(aliases).toHaveLength(1);
    // Only the open CVE speaks for the alias: its decision and its purls.
    expect(aliases[0].analysis).toEqual({ state: 'in_triage', detail: 'Looking.' });
    expect(aliases[0].affects).toEqual([{ ref: link('pkg:npm/lodash@4.17.15') }]);
    expect(aliases[0].references.map((r: any) => r.id)).toEqual(['CVE-2026-0102']);
    // The not-affected CVE names the alias nowhere, its references included.
    expect(byId(doc.vulnerabilities, 'CVE-2026-0101').references).toBeUndefined();
    expect(byId(doc.vulnerabilities, 'CVE-2026-0102').references.map((r: any) => r.id)).toEqual([
      'GHSA-aaaa-bbbb-cccc',
    ]);

    // Two not-affected decisions: the alias keeps the first one.
    const both = buildCycloneDxVex(
      DOC,
      [
        shared('CVE-2026-0101', { status: 'false_positive', comment: 'Not shipped.' }),
        shared('CVE-2026-0102', { status: 'false_positive', comment: 'Not reachable.' }),
      ],
      SBOM_SERIAL,
    ) as any;
    expect(validateAgainst('cyclonedx', both)).toEqual([]);
    expect(
      both.vulnerabilities.map((v: any) => [v['bom-ref'], v.analysis.state, v.analysis.detail]),
    ).toEqual([
      ['CVE-2026-0101:lodash', 'not_affected', 'Not shipped.'],
      ['GHSA-aaaa-bbbb-cccc:lodash', 'not_affected', 'Not shipped.'],
      ['CVE-2026-0102:lodash', 'not_affected', 'Not reachable.'],
    ]);
  });

  it('keeps the entry an id has of its own on a package over an alias of that id', () => {
    const doc = buildCycloneDxVex(
      DOC,
      [
        LODASH,
        entry({
          vulnerabilityId: 'GHSA-p6mc-m468-83gw',
          packageName: 'lodash',
          purls: ['pkg:npm/lodash@4.17.15'],
          status: 'wont_fix',
        }),
      ],
      SBOM_SERIAL,
    ) as any;
    expect(validateAgainst('cyclonedx', doc)).toEqual([]);
    expect(doc.vulnerabilities.map((v: any) => [v['bom-ref'], v.analysis.state])).toEqual([
      ['CVE-2020-8203:lodash', 'not_affected'],
      ['GHSA-p6mc-m468-83gw:lodash', 'exploitable'],
    ]);
  });

  it('maps an open entry to in_triage with its advisory and recommendation', () => {
    const v = byId(out.vulnerabilities, 'CVE-2026-0001');
    expect(v['bom-ref']).toBe('CVE-2026-0001:left-pad');
    expect(v.source).toEqual({
      name: 'NVD',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0001',
    });
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

  it('names the vulnerability, the product with its purls, and each purl as a product', () => {
    const s = byId(out.statements, 'CVE-2026-0010');
    expect(s.vulnerability).toEqual({ name: 'CVE-2026-0010' });
    expect(s.products).toEqual([
      {
        '@id': productId(DOC.project, DOC.target),
        subcomponents: [{ '@id': 'pkg:npm/lodash@4.17.20' }, { '@id': 'pkg:npm/lodash@4.17.21' }],
      },
      { '@id': 'pkg:npm/lodash@4.17.20' },
      { '@id': 'pkg:npm/lodash@4.17.21' },
    ]);
  });

  it('lists the aliases in OpenVEX', () => {
    const doc = buildOpenVex(DOC, [LODASH, entry({ vulnerabilityId: 'CVE-2026-0001' })]) as any;
    expect(validateAgainst('openvex', doc)).toEqual([]);
    expect(doc.statements).toHaveLength(2);
    expect(doc.statements[0].vulnerability).toEqual({
      name: 'CVE-2020-8203',
      aliases: ['GHSA-p6mc-m468-83gw'],
    });
    expect(doc.statements[1].vulnerability).toEqual({ name: 'CVE-2026-0001' });
  });

  it('leaves out an OpenVEX alias that has its own statement on the package', () => {
    const doc = buildOpenVex(DOC, [
      LODASH,
      entry({
        vulnerabilityId: 'GHSA-p6mc-m468-83gw',
        packageName: 'lodash',
        purls: ['pkg:npm/lodash@4.17.15'],
      }),
      // On another package the alias stays.
      { ...LODASH, packageName: 'lodash-es', purls: ['pkg:npm/lodash-es@4.17.15'] },
    ]) as any;
    expect(validateAgainst('openvex', doc)).toEqual([]);
    expect(doc.statements.map((st: any) => [st.vulnerability, st.status])).toEqual([
      [{ name: 'CVE-2020-8203' }, 'not_affected'],
      [{ name: 'GHSA-p6mc-m468-83gw' }, 'under_investigation'],
      [{ name: 'CVE-2020-8203', aliases: ['GHSA-p6mc-m468-83gw'] }, 'not_affected'],
    ]);
  });

  it('leaves out an OpenVEX alias shared with a statement that does not suppress', () => {
    const shared = (vulnerabilityId: string, status: VexEntry['status']) =>
      entry({ vulnerabilityId, packageName: 'lodash', status, aliases: ['GHSA-yyyy-yyyy-yyyy'] });
    const mixed = buildOpenVex(DOC, [
      shared('CVE-2026-0201', 'false_positive'),
      shared('CVE-2026-0202', 'open'),
      shared('CVE-2026-0203', 'false_positive'),
    ]) as any;
    expect(validateAgainst('openvex', mixed)).toEqual([]);
    expect(mixed.statements.map((st: any) => [st.vulnerability, st.status])).toEqual([
      [{ name: 'CVE-2026-0201' }, 'not_affected'],
      [{ name: 'CVE-2026-0202', aliases: ['GHSA-yyyy-yyyy-yyyy'] }, 'under_investigation'],
      [{ name: 'CVE-2026-0203' }, 'not_affected'],
    ]);
    // When every CVE that shares it is not affected, each keeps it.
    const agreed = buildOpenVex(DOC, [
      shared('CVE-2026-0201', 'false_positive'),
      shared('CVE-2026-0203', 'false_positive'),
    ]) as any;
    expect(validateAgainst('openvex', agreed)).toEqual([]);
    expect(agreed.statements.map((st: any) => st.vulnerability.aliases)).toEqual([
      ['GHSA-yyyy-yyyy-yyyy'],
      ['GHSA-yyyy-yyyy-yyyy'],
    ]);
  });

  it('carries the decision of an open entry: timestamp, comment and author in the notes (D8-3)', () => {
    const doc = buildOpenVex(DOC, [
      entry({
        vulnerabilityId: 'CVE-2026-0040',
        comment: 'Reopened after the fix regressed.',
        decidedAt: DECIDED,
        decidedBy: 'Carol',
      }),
      entry({ vulnerabilityId: 'CVE-2026-0041', decidedAt: DECIDED, decidedBy: 'Carol' }),
    ]) as any;
    const [s, uncommented] = doc.statements;
    expect(s.status).toBe('under_investigation');
    expect(s.timestamp).toBe(DECIDED.toISOString());
    expect(s.status_notes).toBe('Reopened after the fix regressed. Decided by Carol.');
    expect(s.impact_statement).toBeUndefined();
    expect(uncommented.status_notes).toBe('Decided by Carol.');
  });

  it('validates an entry with no purls', () => {
    const doc = buildOpenVex(DOC, [entry({ vulnerabilityId: 'CVE-2026-0050', purls: [] })]);
    expect(validateAgainst('openvex', doc)).toEqual([]);
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
