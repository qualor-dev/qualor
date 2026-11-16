import { parsePurl, parseSbom, type SbomEntry, type SbomInventory } from '@qualor/shared';
import { bom, lib, os, sample } from '@qualor/shared/test/sbom';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../../test/db';
import { organizations, projects } from '../../db/schema';
import { toVersionEntries } from '../../sbom/upload';
import { upsertVersion } from '../../versions/store';
import { exportDistribution, exportPackages } from './query';
import { buildCycloneDxSbom, buildSpdxSbom } from './sbom-documents';
import type { ExportDocument } from './types';

const mit = [{ license: { id: 'MIT' } }];

/**
 * Spec §6.11 and ruling R9: the SBOMs whose upload is exported and uploaded again.
 *
 * `licences: false` for the real files: their free-text licences (`permissive`, `public-domain`, an
 * unknown exception) and licences made of several SPDX expressions are rewritten by the 0.15 licence
 * writer (`LicenseRef-…`, AND-joined), which this task does not change. The hand-made files use
 * SPDX ids, which come back as they went.
 */
const CASES: { name: string; text: string; licences?: boolean }[] = [
  {
    name: 'Debian 12.15',
    text: bom([
      os('debian', '12.15'),
      lib('pkg:npm/%40angular/core@16.2.0', { licenses: mit }),
      lib('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1', {
        licenses: [{ license: { id: 'Apache-2.0' } }],
      }),
      lib('pkg:deb/debian/libssl3@3.0.22-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl'),
      lib(
        'pkg:deb/debian/login@1%3A4.13%2Bdfsg1-1?arch=amd64&distro=debian-12&upstream=shadow@1%3A4.13%2Bdfsg1-1',
      ),
      // The epoch as a qualifier, as Trivy writes it.
      lib('pkg:deb/debian/attr@2.4.47-2%2Bb1?arch=amd64&epoch=1&distro=debian-12'),
    ]),
  },
  {
    name: 'Red Hat 8.10',
    text: bom([
      os('redhat', '8.10'),
      lib('pkg:rpm/redhat/openssl-libs@1.1.1k-12.el8_9?arch=x86_64&epoch=1&distro=redhat-8.10'),
      lib(
        'pkg:rpm/redhat/nodejs@18.19.1-1.module%2Del8.10.0?arch=x86_64&distro=redhat-8.10&modularitylabel=nodejs%3A18%3A8090020240112121244%3Aa75119d5',
      ),
    ]),
  },
  {
    name: 'Alpine 3.20.3',
    text: bom([
      os('alpine', '3.20.3'),
      lib('pkg:apk/alpine/libcrypto3@3.3.2-r0?arch=x86_64&distro=3.20.3&upstream=openssl'),
    ]),
  },
  { name: 'trivy-debian', text: sample('trivy-debian.cdx.json'), licences: false },
  { name: 'trivy-alpine', text: sample('trivy-alpine.cdx.json'), licences: false },
  { name: 'trivy-ubi8', text: sample('trivy-ubi8.cdx.json'), licences: false },
  { name: 'trivy-ubi8-outdated', text: sample('trivy-ubi8-outdated.cdx.json'), licences: false },
  { name: 'syft-debian', text: sample('syft-debian.cdx.json'), licences: false },
  { name: 'syft-ubi8', text: sample('syft-ubi8.cdx.json'), licences: false },
  { name: 'trivy-debian (SPDX)', text: sample('trivy-debian.spdx.json'), licences: false },
  { name: 'syft-debian (SPDX)', text: sample('syft-debian.spdx.json'), licences: false },
  { name: 'cdxgen-node', text: sample('cdxgen-node.cdx-1.7.json'), licences: false },
];

function inventoryOf(text: string): SbomInventory {
  const result = parseSbom(text);
  if (!('inventory' in result)) throw new Error(`refused: ${JSON.stringify(result.refusal)}`);
  return result.inventory;
}

/**
 * The licences as a set of terms. The export writes a package's licence list as one AND-joined
 * expression (0.15), so a list and its expression are the same licences: both are cut at the
 * top-level `AND`s.
 */
function terms(licenses: readonly string[]): string[] {
  const out = new Set<string>();
  for (const licence of licenses) {
    let depth = 0;
    let start = 0;
    for (let i = 0; i < licence.length; i++) {
      if (licence[i] === '(') depth++;
      else if (licence[i] === ')') depth--;
      else if (depth === 0 && licence.startsWith(' AND ', i)) {
        out.add(licence.slice(start, i).trim());
        start = i + 5;
      }
    }
    out.add(licence.slice(start).trim());
  }
  return [...out].sort();
}

/**
 * The fields that survive an export: the arch and the modularity label are in an rpm's key only
 * (deb and apk keys never carry them), and `path` and `direct` are not exported (R9).
 */
function survivors(entries: readonly SbomEntry[], licences: boolean): string[] {
  return entries
    .map((e) => {
      const rpm = e.ecosystem === 'rpm';
      return JSON.stringify([
        e.ecosystem,
        e.name,
        e.version,
        licences ? terms(e.licenses) : null,
        e.source,
        rpm ? e.arch : null,
        rpm ? e.modularityLabel : null,
      ]);
    })
    .sort();
}

describe('the export of an SBOM version, re-imported (R9)', () => {
  let t: TestDatabase;
  let projectId: string;
  let n = 0;
  beforeAll(async () => {
    t = await createTestDatabase();
    const [org] = await t.db
      .insert(organizations)
      .values({ key: 'acme', name: 'Acme' })
      .returning();
    const [project] = await t.db
      .insert(projects)
      .values({ organizationId: org!.id, key: 'acme/rt', name: 'Round trip' })
      .returning();
    projectId = project!.id;
  });
  afterAll(async () => {
    await t.close();
  });

  /** Uploads a text as a version, and exports the version's packages and distribution. */
  async function exported(text: string) {
    const inv = inventoryOf(text);
    const result = await upsertVersion(t.db, {
      projectId,
      label: `v${++n}`,
      source: 'sbom',
      tag: null,
      analysisId: null,
      analyzedAt: new Date('2026-11-16T10:00:00Z'),
      inventory: { dependencies: toVersionEntries(inv.entries), ignores: null },
      sbom: { format: inv.format, subject: inv.subject, distribution: inv.distribution },
    });
    if (typeof result === 'string') throw new Error(result);
    const target = { kind: 'version', versionId: result.version.id } as const;
    const distribution = await exportDistribution(t.db, target);
    const packages = await exportPackages(t.db, target, distribution);
    const doc: ExportDocument = {
      project: { key: 'acme/rt', name: 'Round trip' },
      organization: 'Acme',
      target: { kind: 'version', name: result.version.label },
      generatedAt: new Date('2026-11-16T11:00:00Z'),
      serial: '3e671687-395b-41f5-a30f-a58921a69b79',
      toolVersion: '0.16.0',
      distribution,
    };
    return { inv, distribution, packages, doc };
  }

  it.each(CASES)(
    'gives the same inventory in CycloneDX and SPDX: $name',
    async ({ text, licences = true }) => {
      const { inv, distribution, packages, doc } = await exported(text);
      expect(distribution).toEqual(inv.distribution);
      // An OS package without a distribution has no key, so the export names it without a purl.
      const keyed = inv.entries.filter(
        (e) => !['deb', 'rpm', 'apk'].includes(e.ecosystem) || inv.distribution !== null,
      );
      for (const body of [buildCycloneDxSbom(doc, packages), buildSpdxSbom(doc, packages)]) {
        const back = inventoryOf(JSON.stringify(body));
        expect(back.distribution).toEqual(inv.distribution);
        expect(survivors(back.entries, licences)).toEqual(survivors(keyed, licences));
      }
    },
  );

  it.each(CASES)(
    'reads the same source from the purl alone as from the Trivy properties: $name',
    async ({ text }) => {
      const { packages, doc } = await exported(text);
      const strip = (key: string) => (_: string, v: unknown) => (_ === key ? undefined : v);
      const withProperties = inventoryOf(JSON.stringify(buildCycloneDxSbom(doc, packages)));
      const purlOnly = inventoryOf(
        JSON.stringify(buildCycloneDxSbom(doc, packages), strip('properties')),
      );
      expect(survivors(purlOnly.entries, false)).toEqual(survivors(withProperties.entries, false));
      const spdxPurlOnly = inventoryOf(
        JSON.stringify(buildSpdxSbom(doc, packages), strip('sourceInfo')),
      );
      expect(survivors(spdxPurlOnly.entries, false)).toEqual(
        survivors(withProperties.entries, false),
      );
    },
  );

  it('keeps the epoch, the source and the licences of the named packages', async () => {
    const { packages, doc } = await exported(CASES[0]!.text);
    const back = inventoryOf(JSON.stringify(buildCycloneDxSbom(doc, packages)));
    const named = (name: string) => back.entries.find((e) => e.name === name)!;
    expect(named('libssl3').source).toEqual({ name: 'openssl', version: '3.0.22-1~deb12u2' });
    expect(named('login')).toMatchObject({
      version: '1:4.13+dfsg1-1',
      source: { name: 'shadow', version: '1:4.13+dfsg1-1' },
    });
    expect(named('attr').version).toBe('1:2.4.47-2+b1');
    expect(named('@angular/core').licenses).toEqual(['MIT']);
  });

  it('writes a purl that parses to the same type, namespace, name, version and distro', async () => {
    const original = 'pkg:deb/debian/attr@1%3A2.4.47-2%2Bb1?arch=amd64&distro=debian-12';
    const { packages } = await exported(bom([os('debian', '12'), lib(original)]));
    const purl = packages.find((p) => p.name === 'attr')!.purl!;
    const a = parsePurl(original)!;
    const b = parsePurl(purl)!;
    expect([b.type, b.namespace, b.name, b.version, b.qualifiers.distro]).toEqual([
      a.type,
      a.namespace,
      a.name,
      a.version,
      a.qualifiers.distro,
    ]);
  });

  it('exports an OS package of a version without a distribution without a purl', async () => {
    const { packages, doc } = await exported(
      bom([lib('pkg:deb/debian/attr@2.4.47?arch=amd64'), lib('pkg:npm/zod@4.0.0')]),
    );
    expect(packages.find((p) => p.name === 'attr')).toMatchObject({ purl: null, source: null });
    expect(packages.find((p) => p.name === 'zod')?.purl).toBe('pkg:npm/zod@4.0.0');
    const back = inventoryOf(JSON.stringify(buildCycloneDxSbom(doc, packages)));
    expect(back.entries.map((e) => e.name)).toEqual(['zod']);
    expect(back.skipped.noPurl).toBe(1);
  });
});
