import {
  inventoryName,
  inventoryVersion,
  isOsPackageType,
  parsePurl,
  parseSbom,
  type OsPackageType,
} from '@qualor/shared';
import { sample, sampleJson } from '@qualor/shared/test/sbom';
import { describe, expect, it } from 'vitest';
import { osMatchKey } from './purl';
import { buildOsSbom, buildSbom, sbomGroupKey, splitOsVersion, type SbomPackage } from './sbom';

describe('buildSbom', () => {
  it('writes CycloneDX 1.6 with one component per distinct purl', () => {
    const json = buildSbom([
      { purl: 'pkg:npm/lodash@4.17.20', name: 'lodash', version: '4.17.20' },
      { purl: 'pkg:npm/lodash@4.17.20', name: 'lodash', version: '4.17.20' },
      { purl: 'pkg:npm/%40babel/traverse@7.0.0', name: '@babel/traverse', version: '7.0.0' },
      {
        purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
        name: 'org.apache.logging.log4j:log4j-core',
        version: '2.14.1',
      },
    ]);
    const bom = JSON.parse(json);
    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.6');
    expect(bom.version).toBe(1);
    expect(bom.components).toEqual([
      {
        type: 'library',
        'bom-ref': 'pkg:npm/lodash@4.17.20',
        name: 'lodash',
        version: '4.17.20',
        purl: 'pkg:npm/lodash@4.17.20',
      },
      {
        type: 'library',
        'bom-ref': 'pkg:npm/%40babel/traverse@7.0.0',
        name: '@babel/traverse',
        version: '7.0.0',
        purl: 'pkg:npm/%40babel/traverse@7.0.0',
      },
      {
        type: 'library',
        'bom-ref': 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
        name: 'org.apache.logging.log4j:log4j-core',
        version: '2.14.1',
        purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
      },
    ]);
  });

  it('is valid for an empty list', () => {
    expect(JSON.parse(buildSbom([])).components).toEqual([]);
  });
});

/** The `aquasecurity:trivy:<name>` properties of a CycloneDX component, by short name. */
function trivyProperties(component: { properties?: { name: string; value: string }[] }) {
  const props = new Map<string, string>();
  for (const p of component.properties ?? []) {
    if (p.name.startsWith('aquasecurity:trivy:')) props.set(p.name.slice(19), p.value);
  }
  return props;
}

describe('splitOsVersion', () => {
  it.each(['trivy-debian.cdx.json', 'trivy-alpine.cdx.json', 'trivy-ubi8.cdx.json'])(
    'agrees with Trivy on every OS package of %s',
    (file) => {
      const result = parseSbom(sample(file));
      if (!('inventory' in result)) throw new Error('refused');
      const stored = new Map(
        result.inventory.entries
          .filter((e) => isOsPackageType(e.ecosystem))
          .map((e) => [`${e.name}@${e.version}`, e]),
      );
      const components = sampleJson(file).components as {
        type: string;
        name: string;
        purl?: string;
        properties?: { name: string; value: string }[];
      }[];
      let checked = 0;
      for (const c of components) {
        if (c.type !== 'library') continue;
        const props = trivyProperties(c);
        const purl = parsePurl(c.purl ?? '');
        const pkgId = purl === null ? '' : `${inventoryName(purl)}@${inventoryVersion(purl)}`;
        const entry = stored.get(pkgId);
        expect(entry, pkgId).toBeDefined();
        const type = entry!.ecosystem as OsPackageType;
        expect(splitOsVersion(type, entry!.source!.version), pkgId).toEqual({
          epoch: props.get('SrcEpoch') ?? '',
          version: props.get('SrcVersion') ?? '',
          release: props.get('SrcRelease') ?? '',
        });
        checked++;
      }
      expect(checked).toBeGreaterThan(10);
    },
  );

  it.each([
    ['deb', '1:4.13+dfsg1-1+deb12u2', { epoch: '1', version: '4.13+dfsg1', release: '1+deb12u2' }],
    ['deb', '20230311', { epoch: '', version: '20230311', release: '' }],
    ['deb', '1.2-3-4', { epoch: '', version: '1.2-3', release: '4' }],
    ['rpm', '1:1.1.1k-12.el8_9', { epoch: '1', version: '1.1.1k', release: '12.el8_9' }],
    ['rpm', '239-82.el8_10.19', { epoch: '', version: '239', release: '82.el8_10.19' }],
    ['rpm', 'abc:1.0-1', { epoch: 'abc', version: '1.0', release: '1' }],
    ['apk', '3.3.2-r0', { epoch: '', version: '3.3.2-r0', release: '' }],
    ['apk', '1:2-r0', { epoch: '', version: '1:2-r0', release: '' }],
  ] as const)('%s %s', (type, version, expected) => {
    expect(splitOsVersion(type, version)).toEqual(expected);
  });

  it('stays linear on a long hostile version', () => {
    const long = `${'1'.repeat(100_000)}:${'-'.repeat(100_000)}${':'.repeat(100_000)}`;
    const started = performance.now();
    expect(splitOsVersion('deb', long).epoch).toHaveLength(100_000);
    expect(performance.now() - started).toBeLessThan(500);
  });
});

/** An OS package of Debian 12.15 as the re-check hands it over. */
const debPackage = (name: string, version: string, sourceName: string, sourceVersion: string) => {
  const purl = osMatchKey('deb', 'debian', '12.15', name, version, {
    name: sourceName,
    version: sourceVersion,
  });
  return {
    purl,
    name,
    version,
    os: { type: 'deb', family: 'debian', osVersion: '12.15', sourceName, sourceVersion },
  } satisfies SbomPackage;
};

describe('sbomGroupKey', () => {
  it('is empty for a library and one value per OS type, family and version', () => {
    const lib = { purl: 'pkg:npm/a@1', name: 'a', version: '1' };
    const a = debPackage('libssl3', '3.0.22-1~deb12u2', 'openssl', '3.0.22-1~deb12u2');
    const b = debPackage('login', '1:4.13+dfsg1-1', 'shadow', '1:4.13+dfsg1-1');
    expect(sbomGroupKey(lib)).toBe('');
    expect(sbomGroupKey(a)).not.toBe('');
    expect(sbomGroupKey(a)).toBe(sbomGroupKey(b));
    expect(sbomGroupKey({ ...a, os: { ...a.os, osVersion: '12.16' } })).not.toBe(sbomGroupKey(a));
    expect(sbomGroupKey({ ...a, os: { ...a.os, family: 'ubuntu' } })).not.toBe(sbomGroupKey(a));
    // Trivy takes OS packages of one purl type per SBOM.
    expect(sbomGroupKey({ ...a, os: { ...a.os, type: 'rpm' } })).not.toBe(sbomGroupKey(a));
  });
});

describe('buildOsSbom', () => {
  const libssl3 = debPackage('libssl3', '3.0.22-1~deb12u2', 'openssl', '3.0.22-1~deb12u2');
  const login = debPackage('login', '1:4.13+dfsg1-1+deb12u2', 'shadow', '1:4.13+dfsg1-1+deb12u2');

  it('writes one operating-system component and each package with its key and source', () => {
    const bom = JSON.parse(buildOsSbom([libssl3, login, libssl3])) as {
      bomFormat: string;
      specVersion: string;
      components: {
        type: string;
        name: string;
        version: string;
        purl?: string;
        'bom-ref'?: string;
        properties?: { name: string; value: string }[];
      }[];
    };
    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.6');
    const systems = bom.components.filter((c) => c.type === 'operating-system');
    expect(systems).toHaveLength(1);
    expect(systems[0]).toMatchObject({ name: 'debian', version: '12.15' });
    const packages = bom.components.filter((c) => c.type !== 'operating-system');
    expect(packages.map((c) => c.purl)).toEqual([libssl3.purl, login.purl]);
    for (const c of packages) {
      expect(c['bom-ref']).toBe(c.purl);
      expect([...trivyProperties(c).keys()].sort()).toEqual(
        ['PkgType', 'SrcEpoch', 'SrcName', 'SrcRelease', 'SrcVersion'].sort(),
      );
    }
    expect(Object.fromEntries(trivyProperties(packages[0]!))).toEqual({
      PkgType: 'debian',
      SrcName: 'openssl',
      SrcVersion: '3.0.22',
      SrcRelease: '1~deb12u2',
      // Trivy reads SrcEpoch as a number: 0 when there is none, never an empty value.
      SrcEpoch: '0',
    });
    expect(Object.fromEntries(trivyProperties(packages[1]!))).toEqual({
      PkgType: 'debian',
      SrcName: 'shadow',
      SrcVersion: '4.13+dfsg1',
      SrcRelease: '1+deb12u2',
      SrcEpoch: '1',
    });
    expect(packages[1]).toMatchObject({ name: 'login', version: '1:4.13+dfsg1-1+deb12u2' });
  });

  it('keeps stored strings as data, whatever they hold', () => {
    const odd = debPackage('a"b', '1"},{"x', 'src"\\', '2 "]');
    const bom = JSON.parse(buildOsSbom([odd])) as { components: { name: string }[] };
    expect(bom.components).toHaveLength(2);
    expect(bom.components[1]!.name).toBe('a"b');
  });
});
