import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { budgetMs } from '../../test/perf';
import { parseSbom } from './parse';
import type { SbomInventory, SbomRefusal } from './types';

const SAMPLES = join(__dirname, '../../test/sbom-samples');
const sample = (file: string): string => readFileSync(join(SAMPLES, file), 'utf8');

function inventory(text: string): SbomInventory {
  const result = parseSbom(text);
  if (!('inventory' in result)) throw new Error(`refused: ${JSON.stringify(result.refusal)}`);
  return result.inventory;
}

function refusal(text: string): SbomRefusal {
  const result = parseSbom(text);
  if (!('refusal' in result)) throw new Error('not refused');
  return result.refusal;
}

function bom(components: unknown[], extra: Record<string, unknown> = {}): string {
  return JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6', components, ...extra });
}

const lib = (purl: string, more: Record<string, unknown> = {}) => ({
  type: 'library',
  name: 'ignored',
  purl,
  ...more,
});
const os = (name: string, version: string) => ({ type: 'operating-system', name, version });

describe('refusals', () => {
  it('refuses text that is not JSON', () => {
    expect(refusal('not json').code).toBe('SBOM_INVALID');
  });

  it('refuses JSON that is neither CycloneDX nor SPDX', () => {
    expect(refusal('{}').code).toBe('SBOM_INVALID');
    expect(refusal('[]').code).toBe('SBOM_INVALID');
    expect(refusal('"CycloneDX"').code).toBe('SBOM_INVALID');
  });

  it('refuses CycloneDX XML and suggests the JSON export', () => {
    const r = refusal(sample('cyclonedx.xml'));
    expect(r.code).toBe('SBOM_FORMAT_UNSUPPORTED');
    expect(r.message).toMatch(/CycloneDX JSON/);
  });

  it('refuses an in-toto attestation', () => {
    const r = refusal(sample('in-toto.json'));
    expect(r.code).toBe('SBOM_FORMAT_UNSUPPORTED');
    expect(r.message).toMatch(/attestation/i);
  });

  it('refuses SPDX tag-value as not JSON, suggesting the JSON export', () => {
    const r = refusal('SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\nSPDXID: SPDXRef-DOCUMENT\n');
    expect(r.code).toBe('SBOM_INVALID');
    expect(r.message).toMatch(/SPDX 2\.3 JSON/);
  });

  it('refuses an SPDX 3 JSON-LD document', () => {
    const r = refusal(
      JSON.stringify({
        '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
        '@graph': [],
      }),
    );
    expect(r.code).toBe('SBOM_FORMAT_UNSUPPORTED');
  });

  it('names the path of a field with the wrong shape', () => {
    const r = refusal(
      JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6', components: 'x' }),
    );
    expect(r).toMatchObject({ code: 'SBOM_INVALID', path: 'components' });
  });

  it('refuses 50 001 distinct packages and accepts 50 000', () => {
    const packages = (n: number) =>
      bom(
        Array.from({ length: n }, (_, i) => ({
          type: 'library',
          name: 'p',
          purl: `pkg:npm/p${i}@1.0.0`,
        })),
      );
    expect(refusal(packages(50_001)).code).toBe('SBOM_TOO_MANY_PACKAGES');
    expect(inventory(packages(50_000)).entries).toHaveLength(50_000);
  });

  it('counts packages after deduplication', () => {
    const twice = bom([lib('pkg:npm/a@1'), lib('pkg:npm/a@1'), lib('pkg:npm/b@1')]);
    expect(parseSbom(twice, { maxPackages: 2 })).toHaveProperty('inventory');
    expect(parseSbom(twice, { maxPackages: 1 })).toMatchObject({
      refusal: { code: 'SBOM_TOO_MANY_PACKAGES' },
    });
  });
});

describe('multiple OS', () => {
  it('refuses two OS components and names them', () => {
    const r = refusal(bom([os('debian', '12'), os('alpine', '3.20.3')]));
    expect(r.code).toBe('SBOM_MULTIPLE_OS');
    expect(r.message).toContain('debian 12');
    expect(r.message).toContain('alpine 3.20.3');
  });

  it('refuses deb plus apk packages', () => {
    const r = refusal(
      bom([lib('pkg:deb/debian/a@1?distro=debian-12'), lib('pkg:apk/alpine/b@1-r0?distro=3.20.3')]),
    );
    expect(r.code).toBe('SBOM_MULTIPLE_OS');
    expect(r.message).toContain('debian 12');
    expect(r.message).toContain('alpine 3.20.3');
  });

  it('refuses deb plus apk packages that name no distribution', () => {
    expect(refusal(bom([lib('pkg:deb/a@1'), lib('pkg:apk/b@1-r0')])).code).toBe('SBOM_MULTIPLE_OS');
  });

  it('refuses distro=debian-11 and distro=debian-12', () => {
    const r = refusal(
      bom([lib('pkg:deb/debian/a@1?distro=debian-11'), lib('pkg:deb/debian/b@1?distro=debian-12')]),
    );
    expect(r.code).toBe('SBOM_MULTIPLE_OS');
  });

  it('refuses an OS component of one family with packages of another', () => {
    const r = refusal(bom([os('debian', '12.15'), lib('pkg:apk/alpine/b@1-r0?distro=3.20.3')]));
    expect(r.code).toBe('SBOM_MULTIPLE_OS');
  });

  it('refuses 50 000 packages of distinct distros in linear time, naming the first two', () => {
    const text = bom(
      Array.from({ length: 50_000 }, (_, n) => lib(`pkg:deb/debian/p${n}@1?distro=debian-${n}`)),
    );
    const started = performance.now();
    const r = refusal(text);
    expect(performance.now() - started).toBeLessThan(budgetMs(500));
    expect(r.code).toBe('SBOM_MULTIPLE_OS');
    expect(r.message).toContain('(debian 0, debian 1)');
  });

  it('ignores a 1 MB distro qualifier, in linear time', () => {
    const distro = encodeURIComponent(`x${'-1'.repeat(500_000)}\n`);
    const text = bom([lib(`pkg:deb/debian/a@1?distro=${distro}`)]);
    const started = performance.now();
    const inv = inventory(text);
    expect(performance.now() - started).toBeLessThan(budgetMs(500));
    // Only the namespace is left: a family without a version.
    expect(inv.distribution).toBeNull();
    expect(inv.warnings.map((w) => w.code)).toEqual(['SBOM_OS_PACKAGES_UNCHECKED']);
  });

  it('reads 20 000 packages with 2 KB distros in linear time', () => {
    const distro = encodeURIComponent(`x${'-1'.repeat(1_000)}\n`);
    const text = bom(
      Array.from({ length: 20_000 }, (_, n) => lib(`pkg:deb/debian/p${n}@1?distro=${distro}`)),
    );
    const started = performance.now();
    expect(inventory(text).osPackages).toBe(20_000);
    expect(performance.now() - started).toBeLessThan(budgetMs(2_000));
  });

  it('splits a distro at the first dash before a digit, else at the last dash', () => {
    const of = (purl: string) => inventory(bom([lib(purl)])).distribution;
    expect(of('pkg:rpm/opensuse/a@1-1?distro=opensuse-leap-15.5')).toEqual({
      family: 'opensuse-leap',
      version: '15.5',
    });
    expect(of('pkg:deb/debian/a@1?distro=debian-bookworm')).toEqual({
      family: 'debian',
      version: 'bookworm',
    });
    expect(of('pkg:apk/alpine/a@1-r0?distro=3.20.3')).toEqual({
      family: 'alpine',
      version: '3.20.3',
    });
  });

  it('refuses 50 000 OS components of distinct versions in linear time', () => {
    const text = bom(Array.from({ length: 50_000 }, (_, n) => os('debian', String(n))));
    const started = performance.now();
    expect(refusal(text).code).toBe('SBOM_MULTIPLE_OS');
    expect(performance.now() - started).toBeLessThan(budgetMs(500));
  });

  it('takes a distro that lacks the minor version as the same distribution', () => {
    const inv = inventory(bom([os('debian', '12.15'), lib('pkg:deb/debian/a@1?distro=debian-12')]));
    expect(inv.distribution).toEqual({ family: 'debian', version: '12.15' });
    expect(inv.warnings).toEqual([]);
  });

  it("keeps the OS component's version over a longer distro", () => {
    const inv = inventory(bom([os('debian', '12'), lib('pkg:deb/debian/a@1?distro=debian-12.15')]));
    expect(inv.distribution).toEqual({ family: 'debian', version: '12' });
  });

  it('keeps the longer of two versions from the same kind of source', () => {
    const fromComponents = inventory(bom([os('debian', '12'), os('debian', '12.15')]));
    expect(fromComponents.distribution).toEqual({ family: 'debian', version: '12.15' });
    const fromPurls = inventory(
      bom([
        lib('pkg:deb/debian/a@1?distro=debian-12'),
        lib('pkg:deb/debian/b@1?distro=debian-12.15'),
      ]),
    );
    expect(fromPurls.distribution).toEqual({ family: 'debian', version: '12.15' });
  });

  it('takes the version from the purls when the OS component has none', () => {
    const inv = inventory(bom([os('debian', ''), lib('pkg:deb/debian/a@1?distro=debian-12')]));
    expect(inv.distribution).toEqual({ family: 'debian', version: '12' });
    const longer = inventory(
      bom([
        os('debian', ''),
        lib('pkg:deb/debian/a@1?distro=debian-12'),
        lib('pkg:deb/debian/b@1?distro=debian-12.15'),
      ]),
    );
    expect(longer.distribution).toEqual({ family: 'debian', version: '12.15' });
  });

  it('takes the distribution from the purls when there is no OS component', () => {
    const inv = inventory(
      bom([lib('pkg:deb/ubuntu/a@1?distro=ubuntu-22.04'), lib('pkg:deb/ubuntu/b@1')]),
    );
    expect(inv.distribution).toEqual({ family: 'ubuntu', version: '22.04' });
    expect(inv.osPackages).toBe(2);
  });
});

describe('no distribution', () => {
  it('stores OS packages without a distribution as unchecked', () => {
    const inv = inventory(
      bom([lib('pkg:deb/debian/a@1'), lib('pkg:deb/debian/b@2'), lib('pkg:npm/c@3')]),
    );
    expect(inv.distribution).toBeNull();
    expect(inv.osPackages).toBe(2);
    expect(inv.entries).toHaveLength(3);
    expect(inv.warnings.map((w) => w.code)).toEqual(['SBOM_OS_PACKAGES_UNCHECKED']);
  });

  it('keeps an unknown family as the distribution, unchecked', () => {
    const inv = inventory(bom([os('plan9', '1'), lib('pkg:deb/a@1')]));
    expect(inv.distribution).toEqual({ family: 'plan9', version: '1' });
    expect(inv.warnings.map((w) => w.code)).toEqual(['SBOM_OS_PACKAGES_UNCHECKED']);
  });

  it('warns about nothing without OS packages', () => {
    const inv = inventory(bom([os('plan9', '1'), lib('pkg:npm/c@3')]));
    expect(inv.distribution).toEqual({ family: 'plan9', version: '1' });
    expect(inv.warnings).toEqual([]);
  });

  it('uses the binary as its own source when the SBOM names none', () => {
    const inv = inventory(bom([os('debian', '12'), lib('pkg:deb/debian/a@1.0-1')]));
    expect(inv.entries[0]!.source).toEqual({ name: 'a', version: '1.0-1' });
  });

  it('reads an rpm upstream with the epoch, and falls back when it does not parse', () => {
    const inv = inventory(
      bom([
        os('redhat', '8.10'),
        lib('pkg:rpm/redhat/b@2.0-1.el8?epoch=2&upstream=b-src-2.0-1.el8.src.rpm'),
        lib('pkg:rpm/redhat/c@1.0-1.el8?upstream=c.src.rpm'),
        lib('pkg:rpm/redhat/d@1.0-1.el8?upstream=d-1.0-1.el8.rpm'),
      ]),
    );
    expect(inv.entries.map((e) => e.source)).toEqual([
      { name: 'b-src', version: '2:2.0-1.el8' },
      { name: 'c', version: '1.0-1.el8' },
      { name: 'd', version: '1.0-1.el8' },
    ]);
  });
});

describe('strings', () => {
  it('stores a name or a path without NUL', () => {
    const inv = inventory(
      bom(
        [
          os('deb\u0000ian', '12'),
          lib('pkg:deb/debian/a@1', {
            properties: [{ name: 'aquasecurity:trivy:FilePath', value: 'a\u0000b' }],
          }),
        ],
        { metadata: { component: { type: 'application', name: 'sh\u0000op' } } },
      ),
    );
    expect(inv.subject).toBe('shop');
    expect(inv.distribution).toEqual({ family: 'debian', version: '12' });
    expect(inv.entries[0]!.path).toBe('ab');
  });

  it('replaces a lone surrogate in a path or a licence with U+FFFD', () => {
    const inv = inventory(
      bom([
        lib('pkg:npm/a@1', {
          properties: [{ name: 'aquasecurity:trivy:FilePath', value: 'a\ud800b' }],
          licenses: [{ license: { name: 'Odd\ud800' } }],
        }),
      ]),
    );
    expect(inv.entries[0]!.path).toBe('a\ufffdb');
    expect(inv.entries[0]!.licenses).toEqual(['Odd\ufffd']);
  });

  it('counts a purl that decodes to NUL as without purl', () => {
    const inv = inventory(bom([lib('pkg:npm/a%00b@1'), lib('pkg:npm/c\u0000d@1')]));
    expect(inv.entries).toEqual([]);
    expect(inv.skipped.noPurl).toBe(2);
    expect(inv.warnings[0]!.message).not.toContain('\u0000');
  });

  it('ignores a leading byte order mark', () => {
    expect(inventory(`\ufeff${bom([lib('pkg:npm/a@1')])}`).entries).toHaveLength(1);
  });
});

describe('flood guard', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('refuses more than 2 000 000 objects and arrays before JSON.parse', () => {
    const parse = vi.spyOn(JSON, 'parse');
    const r = refusal(`[${'{},'.repeat(2_000_001)}{}]`);
    expect(r.code).toBe('SBOM_TOO_LARGE');
    expect(parse).not.toHaveBeenCalled();
  });

  it('lets 1 000 objects through to JSON.parse', () => {
    const parse = vi.spyOn(JSON, 'parse');
    const r = refusal(`[${'{},'.repeat(999)}{}]`);
    expect(r.code).toBe('SBOM_INVALID');
    expect(parse).toHaveBeenCalledTimes(1);
  });

  it('does not count brackets inside strings, escaped quotes included', () => {
    const name = `"${'{['.repeat(1_100_000)}`;
    const inv = inventory(bom([], { metadata: { component: { type: 'application', name } } }));
    expect(inv.subject).toHaveLength(512);
  });
});
