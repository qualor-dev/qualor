import { afterEach, describe, expect, it, vi } from 'vitest';
import { budgetMs } from '../../test/perf';
import { bom, entry, inventory, lib, os, refusal, sample } from '../../test/sbom';
import { parseSbom } from './parse';

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
    // A codename is no version: the family only (t2m5).
    expect(of('pkg:deb/debian/a@1?distro=debian-bookworm')).toBeNull();
    expect(of('pkg:apk/alpine/a@1-r0?distro=3.20.3')).toEqual({
      family: 'alpine',
      version: '3.20.3',
    });
  });

  it('takes a codename distro next to an OS component as its family, not a second OS (t2m5)', () => {
    // The purl specification's own deb example.
    const spec = inventory(
      bom([os('debian', '8.11'), lib('pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie')]),
    );
    expect(spec.distribution).toEqual({ family: 'debian', version: '8.11' });
    expect(spec.warnings).toEqual([]);
    const named = inventory(
      bom([os('debian', '12.15'), lib('pkg:deb/debian/a@1?distro=debian-bookworm')]),
    );
    expect(named.distribution).toEqual({ family: 'debian', version: '12.15' });
    // Alone, a codename names the family but no version: the packages are not checked.
    const alone = inventory(bom([lib('pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie')]));
    expect(alone.distribution).toBeNull();
    expect(alone.warnings.map((w) => w.code)).toEqual(['SBOM_OS_PACKAGES_UNCHECKED']);
    // Another family's codename is still a second OS.
    expect(
      refusal(bom([os('debian', '12.15'), lib('pkg:deb/ubuntu/a@1?distro=ubuntu-jammy')])).code,
    ).toBe('SBOM_MULTIPLE_OS');
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

  it('warns that RHEL and CentOS releases outside 6–9 are not checked (R29)', () => {
    const warning = (name: string, version: string) =>
      inventory(bom([os(name, version), lib(`pkg:rpm/${name}/bash@5.2.26-6.el10?arch=x86_64`)]))
        .warnings;
    for (const [name, version] of [
      ['redhat', '10.0'],
      ['rhel', '10.1'],
      ['centos', '10'],
      ['redhat', '5.11'],
      ['redhat', 'ten'],
    ] as const) {
      const warnings = warning(name, version);
      expect(
        warnings.map((w) => w.code),
        `${name} ${version}`,
      ).toEqual(['SBOM_OS_PACKAGES_UNCHECKED']);
      expect(warnings[0]!.message).toBe(
        `1 operating-system packages are stored but not checked for vulnerabilities: Trivy 0.74.0 needs the content sets of ${name === 'rhel' ? 'redhat' : name} ${version} images, which Qualor does not keep.`,
      );
    }
    for (const [name, version] of [
      ['redhat', '9.4'],
      ['redhat', '8'],
      ['centos', '7.9.2009'],
      ['centos', '6'],
      ['rocky', '10.0'],
      ['alma', '10.0'],
    ] as const) {
      expect(warning(name, version), `${name} ${version}`).toEqual([]);
    }
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

  /** The sources of these OS purls under one distribution, in order. */
  const sources = (system: ReturnType<typeof os>, purls: string[]) =>
    inventory(bom([system, ...purls.map((p) => lib(p))])).entries.map((e) => e.source);

  it('reads `upstream=<name>@<version>` for deb, each part percent-decoded (Qualor’s key, Syft)', () => {
    expect(
      sources(os('debian', '12.15'), [
        // Qualor's match key: a literal @, the parts encoded on their own.
        'pkg:deb/debian/login@1%3A4.13%2Bdfsg1-1?distro=debian-12.15&upstream=shadow@1%3A4.13%2Bdfsg1-1',
        // Syft: the @ itself encoded.
        'pkg:deb/debian/bash@5.2.15-2%2Bb13?distro=debian-12.15&upstream=bash%405.2.15-2',
        // Syft without a version: the binary's.
        'pkg:deb/debian/libssl3@3.0.22-1~deb12u2?distro=debian-12.15&upstream=openssl',
      ]),
    ).toEqual([
      { name: 'shadow', version: '1:4.13+dfsg1-1' },
      { name: 'bash', version: '5.2.15-2' },
      { name: 'openssl', version: '3.0.22-1~deb12u2' },
    ]);
  });

  it('reads `upstream=<name>@<version>` for rpm, and still Syft’s `.src.rpm` form', () => {
    expect(
      sources(os('redhat', '8.10'), [
        'pkg:rpm/redhat/openssl-libs@1.1.1k-18.el8_6?epoch=1&distro=redhat-8.10&upstream=openssl@1%3A1.1.1k-18.el8_6',
        'pkg:rpm/redhat/libstdc%2B%2B@8.5.0-31.el8_10?distro=redhat-8.10&upstream=gcc@8.5.0-31.el8_10',
        'pkg:rpm/redhat/gmp@6.1.2-11.el8?epoch=1&distro=rhel-8.10&upstream=gmp-6.1.2-11.el8.src.rpm',
      ]),
    ).toEqual([
      { name: 'openssl', version: '1:1.1.1k-18.el8_6' },
      { name: 'gcc', version: '8.5.0-31.el8_10' },
      { name: 'gmp', version: '1:6.1.2-11.el8' },
    ]);
  });

  it('reads `upstream=<name>@<version>` for apk, and still Syft’s bare origin', () => {
    expect(
      sources(os('alpine', '3.20.3'), [
        'pkg:apk/alpine/libcrypto3@3.3.2-r0?distro=3.20.3&upstream=openssl@3.3.2-r0',
        'pkg:apk/alpine/busybox-binsh@1.36.1-r29?arch=x86_64&upstream=busybox',
      ]),
    ).toEqual([
      { name: 'openssl', version: '3.3.2-r0' },
      { name: 'busybox', version: '1.36.1-r29' },
    ]);
  });

  it('falls back to the binary for an `upstream` with nothing before the @', () => {
    expect(sources(os('alpine', '3.20.3'), ['pkg:apk/alpine/a@1-r0?upstream=@2-r0'])).toEqual([
      { name: 'a', version: '1-r0' },
    ]);
  });

  it('reads a long hostile `upstream` in linear time', () => {
    const at = '%40'.repeat(30_000);
    const started = performance.now();
    sources(os('redhat', '8.10'), [`pkg:rpm/redhat/a@1-1?upstream=x${at}-1-1.src.rpm`]);
    expect(performance.now() - started).toBeLessThan(1_000);
  });
});

describe('arch and modularity label (Red Hat-family matching)', () => {
  const LABEL = 'nodejs:18:8090020240112121244:a75119d5';
  /** The one entry of one purl under one distribution. */
  const one = (system: ReturnType<typeof os>, purl: string) =>
    inventory(bom([system, lib(purl)])).entries[0]!;

  it('reads the arch and modularitylabel qualifiers of an rpm', () => {
    const e = one(
      os('redhat', '8.10'),
      `pkg:rpm/redhat/openssl-libs@1.1.1k-12.el8_9?arch=x86_64&epoch=1&modularitylabel=${encodeURIComponent(LABEL)}`,
    );
    expect(e).toMatchObject({
      name: 'openssl-libs',
      version: '1:1.1.1k-12.el8_9',
      arch: 'x86_64',
      modularityLabel: LABEL,
    });
    const plain = one(os('redhat', '8.10'), 'pkg:rpm/redhat/bash@4.4.20-6.el8_10');
    expect([plain.arch, plain.modularityLabel]).toEqual([null, null]);
  });

  it('reads the arch of deb and apk packages too (unused downstream)', () => {
    expect(one(os('debian', '12.15'), 'pkg:deb/debian/libssl3@3.0.22-1?arch=amd64')).toMatchObject({
      arch: 'amd64',
      modularityLabel: null,
    });
    expect(
      one(os('alpine', '3.20.3'), 'pkg:apk/alpine/busybox@1.36.1-r29?arch=x86_64'),
    ).toMatchObject({ arch: 'x86_64', modularityLabel: null });
  });

  it('sets neither for a library, whatever its purl carries', () => {
    expect(
      one(os('debian', '12'), `pkg:npm/a@1?arch=x86_64&modularitylabel=${LABEL}`),
    ).toMatchObject({ arch: null, modularityLabel: null });
  });

  it.each([
    ['a space', 'x86%2064'],
    ['a slash', 'x86%2F64'],
    ['a newline', 'x86_64%0A'],
    ['a colon', 'x86:64'],
    ['a non-ASCII letter', 'x86_%C3%A9'],
    ['65 characters', 'a'.repeat(65)],
  ])('drops an arch with %s to null', (_why, arch) => {
    expect(one(os('redhat', '8.10'), `pkg:rpm/redhat/a@1-1?arch=${arch}`).arch).toBeNull();
  });

  it('keeps an arch of 64 characters from [A-Za-z0-9_.+-]', () => {
    const arch = `${'a'.repeat(58)}_.+-Z9`;
    expect(arch).toHaveLength(64);
    expect(
      one(os('redhat', '8.10'), `pkg:rpm/redhat/a@1-1?arch=${encodeURIComponent(arch)}`).arch,
    ).toBe(arch);
  });

  it.each([
    ['a control character', `${LABEL}%0A`],
    ['a C1 control character', `${LABEL}%C2%85`],
    ['DEL', `${LABEL}%7F`],
    ['257 characters', 'l'.repeat(257)],
  ])('drops a modularity label with %s to null', (_why, label) => {
    expect(
      one(os('redhat', '8.10'), `pkg:rpm/redhat/a@1-1?modularitylabel=${label}`).modularityLabel,
    ).toBeNull();
  });

  it('keeps a modularity label of 256 characters', () => {
    const label = 'l'.repeat(256);
    expect(
      one(os('redhat', '8.10'), `pkg:rpm/redhat/a@1-1?modularitylabel=${label}`).modularityLabel,
    ).toBe(label);
  });

  it('keeps the first arch when one package is listed twice (multilib, a known limit)', () => {
    const inv = inventory(
      bom([
        os('redhat', '8.10'),
        lib('pkg:rpm/redhat/glibc@2.28-251.el8?arch=x86_64'),
        lib('pkg:rpm/redhat/glibc@2.28-251.el8?arch=i686'),
      ]),
    );
    expect(inv.entries).toHaveLength(1);
    expect(inv.entries[0]!.arch).toBe('x86_64');
    expect(inv.skipped.duplicate).toBe(1);
  });

  it('reads them back from a re-imported export: the OS match key is the purl', () => {
    // osMatchKey's rpm form (server/src/vulnerabilities/purl.ts): arch, epoch, distro,
    // modularitylabel, upstream, each part percent-encoded.
    const key =
      'pkg:rpm/redhat/nodejs@18.19.0-1.module%2Bel8.9.0%2B20473%2Bc4e3d824?arch=x86_64&epoch=1&distro=redhat-8.10&modularitylabel=nodejs%3A18%3A8090020240112121244%3Aa75119d5&upstream=nodejs@1%3A18.19.0-1.module%2Bel8.9.0%2B20473%2Bc4e3d824';
    expect(one(os('redhat', '8.10'), key)).toEqual({
      ecosystem: 'rpm',
      name: 'nodejs',
      version: '1:18.19.0-1.module+el8.9.0+20473+c4e3d824',
      path: '',
      licenses: [],
      direct: null,
      source: { name: 'nodejs', version: '1:18.19.0-1.module+el8.9.0+20473+c4e3d824' },
      arch: 'x86_64',
      modularityLabel: LABEL,
    });
  });

  it('reads the arch of every package of the Trivy and Syft UBI 8 samples', () => {
    for (const file of ['trivy-ubi8.cdx.json', 'syft-ubi8.cdx.json']) {
      const inv = inventory(sample(file));
      expect(inv.entries.length, file).toBeGreaterThan(10);
      for (const e of inv.entries) {
        expect(['x86_64', 'noarch'], `${file} ${e.name}`).toContain(e.arch);
      }
      expect(entry(inv, 'openssl-libs').arch).toBe('x86_64');
      expect(entry(inv, 'tzdata').arch).toBe('noarch');
    }
  });

  it('reads a long hostile arch and label in linear time', () => {
    const started = performance.now();
    const e = one(
      os('redhat', '8.10'),
      `pkg:rpm/redhat/a@1-1?arch=${'a'.repeat(300_000)}&modularitylabel=${'l'.repeat(300_000)}`,
    );
    expect([e.arch, e.modularityLabel]).toEqual([null, null]);
    expect(performance.now() - started).toBeLessThan(budgetMs(500));
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

  // Task 16: 64 MiB of numbers in `components` took a 1 GiB server down in JSON.parse.
  it('refuses more than 6 000 000 values before JSON.parse', () => {
    const parse = vi.spyOn(JSON, 'parse');
    const r = refusal(`{"bomFormat":"CycloneDX","components":[${'1,'.repeat(6_000_000)}1]}`);
    expect(r.code).toBe('SBOM_TOO_LARGE');
    expect(r.message).toBe('The SBOM holds more than 6000000 JSON keys and values.');
    expect(parse).not.toHaveBeenCalled();
  });

  it('counts short strings as values', () => {
    const parse = vi.spyOn(JSON, 'parse');
    const r = refusal(`[${'"ab", '.repeat(6_000_000)}"ab"]`);
    expect(r.code).toBe('SBOM_TOO_LARGE');
    expect(parse).not.toHaveBeenCalled();
  });

  it('counts keys as well as values', () => {
    const parse = vi.spyOn(JSON, 'parse');
    // One object and 3 000 001 keys with their values: 6 000 003.
    const r = refusal(`{${'"a":1,'.repeat(3_000_000)}"a":1}`);
    expect(r.code).toBe('SBOM_TOO_LARGE');
    expect(parse).not.toHaveBeenCalled();
  });

  it('lets exactly 6 000 000 values through to JSON.parse', () => {
    const parse = vi.spyOn(JSON, 'parse');
    // The array and 5 999 999 numbers, with white space and line breaks between them.
    const r = refusal(`[\n${'1 ,\t'.repeat(5_999_998)}1\r\n]`);
    expect(r.code).toBe('SBOM_INVALID');
    expect(parse).toHaveBeenCalledTimes(1);
  });

  it('does not count values inside strings', () => {
    const name = `1,"a":[${'1,'.repeat(6_100_000)}`;
    const inv = inventory(bom([], { metadata: { component: { type: 'application', name } } }));
    expect(inv.subject).toHaveLength(512);
  });

  const keys = (n: number) => Array.from({ length: n }, (_, i) => `"k${i}":1`).join(',');

  // Task 16: 4 000 000 unique keys (42 MB) took a 1 GiB server down in JSON.parse.
  it('refuses more than 10 000 distinct keys in one object before JSON.parse', () => {
    const parse = vi.spyOn(JSON, 'parse');
    const r = refusal(`{${keys(10_001)}}`);
    expect(r.code).toBe('SBOM_TOO_LARGE');
    expect(r.message).toBe('The SBOM holds more than 10000 distinct JSON keys.');
    expect(parse).not.toHaveBeenCalled();
  });

  it('refuses more than 10 000 distinct keys spread over objects', () => {
    const parse = vi.spyOn(JSON, 'parse');
    const objects = Array.from({ length: 5_001 }, (_, i) => `{"a${i}":1, "b${i}":[{}]}`);
    expect(refusal(`[${objects.join(',')}]`).code).toBe('SBOM_TOO_LARGE');
    expect(parse).not.toHaveBeenCalled();
  });

  it('counts a repeated key once, and strings that are values or array items not at all', () => {
    const parse = vi.spyOn(JSON, 'parse');
    // 9 998 keys and x and y: 10 000 distinct.
    const repeated = `{"x":{${keys(9_998)}},"y":[${Array(1_000)
      .fill(`{${keys(100)}}`)
      .join(',')}]}`;
    const strings = Array.from({ length: 20_000 }, (_, i) => `"s${i}"`).join(',');
    const values = Array.from({ length: 20_000 }, (_, i) => `{"k1":"v${i}"}`).join(',');
    expect(refusal(`[${repeated},[${strings}],${values}]`).code).toBe('SBOM_INVALID');
    expect(parse).toHaveBeenCalledTimes(1);
  });

  /** A backslash, written without an escape sequence. */
  const BS = String.fromCharCode(0x5c);

  it('ends the scan at an unterminated string or a backslash at the end of the text', () => {
    const parse = vi.spyOn(JSON, 'parse');
    for (const text of ['{"a', `{"a${BS}`, `["a${BS}"`, `{"a":"b${BS}`, '"']) {
      expect(refusal(text).code, text).toBe('SBOM_INVALID');
    }
    expect(parse).toHaveBeenCalledTimes(5);
  });

  it('counts an unterminated last key, a trailing backslash included', () => {
    const parse = vi.spyOn(JSON, 'parse');
    expect(refusal(`{${keys(10_000)},"z`).code).toBe('SBOM_TOO_LARGE');
    expect(refusal(`{${keys(10_000)},"z${BS}`).code).toBe('SBOM_TOO_LARGE');
    expect(parse).not.toHaveBeenCalled();
    expect(refusal(`{${keys(9_999)},"z`).code).toBe('SBOM_INVALID');
    expect(parse).toHaveBeenCalledTimes(1);
  });

  it('compares keys as written, escapes included', () => {
    const parse = vi.spyOn(JSON, 'parse');
    // `k0` is `k0` once decoded, a distinct key as written.
    expect(refusal(`{${keys(10_000)},"${BS}u006b0":1}`).code).toBe('SBOM_TOO_LARGE');
    expect(parse).not.toHaveBeenCalled();
  });

  it('reads a key past an escaped quote and up to an escaped backslash', () => {
    const parse = vi.spyOn(JSON, 'parse');
    // `"q\"<i>"` and `"q<i>\\"`: one string each, so one key each.
    const written = (n: number) =>
      Array.from({ length: n }, (_, i) =>
        i % 2 === 0 ? `"q${BS}"${i}":1` : `"q${i}${BS}${BS}":1`,
      ).join(',');
    expect(refusal(`{${written(10_001)}}`).code).toBe('SBOM_TOO_LARGE');
    expect(parse).not.toHaveBeenCalled();
    expect(refusal(`{${written(10_000)}}`).code).toBe('SBOM_INVALID');
    expect(parse).toHaveBeenCalledTimes(1);
  });

  it('counts a key after white space, and a value at the start of the text', () => {
    const parse = vi.spyOn(JSON, 'parse');
    const spaced = Array.from({ length: 10_001 }, (_, i) => `\t"k${i}" :\r\n1`).join(' ,\n');
    expect(refusal(`{ ${spaced} }`).code).toBe('SBOM_TOO_LARGE');
    // No bracket: the first value is the one at the start, then one after each comma.
    expect(refusal(`  ${'1,'.repeat(6_000_000)}1`).code).toBe('SBOM_TOO_LARGE');
    expect(parse).not.toHaveBeenCalled();
    // A value starts only there: `1 1` counts as one value, and JSON.parse refuses it.
    expect(refusal(`[${'1 '.repeat(6_000_001)}]`).code).toBe('SBOM_INVALID');
    expect(parse).toHaveBeenCalledTimes(1);
  });
});

describe('duplicates and direct', () => {
  it('keeps direct when a later duplicate is not direct', () => {
    const inv = inventory(
      bom(
        [lib('pkg:npm/a@1.0.0', { 'bom-ref': 'a1' }), lib('pkg:npm/a@1.0.0', { 'bom-ref': 'a2' })],
        {
          metadata: { component: { type: 'application', name: 'app', 'bom-ref': 'app' } },
          dependencies: [{ ref: 'app', dependsOn: ['a1'] }],
        },
      ),
    );
    expect(inv.entries).toEqual([expect.objectContaining({ name: 'a', direct: true })]);
    expect(inv.skipped.duplicate).toBe(1);
  });
});
