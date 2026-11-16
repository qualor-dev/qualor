import { describe, expect, it } from 'vitest';
import { bom, entry, inventory, lib, sample } from '../../test/sbom';
import { readCycloneDx } from './cyclonedx';
import { parseSbom } from './parse';
import type { SbomEntry } from './types';

const NO_SKIPS = { noPurl: 0, unsupportedType: 0, duplicate: 0 };
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

describe('trivy debian image', () => {
  const inv = inventory(sample('trivy-debian.cdx.json'));

  it('reads the format, the distribution and the subject', () => {
    expect(inv.format).toBe('CycloneDX 1.7');
    expect(inv.distribution).toEqual({ family: 'debian', version: '12.15' });
    expect(inv.subject).toBe(
      'buildpack-deps:bookworm-curl@sha256:58021c2a0204361b62a23d2e0244d144d74c29af2d678e2a1f7e6611885d6949',
    );
    expect(inv.subjectVersion).toBeNull();
  });

  it('reads libssl3 with its source package openssl', () => {
    expect(entry(inv, 'libssl3')).toEqual({
      ecosystem: 'deb',
      name: 'libssl3',
      version: '3.0.22-1~deb12u2',
      path: '',
      licenses: ['Apache-2.0', 'Artistic-2.0', 'GPL-1.0-only', 'GPL-1.0-or-later'],
      // Trivy's graph names the image and the OS under it, not the packages.
      direct: false,
      source: { name: 'openssl', version: '3.0.22-1~deb12u2' },
      arch: 'amd64',
      modularityLabel: null,
    });
  });

  it('folds the epoch qualifier into login, source shadow', () => {
    const login = entry(inv, 'login');
    expect(login.version).toBe('1:4.13+dfsg1-1+deb12u2');
    // SrcEpoch 1, SrcVersion 4.13+dfsg1, SrcRelease 1+deb12u2.
    expect(login.source).toEqual({ name: 'shadow', version: '1:4.13+dfsg1-1+deb12u2' });
  });

  it('counts every package as an OS package and skips nothing', () => {
    expect(inv.entries).toHaveLength(22);
    expect(inv.osPackages).toBe(inv.entries.filter((e) => e.ecosystem === 'deb').length);
    expect(inv.skipped).toEqual(NO_SKIPS);
    expect(inv.warnings).toEqual([]);
  });
});

describe('syft debian image', () => {
  const inv = inventory(sample('syft-debian.cdx.json'));

  it('takes the distribution from the OS component', () => {
    expect(inv.format).toBe('CycloneDX 1.6');
    expect(inv.distribution).toEqual({ family: 'debian', version: '12.15' });
    expect(inv.subject).toBe('buildpack-deps bookworm-curl');
    expect(inv.subjectVersion).toBe('bookworm-curl');
  });

  it("takes libssl3's source from upstream, the path from syft:location:0:path", () => {
    const libssl3 = entry(inv, 'libssl3');
    expect(libssl3.source).toEqual({ name: 'openssl', version: '3.0.22-1~deb12u2' });
    expect(libssl3.path).toBe('/var/lib/dpkg/status');
    expect(libssl3.direct).toBeNull();
  });

  it('reads an upstream with a version', () => {
    expect(entry(inv, 'bash').source).toEqual({ name: 'bash', version: '5.2.15-2' });
    expect(entry(inv, 'libcap2').source).toEqual({ name: 'libcap2', version: '1:2.66-4+deb12u3' });
  });

  it("agrees with Trivy's file of the same image on every name, version and source", () => {
    const key = (e: SbomEntry) => `${e.name} ${e.version} ${e.source?.name} ${e.source?.version}`;
    const trivy = inventory(sample('trivy-debian.cdx.json'));
    expect(inv.entries.map(key).sort()).toEqual(trivy.entries.map(key).sort());
    expect(inv.osPackages).toBe(22);
    expect(inv.skipped).toEqual(NO_SKIPS);
    expect(inv.warnings).toEqual([]);
  });
});

describe('syft ubi8 rpm', () => {
  const inv = inventory(sample('syft-ubi8.cdx.json'));

  it('maps distro=rhel-8.10 and the namespace redhat to one distribution', () => {
    expect(inv.format).toBe('CycloneDX 1.5');
    expect(inv.distribution).toEqual({ family: 'redhat', version: '8.10' });
    expect(inv.warnings).toEqual([]);
  });

  it('folds epoch=1 into the version and takes the source from upstream, with the epoch', () => {
    const openssl = entry(inv, 'openssl-libs');
    expect(openssl.ecosystem).toBe('rpm');
    expect(openssl.version).toBe('1:1.1.1k-18.el8_6');
    expect(openssl.source).toEqual({ name: 'openssl', version: '1:1.1.1k-18.el8_6' });
    expect(entry(inv, 'libstdc++').source).toEqual({ name: 'gcc', version: '8.5.0-31.el8_10' });
  });

  it("agrees with Trivy's file of the same image", () => {
    const key = (e: SbomEntry) =>
      `${e.name} ${e.version} ${e.source?.name} ${e.source?.version} ${e.arch}`;
    const trivy = inventory(sample('trivy-ubi8.cdx.json'));
    expect(trivy.distribution).toEqual({ family: 'redhat', version: '8.10' });
    expect(inv.entries.map(key).sort()).toEqual(trivy.entries.map(key).sort());
  });
});

describe('trivy alpine image', () => {
  it('reads libcrypto3 with its origin openssl', () => {
    const inv = inventory(sample('trivy-alpine.cdx.json'));
    expect(inv.distribution).toEqual({ family: 'alpine', version: '3.20.3' });
    expect(entry(inv, 'libcrypto3')).toMatchObject({
      ecosystem: 'apk',
      version: '3.3.2-r0',
      source: { name: 'openssl', version: '3.3.2-r0' },
    });
    expect(inv.osPackages).toBe(14);
  });
});

describe.each(['cdxgen-node.cdx-1.5.json', 'cdxgen-node.cdx-1.7.json'])(
  'cdxgen npm: %s',
  (file) => {
    const inv = inventory(sample(file));

    it('reads npm packages, the scoped name decoded', () => {
      expect(inv.entries.map((e) => e.name).sort()).toEqual([
        '@babel/code-frame',
        '@babel/helper-validator-identifier',
        'js-tokens',
        'minimist',
        'picocolors',
      ]);
      expect(inv.entries.every((e) => e.ecosystem === 'npm' && e.source === null)).toBe(true);
      expect(inv.subject).toBe('deps-web 1.0.0');
      expect(inv.subjectVersion).toBe('1.0.0');
      expect(inv.distribution).toBeNull();
      expect(inv.osPackages).toBe(0);
      expect(inv.warnings).toEqual([]);
    });

    it("marks the subject's dependsOn as direct", () => {
      expect(entry(inv, '@babel/code-frame').direct).toBe(true);
      expect(entry(inv, 'minimist').direct).toBe(true);
      expect(entry(inv, 'js-tokens').direct).toBe(false);
      expect(entry(inv, '@babel/helper-validator-identifier').direct).toBe(false);
    });

    it('takes the path from evidence.occurrences and normalises licences', () => {
      expect(entry(inv, 'minimist')).toMatchObject({ path: 'index.js', licenses: ['MIT'] });
      expect(entry(inv, 'picocolors')).toMatchObject({ path: '', licenses: ['ISC'] });
    });
  },
);

describe('spec versions', () => {
  it('accepts syft 1.4', () => {
    const inv = inventory(sample('syft-node.cdx-1.4.json'));
    expect(inv.format).toBe('CycloneDX 1.4');
    expect(entry(inv, '@babel/code-frame').path).toBe('/package-lock.json');
    // The package-lock.json file component.
    expect(inv.skipped).toEqual({ noPurl: 0, unsupportedType: 1, duplicate: 0 });
  });

  it.each(['1.2', '1.3'])('accepts %s', (specVersion) => {
    const inv = inventory(
      JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion,
        version: 1,
        components: [
          { type: 'library', name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' },
        ],
      }),
    );
    expect(inv.format).toBe(`CycloneDX ${specVersion}`);
    expect(inv.entries.map((e) => `${e.name}@${e.version}`)).toEqual(['lodash@4.17.21']);
  });

  it.each(['1.1', '2.0'])('refuses %s', (specVersion) => {
    const result = parseSbom(JSON.stringify({ bomFormat: 'CycloneDX', specVersion }));
    expect(result).toMatchObject({ refusal: { code: 'SBOM_FORMAT_UNSUPPORTED' } });
  });
});

describe('vendor nested', () => {
  it('reads every nested package', () => {
    const inv = inventory(sample('vendor-nested.cdx.json'));
    expect(inv.entries.map((e) => `${e.ecosystem} ${e.name}`)).toEqual([
      'generic example/gateway',
      'maven io.netty:netty-handler',
      'maven io.netty:netty-buffer',
      'maven com.fasterxml.jackson.core:jackson-databind',
      'generic example/console',
      'npm @angular/core',
      'npm tslib',
    ]);
    expect(entry(inv, 'example/gateway').direct).toBe(true);
    expect(entry(inv, 'tslib').direct).toBe(false);
    expect(entry(inv, 'com.fasterxml.jackson.core:jackson-databind').licenses).toEqual([
      'Apache-2.0',
    ]);
    expect(inv.subject).toBe('com.example/appliance 4.2.0');
    expect(inv.warnings).toEqual([]);
  });

  it('reads 32 levels and counts the rest', () => {
    let chain: Record<string, unknown> | undefined;
    for (let level = 40; level >= 1; level--) {
      chain = lib(`pkg:npm/p${level}@1.0.0`, chain === undefined ? {} : { components: [chain] });
    }
    const inv = inventory(bom([chain]));
    expect(inv.entries.map((e) => e.name)).toEqual(
      Array.from({ length: 32 }, (_, i) => `p${i + 1}`),
    );
    expect(inv.warnings).toHaveLength(1);
    expect(inv.warnings[0]!.code).toBe('SBOM_NESTING_TOO_DEEP');
    expect(inv.warnings[0]!.message).toMatch(/\b8\b/);
  });
});

describe('subject', () => {
  it('is no entry, even when components[] repeats its bom-ref', () => {
    const inv = inventory(
      bom([lib('pkg:npm/shop@1.4.0', { 'bom-ref': 'root' }), lib('pkg:npm/lodash@4.17.21')], {
        metadata: {
          component: {
            type: 'application',
            'bom-ref': 'root',
            group: 'acme',
            name: 'shop',
            version: '1.4.0',
          },
        },
      }),
    );
    expect(inv.entries.map((e) => e.name)).toEqual(['lodash']);
    expect(inv.subject).toBe('acme/shop 1.4.0');
    expect(inv.subjectVersion).toBe('1.4.0');
  });

  it('is no entry when a component repeats its purl', () => {
    const inv = inventory(
      bom([lib('pkg:npm/shop@1.4.0'), lib('pkg:npm/lodash@4.17.21')], {
        metadata: { component: { type: 'application', name: 'shop', purl: 'pkg:npm/shop@1.4.0' } },
      }),
    );
    expect(inv.entries.map((e) => e.name)).toEqual(['lodash']);
    expect(inv.subject).toBe('shop');
    expect(inv.subjectVersion).toBeNull();
  });

  it('cuts a long name to 512 without leaving a lone surrogate', () => {
    const name = 'a'.repeat(511) + '\u{1f600}'.repeat(45); // 601 UTF-16 units
    const inv = inventory(bom([], { metadata: { component: { type: 'application', name } } }));
    expect(inv.subject!.length).toBeLessThanOrEqual(512);
    expect(inv.subject!.startsWith('a'.repeat(511))).toBe(true);
    expect(LONE_SURROGATE.test(inv.subject!)).toBe(false);
  });

  it('is null without metadata.component', () => {
    const inv = inventory(bom([]));
    expect(inv.subject).toBeNull();
    expect(inv.subjectVersion).toBeNull();
  });
});

describe('skips', () => {
  it('counts a file component as an unsupported type', () => {
    const inv = inventory(bom([{ type: 'file', name: 'a.txt', purl: 'pkg:generic/a.txt@1' }]));
    expect(inv.skipped).toEqual({ noPurl: 0, unsupportedType: 1, duplicate: 0 });
  });

  it('counts a component without a purl', () => {
    const inv = inventory(bom([{ type: 'library', name: 'a', version: '1' }]));
    expect(inv.skipped).toEqual({ noPurl: 1, unsupportedType: 0, duplicate: 0 });
    expect(inv.warnings).toEqual([]);
  });

  it('counts purls that do not parse and names the first three', () => {
    const inv = inventory(bom(['pkg:', 'pkg:npm/', 'x', 'y'].map((purl) => lib(purl))));
    expect(inv.skipped).toEqual({ noPurl: 4, unsupportedType: 0, duplicate: 0 });
    expect(inv.warnings).toHaveLength(1);
    const { code, message } = inv.warnings[0]!;
    expect(code).toBe('SBOM_PURL_INVALID');
    for (const named of ['"pkg:"', '"pkg:npm/"', '"x"']) expect(message).toContain(named);
    expect(message).not.toContain('"y"');
  });

  it('counts a purl without a version as without purl', () => {
    const inv = inventory(bom([lib('pkg:npm/lodash')]));
    expect(inv.skipped).toEqual({ noPurl: 1, unsupportedType: 0, duplicate: 0 });
    expect(inv.warnings).toEqual([]);
  });

  it('counts an overlong name or version as without purl', () => {
    const inv = inventory(
      bom([lib(`pkg:npm/${'n'.repeat(513)}@1`), lib(`pkg:npm/a@${'1'.repeat(257)}`)]),
    );
    expect(inv.skipped).toEqual({ noPurl: 2, unsupportedType: 0, duplicate: 0 });
  });

  it('counts a purl type outside [a-z0-9-]{1,32} as an unsupported type', () => {
    const inv = inventory(bom([lib('pkg:foo.bar/x@1'), lib(`pkg:${'t'.repeat(33)}/x@1`)]));
    expect(inv.skipped).toEqual({ noPurl: 0, unsupportedType: 2, duplicate: 0 });
  });

  it('stores types Trivy cannot match', () => {
    const inv = inventory(bom([lib('pkg:generic/openssl@3.0.0'), lib('pkg:github/a/b@v1')]));
    expect(inv.entries.map((e) => e.ecosystem)).toEqual(['generic', 'github']);
  });
});

describe('duplicates', () => {
  it('merges the same purl at one path, with the licence union', () => {
    const inv = inventory(
      bom([
        lib('pkg:npm/a@1.0.0', { licenses: [{ license: { id: 'MIT' } }] }),
        lib('pkg:npm/a@1.0.0', { licenses: [{ license: { id: 'Apache-2.0' } }] }),
      ]),
    );
    expect(inv.entries).toHaveLength(1);
    expect(inv.entries[0]!.licenses).toEqual(['Apache-2.0', 'MIT']);
    expect(inv.skipped).toEqual({ noPurl: 0, unsupportedType: 0, duplicate: 1 });
  });

  it('keeps the same purl at two paths', () => {
    const at = (path: string) => ({
      properties: [{ name: 'aquasecurity:trivy:FilePath', value: path }],
    });
    const inv = inventory(
      bom([
        lib('pkg:npm/a@1.0.0', at('a/package-lock.json')),
        lib('pkg:npm/a@1.0.0', at('b/package-lock.json')),
      ]),
    );
    expect(inv.entries.map((e) => e.path)).toEqual(['a/package-lock.json', 'b/package-lock.json']);
    expect(inv.skipped.duplicate).toBe(0);
  });

  it('keeps direct when either says so', () => {
    const inv = inventory(
      bom(
        [lib('pkg:npm/a@1.0.0', { 'bom-ref': 'a1' }), lib('pkg:npm/a@1.0.0', { 'bom-ref': 'a2' })],
        {
          metadata: { component: { type: 'application', name: 'app', 'bom-ref': 'app' } },
          dependencies: [{ ref: 'app', dependsOn: ['a2'] }],
        },
      ),
    );
    expect(inv.entries).toEqual([expect.objectContaining({ name: 'a', direct: true })]);
  });
});

describe('path precedence', () => {
  const trivy = { name: 'aquasecurity:trivy:FilePath', value: 'trivy/path' };
  const syft = { name: 'syft:location:0:path', value: '/syft/path' };
  const evidence = { occurrences: [{ location: 'evidence/path' }, { location: 'second' }] };
  const pathOf = (more: Record<string, unknown>) =>
    inventory(bom([lib('pkg:npm/a@1', more)])).entries[0]!.path;

  it('takes aquasecurity:trivy:FilePath, then syft:location:0:path, then the first occurrence', () => {
    expect(pathOf({ properties: [syft, trivy], evidence })).toBe('trivy/path');
    expect(pathOf({ properties: [syft], evidence })).toBe('/syft/path');
    expect(pathOf({ evidence })).toBe('evidence/path');
    expect(pathOf({})).toBe('');
  });

  it('skips a property without a name, as CycloneDX 1.2 to 1.4 allow (t2m6)', () => {
    const inv = inventory(
      bom([
        lib('pkg:npm/a@1', {
          properties: [{ value: 'no name' }, syft],
        }),
      ]),
    );
    expect(inv.entries[0]!.path).toBe('/syft/path');
  });

  it('cuts a path to 1 024 characters', () => {
    const value = 'p'.repeat(1_100);
    const path = pathOf({ properties: [{ name: 'aquasecurity:trivy:FilePath', value }] });
    expect(path).toBe('p'.repeat(1_024));
  });
});

describe('licences', () => {
  const licensesOf = (licenses: unknown[]) =>
    inventory(bom([lib('pkg:npm/a@1', { licenses })])).entries[0]!.licenses;

  it('reads license.id, license.name and expression, normalised', () => {
    expect(licensesOf([{ license: { id: 'MIT' } }])).toEqual(['MIT']);
    expect(licensesOf([{ license: { name: 'Apache License 2.0' } }])).toEqual(['Apache-2.0']);
    expect(licensesOf([{ expression: 'MIT or Apache-2.0' }])).toEqual(['MIT OR Apache-2.0']);
  });

  it('keeps 16 of 20', () => {
    const many = Array.from({ length: 20 }, (_, i) => ({ license: { name: `L${i + 10}` } }));
    expect(licensesOf(many)).toHaveLength(16);
  });

  it('drops a licence over 256 characters instead of cutting it', () => {
    expect(
      licensesOf([{ license: { name: 'x'.repeat(257) } }, { license: { id: 'MIT' } }]),
    ).toEqual(['MIT']);
  });

  it('drops a long or deeply nested expression without parsing it', () => {
    expect(
      licensesOf([
        { expression: `${'MIT AND '.repeat(5_000)}MIT` },
        { expression: `${'('.repeat(10_000)}MIT${')'.repeat(10_000)}` },
        { expression: '('.repeat(100_000) },
        { license: { id: 'MIT' } },
      ]),
    ).toEqual(['MIT']);
  });

  it('keeps licences named like Object.prototype members as strings', () => {
    expect(
      licensesOf(
        ['constructor', '__proto__', 'toString', 'MIT'].map((name) => ({ license: { name } })),
      ),
    ).toEqual(['MIT', '__proto__', 'constructor', 'toString']);
  });
});

describe('direct', () => {
  const metadata = { component: { type: 'application', name: 'app', 'bom-ref': 'app' } };
  const components = [
    lib('pkg:npm/a@1', { 'bom-ref': 'a' }),
    lib('pkg:npm/b@1', { 'bom-ref': 'b' }),
  ];
  const directOf = (extra: Record<string, unknown>) =>
    inventory(bom(components, { metadata, ...extra })).entries.map((e) => e.direct);

  it("is true for the subject's dependsOn and false for the rest", () => {
    expect(
      directOf({
        dependencies: [
          { ref: 'app', dependsOn: ['a'] },
          { ref: 'a', dependsOn: ['b'] },
        ],
      }),
    ).toEqual([true, false]);
  });

  it('is false when the graph names the subject but not the component', () => {
    expect(directOf({ dependencies: [{ ref: 'app', dependsOn: [] }] })).toEqual([false, false]);
  });

  it('is null without a graph, or when the graph does not name the subject', () => {
    expect(directOf({})).toEqual([null, null]);
    expect(directOf({ dependencies: [{ ref: 'a', dependsOn: ['b'] }] })).toEqual([null, null]);
  });
});

describe('readCycloneDx', () => {
  it('returns the document before the inventory is built', () => {
    const doc = readCycloneDx(
      JSON.parse(sample('trivy-alpine.cdx.json')) as Record<string, unknown>,
    );
    if ('code' in doc) throw new Error(doc.message);
    expect(doc.format).toBe('CycloneDX 1.7');
    expect(doc.operatingSystems).toEqual([{ name: 'alpine', version: '3.20.3' }]);
    expect(doc.components).toHaveLength(14);
    expect(doc.components[0]!.purl.type).toBe('apk');
    expect(doc.tooDeep).toBe(0);
  });

  it('names the JSON path of a field with the wrong shape', () => {
    const result = readCycloneDx({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      components: [{ type: 'library', components: [{ type: 'library', purl: 7 }] }],
    });
    expect(result).toMatchObject({ code: 'SBOM_INVALID', path: 'components.0.components.0.purl' });
  });
});
