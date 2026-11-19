import { describe, expect, it } from 'vitest';
import { budgetMs } from '../../test/perf';
import {
  entry,
  inventory,
  refusal,
  sample,
  sampleJson,
  spdx,
  spdxPkg,
  spdxRel,
} from '../../test/sbom';
import { parseSbom } from './parse';
import { readSpdx } from './spdx';
import type { SbomEntry, SbomInventory } from './types';

const text = (doc: Record<string, unknown>): string => JSON.stringify(doc);
const invOf = (doc: Record<string, unknown>): SbomInventory => inventory(text(doc));
/**
 * The rows of an inventory without what two formats of one image do not share: the path, the
 * direct flag (the CycloneDX graph names the subject, the SPDX one does not) and the licences
 * (CycloneDX lists the terms, SPDX writes one expression with `LicenseRef` ids).
 */
const rows = (inv: SbomInventory) =>
  inv.entries
    .map((e) => ({
      ecosystem: e.ecosystem,
      name: e.name,
      version: e.version,
      source: e.source,
    }))
    .sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`));

describe('trivy debian spdx', () => {
  const inv = inventory(sample('trivy-debian.spdx.json'));

  it('reads the format, the distribution and the subject', () => {
    expect(inv.format).toBe('SPDX 2.3');
    expect(inv.distribution).toEqual({ family: 'debian', version: '12.15' });
    expect(inv.subject).toBe(
      'buildpack-deps:bookworm-curl@sha256:58021c2a0204361b62a23d2e0244d144d74c29af2d678e2a1f7e6611885d6949',
    );
    expect(inv.subjectVersion).toBeNull();
  });

  it('counts the 22 packages, not the OS package or the subject', () => {
    expect(inv.entries).toHaveLength(22);
    expect(inv.osPackages).toBe(22);
    expect(inv.entries.some((e) => e.name === 'debian')).toBe(false);
    expect(inv.skipped).toEqual({ noPurl: 0, unsupportedType: 0, duplicate: 0 });
    expect(inv.warnings).toEqual([]);
  });

  it('reads libssl3 with its source package openssl from sourceInfo', () => {
    const e = entry(inv, 'libssl3');
    expect(e.ecosystem).toBe('deb');
    expect(e.version).toBe('3.0.22-1~deb12u2');
    expect(e.source).toEqual({ name: 'openssl', version: '3.0.22-1~deb12u2' });
    expect([e.arch, e.modularityLabel]).toEqual(['amd64', null]);
    // An SPDX expression stays one string (Trivy's CycloneDX file lists its terms one by one).
    expect(e.licenses).toEqual([
      'Apache-2.0 AND Artistic-2.0 AND GPL-1.0-or-later AND GPL-1.0-only',
    ]);
  });

  it('folds the epoch qualifier into the version, binary and source', () => {
    const e = entry(inv, 'login');
    expect(e.version).toBe('1:4.13+dfsg1-1+deb12u2');
    expect(e.source).toEqual({ name: 'shadow', version: '1:4.13+dfsg1-1+deb12u2' });
  });

  it('has an empty path on every entry', () => {
    expect(inv.entries.every((e) => e.path === '')).toBe(true);
  });

  it('is not direct (the subject has no DEPENDS_ON, others do)', () => {
    expect(inv.entries.every((e) => e.direct === false)).toBe(true);
  });

  it('holds the entries of the CycloneDX file of the same image', () => {
    expect(rows(inv)).toEqual(rows(inventory(sample('trivy-debian.cdx.json'))));
  });
});

describe('syft debian spdx', () => {
  const inv = inventory(sample('syft-debian.spdx.json'));

  it('finds the distribution in the distro qualifiers', () => {
    expect(inv.format).toBe('SPDX 2.3');
    // Every purl says distro=debian-12.15.
    expect(inv.distribution).toEqual({ family: 'debian', version: '12.15' });
    expect(inv.warnings.map((w) => w.code)).not.toContain('SBOM_OS_PACKAGES_UNCHECKED');
  });

  it('reads libssl3 with its source openssl from upstream', () => {
    const e = entry(inv, 'libssl3');
    expect(e.version).toBe('3.0.22-1~deb12u2');
    expect(e.source).toEqual({ name: 'openssl', version: '3.0.22-1~deb12u2' });
  });

  it('reads the upstream version when it differs, and the epoch', () => {
    expect(entry(inv, 'bash').source).toEqual({ name: 'bash', version: '5.2.15-2' });
    expect(entry(inv, 'login').version).toBe('1:4.13+dfsg1-1+deb12u2');
  });

  it('holds the 22 packages, the image root being the subject', () => {
    expect(inv.entries).toHaveLength(22);
    expect(inv.subject).toBe('buildpack-deps bookworm-curl');
    expect(inv.entries.every((e) => e.direct === null)).toBe(true);
  });

  it('holds the same packages as the CycloneDX file of Syft', () => {
    const key = (e: SbomEntry) => `${e.name}@${e.version}`;
    expect(inv.entries.map(key).sort()).toEqual(
      inventory(sample('syft-debian.cdx.json')).entries.map(key).sort(),
    );
  });
});

describe('syft node spdx 2.2', () => {
  it('is accepted as SPDX 2.2', () => {
    const inv = inventory(sample('syft-node.spdx-2.2.json'));
    expect(inv.format).toBe('SPDX 2.2');
    expect(inv.entries.map((e) => `${e.ecosystem}:${e.name}@${e.version}`).sort()).toEqual([
      'npm:@babel/code-frame@7.26.2',
      'npm:@babel/helper-validator-identifier@7.29.7',
      'npm:deps-web@1.0.0',
      'npm:js-tokens@4.0.0',
      'npm:minimist@1.2.5',
      'npm:picocolors@1.1.1',
    ]);
    expect(inv.distribution).toBeNull();
  });
});

describe('licences', () => {
  const one = (more: Record<string, unknown>) =>
    invOf(spdx([spdxPkg('a', 'pkg:npm/a@1', more)])).entries[0]!.licenses;

  it('takes licenseConcluded when it says something', () => {
    expect(one({ licenseConcluded: 'MIT', licenseDeclared: 'Apache-2.0' })).toEqual(['MIT']);
  });

  it('falls back to licenseDeclared on NOASSERTION or NONE', () => {
    expect(one({ licenseConcluded: 'NOASSERTION', licenseDeclared: 'Apache-2.0' })).toEqual([
      'Apache-2.0',
    ]);
    expect(one({ licenseConcluded: 'NONE', licenseDeclared: 'Apache-2.0' })).toEqual([
      'Apache-2.0',
    ]);
  });

  it('keeps nothing when both say nothing', () => {
    expect(one({ licenseConcluded: 'NOASSERTION', licenseDeclared: 'NOASSERTION' })).toEqual([]);
    expect(one({ licenseConcluded: 'NONE', licenseDeclared: 'NONE' })).toEqual([]);
    expect(one({})).toEqual([]);
  });

  it('drops a licence string over 256 characters', () => {
    expect(one({ licenseConcluded: `MIT AND ${'X'.repeat(300)}` })).toEqual([]);
  });
});

describe('direct', () => {
  const pkgs = [
    spdxPkg('root', null),
    spdxPkg('a', 'pkg:npm/a@1'),
    spdxPkg('b', 'pkg:npm/b@1'),
    spdxPkg('c', 'pkg:npm/c@1'),
  ];
  const direct = (relationships: unknown[]) =>
    Object.fromEntries(
      invOf(spdx(pkgs, [spdxRel('DOCUMENT', 'DESCRIBES', 'root'), ...relationships])).entries.map(
        (e) => [e.name, e.direct],
      ),
    );

  it('is true for a DEPENDS_ON from the subject, false for the others', () => {
    expect(direct([spdxRel('root', 'DEPENDS_ON', 'a'), spdxRel('a', 'DEPENDS_ON', 'b')])).toEqual({
      a: true,
      b: false,
      c: false,
    });
  });

  it('is false when other packages depend on each other but the subject on none', () => {
    expect(direct([spdxRel('a', 'DEPENDS_ON', 'b')])).toEqual({ a: false, b: false, c: false });
  });

  it('is null with only CONTAINS', () => {
    expect(direct([spdxRel('root', 'CONTAINS', 'a')])).toEqual({ a: null, b: null, c: null });
  });

  it('is null without a subject', () => {
    const doc = spdx(pkgs, [spdxRel('a', 'DEPENDS_ON', 'b')]);
    expect(invOf(doc).entries.every((e) => e.direct === null)).toBe(true);
  });
});

describe('externalRefs', () => {
  const one = (refs: unknown[]) => invOf(spdx([{ ...spdxPkg('a', null), externalRefs: refs }]));
  const purl = (category: string) => ({
    referenceCategory: category,
    referenceType: 'purl',
    referenceLocator: 'pkg:npm/a@1',
  });

  it('reads PACKAGE-MANAGER and PACKAGE_MANAGER', () => {
    expect(one([purl('PACKAGE-MANAGER')]).entries).toHaveLength(1);
    expect(one([purl('PACKAGE_MANAGER')]).entries).toHaveLength(1);
  });

  it('ignores a SECURITY reference', () => {
    const inv = one([
      { referenceCategory: 'SECURITY', referenceType: 'cpe23Type', referenceLocator: 'cpe:2.3:a' },
      purl('SECURITY'),
    ]);
    expect(inv.entries).toEqual([]);
    expect(inv.skipped.noPurl).toBe(1);
  });

  it('counts a package with no reference as noPurl', () => {
    const inv = invOf(spdx([spdxPkg('a', null), spdxPkg('b', 'pkg:npm/b@1')]));
    expect(inv.entries).toHaveLength(1);
    expect(inv.skipped.noPurl).toBe(1);
  });

  it('counts a purl that does not parse, and warns', () => {
    const inv = invOf(spdx([spdxPkg('a', 'not a purl'), spdxPkg('b', 'pkg:npm/b@1')]));
    expect(inv.skipped.noPurl).toBe(1);
    expect(inv.warnings.map((w) => w.code)).toEqual(['SBOM_PURL_INVALID']);
  });
});

describe('subject and operating system', () => {
  it('finds the subject through documentDescribes', () => {
    const inv = invOf(
      spdx([spdxPkg('root', 'pkg:npm/root@2', { name: 'myapp', versionInfo: '2.0' })], [], {
        documentDescribes: ['SPDXRef-root'],
      }),
    );
    expect(inv.subject).toBe('myapp 2.0');
    expect(inv.subjectVersion).toBe('2.0');
    expect(inv.entries).toEqual([]);
  });

  it('reads DESCRIBED_BY as well as DESCRIBES', () => {
    const inv = invOf(
      spdx(
        [spdxPkg('a', 'pkg:npm/a@1'), spdxPkg('root', null, { name: 'app' })],
        [spdxRel('root', 'DESCRIBED_BY', 'DOCUMENT')],
      ),
    );
    expect(inv.subject).toBe('app 1');
    expect(inv.entries).toHaveLength(1);
  });

  it('has no subject without a described package', () => {
    const inv = invOf(spdx([spdxPkg('a', 'pkg:npm/a@1')]));
    expect(inv.subject).toBeNull();
    expect(inv.subjectVersion).toBeNull();
    expect(inv.entries).toHaveLength(1);
  });

  it.each(['OPERATING-SYSTEM', 'OPERATING_SYSTEM'])(
    'takes a package of purpose %s as the distribution',
    (primaryPackagePurpose) => {
      const inv = invOf(
        spdx([
          spdxPkg('os', null, { name: 'alpine', versionInfo: '3.20.3', primaryPackagePurpose }),
          spdxPkg('a', 'pkg:apk/alpine/a@1-r0'),
        ]),
      );
      expect(inv.distribution).toEqual({ family: 'alpine', version: '3.20.3' });
      expect(inv.entries).toHaveLength(1);
      expect(inv.skipped.noPurl).toBe(0);
    },
  );

  it('reads a source package only from the built-from form of sourceInfo', () => {
    const src = (sourceInfo: string) =>
      invOf(spdx([spdxPkg('a', 'pkg:deb/debian/a@1?distro=debian-12', { sourceInfo })])).entries[0]!
        .source;
    expect(src('built package from: srcpkg 2:3.4-1')).toEqual({
      name: 'srcpkg',
      version: '2:3.4-1',
    });
    expect(src('acquired package info from DPKG DB: /var/lib/dpkg/status')).toEqual({
      name: 'a',
      version: '1',
    });
    expect(src(`built package from: ${'x'.repeat(5_000)} 1`)).toEqual({ name: 'a', version: '1' });
  });
});

describe('refusals', () => {
  it('refuses SPDX 2.1 as unsupported', () => {
    const r = refusal(text(spdx([], [], { spdxVersion: 'SPDX-2.1' })));
    expect(r.code).toBe('SBOM_FORMAT_UNSUPPORTED');
    expect(r.message).toMatch(/SPDX 2\.3 JSON/);
  });

  it('refuses SPDX 3.0 as unsupported', () => {
    const r = refusal(sample('spdx-3.0.json'));
    expect(r.code).toBe('SBOM_FORMAT_UNSUPPORTED');
    expect(r.message).toMatch(/SPDX 2\.3 JSON/);
  });

  it('refuses a document whose SPDXID is not SPDXRef-DOCUMENT', () => {
    const r = refusal(text(spdx([], [], { SPDXID: 'SPDXRef-X' })));
    expect(r.code).toBe('SBOM_INVALID');
    expect(r.path).toBe('SPDXID');
  });

  it('refuses packages that are not an array, naming the path', () => {
    const r = refusal(text(spdx([], [], { packages: {} })));
    expect(r.code).toBe('SBOM_INVALID');
    expect(r.path).toBe('packages');
  });

  it('refuses a package of the wrong shape, naming the path', () => {
    const r = refusal(text(spdx([spdxPkg('a', 'pkg:npm/a@1'), { SPDXID: 5 }])));
    expect(r.code).toBe('SBOM_INVALID');
    expect(r.path).toBe('packages.1.SPDXID');
  });

  it('refuses a relationship of the wrong shape', () => {
    const r = refusal(text(spdx([], [{ spdxElementId: 'SPDXRef-a' }])));
    expect(r.path).toBe('relationships.0.relatedSpdxElement');
  });

  it('refuses SPDX tag-value as not JSON, suggesting the JSON export', () => {
    const r = refusal(sample('spdx.tag-value.spdx'));
    expect(r.code).toBe('SBOM_INVALID');
    expect(r.message).toMatch(/JSON/);
  });

  it('refuses a version that is not a string', () => {
    expect(readSpdx({ spdxVersion: 3 })).toMatchObject({
      code: 'SBOM_INVALID',
      path: 'spdxVersion',
    });
  });
});

describe('hostile input', () => {
  it('bounds and cleans the subject name', () => {
    const inv = invOf(
      spdx(
        [spdxPkg('root', null, { name: `r${'x'.repeat(5_000)}\0` }), spdxPkg('a', 'pkg:npm/a@1')],
        [spdxRel('DOCUMENT', 'DESCRIBES', 'root')],
      ),
    );
    expect(inv.subject!.length).toBeLessThanOrEqual(512);
    expect(inv.subject).not.toContain('\0');
  });

  it('parses 50 000 packages and 100 000 relationships in linear time', () => {
    const packages: unknown[] = [spdxPkg('root', null)];
    const relationships: unknown[] = [spdxRel('DOCUMENT', 'DESCRIBES', 'root')];
    for (let n = 0; n < 50_000; n++) {
      packages.push(spdxPkg(`p${n}`, `pkg:npm/p${n}@1`));
      relationships.push(spdxRel('root', 'DEPENDS_ON', `p${n}`));
      relationships.push(spdxRel(`p${n}`, 'DEPENDS_ON', `p${(n + 1) % 50_000}`));
    }
    const body = text(spdx(packages, relationships));
    const started = performance.now();
    const result = parseSbom(body);
    expect(performance.now() - started).toBeLessThan(budgetMs(3_000));
    expect(result).toHaveProperty('inventory');
    if ('inventory' in result) {
      expect(result.inventory.entries).toHaveLength(50_000);
      expect(result.inventory.entries.every((e) => e.direct === true)).toBe(true);
    }
  });

  it('reads a sample through the reader directly', () => {
    expect(readSpdx(sampleJson('syft-node.spdx-2.2.json'))).toMatchObject({ format: 'SPDX 2.2' });
  });
});

describe('readSpdx: shapes', () => {
  const header = { spdxVersion: 'SPDX-2.3', SPDXID: 'SPDXRef-DOCUMENT' };

  it('reads a document without packages or relationships', () => {
    expect(readSpdx(header)).toEqual({
      format: 'SPDX 2.3',
      subject: null,
      operatingSystems: [],
      components: [],
      skipped: { noPurl: 0, unsupportedType: 0 },
      invalidPurls: [],
      tooDeep: 0,
    });
  });

  it('takes the first of two packages with one SPDXID as the subject, and skips both', () => {
    const inv = invOf(
      spdx(
        [
          spdxPkg('root', 'pkg:npm/root@1', { name: 'first' }),
          spdxPkg('root', 'pkg:npm/root@2', { name: 'second' }),
          spdxPkg('a', 'pkg:npm/a@1'),
        ],
        [spdxRel('DOCUMENT', 'DESCRIBES', 'root')],
      ),
    );
    expect(inv.subject).toBe('first 1');
    expect(inv.entries.map((e) => e.name)).toEqual(['a']);
  });

  it('has no subject for a package without a name, and still reads its graph', () => {
    const inv = invOf(
      spdx(
        [{ SPDXID: 'SPDXRef-root' }, spdxPkg('a', 'pkg:npm/a@1'), spdxPkg('b', 'pkg:npm/b@1')],
        [spdxRel('DOCUMENT', 'DESCRIBES', 'root'), spdxRel('root', 'DEPENDS_ON', 'a')],
      ),
    );
    expect(inv.subject).toBeNull();
    expect(inv.subjectVersion).toBeNull();
    expect(inv.entries.map((e) => [e.name, e.direct])).toEqual([
      ['a', true],
      ['b', false],
    ]);
  });

  it('skips an operating system without a name, and reads one without a version', () => {
    const result = readSpdx(
      spdx([
        { SPDXID: 'SPDXRef-OperatingSystem-a', versionInfo: '12' },
        { SPDXID: 'SPDXRef-x', name: '  ', primaryPackagePurpose: 'OPERATING_SYSTEM' },
        { SPDXID: 'SPDXRef-OperatingSystem-b', name: ' debian ' },
      ]),
    );
    expect(result).toMatchObject({
      operatingSystems: [{ name: 'debian', version: '' }],
      components: [],
      skipped: { noPurl: 0, unsupportedType: 0 },
    });
  });

  it('counts every purl that does not parse and names the first three', () => {
    const result = readSpdx(
      spdx(['pkg:', 'pkg:npm/', 'x', 'y'].map((purl, i) => spdxPkg(`p${i}`, purl))),
    );
    expect(result).toMatchObject({
      invalidPurls: ['pkg:', 'pkg:npm/', 'x'],
      skipped: { noPurl: 4, unsupportedType: 0 },
    });
  });
});
