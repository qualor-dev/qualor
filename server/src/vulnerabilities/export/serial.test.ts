import { describe, expect, it } from 'vitest';
import { sbomSerial } from './serial';
import type { ExportPackage } from './types';

const PROJECT = '0197a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b';
const TARGET = 'branch:0197a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c';

const PACKAGES: ExportPackage[] = [
  {
    ecosystem: 'npm',
    name: 'lodash',
    version: '4.17.21',
    purl: 'pkg:npm/lodash@4.17.21',
    source: null,
    licenses: ['MIT'],
  },
  {
    ecosystem: 'pip',
    name: 'requests',
    version: '2.31.0',
    purl: null,
    source: null,
    licenses: ['Apache-2.0'],
  },
];

describe('sbomSerial', () => {
  it('gives the same serial for the same input', () => {
    expect(sbomSerial(PROJECT, TARGET, PACKAGES)).toBe(sbomSerial(PROJECT, TARGET, PACKAGES));
  });

  it('gives another serial when a package version changes', () => {
    const changed = PACKAGES.map((p) => (p.name === 'lodash' ? { ...p, version: '4.17.20' } : p));
    expect(sbomSerial(PROJECT, TARGET, changed)).not.toBe(sbomSerial(PROJECT, TARGET, PACKAGES));
  });

  it('is a version 8 uuid', () => {
    expect(sbomSerial(PROJECT, TARGET, PACKAGES)).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });

  it('does not depend on the order of the packages or of their licences', () => {
    const reordered = [...PACKAGES].reverse().map((p) => ({
      ...p,
      licenses: [...p.licenses, 'BSD-3-Clause'].reverse(),
    }));
    const extended = PACKAGES.map((p) => ({ ...p, licenses: [...p.licenses, 'BSD-3-Clause'] }));
    expect(sbomSerial(PROJECT, TARGET, reordered)).toBe(sbomSerial(PROJECT, TARGET, extended));
  });

  it('gives another serial for another project or target', () => {
    const serial = sbomSerial(PROJECT, TARGET, PACKAGES);
    expect(sbomSerial(PROJECT, 'version:0197a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c', PACKAGES)).not.toBe(
      serial,
    );
    expect(sbomSerial('0197a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5d', TARGET, PACKAGES)).not.toBe(serial);
  });
});

describe('sbomSerial and the distribution', () => {
  const debian = { family: 'debian', version: '12.15' };
  it('keeps the serial without one, and changes it with one', () => {
    expect(sbomSerial(PROJECT, TARGET, PACKAGES, null)).toBe(sbomSerial(PROJECT, TARGET, PACKAGES));
    expect(sbomSerial(PROJECT, TARGET, PACKAGES, debian)).not.toBe(
      sbomSerial(PROJECT, TARGET, PACKAGES),
    );
    expect(sbomSerial(PROJECT, TARGET, PACKAGES, { ...debian, version: '12.14' })).not.toBe(
      sbomSerial(PROJECT, TARGET, PACKAGES, debian),
    );
  });
});
