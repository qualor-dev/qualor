import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { cycloneDxLicenses, spdxLicense } from './licenses';

const ref = (text: string): string =>
  `LicenseRef-${createHash('sha256').update(text).digest('hex').slice(0, 12)}`;

describe('cycloneDxLicenses', () => {
  it('gives one AND-joined expression for simple ids', () => {
    expect(cycloneDxLicenses(['MIT', 'Apache-2.0'])).toEqual([
      { expression: 'MIT AND Apache-2.0' },
    ]);
    expect(cycloneDxLicenses(['MIT'])).toEqual([{ expression: 'MIT' }]);
  });

  it('writes ids in their canonical spelling', () => {
    expect(cycloneDxLicenses(['mit'])).toEqual([{ expression: 'MIT' }]);
    expect(spdxLicense(['mit', 'apache-2.0'], new Map())).toBe('MIT AND Apache-2.0');
  });

  it('joins a list with a compound entry into one AND expression', () => {
    expect(cycloneDxLicenses(['MIT OR Apache-2.0', 'BSD-3-Clause'])).toEqual([
      { expression: '(MIT OR Apache-2.0) AND BSD-3-Clause' },
    ]);
  });

  it('gives names for every entry when one is free text', () => {
    expect(cycloneDxLicenses(['MIT', 'Some Custom Licence'])).toEqual([
      { license: { name: 'MIT' } },
      { license: { name: 'Some Custom Licence' } },
    ]);
  });

  it('treats a term that is not a real SPDX id as unparsable', () => {
    expect(cycloneDxLicenses(['Foo-1.0'])).toEqual([{ license: { name: 'Foo-1.0' } }]);
    expect(cycloneDxLicenses(['MIT WITH Not-An-Exception'])).toEqual([
      { license: { name: 'MIT WITH Not-An-Exception' } },
    ]);
  });

  it('keeps a valid WITH exception as an expression', () => {
    expect(cycloneDxLicenses(['GPL-2.0-only WITH Classpath-exception-2.0'])).toEqual([
      { expression: 'GPL-2.0-only WITH Classpath-exception-2.0' },
    ]);
  });

  it('gives undefined for an empty list', () => {
    expect(cycloneDxLicenses([])).toBeUndefined();
  });
});

describe('spdxLicense', () => {
  it('AND-joins simple ids', () => {
    const extracted = new Map<string, string>();
    expect(spdxLicense(['MIT', 'Apache-2.0'], extracted)).toBe('MIT AND Apache-2.0');
    expect(extracted.size).toBe(0);
  });

  it('parenthesises an OR inside the AND', () => {
    expect(spdxLicense(['MIT OR Apache-2.0', 'BSD-3-Clause'], new Map())).toBe(
      '(MIT OR Apache-2.0) AND BSD-3-Clause',
    );
  });

  it('replaces free text by a LicenseRef and records its text', () => {
    const extracted = new Map<string, string>();
    expect(spdxLicense(['MIT', 'Some Custom Licence'], extracted)).toBe(
      `MIT AND ${ref('Some Custom Licence')}`,
    );
    expect([...extracted]).toEqual([[ref('Some Custom Licence'), 'Some Custom Licence']]);
    expect(ref('Some Custom Licence')).toMatch(/^LicenseRef-[0-9a-f]{12}$/);
  });

  it('treats a term that is not a real SPDX id as unparsable', () => {
    const extracted = new Map<string, string>();
    expect(spdxLicense(['Foo-1.0'], extracted)).toBe(ref('Foo-1.0'));
    expect(extracted.get(ref('Foo-1.0'))).toBe('Foo-1.0');
  });

  it('gives NOASSERTION for an empty list', () => {
    expect(spdxLicense([], new Map())).toBe('NOASSERTION');
  });
});
