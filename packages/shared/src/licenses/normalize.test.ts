import { describe, expect, it } from 'vitest';
import { normalizeLicense } from './normalize';

describe('normalizeLicense on hostile input', () => {
  it.each(['constructor', '__proto__', 'toString', 'hasOwnProperty'])(
    'returns %s as a string, not an Object.prototype member',
    (raw) => {
      expect(normalizeLicense(raw)).toBe(raw);
    },
  );

  it('returns a text too long to parse as written, without throwing', () => {
    const chain = `${'MIT AND '.repeat(5_000)}MIT`;
    expect(normalizeLicense(chain)).toBe(chain);
    const nested = `${'('.repeat(10_000)}MIT${')'.repeat(10_000)}`;
    expect(normalizeLicense(nested)).toBe(nested);
  });
});

describe('normalizeLicense', () => {
  it.each([
    ['GPLv2', 'GPL-2.0-only'],
    ['GPLv2+', 'GPL-2.0-or-later'],
    ['GPL-2.0', 'GPL-2.0-only'],
    ['GPL-2.0+', 'GPL-2.0-or-later'],
    ['GPLv3', 'GPL-3.0-only'],
    ['GPLv3+', 'GPL-3.0-or-later'],
    ['GPL-3.0', 'GPL-3.0-only'],
    ['GPL-3.0+', 'GPL-3.0-or-later'],
    ['LGPLv2.1', 'LGPL-2.1-only'],
    ['LGPLv2.1+', 'LGPL-2.1-or-later'],
    ['LGPL-2.1', 'LGPL-2.1-only'],
    ['LGPL-2.1+', 'LGPL-2.1-or-later'],
    ['LGPLv3', 'LGPL-3.0-only'],
    ['LGPLv3+', 'LGPL-3.0-or-later'],
    ['LGPL-3.0', 'LGPL-3.0-only'],
    ['LGPL-3.0+', 'LGPL-3.0-or-later'],
    ['AGPLv3', 'AGPL-3.0-only'],
    ['AGPLv3+', 'AGPL-3.0-or-later'],
    ['AGPL-3.0', 'AGPL-3.0-only'],
    ['AGPL-3.0+', 'AGPL-3.0-or-later'],
    ['Apache 2.0', 'Apache-2.0'],
    ['Apache-2', 'Apache-2.0'],
    ['Apache License 2.0', 'Apache-2.0'],
    ['BSD', 'BSD-3-Clause'],
    ['BSD-2', 'BSD-2-Clause'],
    ['BSD-3', 'BSD-3-Clause'],
    ['MIT License', 'MIT'],
    ['ISC License', 'ISC'],
  ])('maps %s to %s', (raw, expected) => {
    expect(normalizeLicense(raw)).toBe(expected);
  });

  it('is case-insensitive and trims', () => {
    expect(normalizeLicense('  mit  ')).toBe('MIT');
    expect(normalizeLicense('apache license 2.0')).toBe('Apache-2.0');
    expect(normalizeLicense('gplv2+')).toBe('GPL-2.0-or-later');
    expect(normalizeLicense('MIT license')).toBe('MIT');
    expect(normalizeLicense('apache-2.0')).toBe('Apache-2.0');
  });

  it('canonicalises the ids inside an expression', () => {
    expect(normalizeLicense('mit or gpl-2.0+')).toBe('MIT OR GPL-2.0-or-later');
    expect(normalizeLicense('(mit or apache-2.0) and bsd-3-clause')).toBe(
      '(MIT OR Apache-2.0) AND BSD-3-Clause',
    );
  });

  it('returns what it cannot map as it is, trimmed', () => {
    expect(normalizeLicense('Public Domain')).toBe('Public Domain');
    expect(normalizeLicense('  Weird-Licence ')).toBe('Weird-Licence');
    expect(normalizeLicense('SEE LICENSE IN LICENSE.txt')).toBe('SEE LICENSE IN LICENSE.txt');
    expect(normalizeLicense('')).toBe('');
  });
});
