import { describe, expect, it } from 'vitest';
import { setYamlOverride } from './yaml';

const WORKSPACE = `packages:
  - 'packages/*'

overrides:
  qf-unused: 1.0.0
  '@scope/b': ^2.0.0

catalog:
  react: ^19.0.0
`;

describe('setYamlOverride (ruling F15)', () => {
  it('adds a pin after the last entry of the block map, keeping every other byte', () => {
    expect(setYamlOverride(WORKSPACE, 'qf-a', '^1.2.6')).toBe(
      WORKSPACE.replace("  '@scope/b': ^2.0.0\n", "  '@scope/b': ^2.0.0\n  qf-a: ^1.2.6\n"),
    );
  });

  it('quotes a key YAML would not read as plain text', () => {
    expect(setYamlOverride(WORKSPACE, '@scope/c', '^1.0.1')).toContain("  '@scope/c': ^1.0.1\n");
    expect(setYamlOverride(WORKSPACE, 'qf-a@>=1.0.0 <2.0.0', '^1.2.6')).toContain(
      "  'qf-a@>=1.0.0 <2.0.0': ^1.2.6\n",
    );
  });

  it('replaces the value of an existing pin only, in its quoting style', () => {
    expect(setYamlOverride(WORKSPACE, '@scope/b', '^2.0.3')).toBe(
      WORKSPACE.replace("'@scope/b': ^2.0.0", "'@scope/b': ^2.0.3"),
    );
    const quoted = 'overrides:\n  "qf-a": "1.2.5"\n  qf-b: \'1.0.0\'\n';
    expect(setYamlOverride(quoted, 'qf-a', '^1.2.6')).toBe(
      'overrides:\n  "qf-a": "^1.2.6"\n  qf-b: \'1.0.0\'\n',
    );
    expect(setYamlOverride(quoted, 'qf-b', '^1.0.1')).toBe(
      'overrides:\n  "qf-a": "1.2.5"\n  qf-b: \'^1.0.1\'\n',
    );
  });

  it('keeps CRLF line endings and a missing final newline', () => {
    const crlf = 'overrides:\r\n    qf-x: 1.0.0\r\n';
    expect(setYamlOverride(crlf, 'qf-a', '^1.2.6')).toBe(
      'overrides:\r\n    qf-x: 1.0.0\r\n    qf-a: ^1.2.6\r\n',
    );
    expect(setYamlOverride('overrides:\n  qf-x: 1.0.0', 'qf-a', '^1.2.6')).toBe(
      'overrides:\n  qf-x: 1.0.0\n  qf-a: ^1.2.6',
    );
  });

  it('finds overrides on the first line after a byte order mark, and keeps the mark (Ruling T13e)', () => {
    expect(setYamlOverride('﻿overrides:\n  qf-x: 1.0.0\n', 'qf-a', '^1.2.6')).toBe(
      '﻿overrides:\n  qf-x: 1.0.0\n  qf-a: ^1.2.6\n',
    );
    expect(setYamlOverride('﻿overrides:\r\n  qf-a: 1.2.5\r\n', 'qf-a', '^1.2.6')).toBe(
      '﻿overrides:\r\n  qf-a: ^1.2.6\r\n',
    );
  });

  it('fills an empty overrides key with the indent the file uses elsewhere', () => {
    expect(setYamlOverride("packages:\n    - '.'\noverrides:\n", 'qf-a', '^1.2.6')).toBe(
      "packages:\n    - '.'\noverrides:\n    qf-a: ^1.2.6\n",
    );
  });

  it.each([
    ['flow style', 'overrides: { qf-x: 1.0.0 }\n'],
    ['an empty flow map', 'overrides: {}\n'],
    ['an anchor', 'overrides: &pins\n  qf-x: 1.0.0\n'],
    ['an alias value', 'base: &v 1.0.0\noverrides:\n  qf-x: *v\n'],
    ['a comment inside the map', 'overrides:\n  # pinned for CVE-1\n  qf-x: 1.0.0\n'],
    ['a trailing comment on an entry', 'overrides:\n  qf-x: 1.0.0 # why\n'],
    ['a nested map', 'overrides:\n  qf-x:\n    a: 1\n'],
    ['a tag', 'overrides:\n  qf-x: !!str 1.0.0\n'],
    ['no overrides key', 'packages:\n  - .\n'],
    ['two documents', 'overrides:\n  qf-x: 1.0.0\n---\na: 1\n'],
  ])('is null for %s', (_what, text) => {
    expect(setYamlOverride(text, 'qf-a', '^1.2.6')).toBeNull();
  });

  it('ignores a comment line after the map', () => {
    const text = 'overrides:\n  qf-x: 1.0.0\n# the catalog\ncatalog:\n  a: 1.0.0\n';
    expect(setYamlOverride(text, 'qf-a', '^1.2.6')).toBe(
      'overrides:\n  qf-x: 1.0.0\n  qf-a: ^1.2.6\n# the catalog\ncatalog:\n  a: 1.0.0\n',
    );
  });
});
