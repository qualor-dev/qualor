import { describe, expect, it } from 'vitest';
import { checkGoMod, checkGoSum, readGoMod, readGoSum } from './go';
import type { FixCheckContext, FixFileChange } from './types';

const PKG = 'example.com/qf';

const ctx = (lockfile = 'go.mod'): FixCheckContext => ({
  family: 'go',
  packageName: PKG,
  targets: [{ installed: 'v1.2.5', target: 'v1.2.6', lockfile }],
});

function mod(path: string, base: string, next: string) {
  return checkGoMod({ path, base, next } satisfies FixFileChange, ctx(path));
}

function sum(path: string, base: string, next: string) {
  return checkGoSum({ path, base, next } satisfies FixFileChange, ctx('go.mod'));
}

const GO_MOD = (qf: string, extra = '') => `module example.com/app

go 1.22

require (
\t${PKG} ${qf}
\tgolang.org/x/text v0.14.0
)

require example.com/lib v0.3.0 // indirect
${extra}`;

const BASE = GO_MOD('v1.2.5');

describe('readGoMod', () => {
  it('reads the module, the directives and the requires of blocks and single lines', () => {
    const text = `// Deprecated: use example.com/app/v2.
module example.com/app

go 1.22

toolchain go1.22.4

require (
\texample.com/qf v1.2.5
\tgolang.org/x/text v0.14.0 // indirect
\t"example.com/quoted" v0.1.0 // indirect; needed by tests
)

require example.com/lib v0.3.0 // indirect

replace example.com/old => example.com/new v1.0.0

exclude (
\texample.com/bad v0.0.1
)

retract [v1.0.0, v1.0.1]
`;
    expect(readGoMod(text)).toEqual({
      module: 'example.com/app',
      directives: [
        { verb: 'module', text: 'example.com/app' },
        { verb: 'go', text: '1.22' },
        { verb: 'toolchain', text: 'go1.22.4' },
        { verb: 'replace', text: 'example.com/old => example.com/new v1.0.0' },
        { verb: 'exclude', text: 'example.com/bad v0.0.1' },
        { verb: 'retract', text: '[ v1.0.0 , v1.0.1 ]' },
      ],
      requires: [
        { path: 'example.com/qf', version: 'v1.2.5', indirect: false },
        { path: 'golang.org/x/text', version: 'v0.14.0', indirect: true },
        { path: 'example.com/quoted', version: 'v0.1.0', indirect: true },
        { path: 'example.com/lib', version: 'v0.3.0', indirect: true },
      ],
    });
  });

  it('reads CRLF line endings and a BOM', () => {
    const text = '\uFEFF' + BASE.replaceAll('\n', '\r\n');
    expect(readGoMod(text)).toEqual(readGoMod(BASE));
  });

  it.each([
    ['an unterminated block', 'module a\n\nrequire (\n\tb v1.0.0\n'],
    ['a stray closing parenthesis', 'module a\n)\n'],
    ['a block that does not start at the end of its line', 'module a\nrequire ( b v1.0.0\n)\n'],
    ['a require with three arguments', 'module a\nrequire b v1.0.0 v2.0.0\n'],
    ['two module lines', 'module a\nmodule b\n'],
    ['a /* comment', 'module a\n/* x */\n'],
    ['a newline inside a string', 'module a\nrequire "b\nc" v1.0.0\n'],
    ['an escape inside a string', 'module a\nrequire "b\\u0063" v1.0.0\n'],
    ['a control character', 'module a\nrequire b\u0007 v1.0.0\n'],
    ['a non-breaking space', 'module a\nrequire b\u00a0v1.0.0\n'],
    ['a brace', 'module a\nretract {v1.0.0}\n'],
    ['a quoted verb', 'module a\n"require" b v1.0.0\n'],
  ])('throws on %s', (_name, text) => {
    expect(() => readGoMod(text)).toThrow();
  });
});

describe('checkGoMod', () => {
  it('accepts a version raise of the package and an added // indirect require', () => {
    const next = GO_MOD('v1.2.6', 'require example.com/dep v0.2.0 // indirect\n');
    expect(mod('go.mod', BASE, next)).toEqual({ ok: true });
  });

  it('accepts raised requires of other modules, a dropped // indirect require, and a moved line', () => {
    const next = `module example.com/app

go 1.22

require (
\t${PKG} v1.2.6
\tgolang.org/x/text v0.15.0
)
`;
    expect(mod('svc/a/go.mod', BASE, next)).toEqual({ ok: true });
  });

  it('accepts the package added as its own require (transitive), direct or // indirect', () => {
    const base = 'module example.com/app\n\ngo 1.22\n';
    expect(mod('go.mod', base, `${base}\nrequire ${PKG} v1.2.6 // indirect\n`)).toEqual({
      ok: true,
    });
    expect(mod('go.mod', base, `${base}\nrequire ${PKG} v1.2.6\n`)).toEqual({ ok: true });
  });

  it('accepts a // indirect marker that comes or goes', () => {
    const next = GO_MOD('v1.2.6 // indirect').replace(
      'example.com/lib v0.3.0 // indirect',
      'example.com/lib v0.3.0',
    );
    expect(mod('go.mod', BASE, next)).toEqual({ ok: true });
  });

  it('keeps CRLF and a BOM readable', () => {
    const base = '\uFEFF' + BASE.replaceAll('\n', '\r\n');
    const next = '\uFEFF' + GO_MOD('v1.2.6').replaceAll('\n', '\r\n');
    expect(mod('go.mod', base, next)).toEqual({ ok: true });
  });

  describe('smuggling (§11.8)', () => {
    it.each([
      ['an added replace', GO_MOD('v1.2.6', 'replace example.com/a => ../evil\n')],
      [
        'an added replace block',
        GO_MOD('v1.2.6', 'replace (\n\texample.com/qf v1.2.6 => ../evil\n)\n'),
      ],
      ['an added toolchain', GO_MOD('v1.2.6', 'toolchain go1.30.0\n')],
      ['an added exclude', GO_MOD('v1.2.6', 'exclude example.com/qf v1.2.5\n')],
      ['an added retract', GO_MOD('v1.2.6', 'retract v0.1.0\n')],
      ['an added tool', GO_MOD('v1.2.6', 'tool example.com/evil/cmd\n')],
      ['an added godebug', GO_MOD('v1.2.6', 'godebug default=go1.21\n')],
      ['an unknown directive', GO_MOD('v1.2.6', 'evil example.com/x\n')],
      ['a changed go line', GO_MOD('v1.2.6').replace('go 1.22', 'go 1.23')],
      ['a changed module line', GO_MOD('v1.2.6').replace('module example.com/app', 'module x')],
    ])('refuses %s as go_directive', (_name, next) => {
      expect(mod('go.mod', BASE, next)).toEqual({
        ok: false,
        rule: 'go_directive',
        path: 'go.mod',
      });
    });

    it('refuses a changed replace in a base that has one', () => {
      const base = GO_MOD('v1.2.5', 'replace example.com/a => example.com/b v1.0.0\n');
      const next = GO_MOD('v1.2.6', 'replace example.com/a => ../evil\n');
      expect(mod('go.mod', base, next)).toMatchObject({ rule: 'go_directive' });
      // The same replace written as a block is the same directive.
      const block = GO_MOD('v1.2.6', 'replace (\n\texample.com/a => example.com/b v1.0.0\n)\n');
      expect(mod('go.mod', base, block)).toEqual({ ok: true });
    });
  });

  it('refuses a lowered require as other_change', () => {
    const next = GO_MOD('v1.2.6').replace('golang.org/x/text v0.14.0', 'golang.org/x/text v0.13.0');
    expect(mod('go.mod', BASE, next)).toEqual({
      ok: false,
      rule: 'other_change',
      path: 'go.mod',
    });
  });

  it('refuses a dropped direct require as other_change', () => {
    const next = GO_MOD('v1.2.6').replace('\tgolang.org/x/text v0.14.0\n', '');
    expect(mod('go.mod', BASE, next)).toMatchObject({ rule: 'other_change' });
  });

  it('refuses an added direct require of another module as new_dependency', () => {
    const next = GO_MOD('v1.2.6', 'require example.com/evil v1.0.0\n');
    expect(mod('go.mod', BASE, next)).toMatchObject({ rule: 'new_dependency' });
  });

  it.each(['master', 'latest', 'v1.2', 'v1.2.x'])(
    'refuses the version %s, which is no Go module version, as bad_spec',
    (version) => {
      expect(mod('go.mod', BASE, GO_MOD(version))).toMatchObject({ rule: 'bad_spec' });
      const added = GO_MOD('v1.2.6', `require example.com/dep ${version} // indirect\n`);
      expect(mod('go.mod', BASE, added)).toMatchObject({ rule: 'bad_spec' });
    },
  );

  it('refuses the package below its target as below_target', () => {
    expect(mod('go.mod', BASE, BASE)).toEqual({ ok: false, rule: 'below_target', path: 'go.mod' });
    const pseudo = GO_MOD('v1.2.6-0.20240101000000-abcdefabcdef');
    expect(mod('go.mod', BASE, pseudo)).toMatchObject({ rule: 'below_target' });
    expect(mod('go.mod', BASE, GO_MOD('v1.3.0'))).toEqual({ ok: true });
  });

  it('applies only the targets of this go.mod (Ruling F14)', () => {
    const other = checkGoMod({ path: 'svc/b/go.mod', base: BASE, next: BASE }, ctx('svc/a/go.mod'));
    expect(other).toEqual({ ok: true });
  });

  it('refuses a duplicated require of a module as other_change', () => {
    const next = GO_MOD('v1.2.6', `require ${PKG} v1.2.7\n`);
    expect(mod('go.mod', BASE, next)).toMatchObject({ rule: 'other_change' });
  });

  it('answers unparsable, without throwing, for a file it cannot read', () => {
    expect(mod('go.mod', BASE, 'module a\nrequire (\n')).toEqual({
      ok: false,
      rule: 'unparsable',
      path: 'go.mod',
    });
  });
});

const H = (c: string) => `h1:${c.repeat(43)}=`;

const GO_SUM = (qf: string) => `${PKG} ${qf} ${H('a')}
${PKG} ${qf}/go.mod ${H('b')}
golang.org/x/text v0.14.0 ${H('c')}
golang.org/x/text v0.14.0/go.mod ${H('d')}
`;

describe('readGoSum', () => {
  it('reads each line as a registry entry, /go.mod lines included, the h1: hash as integrity', () => {
    expect(readGoSum(GO_SUM('v1.2.5'))).toEqual([
      {
        name: PKG,
        version: 'v1.2.5',
        source: null,
        kind: 'registry',
        integrity: H('a'),
        dependencies: [],
        dependents: [],
      },
      {
        name: PKG,
        version: 'v1.2.5/go.mod',
        source: null,
        kind: 'registry',
        integrity: H('b'),
        dependencies: [],
        dependents: [],
      },
      expect.objectContaining({ name: 'golang.org/x/text', version: 'v0.14.0' }),
      expect.objectContaining({ name: 'golang.org/x/text', version: 'v0.14.0/go.mod' }),
    ]);
  });

  it('reads a line without an h1: hash with no integrity, and throws on a malformed line', () => {
    expect(readGoSum(`${PKG} v1.2.6 sha256:abc\n${PKG} v1.2.7\n`)).toMatchObject([
      { version: 'v1.2.6', integrity: null },
      { version: 'v1.2.7', integrity: null },
    ]);
    expect(() => readGoSum(`${PKG}\n`)).toThrow();
    expect(() => readGoSum(`${PKG} v1.2.6 ${H('a')} extra\n`)).toThrow();
  });
});

describe('checkGoSum', () => {
  it('accepts new lines with h1: hashes, and does not check targets (Ruling F14)', () => {
    expect(sum('go.sum', GO_SUM('v1.2.5'), GO_SUM('v1.2.6'))).toEqual({ ok: true });
    // go.sum keeps old lines; the package's versions there are no evidence of the build.
    expect(sum('go.sum', GO_SUM('v1.2.5'), GO_SUM('v1.2.5'))).toEqual({ ok: true });
  });

  it('accepts new lines of modules the base did not have (no graph to follow)', () => {
    const next = `${GO_SUM('v1.2.6')}example.com/dep v0.2.0 ${H('e')}\n`;
    expect(sum('go.sum', GO_SUM('v1.2.5'), next)).toEqual({ ok: true });
  });

  it.each([
    ['without h1:', `${PKG} v1.2.6 sha256:abc`],
    ['without a hash', `${PKG} v1.2.6`],
    ['with an empty h1:', `${PKG} v1.2.6 h1:`],
  ])('refuses a new line %s as missing_integrity', (_name, line) => {
    expect(sum('go.sum', GO_SUM('v1.2.5'), `${GO_SUM('v1.2.5')}${line}\n`)).toEqual({
      ok: false,
      rule: 'missing_integrity',
      path: 'go.sum',
    });
  });

  it('answers unparsable for a malformed line', () => {
    expect(sum('go.sum', GO_SUM('v1.2.5'), `${PKG}\n`)).toMatchObject({ rule: 'unparsable' });
  });
});
