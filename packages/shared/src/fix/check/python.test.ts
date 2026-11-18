import { describe, expect, it } from 'vitest';
import {
  checkPyproject,
  checkPythonLock,
  normalizePythonName,
  pythonLockfileAdditions,
  readPoetryLock,
  readPyproject,
  readUvLock,
} from './python';
import type { FixCheckContext, FixFileChange, LockEntry } from './types';

const ctx = (lockfile: string, packageName = 'qf-a'): FixCheckContext => ({
  family: 'python',
  packageName,
  targets: [{ installed: '1.2.5', target: '1.2.6', lockfile }],
});

function pyproject(base: string, next: string, packageName = 'qf-a') {
  const path = 'pyproject.toml';
  return checkPyproject({ path, base, next } satisfies FixFileChange, ctx('uv.lock', packageName));
}

function lock(path: string, base: string, next: string, packageName = 'qf-a') {
  return checkPythonLock({ path, base, next } satisfies FixFileChange, ctx(path, packageName));
}

const refused = (rule: string, path: string) => ({ ok: false, rule, path });

describe('normalizePythonName', () => {
  it.each([
    ['Django_Rest', 'django-rest'],
    ['django.rest', 'django-rest'],
    ['Django--__..Rest', 'django-rest'],
    ['qf-a', 'qf-a'],
    ['QF_A', 'qf-a'],
  ])('%s → %s (PEP 503)', (name, normalized) => {
    expect(normalizePythonName(name)).toBe(normalized);
  });
});

describe('readPyproject', () => {
  it('reads TOML with comments, CRLF and a BOM into own keys only', () => {
    const doc = readPyproject('\uFEFF# c\r\n[project]\r\nname = "app" # x\r\n"__proto__" = 1\r\n');
    const project = doc.project as Record<string, unknown>;
    expect(Object.keys(doc)).toEqual(['project']);
    expect(Object.keys(project)).toEqual(['name', '__proto__']);
    expect(project.name).toBe('app');
    expect(Object.getOwnPropertyDescriptor(project, '__proto__')?.value).toBe(1);
  });

  it('throws on a file that is not TOML', () => {
    expect(() => readPyproject('[project\nname = ')).toThrow();
    expect(() => readPyproject('a = 1\na = 2\n')).toThrow();
  });
});

const UV_PYPROJECT = (dep: string, extra = '') => `[project]
name = "app"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
    # web
    "${dep}",
    "requests>=2.31 ; python_version >= '3.11'",
]

[project.optional-dependencies]
fast = ["qf-a[speed]>=1.2.5"]

[dependency-groups]
dev = ["pytest>=8", {include-group = "lint"}]
lint = ["ruff"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
${extra}`;

describe('checkPyproject', () => {
  it('accepts qf-a>=1.2.5 → qf-a>=1.2.6 with comments elsewhere', () => {
    const base = UV_PYPROJECT('qf-a>=1.2.5');
    expect(pyproject(base, UV_PYPROJECT('qf-a>=1.2.6'))).toEqual({ ok: true });
    expect(pyproject(base, UV_PYPROJECT('qf-a>=1.2.6,<2'))).toEqual({ ok: true });
    expect(pyproject(base, UV_PYPROJECT('qf-a==1.2.6'))).toEqual({ ok: true });
    expect(pyproject(base, UV_PYPROJECT('qf-a~=1.2.6'))).toEqual({ ok: true });
    expect(pyproject(base, UV_PYPROJECT('qf-a (>=1.2.6)'))).toEqual({ ok: true });
  });

  it('accepts the specifier in optional dependencies and dependency groups, with extras and markers kept', () => {
    const base = UV_PYPROJECT('qf-a>=1.2.5', '').replace(
      '"pytest>=8"',
      '"qf-a>=1.2.5; sys_platform == \'linux\'"',
    );
    const next = UV_PYPROJECT('qf-a>=1.2.6')
      .replace('qf-a[speed]>=1.2.5', 'qf-a[speed]>=1.2.6')
      .replace('"pytest>=8"', '"qf-a>=1.2.6; sys_platform == \'linux\'"');
    expect(pyproject(base, next)).toEqual({ ok: true });
  });

  it('refuses changed extras or markers as other_change', () => {
    const base = UV_PYPROJECT('qf-a>=1.2.5');
    const extras = UV_PYPROJECT('qf-a>=1.2.5').replace('qf-a[speed]>=1.2.5', 'qf-a[evil]>=1.2.6');
    expect(pyproject(base, extras)).toEqual(refused('other_change', 'pyproject.toml'));
    expect(pyproject(base, UV_PYPROJECT("qf-a>=1.2.6; os_name == 'nt'"))).toEqual(
      refused('other_change', 'pyproject.toml'),
    );
  });

  it('accepts tool.uv.override-dependencies added, the tables created when absent', () => {
    const base = UV_PYPROJECT('requests-toolbelt>=1');
    const created = `${base}\n[tool.uv]\noverride-dependencies = ["qf-a>=1.2.6"]\n`;
    expect(pyproject(base, created)).toEqual({ ok: true });
    const withUv = `${base}\n[tool.uv]\ndev-dependencies = []\n`;
    const extended = `${base}\n[tool.uv]\ndev-dependencies = []\noverride-dependencies = ["other>=1", "qf-a>=1.2.6"]\n`;
    expect(
      pyproject(
        `${base}\n[tool.uv]\ndev-dependencies = []\noverride-dependencies = ["other>=1"]\n`,
        extended,
      ),
    ).toEqual({ ok: true });
    expect(pyproject(withUv, `${withUv}override-dependencies = ["qf-a>=1.2.6"]\n`)).toEqual({
      ok: true,
    });
  });

  it('accepts a changed override entry, and refuses an override of another package', () => {
    const at = (entries: string) =>
      `${UV_PYPROJECT('x>=1')}\n[tool.uv]\noverride-dependencies = [${entries}]\n`;
    expect(pyproject(at('"qf-a>=1.2.5"'), at('"qf-a>=1.2.6"'))).toEqual({ ok: true });
    expect(pyproject(at('"qf-a>=1.2.5"'), at('"qf-a>=1.2.6", "evil>=1"'))).toEqual(
      refused('other_change', 'pyproject.toml'),
    );
  });

  it('accepts a Poetry constraint changed, added, or changed in a group', () => {
    const poetry = (deps: string, group = 'pytest = "^8"') => `[tool.poetry]
name = "app"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.11"
${deps}

[tool.poetry.group.dev.dependencies]
${group}

[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"
`;
    expect(pyproject(poetry('qf-a = "^1.2.5"'), poetry('qf-a = "^1.2.6"'))).toEqual({ ok: true });
    expect(
      pyproject(
        poetry('qf-a = { version = "^1.2.5", extras = ["x"] }'),
        poetry('qf-a = { version = "^1.2.6", extras = ["x"] }'),
      ),
    ).toEqual({ ok: true });
    // The transitive pin: an added constraint, with Qualor's comment.
    expect(
      pyproject(
        poetry('requests = "^2"'),
        poetry(
          'requests = "^2"\n# Qualor: pinned for CVE-1; remove when x requires 1.2.6 or later\nqf-a = "^1.2.6"',
        ),
      ),
    ).toEqual({ ok: true });
    expect(
      pyproject(poetry('x = "1"', 'qf-a = ">=1.2.5,<2"'), poetry('x = "1"', 'qf-a = ">=1.2.6,<2"')),
    ).toEqual({
      ok: true,
    });
    expect(
      pyproject(poetry('x = "1"', 'qf-a = "^1.2.5"'), poetry('x = "1"', 'qf-a = "*"')),
    ).toEqual({ ok: true });
  });

  it('accepts a Poetry constraint added to a PEP 621 project, the tables created', () => {
    const base = UV_PYPROJECT('requests>=2');
    const next = `${base}\n[tool.poetry.dependencies]\nqf-a = "^1.2.6"\n`;
    expect(pyproject(base, next)).toEqual({ ok: true });
  });

  it('refuses Poetry changes beyond the version', () => {
    const poetry = (deps: string) => `[tool.poetry.dependencies]\npython = "^3.11"\n${deps}\n`;
    const cases: [string, string, string][] = [
      [
        'qf-a = { version = "^1.2.5", extras = ["x"] }',
        'qf-a = { version = "^1.2.6", extras = ["y"] }',
        'other_change',
      ],
      [
        'qf-a = { version = "^1.2.5" }',
        'qf-a = { version = "^1.2.6", source = "evil" }',
        'other_change',
      ],
      ['qf-a = "^1.2.5"', 'qf-a = { git = "https://evil.example/qf-a.git" }', 'bad_spec'],
      ['qf-a = "^1.2.5"', 'qf-a = { path = "../evil" }', 'bad_spec'],
      ['qf-a = "^1.2.5"', 'qf-a = { url = "https://evil.example/qf-a.whl" }', 'bad_spec'],
      ['qf-a = "^1.2.5"', 'qf-a = "https://evil.example/qf-a.whl"', 'bad_spec'],
      ['qf-a = "^1.2.5"', 'qf-a = ""', 'bad_spec'],
      ['x = "1"', 'x = "1"\nqf-a = { git = "https://evil.example/qf-a.git" }', 'bad_spec'],
      ['x = "1"', 'x = "1"\nqf-a = { version = "^1.2.6", source = "evil" }', 'other_change'],
      ['x = "1"', 'x = "1"\nevil = "^1"', 'new_dependency'],
      ['qf-a = "^1.2.5"', 'qf_a = "^1.2.6"', 'other_change'],
      ['qf-a = "^1.2.5"', 'qf-a = "^1.2.5"\nQF_A = "^1.2.6"', 'other_change'],
      ['qf-a = "^1.2.5"', 'qf-a = ["^1.2.6"]', 'other_change'],
    ];
    for (const [before, after, rule] of cases) {
      expect(pyproject(poetry(before), poetry(after)), after).toEqual(
        refused(rule, 'pyproject.toml'),
      );
    }
  });

  it('refuses a direct reference (@ url) as bad_spec', () => {
    const base = UV_PYPROJECT('qf-a>=1.2.5');
    for (const dep of [
      'qf-a @ https://evil.example/a.whl',
      'qf-a@ git+https://evil.example/a',
      'qf-a @ file:///tmp/a',
    ]) {
      expect(pyproject(base, UV_PYPROJECT(dep)), dep).toEqual(
        refused('bad_spec', 'pyproject.toml'),
      );
    }
    const override = (entry: string) =>
      `${base}\n[tool.uv]\noverride-dependencies = ["${entry}"]\n`;
    expect(pyproject(base, override('qf-a @ https://evil.example/a.whl'))).toEqual(
      refused('bad_spec', 'pyproject.toml'),
    );
  });

  it.each(['qf-a', 'qf-a>=', 'qf-a===1.2.6', 'qf-a>=latest', 'qf-a>=1.2.6 extra'])(
    'refuses the requirement %j as bad_spec',
    (dep) => {
      expect(pyproject(UV_PYPROJECT('qf-a>=1.2.5'), UV_PYPROJECT(dep))).toEqual(
        refused('bad_spec', 'pyproject.toml'),
      );
    },
  );

  it('refuses a changed [build-system] and anything else as other_change', () => {
    const base = UV_PYPROJECT('qf-a>=1.2.5');
    expect(
      pyproject(base, UV_PYPROJECT('qf-a>=1.2.6').replace('"hatchling"]', '"hatchling", "evil"]')),
    ).toEqual(refused('other_change', 'pyproject.toml'));
    expect(
      pyproject(
        base,
        `${UV_PYPROJECT('qf-a>=1.2.6')}\n[[tool.uv.index]]\nurl = "https://evil.example/simple"\n`,
      ),
    ).toEqual(refused('other_change', 'pyproject.toml'));
    expect(
      pyproject(
        base,
        `${UV_PYPROJECT('qf-a>=1.2.6')}\n[tool.uv]\nconstraint-dependencies = ["qf-a>=1.2.6"]\n`,
      ),
    ).toEqual(refused('other_change', 'pyproject.toml'));
    expect(
      pyproject(base, UV_PYPROJECT('qf-a>=1.2.6').replace('name = "app"', 'name = "evil"')),
    ).toEqual(refused('other_change', 'pyproject.toml'));
  });

  it('refuses a new requirement of another package as new_dependency', () => {
    const base = UV_PYPROJECT('qf-a>=1.2.5');
    const next = UV_PYPROJECT('qf-a>=1.2.6').replace('    # web\n', '    # web\n    "evil>=1",\n');
    expect(pyproject(base, next)).toEqual(refused('new_dependency', 'pyproject.toml'));
  });

  it('python names (Review Focus 3): Django_Rest in pyproject is the package django-rest', () => {
    const base = UV_PYPROJECT('Django_Rest>=3.14.0');
    expect(pyproject(base, UV_PYPROJECT('Django_Rest>=3.15.0'), 'django-rest')).toEqual({
      ok: true,
    });
    expect(pyproject(base, UV_PYPROJECT('Django_Rest>=3.15.0'), 'Django.Rest')).toEqual({
      ok: true,
    });
    const poetry = (v: string) => `[tool.poetry.dependencies]\nDjango_Rest = "${v}"\n`;
    expect(pyproject(poetry('^3.14'), poetry('^3.15'), 'django-rest')).toEqual({ ok: true });
  });

  it('keeps CRLF and a BOM readable (Review Focus 1)', () => {
    const base = '\uFEFF' + UV_PYPROJECT('qf-a>=1.2.5').replaceAll('\n', '\r\n');
    const next = '\uFEFF' + UV_PYPROJECT('qf-a>=1.2.6').replaceAll('\n', '\r\n');
    expect(pyproject(base, next)).toEqual({ ok: true });
  });

  it('compares dates and NaN by value', () => {
    const base = `${UV_PYPROJECT('qf-a>=1.2.5')}\n[tool.x]\nwhen = 1979-05-27T07:32:00Z\nday = 1979-05-27\nn = nan\n`;
    const next = base.replace('qf-a>=1.2.5', 'qf-a>=1.2.6');
    expect(pyproject(base, next)).toEqual({ ok: true });
    expect(pyproject(base, next.replace('1979-05-27\n', '1979-05-28\n'))).toEqual(
      refused('other_change', 'pyproject.toml'),
    );
    expect(pyproject(base, next.replace('day = 1979-05-27', 'day = "1979-05-27"'))).toEqual(
      refused('other_change', 'pyproject.toml'),
    );
  });

  it('answers unparsable, without throwing, for a file it cannot read', () => {
    expect(pyproject(UV_PYPROJECT('qf-a>=1.2.5'), '[project\n')).toEqual(
      refused('unparsable', 'pyproject.toml'),
    );
  });
});

// ---------------------------------------------------------------------------------------------
// uv.lock

const FILES = 'https://files.pythonhosted.org/packages/ab/cd';
const SHA = (c: string) => `sha256:${c.repeat(64)}`;

/** A file of a package on files.pythonhosted.org, its name as wheels write it. */
const pypiFile = (name: string, version: string, suffix: string) =>
  FILES + '/' + name.replaceAll('-', '_') + '-' + version + suffix;

const uvDependency = (name: string) => `    { name = "${name}" },`;

const uvDependencies = (deps: readonly string[]) =>
  deps.length === 0 ? '' : 'dependencies = [\n' + deps.map(uvDependency).join('\n') + '\n]\n';

const uvPackage = (
  name: string,
  version: string,
  { deps = [] as string[], registry = 'https://pypi.org/simple', sdist = '', wheel = '' } = {},
) => {
  const sdistUrl = sdist || pypiFile(name, version, '.tar.gz');
  const wheelUrl = wheel || pypiFile(name, version, '-py3-none-any.whl');
  return `
[[package]]
name = "${name}"
version = "${version}"
source = { registry = "${registry}" }
${uvDependencies(deps)}sdist = { url = "${sdistUrl}", hash = "${SHA('a')}", size = 100 }
wheels = [
    { url = "${wheelUrl}", hash = "${SHA('b')}", size = 90 },
]
`;
};

const UV_LOCK = (qfA: string, more = '') => `version = 1
revision = 2
requires-python = ">=3.11"

[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "qf-b" },
]

[package.metadata]
requires-dist = [{ name = "qf-b", specifier = ">=2" }]
${uvPackage('qf-a', qfA)}${uvPackage('qf-b', '2.0.0', { deps: ['qf-a'] })}${more}`;

describe('readUvLock', () => {
  it('reads registry packages per artifact and their index, with hashes and dependents', () => {
    const entries = readUvLock(UV_LOCK('1.2.5'));
    const qfA = entries.filter((e) => e.name === 'qf-a');
    expect(qfA.map((e) => [e.source, e.kind, e.integrity])).toEqual([
      [`${FILES}/qf_a-1.2.5.tar.gz`, 'registry', SHA('a')],
      [`${FILES}/qf_a-1.2.5-py3-none-any.whl`, 'registry', SHA('b')],
      ['https://pypi.org/simple', 'registry', `${SHA('a')} ${SHA('b')}`],
    ]);
    expect(qfA.every((e) => e.version === '1.2.5' && e.dependents.join() === 'qf-b')).toBe(true);
    const app = entries.find((e) => e.name === 'app');
    expect(app).toMatchObject({
      kind: 'path',
      source: '.',
      dependencies: ['qf-b'],
      dependents: [],
    });
    expect(entries.find((e) => e.name === 'qf-b')?.dependencies).toEqual(['qf-a']);
  });

  it('reads each source kind', () => {
    const kinds = (source: string) =>
      readUvLock(`version = 1\n\n[[package]]\nname = "x"\nversion = "1"\nsource = ${source}\n`).map(
        (e) => [e.kind, e.source],
      );
    expect(kinds('{ git = "https://github.com/x/x?rev=main#abc" }')).toEqual([
      ['git', 'https://github.com/x/x?rev=main#abc'],
    ]);
    expect(kinds('{ path = "dist/x-1-py3-none-any.whl" }')).toEqual([
      ['file', 'dist/x-1-py3-none-any.whl'],
    ]);
    expect(kinds('{ directory = "../x" }')).toEqual([['path', '../x']]);
    expect(kinds('{ editable = "../x" }')).toEqual([['path', '../x']]);
    expect(kinds('{ virtual = "." }')).toEqual([['path', '.']]);
    expect(kinds('{ url = "https://example.com/x-1.tar.gz" }')).toEqual([
      ['tarball', 'https://example.com/x-1.tar.gz'],
    ]);
    expect(kinds('{ registry = "https://pypi.org/simple", git = "https://x" }')).toEqual([
      ['other', null],
    ]);
  });

  it('normalises names and follows optional and dev dependencies', () => {
    const text = `version = 1

[[package]]
name = "App"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "Django_Rest" }]

[package.optional-dependencies]
fast = [{ name = "Q.F_A" }]

[package.dev-dependencies]
dev = [{ name = "pytest" }]
`;
    expect(readUvLock(text)[0]).toMatchObject({
      name: 'app',
      dependencies: ['django-rest', 'pytest', 'q-f-a'],
    });
  });

  it('throws on a file it cannot read', () => {
    expect(() => readUvLock('version = 1\npackage = 3\n')).toThrow();
    expect(() =>
      readUvLock('version = 1\n[[package]]\nversion = "1"\nsource = { virtual = "." }\n'),
    ).toThrow();
    expect(() => readUvLock('[[package]\n')).toThrow();
  });
});

describe('checkPythonLock: uv.lock', () => {
  it('accepts the bump', () => {
    expect(lock('uv.lock', UV_LOCK('1.2.5'), UV_LOCK('1.2.6'))).toEqual({ ok: true });
  });

  it('refuses an entry from https://evil.example/simple as new_source', () => {
    const evilIndex = UV_LOCK('1.2.5').replace(
      uvPackage('qf-a', '1.2.5'),
      uvPackage('qf-a', '1.2.6', { registry: 'https://evil.example/simple' }),
    );
    expect(lock('uv.lock', UV_LOCK('1.2.5'), evilIndex)).toEqual(refused('new_source', 'uv.lock'));
    const evilFiles = UV_LOCK('1.2.5').replace(
      uvPackage('qf-a', '1.2.5'),
      uvPackage('qf-a', '1.2.6', { sdist: 'https://evil.example/simple/qf_a-1.2.6.tar.gz' }),
    );
    expect(lock('uv.lock', UV_LOCK('1.2.5'), evilFiles)).toEqual(refused('new_source', 'uv.lock'));
  });

  it('accepts a private index the base already used', () => {
    const PRIVATE = 'https://pypi.internal.example';
    const at = (v: string) =>
      UV_LOCK('1.2.5').replace(
        uvPackage('qf-a', '1.2.5'),
        uvPackage('qf-a', v, {
          registry: `${PRIVATE}/simple`,
          sdist: `${PRIVATE}/files/qf_a-${v}.tar.gz`,
          wheel: `${PRIVATE}/files/qf_a-${v}-py3-none-any.whl`,
        }),
      );
    expect(lock('uv.lock', at('1.2.5'), at('1.2.6'))).toEqual({ ok: true });
  });

  it('refuses a git source as source_kind', () => {
    const git = UV_LOCK('1.2.5').replace(
      uvPackage('qf-a', '1.2.5'),
      '\n[[package]]\nname = "qf-a"\nversion = "1.2.6"\nsource = { git = "https://github.com/evil/qf-a?rev=main#abc" }\n',
    );
    expect(lock('uv.lock', UV_LOCK('1.2.5'), git)).toEqual(refused('source_kind', 'uv.lock'));
  });

  describe('Ruling T4a: archive file names belong to the entry', () => {
    it('refuses an sdist of another package on files.pythonhosted.org as source_kind', () => {
      const next = UV_LOCK('1.2.5').replace(
        uvPackage('qf-a', '1.2.5'),
        uvPackage('qf-a', '1.2.6', { sdist: `${FILES}/evil-6.6.6.tar.gz` }),
      );
      expect(lock('uv.lock', UV_LOCK('1.2.5'), next)).toEqual(refused('source_kind', 'uv.lock'));
    });

    it('refuses a wheel of another package as source_kind', () => {
      const next = UV_LOCK('1.2.5').replace(
        uvPackage('qf-a', '1.2.5'),
        uvPackage('qf-a', '1.2.6', { wheel: `${FILES}/evil-6.6.6-py3-none-any.whl` }),
      );
      expect(lock('uv.lock', UV_LOCK('1.2.5'), next)).toEqual(refused('source_kind', 'uv.lock'));
    });

    it('refuses an archive of another version, or of no known kind, as source_kind', () => {
      for (const sdist of [
        `${FILES}/qf_a-1.2.7.tar.gz`,
        `${FILES}/qf_a-1.2.6.egg`,
        `${FILES}/qf_a.tar.gz`,
        `${FILES}/`,
      ]) {
        const next = UV_LOCK('1.2.5').replace(
          uvPackage('qf-a', '1.2.5'),
          uvPackage('qf-a', '1.2.6', { sdist }),
        );
        expect(lock('uv.lock', UV_LOCK('1.2.5'), next), sdist).toEqual(
          refused('source_kind', 'uv.lock'),
        );
      }
    });

    it('accepts Django_Rest-3.14.0-py3-none-any.whl and a legacy Django-4.2.tar.gz', () => {
      const pkg = (name: string, v: string, sdist: string, wheel: string) =>
        uvPackage(name, v, { sdist: `${FILES}/${sdist}`, wheel: `${FILES}/${wheel}` });
      const base = UV_LOCK(
        '1.2.6',
        pkg('django', '4.1', 'Django-4.1.tar.gz', 'Django-4.1-py3-none-any.whl') +
          pkg(
            'django-rest',
            '3.13.0',
            'django-rest-3.13.0.tar.gz',
            'Django_Rest-3.13.0-py3-none-any.whl',
          ),
      ).replace(
        '{ name = "qf-a" },',
        '{ name = "qf-a" },\n    { name = "django" },\n    { name = "django-rest" },',
      );
      const legacy = base.replace(
        pkg('django', '4.1', 'Django-4.1.tar.gz', 'Django-4.1-py3-none-any.whl'),
        pkg('django', '4.2', 'Django-4.2.tar.gz', 'Django-4.2-py3-none-any.whl'),
      );
      const wheel = base.replace(
        pkg(
          'django-rest',
          '3.13.0',
          'django-rest-3.13.0.tar.gz',
          'Django_Rest-3.13.0-py3-none-any.whl',
        ),
        pkg(
          'django-rest',
          '3.14.0',
          'django-rest-3.14.0.tar.gz',
          'Django_Rest-3.14.0-py3-none-any.whl',
        ),
      );
      expect(legacy).not.toBe(base);
      expect(wheel).not.toBe(base);
      const target = (packageName: string, installed: string, t: string): FixCheckContext => ({
        family: 'python',
        packageName,
        targets: [{ installed, target: t, lockfile: 'uv.lock' }],
      });
      expect(
        checkPythonLock(
          { path: 'uv.lock', base, next: wheel },
          target('Django_Rest', '3.13.0', '3.14.0'),
        ),
      ).toEqual({ ok: true });
      expect(
        checkPythonLock({ path: 'uv.lock', base, next: legacy }, target('django', '4.1', '4.2')),
      ).toEqual({ ok: true });
    });
  });

  it('refuses a new entry without a hash as missing_integrity', () => {
    const next = UV_LOCK('1.2.6').replace(`hash = "${SHA('a')}", size = 100`, 'size = 100');
    expect(next).not.toBe(UV_LOCK('1.2.6'));
    expect(lock('uv.lock', UV_LOCK('1.2.5'), next)).toEqual(
      refused('missing_integrity', 'uv.lock'),
    );
  });

  it('refuses a new entry no package path reaches as new_dependency', () => {
    expect(lock('uv.lock', UV_LOCK('1.2.5'), UV_LOCK('1.2.6', uvPackage('evil', '1.0.0')))).toEqual(
      refused('new_dependency', 'uv.lock'),
    );
  });

  it('refuses an existing package that gains a dependency as other_change (Ruling T3j/T3l)', () => {
    const next = UV_LOCK('1.2.6', uvPackage('evil', '1.0.0')).replace(
      uvPackage('qf-b', '2.0.0', { deps: ['qf-a'] }),
      uvPackage('qf-b', '2.0.0', { deps: ['qf-a', 'evil'] }),
    );
    expect(lock('uv.lock', UV_LOCK('1.2.5'), next)).toEqual(refused('other_change', 'uv.lock'));
  });

  it('accepts a new dependency of the new package version (Ruling T3e)', () => {
    const next = UV_LOCK('1.2.6', uvPackage('qf-c', '1.0.0')).replace(
      uvPackage('qf-a', '1.2.6'),
      uvPackage('qf-a', '1.2.6', { deps: ['qf-c'] }),
    );
    expect(lock('uv.lock', UV_LOCK('1.2.5'), next)).toEqual({ ok: true });
  });

  it('refuses the package still below its target as below_target, by its normalised name', () => {
    expect(lock('uv.lock', UV_LOCK('1.2.5'), UV_LOCK('1.2.5'))).toEqual(
      refused('below_target', 'uv.lock'),
    );
    expect(lock('uv.lock', UV_LOCK('1.2.5'), UV_LOCK('1.2.5'), 'QF_A')).toEqual(
      refused('below_target', 'uv.lock'),
    );
    expect(lock('uv.lock', UV_LOCK('1.2.5'), UV_LOCK('1.2.6'), 'QF_A')).toEqual({ ok: true });
  });

  it('refuses a lockfile whose format version changed as unparsable', () => {
    expect(
      lock('uv.lock', UV_LOCK('1.2.5'), UV_LOCK('1.2.6').replace('version = 1\n', 'version = 2\n')),
    ).toEqual(refused('unparsable', 'uv.lock'));
  });
});

// ---------------------------------------------------------------------------------------------
// poetry.lock

const poetryFiles = (name: string, version: string) =>
  [
    `    {file = "${name.replaceAll('-', '_')}-${version}-py3-none-any.whl", hash = "${SHA('c')}"},`,
    `    {file = "${name}-${version}.tar.gz", hash = "${SHA('d')}"},`,
  ].join('\n');

const tomlTable = (header: string, body: string) => (body ? `\n[${header}]\n${body}\n` : '');

const poetryPackage = (
  name: string,
  version: string,
  { deps = '', files = '', source = '' } = {},
) => `
[[package]]
name = "${name}"
version = "${version}"
description = ""
optional = false
python-versions = ">=3.8"
files = [
${files || poetryFiles(name, version)}
]
${tomlTable('package.dependencies', deps)}${tomlTable('package.source', source)}`;

const POETRY_LOCK = (
  qfA: string,
  more = '',
) => `# This file is automatically @generated by Poetry 2.1.1 and should not be changed by hand.
${poetryPackage('qf-a', qfA)}${poetryPackage('qf-b', '2.0.0', { deps: 'qf-a = ">=1.2"' })}${more}
[metadata]
lock-version = "2.1"
python-versions = "^3.11"
content-hash = "abc"
`;

describe('readPoetryLock', () => {
  it('reads one entry per file, files[].hash as integrity, dependents from dependencies', () => {
    const qfA = readPoetryLock(POETRY_LOCK('1.2.5')).filter((e) => e.name === 'qf-a');
    expect(qfA.map((e) => [e.version, e.source, e.kind, e.integrity, e.dependents])).toEqual([
      ['1.2.5', null, 'registry', SHA('c'), ['qf-b']],
      ['1.2.5', null, 'registry', SHA('d'), ['qf-b']],
    ]);
  });

  it('reads [package.source]: legacy as registry with its url, git, file, directory and url', () => {
    const kinds = (source: string) =>
      readPoetryLock(POETRY_LOCK('1.2.5', poetryPackage('x', '1.0', { source })))
        .filter((e) => e.name === 'x')
        .map((e) => [e.kind, e.source]);
    expect(
      kinds(
        'type = "legacy"\nurl = "https://pypi.internal.example/simple"\nreference = "internal"',
      ),
    ).toEqual([
      ['registry', 'https://pypi.internal.example/simple#poetry-reference=internal'],
      ['registry', 'https://pypi.internal.example/simple#poetry-reference=internal'],
    ]);
    expect(
      kinds(
        'type = "git"\nurl = "https://github.com/x/x.git"\nreference = "main"\nresolved_reference = "abc"',
      )[0],
    ).toEqual([
      'git',
      'https://github.com/x/x.git#reference=main&resolved_reference=abc&subdirectory=',
    ]);
    expect(kinds('type = "file"\nurl = "dist/x-1.0.tar.gz"')[0]).toEqual([
      'file',
      'dist/x-1.0.tar.gz#reference=&resolved_reference=&subdirectory=',
    ]);
    expect(kinds('type = "directory"\nurl = "../x"')[0]).toEqual([
      'path',
      '../x#reference=&resolved_reference=&subdirectory=',
    ]);
    expect(kinds('type = "url"\nurl = "https://example.com/x-1.0.tar.gz"')[0]).toEqual([
      'tarball',
      'https://example.com/x-1.0.tar.gz#reference=&resolved_reference=&subdirectory=',
    ]);
    expect(kinds('type = "evil"\nurl = "https://example.com/"')[0]).toEqual([
      'other',
      'https://example.com/#reference=&resolved_reference=&subdirectory=',
    ]);
  });

  it('reads Poetry 1.x [metadata.files]', () => {
    const old = `[[package]]
name = "Qf_A"
version = "1.2.5"
category = "main"
optional = false
python-versions = "*"

[metadata]
lock-version = "1.1"
python-versions = "^3.8"
content-hash = "abc"

[metadata.files]
Qf_A = [
    {file = "Qf_A-1.2.5.tar.gz", hash = "${SHA('e')}"},
]
`;
    expect(readPoetryLock(old)).toMatchObject([
      { name: 'qf-a', version: '1.2.5', kind: 'registry', integrity: SHA('e') },
    ]);
  });
});

describe('checkPythonLock: poetry.lock', () => {
  it('accepts the bump', () => {
    expect(lock('poetry.lock', POETRY_LOCK('1.2.5'), POETRY_LOCK('1.2.6'))).toEqual({ ok: true });
  });

  it('refuses a files[] entry naming another package as source_kind (Ruling T4a)', () => {
    const next = POETRY_LOCK('1.2.5').replace(
      poetryPackage('qf-a', '1.2.5'),
      poetryPackage('qf-a', '1.2.6', {
        files: `    {file = "evil-6.6.6-py3-none-any.whl", hash = "${SHA('f')}"},`,
      }),
    );
    expect(lock('poetry.lock', POETRY_LOCK('1.2.5'), next)).toEqual(
      refused('source_kind', 'poetry.lock'),
    );
  });

  it('refuses a new legacy source on another host as new_source', () => {
    const next = POETRY_LOCK('1.2.5').replace(
      poetryPackage('qf-a', '1.2.5'),
      poetryPackage('qf-a', '1.2.6', {
        source: 'type = "legacy"\nurl = "https://evil.example/simple"\nreference = "evil"',
      }),
    );
    expect(lock('poetry.lock', POETRY_LOCK('1.2.5'), next)).toEqual(
      refused('new_source', 'poetry.lock'),
    );
  });

  it('refuses a git source as source_kind, and a file without a hash as missing_integrity', () => {
    const git = POETRY_LOCK('1.2.5').replace(
      poetryPackage('qf-a', '1.2.5'),
      poetryPackage('qf-a', '1.2.6', {
        files: '',
        source: 'type = "git"\nurl = "https://github.com/evil/qf-a.git"\nreference = "main"',
      }),
    );
    expect(lock('poetry.lock', POETRY_LOCK('1.2.5'), git)).toEqual(
      refused('source_kind', 'poetry.lock'),
    );
    const unhashed = POETRY_LOCK('1.2.6').replace(`, hash = "${SHA('c')}"`, '');
    expect(lock('poetry.lock', POETRY_LOCK('1.2.5'), unhashed)).toEqual(
      refused('missing_integrity', 'poetry.lock'),
    );
  });

  it('python names (Review Focus 3): Django_Rest and django-rest are one package', () => {
    const at = (v: string) =>
      POETRY_LOCK(
        '1.2.6',
        poetryPackage('django-rest', v, {
          files: `    {file = "Django_Rest-${v}-py3-none-any.whl", hash = "${SHA(v === '3.14.0' ? 'a' : 'b')}"},`,
        }),
      ).replace('qf-a = ">=1.2"', 'qf-a = ">=1.2"\ndjango-rest = "*"');
    const context: FixCheckContext = {
      family: 'python',
      packageName: 'Django_Rest',
      targets: [{ installed: '3.13.0', target: '3.14.0', lockfile: 'poetry.lock' }],
    };
    expect(
      checkPythonLock({ path: 'poetry.lock', base: at('3.13.0'), next: at('3.14.0') }, context),
    ).toEqual({ ok: true });
    expect(
      checkPythonLock({ path: 'poetry.lock', base: at('3.13.0'), next: at('3.13.0') }, context),
    ).toEqual(refused('below_target', 'poetry.lock'));
  });

  it('answers unparsable, and other_change for a file that is no Python lockfile', () => {
    expect(lock('poetry.lock', POETRY_LOCK('1.2.5'), '[[package]\n')).toEqual(
      refused('unparsable', 'poetry.lock'),
    );
    expect(lock('requirements.txt', 'a', 'b')).toEqual(refused('other_change', 'requirements.txt'));
  });
});

describe('pythonLockfileAdditions (Ruling T3i)', () => {
  it('lists each added package once, with its name and version', () => {
    const next = UV_LOCK('1.2.6', uvPackage('qf-c', '1.0.0')).replace(
      uvPackage('qf-a', '1.2.6'),
      uvPackage('qf-a', '1.2.6', { deps: ['qf-c'] }),
    );
    const added = pythonLockfileAdditions({ path: 'uv.lock', base: UV_LOCK('1.2.5'), next }) ?? [];
    expect(added.map((e: LockEntry) => `${e.name}@${e.version}`)).toEqual([
      'qf-a@1.2.6',
      'qf-c@1.0.0',
    ]);
    const poetry = pythonLockfileAdditions({
      path: 'poetry.lock',
      base: POETRY_LOCK('1.2.5'),
      next: POETRY_LOCK('1.2.6'),
    });
    expect(poetry?.map((e) => `${e.name}@${e.version}`)).toEqual(['qf-a@1.2.6']);
  });

  it('is null for a file that is no Python lockfile or cannot be read', () => {
    expect(pythonLockfileAdditions({ path: 'yarn.lock', base: '', next: '' })).toBeNull();
    expect(
      pythonLockfileAdditions({ path: 'uv.lock', base: UV_LOCK('1.2.5'), next: '[[package]\n' }),
    ).toBeNull();
  });
});

// ---------------------------------------------------------------------------------------------
// Fix round 1 (task-4-fix-1.md): C1 Poetry source fields, I2 Poetry legacy references, Ruling T4f
// a package keeps its registry, M1 uv overrides take no extras or markers

describe('fix round 1: Poetry sources keep their reference and subdirectory (C1)', () => {
  const COMMIT = 'a'.repeat(40);
  const lib = (kind: string, fields: string) =>
    poetryPackage('lib', '0.1.0', {
      files: ' ',
      source: `type = "${kind}"\nurl = "https://github.com/org/lib.git"\n${fields}`,
    });
  const at = (qfA: string, kind: string, fields: string) => POETRY_LOCK(qfA, lib(kind, fields));
  const GIT = `reference = "main"\nresolved_reference = "${COMMIT}"`;

  it('accepts a bump next to an unchanged git dependency', () => {
    expect(lock('poetry.lock', at('1.2.5', 'git', GIT), at('1.2.6', 'git', GIT))).toEqual({
      ok: true,
    });
  });

  it.each([
    ['resolved_reference changed (P1)', GIT.replace(COMMIT, 'e'.repeat(40))],
    ['reference changed', GIT.replace('"main"', '"evil"')],
    ['subdirectory added (P1b)', `${GIT}\nsubdirectory = "evil"`],
  ])('refuses a git dependency with its %s as source_kind', (_name, fields) => {
    expect(lock('poetry.lock', at('1.2.5', 'git', GIT), at('1.2.6', 'git', fields))).toEqual(
      refused('source_kind', 'poetry.lock'),
    );
  });

  it.each(['url', 'file', 'directory'])(
    'refuses a %s dependency whose subdirectory changed as source_kind',
    (kind) => {
      const before = at('1.2.5', kind, 'subdirectory = "a"');
      expect(lock('poetry.lock', before, at('1.2.6', kind, 'subdirectory = "b"'))).toEqual(
        refused('source_kind', 'poetry.lock'),
      );
    },
  );

  it('reads the fields into the source', () => {
    const entry = readPoetryLock(at('1.2.6', 'git', `${GIT}\nsubdirectory = "pkg"`)).find(
      (e) => e.name === 'lib',
    );
    expect(entry?.source).toBe(
      `https://github.com/org/lib.git#reference=main&resolved_reference=${COMMIT}&subdirectory=pkg`,
    );
  });
});

describe('fix round 1: a Poetry legacy source by its reference and url (I2, Ruling T4f)', () => {
  const PRIVATE = 'https://pypi.internal.example/simple';
  const legacy = (reference: string, url = PRIVATE) =>
    `type = "legacy"\nurl = "${url}"\nreference = "${reference}"`;
  const at = (qfA: string, source: string, more = '') =>
    POETRY_LOCK('1.2.5', more).replace(
      poetryPackage('qf-a', '1.2.5'),
      poetryPackage('qf-a', qfA, source === '' ? {} : { source }),
    );

  it('accepts the package bumped on its own legacy source', () => {
    const before = at('1.2.5', legacy('internal'));
    expect(lock('poetry.lock', before, at('1.2.6', legacy('internal')))).toEqual({ ok: true });
  });

  it('refuses another reference on the same url as new_source (P3)', () => {
    const before = at('1.2.5', legacy('internal'));
    expect(lock('poetry.lock', before, at('1.2.6', legacy('other')))).toEqual(
      refused('new_source', 'poetry.lock'),
    );
  });

  it('refuses a legacy reference the base has none of, also for a brand-new name', () => {
    const fresh = poetryPackage('qf-n', '1.0.0', { source: legacy('internal') });
    const next = at('1.2.6', '', fresh).replace('qf-a = ">=1.2"', 'qf-a = ">=1.2"\nqf-n = "*"');
    expect(next).toContain('qf-n = "*"');
    expect(lock('poetry.lock', at('1.2.5', ''), next)).toEqual(
      refused('new_source', 'poetry.lock'),
    );
  });

  it('refuses the package moved from its legacy source to PyPI as new_source (Ruling T4f)', () => {
    expect(lock('poetry.lock', at('1.2.5', legacy('internal')), at('1.2.6', ''))).toEqual(
      refused('new_source', 'poetry.lock'),
    );
  });

  it('reads a legacy url with a fragment, which would blur the reference, as other', () => {
    const entries = readPoetryLock(at('1.2.6', legacy('internal', `${PRIVATE}#x`)));
    expect(entries.find((e) => e.name === 'qf-a')?.kind).toBe('other');
  });
});

describe('fix round 1: a package keeps its index in uv.lock (Ruling T4f)', () => {
  const PRIVATE = 'https://pypi.internal.example';
  const privately = (v: string, deps: string[] = []) =>
    uvPackage('qf-a', v, {
      deps,
      registry: `${PRIVATE}/simple`,
      sdist: `${PRIVATE}/files/qf_a-${v}.tar.gz`,
      wheel: `${PRIVATE}/files/qf_a-${v}-py3-none-any.whl`,
    });
  const at = (pkg: string, more = '') =>
    UV_LOCK('1.2.5', more).replace(uvPackage('qf-a', '1.2.5'), pkg);

  it('refuses the package moved from its private index to PyPI as new_source', () => {
    const next = at(uvPackage('qf-a', '1.2.6'));
    expect(lock('uv.lock', at(privately('1.2.5')), next)).toEqual(refused('new_source', 'uv.lock'));
  });

  it('accepts a brand-new dependency from PyPI next to the private package', () => {
    const next = at(privately('1.2.6', ['qf-c']), uvPackage('qf-c', '1.0.0'));
    expect(lock('uv.lock', at(privately('1.2.5')), next)).toEqual({ ok: true });
  });
});

describe('fix round 1: uv overrides take no extras or markers (M1)', () => {
  const base = UV_PYPROJECT('requests-toolbelt>=1');
  const override = (entry: string) => `${base}\n[tool.uv]\noverride-dependencies = ["${entry}"]\n`;

  it.each([
    ['extras and a marker (P4)', "qf-a[all]>=1.2.6 ; python_version < '2'"],
    ['a marker', "qf-a>=1.2.6 ; python_version < '2'"],
    ['extras', 'qf-a[all]>=1.2.6'],
  ])('refuses an added override with %s as other_change', (_name, entry) => {
    expect(pyproject(base, override(entry))).toEqual(refused('other_change', 'pyproject.toml'));
  });

  it('accepts a changed override that keeps its marker, refuses one that changes it', () => {
    const before = override("qf-a>=1.2.5 ; sys_platform == 'linux'");
    expect(pyproject(before, override("qf-a>=1.2.6 ; sys_platform == 'linux'"))).toEqual({
      ok: true,
    });
    expect(pyproject(before, override("qf-a>=1.2.6 ; sys_platform == 'win32'"))).toEqual(
      refused('other_change', 'pyproject.toml'),
    );
  });
});

describe('fix round 1: PEP 508 white space is space and tab only (I1)', () => {
  it('refuses the package requirement with another white space as bad_spec', () => {
    const NBSP = String.fromCharCode(0xa0);
    const base = UV_PYPROJECT('qf-a>=1.2.5');
    expect(pyproject(base, UV_PYPROJECT(`qf-a>=1.2.6${NBSP}`))).toEqual(
      refused('bad_spec', 'pyproject.toml'),
    );
    expect(pyproject(base, UV_PYPROJECT('qf-a >=\t1.2.6 '))).toEqual({ ok: true });
  });
});

// ---------------------------------------------------------------------------------------------
// Fix round 2 (task-4-fix-2.md): the C1 and M1 residuals

describe('fix round 2: Poetry source fields that are no strings, or no url (C1 residual)', () => {
  const lib = (fields: string) =>
    poetryPackage('lib', '0.1.0', { files: ' ', source: `type = "git"\n${fields}` });
  const at = (qfA: string, fields: string) => POETRY_LOCK(qfA, lib(fields));
  const GIT = 'url = "https://github.com/org/lib.git"\nreference = "main"';

  it.each([
    ['resolved_reference added as a TOML integer', GIT, `${GIT}\nresolved_reference = 1234567`],
    ['subdirectory added as a TOML array', GIT, `${GIT}\nsubdirectory = ["evil"]`],
    ['reference changed on a source without url', 'reference = "main"', 'reference = "evil"'],
  ])('refuses a git dependency with its %s as source_kind', (_name, before, after) => {
    expect(lock('poetry.lock', at('1.2.5', before), at('1.2.6', after))).toEqual(
      refused('source_kind', 'poetry.lock'),
    );
  });

  it('reads such a source as kind other, the raw field values in its source', () => {
    const entry = readPoetryLock(at('1.2.6', `${GIT}\nsubdirectory = ["evil"]`)).find(
      (e) => e.name === 'lib',
    );
    expect(entry?.kind).toBe('other');
    expect(entry?.source).toContain(encodeURIComponent('["evil"]'));
    const noUrl = readPoetryLock(at('1.2.6', 'reference = "main"')).find((e) => e.name === 'lib');
    expect(noUrl).toMatchObject({ kind: 'other' });
    expect(noUrl?.source).toContain('reference=main');
  });

  it('accepts such an entry the base has unchanged', () => {
    const odd = `${GIT}\nsubdirectory = ["evil"]`;
    expect(lock('poetry.lock', at('1.2.5', odd), at('1.2.6', odd))).toEqual({ ok: true });
  });
});

describe('fix round 2: the shapes of the package’s overrides stay as they were (M1 residual)', () => {
  const base = UV_PYPROJECT('requests-toolbelt>=1');
  const overrides = (...entries: string[]) => {
    const list = entries.map((e) => JSON.stringify(e)).join(', ');
    return `${base}\n[tool.uv]\noverride-dependencies = [${list}]\n`;
  };
  const linux = (v: string) => `qf-a>=${v} ; sys_platform == 'linux'`;
  const win = (v: string) => `qf-a>=${v} ; sys_platform == 'win32'`;

  it('refuses two base markers turned into one as other_change', () => {
    expect(
      pyproject(overrides(linux('1.2.5'), win('1.2.5')), overrides(win('1.2.6'), win('1.2.6'))),
    ).toEqual(refused('other_change', 'pyproject.toml'));
  });

  it('accepts both markers bumped, in any order', () => {
    const before = overrides(linux('1.2.5'), win('1.2.5'));
    expect(pyproject(before, overrides(win('1.2.6'), linux('1.2.6')))).toEqual({ ok: true });
  });

  it('refuses the package’s override removed, wholly or one of two, as other_change', () => {
    expect(pyproject(overrides('qf-a>=1.2.5'), overrides())).toEqual(
      refused('other_change', 'pyproject.toml'),
    );
    expect(pyproject(overrides(linux('1.2.5'), win('1.2.5')), overrides(linux('1.2.6')))).toEqual(
      refused('other_change', 'pyproject.toml'),
    );
  });

  it('still accepts a brand-new override without extras or marker', () => {
    expect(pyproject(overrides('other>=1'), overrides('other>=1', 'qf-a>=1.2.6'))).toEqual({
      ok: true,
    });
  });
});
