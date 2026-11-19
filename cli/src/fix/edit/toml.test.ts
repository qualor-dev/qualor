import { readPyproject } from '@qualor/shared/fix';
import { describe, expect, it } from 'vitest';
import {
  oneLine,
  replaceInSection,
  setTomlArrayEntry,
  setTomlKey,
  tomlSectionName,
  tomlSections,
  tomlString,
  tomlValue,
} from './toml';

const PYPROJECT = `# The app's metadata.
[project]
name = "app" # the distribution name
version = "0.1.0"
dependencies = [ # web
    "qf-a>=1.2.5",
    "requests>=2.31 ; python_version >= '3.11'",
]

[project.optional-dependencies]
fast = ["qf-a[speed]>=1.2.5"] # extras

[ tool . "uv" ]
dev-dependencies = []

[tool."my.tool"]
note = """
[not.a.header]
"""

[[tool.uv.index]]
url = "https://pypi.internal.example/simple"

[[tool.uv.index]]
url = "https://mirror.example/simple"
`;

/** Each section's header line, as `tomlSections` spans it. */
const headerLines = (text: string) =>
  tomlSections(text).map((s) => text.slice(s.start, text.indexOf('\n', s.start)));

describe('tomlSections', () => {
  it('reads dotted names, quoted parts, comments after values and arrays of tables', () => {
    expect(tomlSections(PYPROJECT).map((s) => s.name)).toEqual([
      'project',
      'project.optional-dependencies',
      'tool.uv',
      'tool."my.tool"',
      'tool.uv.index',
      'tool.uv.index',
    ]);
    expect(headerLines(PYPROJECT)).toEqual([
      '[project]',
      '[project.optional-dependencies]',
      '[ tool . "uv" ]',
      '[tool."my.tool"]',
      '[[tool.uv.index]]',
      '[[tool.uv.index]]',
    ]);
  });

  it('spans each section from its header line to the next header line', () => {
    const sections = tomlSections(PYPROJECT);
    for (const [i, s] of sections.entries()) {
      expect(s.end).toBe(sections[i + 1]?.start ?? PYPROJECT.length);
    }
    const project = PYPROJECT.slice(sections[0]?.start, sections[0]?.end);
    expect(project.startsWith('[project]\n')).toBe(true);
    expect(project.endsWith(`python_version >= '3.11'",\n]\n\n`)).toBe(true);
  });

  it('never takes a [ inside a multi-line string or a multi-line array for a header', () => {
    const text = 'a = [\n[1, 2],\n[3],\n]\nb = """\n[x]\n"""\nc = \'\'\'\n[[y]]\n\'\'\'\n[z]\n';
    expect(tomlSections(text).map((s) => s.name)).toEqual(['z']);
  });

  it('reads CRLF line endings and a byte order mark', () => {
    const text = '\uFEFF[project]\r\nname = "app"\r\n\r\n[tool.uv]\r\n';
    const uv = text.indexOf('[tool.uv]');
    expect(tomlSections(text)).toEqual([
      { name: 'project', start: 1, end: uv },
      { name: 'tool.uv', start: uv, end: text.length },
    ]);
  });

  it('throws on a text it cannot read', () => {
    expect(() => tomlSections('[project\nname = "app"\n')).toThrow(/not TOML/);
    expect(() => tomlSections('name = "app\n')).toThrow(/not TOML/);
  });
});

describe('tomlSectionName and tomlString', () => {
  it('writes bare parts bare and every other part as a basic string', () => {
    expect(tomlSectionName(['tool', 'poetry', 'dependencies', 'Django_Rest'])).toBe(
      'tool.poetry.dependencies.Django_Rest',
    );
    expect(tomlSectionName(['tool', 'zope.interface', 'a b'])).toBe('tool."zope.interface"."a b"');
  });

  it('escapes quotes, backslashes and control characters', () => {
    expect(tomlString('a"b\\c\nd\u007f')).toBe('"a\\"b\\\\c\\u000ad\\u007f"');
    expect(readPyproject(`k = ${tomlString('a"b\\c\nd')}\n`)).toEqual({ k: 'a"b\\c\nd' });
  });

  it('oneLine drops line breaks and other control characters', () => {
    expect(oneLine('a\r\n[tool.evil]\tb\u2028c\u0000')).toBe('a[tool.evil]bc');
  });
});

describe('replaceInSection', () => {
  it('replaces the first exact occurrence inside the section only', () => {
    const text = '[a]\nx = "qf-a>=1"\n\n[b]\ny = ["qf-a>=1", "qf-a>=1"]\n';
    expect(replaceInSection(text, 'b', '"qf-a>=1"', '"qf-a>=2"')).toBe(
      '[a]\nx = "qf-a>=1"\n\n[b]\ny = ["qf-a>=2", "qf-a>=1"]\n',
    );
  });

  it('skips occurrences inside comments', () => {
    const text = '[project]\ndependencies = [ # was "qf-a>=1.2.5"\n    "qf-a>=1.2.5",\n]\n';
    expect(replaceInSection(text, 'project', '"qf-a>=1.2.5"', '"qf-a>=1.2.6"')).toBe(
      '[project]\ndependencies = [ # was "qf-a>=1.2.5"\n    "qf-a>=1.2.6",\n]\n',
    );
  });

  it('answers null for a missing section or text', () => {
    expect(replaceInSection(PYPROJECT, 'tool.poetry', 'x', 'y')).toBeNull();
    expect(replaceInSection(PYPROJECT, 'tool.uv', '"qf-a>=1.2.5"', 'y')).toBeNull();
    expect(replaceInSection(PYPROJECT, 'project', '', 'y')).toBeNull();
  });
});

describe('tomlValue', () => {
  it('spans a key’s value without its comment', () => {
    const span = tomlValue(PYPROJECT, 'project', 'name');
    expect(PYPROJECT.slice(span?.start, span?.end)).toBe('"app"');
    const deps = tomlValue(PYPROJECT, 'project.optional-dependencies', 'fast');
    expect(PYPROJECT.slice(deps?.start, deps?.end)).toBe('["qf-a[speed]>=1.2.5"]');
  });

  it('finds quoted keys by their text, and answers null for a missing one', () => {
    const text =
      '[tool.poetry.dependencies]\n"Django_Rest" = { version = "^3.14", extras = ["x"] }\n';
    const span = tomlValue(text, 'tool.poetry.dependencies', 'Django_Rest');
    expect(text.slice(span?.start, span?.end)).toBe('{ version = "^3.14", extras = ["x"] }');
    expect(tomlValue(text, 'tool.poetry.dependencies', 'django-rest')).toBeNull();
    expect(tomlValue(text, 'tool.poetry', 'Django_Rest')).toBeNull();
  });
});

describe('setTomlArrayEntry', () => {
  const add = (text: string) =>
    setTomlArrayEntry(text, 'tool.uv', 'override-dependencies', 'qf-a>=1.2.6,<2');

  it('creates the section and the array at the end of the file', () => {
    expect(add('[project]\nname = "app"\n')).toBe(
      '[project]\nname = "app"\n\n[tool.uv]\noverride-dependencies = ["qf-a>=1.2.6,<2"]\n',
    );
    expect(add('[project]\nname = "app"\n\n')).toBe(
      '[project]\nname = "app"\n\n[tool.uv]\noverride-dependencies = ["qf-a>=1.2.6,<2"]\n',
    );
    expect(add('[project]\nname = "app"')).toBe(
      '[project]\nname = "app"\n\n[tool.uv]\noverride-dependencies = ["qf-a>=1.2.6,<2"]\n',
    );
  });

  it('adds the array after the last key of an existing section', () => {
    const text = '[tool.uv]\ndev-dependencies = []\n# about the index\n\n[[tool.uv.index]]\n';
    expect(add(text)).toBe(
      '[tool.uv]\ndev-dependencies = []\noverride-dependencies = ["qf-a>=1.2.6,<2"]\n# about the index\n\n[[tool.uv.index]]\n',
    );
  });

  it('extends a one-line array, empty or not, with or without a trailing comma', () => {
    const at = (array: string) => `[tool.uv]\noverride-dependencies = ${array} # pins\n`;
    expect(add(at('[]'))).toBe(at('["qf-a>=1.2.6,<2"]'));
    expect(add(at('["other>=1"]'))).toBe(at('["other>=1", "qf-a>=1.2.6,<2"]'));
    expect(add(at("['other>=1',]"))).toBe(at('[\'other>=1\', "qf-a>=1.2.6,<2",]'));
  });

  it('extends a multi-line array at its indentation, keeping comments after values', () => {
    const before = ['[tool.uv]', 'override-dependencies = [', '  "other>=1", # why', ']', ''].join(
      '\n',
    );
    expect(add(before)).toBe(
      [
        '[tool.uv]',
        'override-dependencies = [',
        '  "other>=1", # why',
        '  "qf-a>=1.2.6,<2",',
        ']',
        '',
      ].join('\n'),
    );
    const noComma = before.replace('"other>=1", # why', '"other>=1" # why');
    expect(add(noComma)).toBe(
      [
        '[tool.uv]',
        'override-dependencies = [',
        '  "other>=1", # why',
        '  "qf-a>=1.2.6,<2"',
        ']',
        '',
      ].join('\n'),
    );
    expect(add('[tool.uv]\noverride-dependencies = [\n]\n')).toBe(
      '[tool.uv]\noverride-dependencies = [\n    "qf-a>=1.2.6,<2",\n]\n',
    );
  });

  it('keeps CRLF line endings', () => {
    const text =
      '[project]\r\nname = "app"\r\n\r\n[tool.uv]\r\noverride-dependencies = [\r\n    "x>=1",\r\n]\r\n';
    expect(add(text)).toBe(
      '[project]\r\nname = "app"\r\n\r\n[tool.uv]\r\noverride-dependencies = [\r\n    "x>=1",\r\n    "qf-a>=1.2.6,<2",\r\n]\r\n',
    );
    expect(add('[project]\r\nname = "app"\r\n')).toBe(
      '[project]\r\nname = "app"\r\n\r\n[tool.uv]\r\noverride-dependencies = ["qf-a>=1.2.6,<2"]\r\n',
    );
  });

  it('throws when the key holds no array', () => {
    expect(() => add('[tool.uv]\noverride-dependencies = "x"\n')).toThrow(/not an array/);
  });
});

describe('setTomlKey', () => {
  it('replaces the value of an existing key, keeping its comment', () => {
    const text = '[tool.poetry.dependencies]\npython = "^3.11"\nqf-a = "^1.2.5" # web\n';
    expect(setTomlKey(text, 'tool.poetry.dependencies', 'qf-a', '"^1.2.6"', '# ignored')).toBe(
      '[tool.poetry.dependencies]\npython = "^3.11"\nqf-a = "^1.2.6" # web\n',
    );
  });

  it('adds a key after the last key of the section, with its comment on the line above', () => {
    const text =
      '[tool.poetry.dependencies]\npython = "^3.11"\n\n[tool.poetry.group.dev.dependencies]\n';
    expect(
      setTomlKey(text, 'tool.poetry.dependencies', 'zope.interface', '"^5.4"', '# Qualor: pinned'),
    ).toBe(
      '[tool.poetry.dependencies]\npython = "^3.11"\n# Qualor: pinned\n"zope.interface" = "^5.4"\n\n[tool.poetry.group.dev.dependencies]\n',
    );
  });

  it('creates a missing section, and keeps the comment on one line', () => {
    expect(
      setTomlKey(
        '[project]\r\nname = "app"\r\n',
        'tool.poetry.dependencies',
        'qf-a',
        '"^1.2.6"',
        '# for\r\n[tool.evil]',
      ),
    ).toBe(
      '[project]\r\nname = "app"\r\n\r\n[tool.poetry.dependencies]\r\n# for[tool.evil]\r\nqf-a = "^1.2.6"\r\n',
    );
  });

  it('reads the result back as the planned document', () => {
    const text = setTomlKey(PYPROJECT, 'tool.uv', 'package', 'false');
    const doc = readPyproject(text) as { tool: { uv: Record<string, unknown> } };
    expect(doc.tool.uv).toMatchObject({ 'dev-dependencies': [], package: false });
  });
});
