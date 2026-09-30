import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { parseConfig, SWIFTLINT_RULES } from '@qualor/shared';
import { describe, expect, it, vi } from 'vitest';
import type * as Yaml from 'yaml';
import { parse } from 'yaml';
import { useTempDirs, writeTree } from '../../test/tmp';
import {
  checkSwiftlintConfig,
  loadSwiftlintConfig,
  MAX_SWIFTLINT_CONFIG_ALIASES,
  MAX_SWIFTLINT_CONFIG_BYTES,
  parseSwiftlintYaml,
  planSwiftlintConfig,
  QUALOR_DEFAULT,
  QUALOR_SWIFTLINT_DEFAULTS,
  type SwiftlintPlan,
} from './swiftlint-config';

// Any exception of the YAML parser (a RangeError on a document nested past the stack) must be a
// skip reason, never a CLI crash (ruling F9, E14 parity). The yaml package turns its own stack
// overflow into a parse error, so a throw is simulated for one marker text.
vi.mock('yaml', async (importOriginal) => {
  const yaml = await importOriginal<typeof Yaml>();
  return {
    ...yaml,
    parseDocument: (...args: Parameters<typeof yaml.parseDocument>) => {
      if (args[0].includes('THROW-RANGE-ERROR-PARSE'))
        throw new RangeError('Maximum call stack size exceeded');
      return yaml.parseDocument(...args);
    },
  };
});

const tmp = useTempDirs();
const posix = process.platform !== 'win32';
const SOURCEKIT = [...SWIFTLINT_RULES].filter(([, r]) => r.sourceKit).map(([id]) => id);
const bytes = (s: string) => new TextEncoder().encode(s);
/** A backslash, spelled so that no editing tool rewrites an escape sequence in expected text. */
const BS = String.fromCharCode(92);

function parsed(yaml: string): Record<string, unknown> {
  const r = parseSwiftlintYaml(bytes(yaml));
  if ('error' in r) throw new Error(r.error);
  return r.ok;
}
function plan(yaml: string, dir = ''): SwiftlintPlan {
  const p = planSwiftlintConfig(parsed(yaml), dir, '.swiftlint.yml');
  if ('skip' in p) throw new Error(JSON.stringify(p));
  return p;
}
const written = (p: SwiftlintPlan) => parse(p.yaml, { version: '1.1' }) as Record<string, unknown>;
const skipOf = (yaml: string) => planSwiftlintConfig(parsed(yaml), '', '.swiftlint.yml');

describe('planSwiftlintConfig (config.md §6, plan 8F)', () => {
  it("is SwiftLint's default with the SourceKit rules disabled for an empty configuration", () => {
    const p = planSwiftlintConfig({}, '', 'x.yml');
    expect(p).toMatchObject({
      included: [],
      excluded: [],
      dropped: [],
      notRun: [],
      source: 'x.yml',
    });
    expect(written(p as SwiftlintPlan)).toEqual({ disabled_rules: SOURCEKIT });
  });

  it('keeps rule choices and rule configurations, and adds the SourceKit rules to disabled_rules', () => {
    const p = plan(
      'disabled_rules: [trailing_whitespace]\nopt_in_rules: [force_unwrapping]\nline_length: 100\nidentifier_name:\n  min_length: 2\nindentation: 2\n',
    );
    expect(written(p)).toEqual({
      opt_in_rules: ['force_unwrapping'],
      disabled_rules: ['trailing_whitespace', ...SOURCEKIT],
      line_length: 100,
      identifier_name: { min_length: 2 },
      indentation: 2,
    });
    expect(p.dropped).toEqual([]);
  });

  it('keeps kept rule settings that hold regular expressions as they are (ruling F11)', () => {
    const p = plan('line_length:\n  excluded_lines_patterns: ["^(a+)+$"]\n');
    expect(written(p)['line_length']).toEqual({ excluded_lines_patterns: ['^(a+)+$'] });
  });

  it('drops every key that writes, fetches, changes severities or the exit code, and unknown keys', () => {
    const p = plan(
      [
        'write_baseline: /tmp/marker.json',
        'baseline: b.json',
        'cache_path: /tmp/cache',
        'check_for_updates: true',
        'reporter: html',
        'strict: true',
        'lenient: true',
        'warning_threshold: 1',
        'allow_zero_lintable_files: true',
        'swiftlint_version: 0.50.0',
        'remote_timeout: 10',
        'remote_timeout_if_cached: 1',
        'analyzer_rules: [unused_import]',
        'not_a_rule: 1',
        '',
      ].join('\n'),
    );
    expect(Object.keys(written(p))).toEqual(['disabled_rules']);
    expect(p.dropped).toEqual([
      'write_baseline',
      'baseline',
      'cache_path',
      'check_for_updates',
      'reporter',
      'strict',
      'lenient',
      'warning_threshold',
      'allow_zero_lintable_files',
      'swiftlint_version',
      'remote_timeout',
      'remote_timeout_if_cached',
      'analyzer_rules',
      'not_a_rule',
    ]);
  });

  it('shows a dropped key with control characters safely', () => {
    expect(plan('"a\\nb": 1\n').dropped).toEqual(['a?b']);
  });

  it('leaves custom_rules out as a rule that cannot run (SourceKit)', () => {
    const p = plan('custom_rules:\n  leak:\n    regex: "x"\n    message: "${CI_JOB_TOKEN}"\n');
    expect(written(p)).not.toHaveProperty('custom_rules');
    expect(p.yaml).not.toContain('CI_JOB_TOKEN');
    expect(p.notRun).toEqual(['custom_rules']);
  });

  it('removes SourceKit rules from opt_in_rules and only_rules and says which', () => {
    const optIn = plan('opt_in_rules: [explicit_self, force_unwrapping]\n');
    expect(written(optIn)['opt_in_rules']).toEqual(['force_unwrapping']);
    expect(optIn.notRun).toEqual(['explicit_self']);
    const only = plan('only_rules: [colon, statement_position]\n');
    expect(written(only)).toEqual({ only_rules: ['colon'] });
    expect(only.notRun).toEqual(['statement_position']);
  });

  it('keeps opt_in_rules: [all], with the SourceKit rules disabled', () => {
    expect(written(plan('opt_in_rules: [all]\n'))).toEqual({
      opt_in_rules: ['all'],
      disabled_rules: SOURCEKIT,
    });
  });

  it('skips when only_rules has nothing left to run', () => {
    expect(skipOf('only_rules: [statement_position]\n')).toEqual({
      skip: '.swiftlint.yml: every rule in only_rules needs SourceKit, which the bundled SwiftLint does not have',
    });
  });

  it('skips only_rules together with disabled_rules or opt_in_rules, which SwiftLint refuses (ruling F3)', () => {
    for (const other of [
      'disabled_rules: [colon]',
      'opt_in_rules: [force_unwrapping]',
      'enabled_rules: [x]',
    ]) {
      expect(skipOf(`only_rules: [colon]\n${other}\n`), other).toEqual({
        skip: '.swiftlint.yml: only_rules cannot be combined with disabled_rules, opt_in_rules or enabled_rules (SwiftLint refuses such a configuration)',
      });
    }
  });

  it('skips a configuration that uses parent_config or child_config, naming the way out', () => {
    for (const key of [
      'parent_config: http://127.0.0.1:9/p.yml',
      'child_config: shared/child.yml',
    ]) {
      expect(skipOf(`${key}\n`), key).toEqual({
        skip: `.swiftlint.yml uses ${key.slice(0, key.indexOf(':'))}, which Qualor does not follow (config.md §6); make it self-contained, or set analyzers.swiftlint.configFile: qualor-default`,
      });
    }
  });

  it('turns included and excluded into globs relative to the configuration, refusing escapes', () => {
    const p = plan(
      'included: [Sources, "./App"]\nexcluded: [Pods, "**/Generated", /etc, ../x, "!Sources", "~/x", "a\\\\b", "C:/x", "./!foo", ".//~x"]\n',
      'ios',
    );
    expect(p.included).toEqual(['ios/Sources', 'ios/Sources/**', 'ios/App', 'ios/App/**']);
    expect(p.excluded).toEqual([
      'ios/Pods',
      'ios/Pods/**',
      'ios/**/Generated',
      'ios/**/Generated/**',
    ]);
    expect(p.dropped).toEqual([
      'excluded: /etc',
      'excluded: ../x',
      'excluded: !Sources',
      'excluded: ~/x',
      'excluded: a\\b',
      'excluded: C:/x',
      // Checked after the leading ./ is stripped too (final review minor 2).
      'excluded: ./!foo',
      'excluded: .//~x',
    ]);
    expect(written(p)).not.toHaveProperty('included');
    expect(written(p)).not.toHaveProperty('excluded');
    expect(plan('excluded: Pods\n').excluded).toEqual(['Pods', 'Pods/**']);
  });

  it('reads . and ./ as the configuration directory itself (fix round 1, m3)', () => {
    expect(plan('included: [., ./, .//]\n', 'ios').included).toEqual([
      'ios',
      'ios/**',
      'ios',
      'ios/**',
      'ios',
      'ios/**',
    ]);
    expect(plan('included: [.]\n').included).toEqual(['**']);
    expect(plan('included: ["/", ""]\n').dropped).toEqual(['included: /', 'included: ']);
  });

  it('skips rule lists that are not lists of identifiers, and path lists that are not lists', () => {
    expect(skipOf('disabled_rules: {a: 1}\n')).toEqual({
      skip: '.swiftlint.yml: disabled_rules must be a list of rule identifiers',
    });
    expect(skipOf('excluded: {a: 1}\n')).toEqual({
      skip: '.swiftlint.yml: excluded must be a list of paths',
    });
  });

  it('reads booleans as Yams does: yes/no/on/off/true/false, never y or n (fix round 1, I1)', () => {
    const p = plan(
      'identifier_name:\n  excluded: [x, y, n, Y, N, id]\nfile_name:\n  a: yes\n  b: Off\n  c: TRUE\n  d: "yes"\n',
    );
    expect(written(p)['identifier_name']).toEqual({ excluded: ['x', 'y', 'n', 'Y', 'N', 'id'] });
    expect(written(p)['file_name']).toEqual({ a: true, b: false, c: true, d: 'yes' });
    expect(p.yaml).toContain('"excluded":\n    - "x"\n    - "y"\n    - "n"\n');
    expect(p.yaml).toContain('"a": true\n');
    expect(p.yaml).toContain('"d": "yes"\n');
    // Yams's floats need a digit: a bare `.` is a string (fix round 1, Minor 3).
    expect(parseSwiftlintYaml(bytes('v: [., 1.5, .5, 5., 7]\n'))).toEqual({
      ok: { v: ['.', 1.5, 0.5, 5, 7] },
    });
  });

  it('writes every string and key double-quoted, so Yams reads each as a string (fix round 1, m1)', () => {
    const p = plan(
      'expiring_todo:\n  date: 2026-01-01\n  oct: "0o17"\n  num: "1e3"\n  "<<": {a: 1}\n  n: 12\n  f: 1.5\n  e: []\n  m: {}\n  z: null\n',
    );
    expect(p.yaml.split('\n').slice(1).join('\n')).toBe(
      [
        '"disabled_rules":',
        ...SOURCEKIT.map((id) => `  - "${id}"`),
        '"expiring_todo":',
        '  "date": "2026-01-01"',
        '  "oct": "0o17"',
        '  "num": "1e3"',
        '  "<<":',
        '    "a": 1',
        '  "n": 12',
        '  "f": 1.5',
        '  "e": []',
        '  "m": {}',
        '  "z": null',
        '',
      ].join('\n'),
    );
  });

  it('escapes every character outside printable ASCII, so libyaml reads it back (fix round 1, I2)', () => {
    const value =
      'a\u{7f}b\u{9f}c\u{85}d\u{2028}e\u{2029}f\u{feff}g\u{fffe}h\u{e9}i\u{1f600}j\u{1}k"l\\m\tn\no';
    const p = planSwiftlintConfig({ line_length: { message: value } }, '', 'x.yml');
    if ('skip' in p) throw new Error(p.skip);
    expect(p.yaml.split('\n').slice(1).join('\n')).toMatch(/^[\x20-\x7e\n]*$/);
    expect(p.yaml).toContain(
      '"message": "a%x7fb%x9fc%x85d%u2028e%u2029f%ufeffg%ufffeh%xe9i%U0001f600j%x01k%"l%%m%x09n%x0ao"'.replaceAll(
        '%',
        BS,
      ),
    );
    expect(written(p)['line_length']).toEqual({ message: value });
  });

  it('skips a value holding a lone surrogate, which libyaml cannot read (fix round 1, I2)', () => {
    expect(
      planSwiftlintConfig({ line_length: { message: 'a\u{d800}b' } }, '', '.swiftlint.yml'),
    ).toEqual({
      skip: '.swiftlint.yml holds a lone UTF-16 surrogate, which SwiftLint cannot read',
    });
  });

  it('writes $ as an escape, so SwiftLint expands no ${VAR} in a kept value (fix round 1, m2)', () => {
    const p = plan('identifier_name:\n  excluded: ["${CI_JOB_TOKEN}", "$HOME"]\n');
    expect(p.yaml).not.toContain('$');
    expect(p.yaml).toContain(`"${BS}x24{CI_JOB_TOKEN}"`);
    expect(written(p)['identifier_name']).toEqual({ excluded: ['${CI_JOB_TOKEN}', '$HOME'] });
  });

  it('writes the source name safely into the header, $ included (final review minor 2)', () => {
    const p = planSwiftlintConfig({}, '', 'a\nwrite_baseline: x\u{2028}\u{e9}${HOME}.yml');
    if (!('yaml' in p)) throw new Error(JSON.stringify(p));
    expect(p.yaml.split('\n')[0]).toBe(
      '# Written by Qualor from a?write_baseline: x???{HOME}.yml (config.md §6).',
    );
    // SwiftLint replaces ${VAR} in the whole text, comments included.
    expect(p.yaml).not.toContain('$');
  });

  it('lists rule ids SwiftLint does not know, once each (final review minor 9)', () => {
    const p = plan(
      [
        'opt_in_rules: [all, also_bad, my_rule, force_unwrapping]',
        'disabled_rules: [not_a_rule, todo, also_bad, all, custom_rules]',
        'custom_rules:',
        '  my_rule:',
        '    regex: foo',
        '',
      ].join('\n'),
    );
    // `all` is an opt_in_rules value only; a custom rule's id and custom_rules are ids.
    expect(p.unknownRules).toEqual(['also_bad', 'not_a_rule', 'all']);
    const only = plan('only_rules: [colon, all, "bad\\nid"]\n');
    expect(only.unknownRules).toEqual(['all', 'bad\nid']);
    expect(plan('disabled_rules: [todo]\n').unknownRules).toEqual([]);
  });

  it('skips when writing the configuration throws (fix round 1, m4)', () => {
    let deep: unknown = 1;
    for (let i = 0; i < 100_000; i++) deep = [deep];
    expect(planSwiftlintConfig({ line_length: deep }, '', '.swiftlint.yml')).toEqual({
      skip: '.swiftlint.yml cannot be written as YAML',
    });
  });
});

describe('parseSwiftlintYaml', () => {
  it('refuses what is not a readable YAML mapping', () => {
    expect(parseSwiftlintYaml(bytes('a: [1\n'))).toEqual({ error: 'cannot be parsed as YAML' });
    expect(parseSwiftlintYaml(bytes('a: 1\na: 2\n'))).toEqual({
      error: 'cannot be parsed as YAML',
    });
    expect(parseSwiftlintYaml(bytes('- a\n'))).toEqual({ error: 'is not a YAML mapping' });
    expect(parseSwiftlintYaml(new Uint8Array([0x61, 0x3a, 0x20, 0xff]))).toEqual({
      error: 'is not UTF-8',
    });
    expect(parseSwiftlintYaml(bytes('key: !!binary aGVsbG8=\n'))).toEqual({
      error: 'holds a YAML value SwiftLint cannot read',
    });
    expect(parseSwiftlintYaml(bytes('key: !custom x\n'))).toEqual({
      error: 'holds a YAML value SwiftLint cannot read',
    });
  });

  it('refuses an alias bomb', () => {
    const bomb = ['a: &a [x, x, x, x, x, x, x, x, x, x]'];
    for (let i = 0; i < 8; i++) {
      const prev = i === 0 ? 'a' : 'b'.repeat(i);
      bomb.push(`${'b'.repeat(i + 1)}: &${'b'.repeat(i + 1)} [*${prev}, *${prev}]`);
    }
    expect(parseSwiftlintYaml(bytes(`${bomb.join('\n')}\n`))).toEqual({
      error: 'expands too many YAML aliases',
    });
  });

  it(`refuses more than ${MAX_SWIFTLINT_CONFIG_ALIASES} aliases, and accepts that many (E14 parity)`, () => {
    const doc = (n: number) =>
      `a: &a 1\nb: [${Array.from({ length: n }, () => '*a').join(', ')}]\n`;
    expect(MAX_SWIFTLINT_CONFIG_ALIASES).toBe(50);
    expect(parseSwiftlintYaml(bytes(doc(50)))).toMatchObject({ ok: { a: 1 } });
    expect(parseSwiftlintYaml(bytes(doc(51)))).toEqual({
      error: 'has more than 50 YAML aliases',
    });
  });

  it('refuses a deeply nested document, and a parser that throws, as unparsable (ruling F9)', () => {
    const depth = 100_000;
    expect(parseSwiftlintYaml(bytes(`a: ${'['.repeat(depth)}${']'.repeat(depth)}\n`))).toEqual({
      error: 'cannot be parsed as YAML',
    });
    expect(parseSwiftlintYaml(bytes('a: THROW-RANGE-ERROR-PARSE\n'))).toEqual({
      error: 'cannot be parsed as YAML',
    });
  });

  it('reads an empty file as an empty mapping, and applies merge keys as Yams does', () => {
    expect(parseSwiftlintYaml(bytes(''))).toEqual({ ok: {} });
    expect(
      parseSwiftlintYaml(bytes('base: &b {min_length: 2}\nidentifier_name:\n  <<: *b\n')),
    ).toEqual({
      ok: { base: { min_length: 2 }, identifier_name: { min_length: 2 } },
    });
  });
});

describe("Qualor's defaults layer (ruling F5)", () => {
  it('pins the text', () => {
    expect(QUALOR_SWIFTLINT_DEFAULTS).toBe(
      `# Qualor's defaults for a project without a SwiftLint configuration (config.md §6).
disabled_rules:
  - todo
  - multiple_closures_with_trailing_closure
  - trailing_comma
  - comment_spacing
trailing_whitespace:
  ignores_empty_lines: true
identifier_name:
  excluded: [i, j, k, x, "y", z, id]
line_length:
  ignores_urls: true
  ignores_comments: true
opening_brace:
  ignore_multiline_statement_conditions: true
  ignore_multiline_type_headers: true
  ignore_multiline_function_signatures: true
nesting:
  type_level: 2
`,
    );
  });

  it('is what SwiftLint gets without a project configuration, or with configFile: qualor-default', () => {
    const root = tmp();
    const expected = {
      disabled_rules: [
        'todo',
        'multiple_closures_with_trailing_closure',
        'trailing_comma',
        'comment_spacing',
        ...SOURCEKIT,
      ],
      trailing_whitespace: { ignores_empty_lines: true },
      identifier_name: { excluded: ['i', 'j', 'k', 'x', 'y', 'z', 'id'] },
      line_length: { ignores_urls: true, ignores_comments: true },
      opening_brace: {
        ignore_multiline_statement_conditions: true,
        ignore_multiline_type_headers: true,
        ignore_multiline_function_signatures: true,
      },
      nesting: { type_level: 2 },
    };
    const none = loadSwiftlintConfig(root, null) as SwiftlintPlan;
    expect(none).toMatchObject({ source: QUALOR_DEFAULT, dropped: [], notRun: [] });
    expect(written(none)).toEqual(expected);
    writeTree(root, { '.swiftlint.yml': 'line_length: 90\n' });
    expect(written(loadSwiftlintConfig(root, QUALOR_DEFAULT) as SwiftlintPlan)).toEqual(expected);
  });

  it('is not used with a project configuration', () => {
    const root = tmp();
    writeTree(root, { '.swiftlint.yml': 'line_length: 90\n' });
    expect(written(loadSwiftlintConfig(root, null) as SwiftlintPlan)).toEqual({
      disabled_rules: SOURCEKIT,
      line_length: 90,
    });
  });
});

describe('loadSwiftlintConfig and checkSwiftlintConfig', () => {
  const cfg = (configFile: string | null) =>
    parseConfig({ version: 1, analyzers: { swiftlint: { configFile } } });

  it("uses the root .swiftlint.yml, else Qualor's default; configFile names another or qualor-default", () => {
    const root = tmp();
    expect(loadSwiftlintConfig(root, null)).toMatchObject({ source: 'qualor-default' });
    writeTree(root, {
      '.swiftlint.yml': 'line_length: 90\n',
      'ios/lint.yml': 'excluded: [Pods]\n',
      'Sources/.swiftlint.yml': 'write_baseline: x\n',
    });
    expect(loadSwiftlintConfig(root, null)).toMatchObject({ source: '.swiftlint.yml' });
    expect(loadSwiftlintConfig(root, 'ios/lint.yml')).toMatchObject({
      source: 'ios/lint.yml',
      excluded: ['ios/Pods', 'ios/Pods/**'],
    });
    expect(loadSwiftlintConfig(root, './ios//lint.yml')).toMatchObject({ source: 'ios/lint.yml' });
    expect(loadSwiftlintConfig(root, 'qualor-default')).toMatchObject({ source: 'qualor-default' });
    expect(loadSwiftlintConfig(root, 'missing.yml')).toEqual({
      skip: 'configFile missing.yml does not exist',
    });
  });

  it('is a configuration error (exit 2) only for a configFile that is a URL or outside the repository (ruling F3)', () => {
    const root = tmp();
    const outside = tmp();
    writeFileSync(path.join(outside, 'x.yml'), 'line_length: 1\n');
    const url = 'configFile https://example.com/x.yml is a URL (only repository files)';
    expect(checkSwiftlintConfig(root, cfg('https://example.com/x.yml'))).toBe(url);
    expect(loadSwiftlintConfig(root, 'https://example.com/x.yml')).toEqual({ error: url });
    const out = 'configFile ../x.yml is outside the repository';
    expect(checkSwiftlintConfig(root, cfg('../x.yml'))).toBe(out);
    expect(loadSwiftlintConfig(root, '../x.yml')).toEqual({ error: out });
    expect(checkSwiftlintConfig(root, cfg(path.join(outside, 'x.yml')))).toMatch(
      /is outside the repository$/,
    );
    expect(checkSwiftlintConfig(root, cfg(null))).toBeNull();
    expect(checkSwiftlintConfig(root, cfg('qualor-default'))).toBeNull();
    expect(checkSwiftlintConfig(root, cfg('missing.yml'))).toBeNull();
  });

  it('skips on every problem of the file itself, which is never a configuration error (ruling F3)', () => {
    const cases: [Record<string, string | Uint8Array> | null, string][] = [
      [{ '.swiftlint.yml': 'a: [1\n' }, '.swiftlint.yml cannot be parsed as YAML'],
      [{ '.swiftlint.yml': '- a\n' }, '.swiftlint.yml is not a YAML mapping'],
      [
        { '.swiftlint.yml': new Uint8Array([0x61, 0x3a, 0x20, 0xff]) },
        '.swiftlint.yml is not UTF-8',
      ],
      [
        { '.swiftlint.yml': `# ${'x'.repeat(MAX_SWIFTLINT_CONFIG_BYTES)}\n` },
        '.swiftlint.yml is larger than 1 MiB',
      ],
      [
        { '.swiftlint.yml': 'only_rules: [colon]\ndisabled_rules: [x]\n' },
        '.swiftlint.yml: only_rules cannot be combined with disabled_rules, opt_in_rules or enabled_rules (SwiftLint refuses such a configuration)',
      ],
      [
        { '.swiftlint.yml': 'parent_config: p.yml\n' },
        '.swiftlint.yml uses parent_config, which Qualor does not follow (config.md §6); make it self-contained, or set analyzers.swiftlint.configFile: qualor-default',
      ],
    ];
    for (const [files, reason] of cases) {
      const root = tmp();
      if (files !== null) writeTree(root, files);
      expect(loadSwiftlintConfig(root, null), reason).toEqual({ skip: reason });
      expect(checkSwiftlintConfig(root, cfg(null)), reason).toBeNull();
    }
    const dir = tmp();
    mkdirSync(path.join(dir, '.swiftlint.yml'));
    expect(loadSwiftlintConfig(dir, null)).toEqual({
      skip: '.swiftlint.yml is not a regular file',
    });
    mkdirSync(path.join(dir, 'conf'));
    expect(loadSwiftlintConfig(dir, 'conf')).toEqual({ skip: 'conf is not a regular file' });
    expect(checkSwiftlintConfig(dir, cfg('conf'))).toBeNull();
  });

  it.runIf(posix)('skips a .swiftlint.yml that links out of the repository (ruling E6/D8)', () => {
    const root = tmp();
    const outside = tmp();
    writeFileSync(path.join(outside, 'x.yml'), 'line_length: 1\n');
    symlinkSync(path.join(outside, 'x.yml'), path.join(root, '.swiftlint.yml'));
    expect(loadSwiftlintConfig(root, null)).toEqual({
      skip: '.swiftlint.yml is outside the repository',
    });
    expect(checkSwiftlintConfig(root, cfg(null))).toBeNull();
    symlinkSync(outside, path.join(root, 'shared'));
    expect(loadSwiftlintConfig(root, 'shared/x.yml')).toEqual({
      skip: 'shared/x.yml is outside the repository',
    });
    expect(checkSwiftlintConfig(root, cfg('shared/x.yml'))).toBeNull();
  });

  it.runIf(posix)(
    'uses a .swiftlint.yml that links to a file inside the repository (ruling E6)',
    () => {
      const root = tmp();
      writeTree(root, { 'config/swiftlint.yml': 'line_length: 90\n' });
      symlinkSync(path.join(root, 'config', 'swiftlint.yml'), path.join(root, '.swiftlint.yml'));
      expect(loadSwiftlintConfig(root, null)).toMatchObject({ source: '.swiftlint.yml' });
    },
  );

  it.runIf(posix)('skips on a dangling .swiftlint.yml link', () => {
    const root = tmp();
    symlinkSync(path.join(root, 'nowhere.yml'), path.join(root, '.swiftlint.yml'));
    expect(loadSwiftlintConfig(root, null)).toEqual({ skip: '.swiftlint.yml cannot be read' });
  });
});
