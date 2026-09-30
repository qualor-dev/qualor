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

// Any exception of the YAML parser or writer (a RangeError on a document nested past the stack)
// must be a skip reason, never a CLI crash (ruling F9, E14 parity). The yaml package turns its own
// stack overflow into a parse error, so a throw is simulated for one marker text.
vi.mock('yaml', async (importOriginal) => {
  const yaml = await importOriginal<typeof Yaml>();
  const marked = (v: unknown) => JSON.stringify(v ?? null).includes('THROW-RANGE-ERROR');
  return {
    ...yaml,
    parseDocument: (...args: Parameters<typeof yaml.parseDocument>) => {
      if (args[0].includes('THROW-RANGE-ERROR-PARSE'))
        throw new RangeError('Maximum call stack size exceeded');
      return yaml.parseDocument(...args);
    },
    stringify: (...args: Parameters<typeof yaml.stringify>) => {
      if (marked(args[0])) throw new RangeError('Maximum call stack size exceeded');
      return yaml.stringify(...args);
    },
  };
});

const tmp = useTempDirs();
const posix = process.platform !== 'win32';
const SOURCEKIT = [...SWIFTLINT_RULES].filter(([, r]) => r.sourceKit).map(([id]) => id);
const bytes = (s: string) => new TextEncoder().encode(s);

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
      'included: [Sources, "./App"]\nexcluded: [Pods, "**/Generated", /etc, ../x, "!Sources", "~/x", "a\\\\b", "C:/x"]\n',
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
    ]);
    expect(written(p)).not.toHaveProperty('included');
    expect(written(p)).not.toHaveProperty('excluded');
    expect(plan('excluded: Pods\n').excluded).toEqual(['Pods', 'Pods/**']);
  });

  it('skips rule lists that are not lists of identifiers, and path lists that are not lists', () => {
    expect(skipOf('disabled_rules: {a: 1}\n')).toEqual({
      skip: '.swiftlint.yml: disabled_rules must be a list of rule identifiers',
    });
    expect(skipOf('excluded: {a: 1}\n')).toEqual({
      skip: '.swiftlint.yml: excluded must be a list of paths',
    });
  });

  it('reads and writes YAML 1.1 like SwiftLint (Yams), so every value means what it meant', () => {
    // A quoted "yes" stays a string; a bare yes is a boolean in YAML 1.1, for Yams and for us.
    expect(plan('file_name:\n  severity: "yes"\n').yaml).toContain('severity: "yes"');
    expect(written(plan('file_name:\n  flag: yes\n'))['file_name']).toEqual({ flag: true });
    // A date stays the text it was (SwiftLint's own reader decides what it is).
    expect(plan('expiring_todo:\n  date: 2026-01-01\n').yaml).toContain('date: 2026-01-01');
  });

  it('skips a kept value holding a character that Yams reads as a line break', () => {
    for (const c of ['\\u2028', '\\u2029', '\\x85']) {
      expect(skipOf(`line_length:\n  message: "x${c}write_baseline:/tmp/m"\n`), c).toEqual({
        skip: '.swiftlint.yml holds U+0085, U+2028 or U+2029, which SwiftLint reads as a line break',
      });
    }
  });

  it('writes the source name safely into the header', () => {
    const p = planSwiftlintConfig({}, '', 'a\nwrite_baseline: x\u2028.yml');
    expect('yaml' in p && p.yaml.split('\n')[0]).toBe(
      '# Written by Qualor from a?write_baseline: x?.yml (config.md §6).',
    );
  });

  it('skips when writing the configuration throws', () => {
    expect(skipOf('line_length:\n  message: THROW-RANGE-ERROR\n')).toEqual({
      skip: '.swiftlint.yml cannot be parsed as YAML',
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
trailing_whitespace:
  ignores_empty_lines: true
identifier_name:
  excluded: [i, j, k, x, "y", z, id]
line_length:
  ignores_urls: true
  ignores_comments: true
`,
    );
  });

  it('is what SwiftLint gets without a project configuration, or with configFile: qualor-default', () => {
    const root = tmp();
    const expected = {
      disabled_rules: ['todo', 'multiple_closures_with_trailing_closure', ...SOURCEKIT],
      trailing_whitespace: { ignores_empty_lines: true },
      identifier_name: { excluded: ['i', 'j', 'k', 'x', 'y', 'z', 'id'] },
      line_length: { ignores_urls: true, ignores_comments: true },
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
