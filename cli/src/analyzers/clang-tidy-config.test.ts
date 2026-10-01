import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { CLANG_TIDY_BUILTIN_CHECKS, CLANG_TIDY_DEFAULT_CHECKS, parseConfig } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { useTempDirs, writeTree } from '../../test/tmp';
import {
  checkClangTidyConfig,
  loadClangTidyConfig,
  MAX_CLANG_TIDY_CONFIG_BYTES,
  type ClangTidyPlan,
} from './clang-tidy-config';

const tmp = useTempDirs();
const plan = (root: string, configFile: string | null = null): ClangTidyPlan => {
  const p = loadClangTidyConfig(root, configFile);
  if (!('json' in p)) throw new Error(JSON.stringify(p));
  return p;
};
const written = (p: ClangTidyPlan) => JSON.parse(p.json) as Record<string, unknown>;

describe('loadClangTidyConfig (config.md §6.2, plan 9D)', () => {
  it("uses Qualor's default checks without a .clang-tidy, and with configFile: qualor-default", () => {
    const root = tmp();
    expect(written(plan(root))).toEqual({ Checks: CLANG_TIDY_DEFAULT_CHECKS });
    writeTree(root, { '.clang-tidy': "Checks: '-*,readability-*'\n" });
    expect(written(plan(root, 'qualor-default'))).toEqual({ Checks: CLANG_TIDY_DEFAULT_CHECKS });
    expect(plan(root, 'qualor-default').source).toBe('qualor-default');
  });

  it('keeps Checks, CheckOptions and the extension lists, and drops every other key (Review Focus 1)', () => {
    const root = tmp();
    writeTree(root, {
      '.clang-tidy': [
        'Checks: >',
        '  -*,',
        '  bugprone-*,',
        '  readability-identifier-length',
        'CheckOptions:',
        '  readability-identifier-length.MinimumVariableNameLength: 2',
        '  - key: ignored-because-mixed',
        '',
      ].join('\n'),
    });
    // a mapping mixed with a list item is not YAML: a skip
    expect(loadClangTidyConfig(root, null)).toEqual({
      skip: '.clang-tidy cannot be parsed as YAML',
    });
    writeTree(root, {
      '.clang-tidy': [
        "Checks: '-*,bugprone-*'",
        'CheckOptions:',
        '  - key: readability-identifier-length.MinimumVariableNameLength',
        '    value: 2',
        'HeaderFileExtensions: [h, hpp]',
        "ExtraArgs: ['-fplugin=./evil.so']",
        "ExtraArgsBefore: ['-Xclang', '-load']",
        'InheritParentConfig: true',
        "WarningsAsErrors: '*'",
        "HeaderFilterRegex: '.*'",
        'SystemHeaders: true',
        'FormatStyle: file',
        'User: someone',
        'UseColor: true',
        'CustomChecks: []',
        'RemovedArgs: [-Werror]',
        'Unknown: 1',
        '',
      ].join('\n'),
    });
    const p = plan(root);
    expect(written(p)).toEqual({
      Checks: '-*,bugprone-*',
      CheckOptions: { 'readability-identifier-length.MinimumVariableNameLength': '2' },
      HeaderFileExtensions: ['h', 'hpp'],
    });
    expect(p.dropped).toEqual([
      'ExtraArgs',
      'ExtraArgsBefore',
      'InheritParentConfig',
      'WarningsAsErrors',
      'HeaderFilterRegex',
      'SystemHeaders',
      'FormatStyle',
      'User',
      'UseColor',
      'CustomChecks',
      'RemovedArgs',
      'Unknown',
    ]);
    expect(p.source).toBe('.clang-tidy');
  });

  it("joins a block or list of Checks, and falls back to clang-tidy's own default without Checks", () => {
    const root = tmp();
    writeTree(root, { '.clang-tidy': 'Checks:\n  - "-*"\n  - "bugprone-*"\n' });
    expect(written(plan(root))['Checks']).toBe('-*,bugprone-*');
    writeTree(root, { '.clang-tidy': 'Checks: >\n  -*,\n  bugprone-*\n' });
    expect(written(plan(root))['Checks']).toBe('-*,bugprone-*');
    writeTree(root, { '.clang-tidy': 'CheckOptions:\n  a.b: 1\n' });
    expect(written(plan(root))).toEqual({
      Checks: CLANG_TIDY_BUILTIN_CHECKS,
      CheckOptions: { 'a.b': '1' },
    });
  });

  it('drops global static analyzer settings and checker options that name a file, keeping the rest (ruling D9-11)', () => {
    const root = tmp();
    writeTree(root, {
      '.clang-tidy': [
        "Checks: '-*,clang-analyzer-*'",
        'CheckOptions:',
        '  clang-analyzer-ctu-invocation-list: /etc/secret-invocations.yml',
        '  clang-analyzer-dump-entry-point-stats-to-csv: /tmp/out.csv',
        '  clang-analyzer-model-path: models',
        '  clang-analyzer-alpha.security.taint.TaintPropagation:Config: taint.yml',
        '  clang-analyzer-optin.cplusplus.UninitializedObject:Pedantic: x/../y',
        '  clang-analyzer-core.NullDereference:SuppressAddressSpaces: false',
        '  clang-analyzer-unix.DynamicMemoryModeling:Optimistic: true',
        '  readability-identifier-length.MinimumVariableNameLength: 2',
        '',
      ].join('\n'),
    });
    const p = plan(root);
    expect(written(p)).toEqual({
      Checks: '-*,clang-analyzer-*',
      CheckOptions: {
        'clang-analyzer-core.NullDereference:SuppressAddressSpaces': 'false',
        'clang-analyzer-unix.DynamicMemoryModeling:Optimistic': 'true',
        'readability-identifier-length.MinimumVariableNameLength': '2',
      },
    });
    expect(p.droppedOptions).toEqual([
      'clang-analyzer-ctu-invocation-list (a global static analyzer setting)',
      'clang-analyzer-dump-entry-point-stats-to-csv (a global static analyzer setting)',
      'clang-analyzer-model-path (a global static analyzer setting)',
      'clang-analyzer-alpha.security.taint.TaintPropagation:Config (a static analyzer option that names a file)',
      'clang-analyzer-optin.cplusplus.UninitializedObject:Pedantic (a static analyzer option that names a file)',
    ]);
    // Keys only: no value reaches the log line.
    expect(p.droppedOptions.join(' ')).not.toMatch(/secret|out\.csv|taint\.yml/);
    expect(p.dropped).toEqual([]);
  });

  it('skips what it cannot read safely', () => {
    const root = tmp();
    const cases: [string, string][] = [
      ['a: [1\n', '.clang-tidy cannot be parsed as YAML'],
      ['- a\n', '.clang-tidy is not a YAML mapping'],
      ["Checks: '-*;rm -rf'\n", '.clang-tidy: Checks holds characters no check name uses'],
      [
        'CheckOptions: 3\n',
        '.clang-tidy: CheckOptions must be a mapping or a list of key/value pairs',
      ],
      [
        'HeaderFileExtensions: [../x]\n',
        '.clang-tidy: HeaderFileExtensions must be a list of extensions',
      ],
    ];
    for (const [text, skip] of cases) {
      writeFileSync(path.join(root, '.clang-tidy'), text);
      expect(loadClangTidyConfig(root, null), text).toEqual({ skip });
    }
    writeFileSync(path.join(root, '.clang-tidy'), `# ${'x'.repeat(MAX_CLANG_TIDY_CONFIG_BYTES)}\n`);
    expect(loadClangTidyConfig(root, null)).toEqual({ skip: '.clang-tidy is larger than 1 MiB' });
    expect(loadClangTidyConfig(root, 'tools/tidy.yml')).toEqual({
      skip: 'configFile tools/tidy.yml does not exist',
    });
  });

  it('is a configuration error only for a configFile or compileCommands that is a URL or outside the repository', () => {
    const cfg = (o: Record<string, unknown>) =>
      parseConfig({ version: 1, analyzers: { 'clang-tidy': o } } as never);
    expect(checkClangTidyConfig('/r', cfg({ configFile: 'https://x/.clang-tidy' }))).toBe(
      'analyzers.clang-tidy.configFile https://x/.clang-tidy is a URL (only repository files)',
    );
    expect(checkClangTidyConfig('/r', cfg({ configFile: '../.clang-tidy' }))).toBe(
      'analyzers.clang-tidy.configFile ../.clang-tidy is outside the repository',
    );
    expect(checkClangTidyConfig('/r', cfg({ compileCommands: '/abs/cc.json' }))).toMatch(
      /outside the repository/,
    );
    expect(checkClangTidyConfig('/r', cfg({ configFile: 'qualor-default' }))).toBeNull();
  });

  it.runIf(process.platform !== 'win32')(
    'skips a .clang-tidy that links out of the repository, and ignores nested ones',
    () => {
      const root = tmp();
      const outside = tmp();
      writeFileSync(path.join(outside, 'x'), "Checks: '-*'\n");
      symlinkSync(path.join(outside, 'x'), path.join(root, '.clang-tidy'));
      expect(loadClangTidyConfig(root, null)).toEqual({
        skip: '.clang-tidy is outside the repository',
      });
      const other = tmp();
      mkdirSync(path.join(other, 'src'));
      writeFileSync(path.join(other, 'src/.clang-tidy'), "Checks: '-*'\n");
      expect(written(plan(other))).toEqual({ Checks: CLANG_TIDY_DEFAULT_CHECKS });
    },
  );
});
