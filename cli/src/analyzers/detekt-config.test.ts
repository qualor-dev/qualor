import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { parseConfig } from '@qualor/shared';
import { describe, expect, it, vi } from 'vitest';
import type * as Yaml from 'yaml';
import { useTempDirs, writeTree } from '../../test/tmp';
import {
  checkDetektConfig,
  DETEKT_CONFIG_CANDIDATES,
  detektConfig,
  MAX_DETEKT_CONFIG_ALIASES,
  MAX_DETEKT_CONFIG_BYTES,
  QUALOR_DETEKT_DEFAULTS,
  QUALOR_DETEKT_OVERLAY,
} from './detekt-config';

// A parser exception (a RangeError on a document nested past the stack) must be a skip reason,
// never a CLI crash (ruling E14). The yaml package turns its own stack overflow into a parse
// error, so a throw is simulated for one marker text.
vi.mock('yaml', async (importOriginal) => {
  const yaml = await importOriginal<typeof Yaml>();
  return {
    ...yaml,
    parseDocument: (...args: Parameters<typeof yaml.parseDocument>) => {
      if (args[0].includes('THROW-RANGE-ERROR'))
        throw new RangeError('Maximum call stack size exceeded');
      return yaml.parseDocument(...args);
    },
  };
});

const tmp = useTempDirs();
const posix = process.platform !== 'win32';
const cfg = (configFile?: string) =>
  parseConfig({
    version: 1,
    ...(configFile !== undefined && { analyzers: { detekt: { configFile } } }),
  });
const OK = 'style:\n  MagicNumber:\n    active: false\n';

describe('detektConfig (config.md §6)', () => {
  it('uses detekt defaults without a project config', () => {
    expect(detektConfig(tmp(), cfg())).toEqual({ kind: 'none' });
  });

  it('finds the first candidate, the Gradle plugin default first', () => {
    expect(DETEKT_CONFIG_CANDIDATES).toEqual([
      'config/detekt/detekt.yml',
      'config/detekt.yml',
      'detekt.yml',
      '.detekt.yml',
    ]);
    const root = tmp();
    writeTree(root, { 'detekt.yml': 'a: 1\n', 'config/detekt/detekt.yml': OK });
    expect(detektConfig(root, cfg())).toEqual({
      kind: 'project',
      rel: 'config/detekt/detekt.yml',
      text: OK,
    });
  });

  it('uses configFile instead of the candidates, and skips a missing one', () => {
    const root = tmp();
    writeTree(root, { 'detekt.yml': 'a: 1\n', 'lint/k.yml': OK });
    expect(detektConfig(root, cfg('lint/k.yml'))).toEqual({
      kind: 'project',
      rel: 'lint/k.yml',
      text: OK,
    });
    expect(detektConfig(root, cfg('lint/none.yml'))).toEqual({
      kind: 'skip',
      reason: 'configFile lint/none.yml does not exist',
    });
    expect(checkDetektConfig(root, cfg('lint/none.yml'))).toBeNull();
  });

  it('refuses a configFile outside the repository: an invalid qualor.yml setting (exit 2, ruling E7)', () => {
    const root = tmp();
    const reason = 'configFile ../outside.yml is outside the repository';
    expect(checkDetektConfig(root, cfg('../outside.yml'))).toBe(reason);
    expect(detektConfig(root, cfg('../outside.yml'))).toEqual({ kind: 'error', reason });
    const abs = path.join(tmp(), 'x.yml');
    writeFileSync(abs, OK);
    expect(checkDetektConfig(root, cfg(abs))).toBe(`configFile ${abs} is outside the repository`);
  });

  it.runIf(posix)('uses a config that links to a file inside the repository (ruling E6)', () => {
    const root = tmp();
    writeTree(root, { 'shared/lint.yml': OK });
    mkdirSync(path.join(root, 'config', 'detekt'), { recursive: true });
    symlinkSync(
      path.join('..', '..', 'shared', 'lint.yml'),
      path.join(root, 'config', 'detekt', 'detekt.yml'),
    );
    expect(detektConfig(root, cfg())).toEqual({
      kind: 'project',
      rel: 'config/detekt/detekt.yml',
      text: OK,
    });
  });

  it.runIf(posix)(
    'skips on a config that links out of the repository, never reading it (ruling E6, E7)',
    () => {
      const root = tmp();
      const outside = path.join(tmp(), 'x.yml');
      writeFileSync(outside, OK);
      mkdirSync(path.join(root, 'config', 'detekt'), { recursive: true });
      symlinkSync(outside, path.join(root, 'config', 'detekt', 'detekt.yml'));
      const reason = 'config/detekt/detekt.yml is outside the repository';
      expect(detektConfig(root, cfg())).toEqual({ kind: 'skip', reason });
      expect(checkDetektConfig(root, cfg())).toBeNull();
      // The same for a named configFile that links out: a checkout problem, not qualor.yml's.
      symlinkSync(outside, path.join(root, 'k.yml'));
      expect(detektConfig(root, cfg('k.yml'))).toEqual({
        kind: 'skip',
        reason: 'k.yml is outside the repository',
      });
      expect(checkDetektConfig(root, cfg('k.yml'))).toBeNull();
    },
  );

  it.runIf(posix)('skips on a config below a directory that links out of the repository', () => {
    const root = tmp();
    const outside = tmp();
    writeTree(outside, { 'detekt/detekt.yml': OK });
    symlinkSync(outside, path.join(root, 'config'));
    expect(detektConfig(root, cfg())).toEqual({
      kind: 'skip',
      reason: 'config/detekt/detekt.yml is outside the repository',
    });
  });

  it.runIf(posix)('skips on a dangling link', () => {
    const root = tmp();
    symlinkSync(path.join(root, 'nowhere.yml'), path.join(root, 'detekt.yml'));
    expect(detektConfig(root, cfg())).toEqual({
      kind: 'skip',
      reason: 'detekt.yml cannot be read',
    });
  });

  const aliases = (n: number) =>
    `x: &t "1"\nstyle:\n${Array.from({ length: n }, (_, i) => `  k${i}: *t\n`).join('')}`;
  const deep = `${'['.repeat(20_000)}${']'.repeat(20_000)}\n`;

  it.each([
    [
      'a directory',
      (root: string) => mkdirSync(path.join(root, 'detekt.yml')),
      'detekt.yml is not a regular file',
    ],
    [
      'too large',
      (root: string) =>
        writeFileSync(
          path.join(root, 'detekt.yml'),
          `a: "${'x'.repeat(MAX_DETEKT_CONFIG_BYTES)}"\n`,
        ),
      'detekt.yml is larger than 1 MiB',
    ],
    [
      'not UTF-8',
      (root: string) =>
        writeFileSync(path.join(root, 'detekt.yml'), Buffer.from([0x61, 0x3a, 0x20, 0xff, 0x0a])),
      'detekt.yml is not UTF-8',
    ],
    [
      'not YAML',
      (root: string) => writeFileSync(path.join(root, 'detekt.yml'), 'a: [\n'),
      'detekt.yml is not valid YAML',
    ],
    [
      'a duplicate key',
      (root: string) => writeFileSync(path.join(root, 'detekt.yml'), 'a: 1\na: 2\n'),
      'detekt.yml is not valid YAML',
    ],
    [
      'two documents',
      (root: string) => writeFileSync(path.join(root, 'detekt.yml'), 'a: 1\n---\nb: 2\n'),
      'detekt.yml is not valid YAML',
    ],
    [
      'a list',
      (root: string) => writeFileSync(path.join(root, 'detekt.yml'), '- 1\n'),
      'detekt.yml is not a YAML mapping',
    ],
    [
      'empty',
      (root: string) => writeFileSync(path.join(root, 'detekt.yml'), ''),
      'detekt.yml is not a YAML mapping',
    ],
    [
      'an explicit tag',
      (root: string) =>
        writeFileSync(
          path.join(root, 'detekt.yml'),
          'style:\n  MagicNumber: !!java.net.URL ["http://x"]\n',
        ),
      'detekt.yml has an explicit YAML tag',
    ],
    [
      'a harmless-looking tag',
      (root: string) => writeFileSync(path.join(root, 'detekt.yml'), 'a: !!str 1\n'),
      'detekt.yml has an explicit YAML tag',
    ],
    [
      'more than 50 aliases (ruling E14)',
      (root: string) => writeFileSync(path.join(root, 'detekt.yml'), aliases(51)),
      'detekt.yml has more than 50 YAML aliases',
    ],
    [
      'nested too deeply to parse (ruling E14)',
      (root: string) => writeFileSync(path.join(root, 'detekt.yml'), `a: ${deep}`),
      'detekt.yml is not valid YAML',
    ],
    [
      'one the parser throws on (ruling E14)',
      (root: string) => writeFileSync(path.join(root, 'detekt.yml'), 'a: THROW-RANGE-ERROR\n'),
      'detekt.yml is not valid YAML',
    ],
  ])('skips on a config that is %s, never exit 2 (ruling E7)', (_name, write, reason) => {
    const root = tmp();
    write(root);
    expect(checkDetektConfig(root, cfg())).toBeNull();
    expect(detektConfig(root, cfg())).toEqual({ kind: 'skip', reason });
  });

  it('accepts aliases up to the limit and ordinary scalars', () => {
    expect(MAX_DETEKT_CONFIG_ALIASES).toBe(50);
    const root = tmp();
    writeTree(root, {
      '.detekt.yml': 'x: &t ["1"]\nstyle:\n  MagicNumber:\n    ignoreNumbers: *t\n',
    });
    expect(checkDetektConfig(root, cfg())).toBeNull();
    expect(detektConfig(root, cfg()).kind).toBe('project');
    writeTree(root, { '.detekt.yml': aliases(50) });
    expect(detektConfig(root, cfg()).kind).toBe('project');
  });

  it('shows a configFile name with control characters safely', () => {
    const root = tmp();
    expect(detektConfig(root, cfg('a\nb.yml'))).toEqual({
      kind: 'skip',
      reason: 'configFile a?b.yml does not exist',
    });
  });
});

describe('the configs Qualor passes to detekt (config.md §6)', () => {
  it('pins the Compose defaults layer, used only without a project config (final review, Important 1)', () => {
    // detekt's own Jetpack Compose guidance (detekt.dev/docs/introduction/compose).
    expect(QUALOR_DETEKT_DEFAULTS).toBe(
      [
        "# Qualor's defaults for a project without a detekt config: detekt's Jetpack Compose settings.",
        'naming:',
        '  FunctionNaming:',
        "    ignoreAnnotated: ['Composable']",
        '  TopLevelPropertyNaming:',
        "    constantPattern: '[A-Z][A-Za-z0-9]*'",
        'complexity:',
        '  LongParameterList:',
        '    ignoreDefaultParameters: true',
        'style:',
        '  MagicNumber:',
        '    ignorePropertyDeclaration: true',
        '    ignoreCompanionObjectPropertyDeclaration: true',
        '  UnusedPrivateMember:',
        "    ignoreAnnotated: ['Preview']",
        '',
      ].join('\n'),
    );
  });

  it('pins the overlay: only the keys with an effect in detekt 1.23.8 (ruling E21)', () => {
    expect(QUALOR_DETEKT_OVERLAY).toBe(
      [
        "# Qualor's settings over detekt's defaults and the project's config (config.md §6).",
        'config:',
        '  validation: false',
        'output-reports:',
        '  active: true',
        'comments:',
        '  AbsentOrWrongFileLicense:',
        '    active: false',
        '',
      ].join('\n'),
    );
  });
});
