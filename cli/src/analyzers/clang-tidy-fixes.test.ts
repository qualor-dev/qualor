import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { useTempDirs, writeTree } from '../../test/tmp';
import { clangTidyFixesToSarif } from './clang-tidy-fixes';

const tmp = useTempDirs();

interface Note {
  message: string;
  offset: number;
  file?: string;
}

/** One diagnostic as clang-tidy 22.1.8 exports it (fact F8). */
function diag(o: {
  name: string;
  message: string;
  file: string;
  offset: number;
  build: string;
  level?: string;
  note?: Note;
  notes?: Note[];
}): string {
  const q = (s: string) => `'${s.replaceAll("'", "''")}'`;
  const notes = o.notes ?? (o.note === undefined ? [] : [o.note]);
  return [
    `  - DiagnosticName:  ${o.name}`,
    '    DiagnosticMessage:',
    `      Message:         ${q(o.message)}`,
    `      FilePath:        ${q(o.file)}`,
    `      FileOffset:      ${o.offset}`,
    '      Replacements:    []',
    ...(notes.length === 0
      ? []
      : [
          '    Notes:',
          ...notes.flatMap((n) => [
            `      - Message:         ${q(n.message)}`,
            `        FilePath:        ${q(n.file ?? o.file)}`,
            `        FileOffset:      ${n.offset}`,
            '        Replacements:    []',
          ]),
        ]),
    `    Level:           ${o.level ?? 'Warning'}`,
    `    BuildDirectory:  ${q(o.build)}`,
  ].join('\n');
}
const doc = (diags: string[]) =>
  `---\nMainSourceFile:  'x'\nDiagnostics:\n${diags.join('\n')}\n...\n`;

describe('clangTidyFixesToSarif (config.md §6.2, plan 9D)', () => {
  it('turns byte offsets into lines and columns of the file, notes into related locations', () => {
    const root = tmp();
    const text = 'int a;\n// é\nint describe(std::string label) {\n  return label.size();\n}\n';
    writeTree(root, { 'src/m.cpp': text });
    const use = Buffer.from(text.slice(0, text.indexOf('label.size'))).length;
    const decl = Buffer.from(text.slice(0, text.indexOf('std::string label'))).length;
    const { log, compileErrors, unplaced } = clangTidyFixesToSarif(
      doc([
        diag({
          name: 'bugprone-use-after-move',
          message: "'label' used after it was moved",
          file: 'src/m.cpp',
          offset: use,
          build: root,
          note: { message: 'move occurred here', offset: decl },
        }),
      ]),
      { root, version: '22.1.8' },
    );
    expect([compileErrors, unplaced]).toEqual([0, 0]);
    expect(log.runs[0]!.tool.driver).toMatchObject({
      name: 'clang-tidy',
      version: '22.1.8',
      rules: [{ id: 'bugprone-use-after-move' }],
    });
    expect(log.runs[0]!.results).toEqual([
      {
        ruleId: 'bugprone-use-after-move',
        level: 'warning',
        message: { text: "'label' used after it was moved" },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: 'src/m.cpp' },
              region: { startLine: 4, startColumn: 10 },
            },
          },
        ],
        relatedLocations: [
          {
            physicalLocation: {
              artifactLocation: { uri: 'src/m.cpp' },
              region: { startLine: 3, startColumn: 14 },
            },
            message: { text: 'move occurred here' },
          },
        ],
      },
    ]);
  });

  it('resolves paths against BuildDirectory, absolute ones too; encodes awkward names', () => {
    const root = tmp();
    writeTree(root, { 'src/a b#%.cpp': 'int x = 1 / 0;\n', 'build/.keep': '' });
    const { log } = clangTidyFixesToSarif(
      doc([
        diag({
          name: 'clang-analyzer-core.DivideZero',
          message: 'Division by zero',
          file: '../src/a b#%.cpp',
          offset: 8,
          build: path.join(root, 'build'),
        }),
        diag({
          name: 'clang-analyzer-core.DivideZero',
          message: 'Division by zero',
          file: path.join(root, 'src/a b#%.cpp'),
          offset: 8,
          build: '/elsewhere',
        }),
      ]),
      { root, version: '22.1.8' },
    );
    expect(
      log.runs[0]!.results!.map((r) => r.locations![0]!.physicalLocation!.artifactLocation!.uri),
    ).toEqual(['src/a%20b%23%25.cpp', 'src/a%20b%23%25.cpp']);
    expect(log.runs[0]!.results!.map((r) => r.locations![0]!.physicalLocation!.region)).toEqual([
      { startLine: 1, startColumn: 9 },
      { startLine: 1, startColumn: 9 },
    ]);
  });

  it('counts compile errors and diagnostics it cannot place, instead of reporting them (decision 6)', () => {
    const root = tmp();
    const outside = tmp();
    writeTree(root, { 'a.cpp': 'int x = ;\n' });
    writeFileSync(path.join(outside, 'h.h'), 'int y;\n');
    const { log, compileErrors, unplaced } = clangTidyFixesToSarif(
      doc([
        diag({
          name: 'clang-diagnostic-error',
          message: 'expected expression',
          file: 'a.cpp',
          offset: 8,
          build: root,
          level: 'Error',
        }),
        diag({
          name: 'bugprone-x',
          message: 'outside',
          file: path.join(outside, 'h.h'),
          offset: 0,
          build: root,
        }),
        diag({ name: 'bugprone-y', message: 'gone', file: 'missing.cpp', offset: 0, build: root }),
        diag({
          name: 'bugprone-z',
          message: 'past the end',
          file: 'a.cpp',
          offset: 9999,
          build: root,
        }),
      ]),
      { root, version: '22.1.8' },
    );
    expect(log.runs[0]!.results).toEqual([]);
    expect(compileErrors).toBe(1);
    expect(unplaced).toBe(3);
  });

  it('drops and counts notes outside the repository or the scope, never quoting their path (ruling D9-9)', () => {
    const root = tmp();
    const outside = tmp();
    const host = path.join(outside, 'host-secret.h');
    writeFileSync(host, 'inline int *get() { return nullptr; }\n');
    writeTree(root, {
      'a.cpp': '#include "x"\nint f() { return *get(); }\n',
      'vendor/v.h': 'int v;\n',
    });
    const { log, unplaced } = clangTidyFixesToSarif(
      doc([
        diag({
          name: 'clang-analyzer-core.NullDereference',
          message: 'Dereference of null pointer',
          file: 'a.cpp',
          offset: 23,
          build: root,
          notes: [
            { message: "Calling 'get'", offset: 23 },
            { message: 'Returning null pointer', offset: 20, file: host },
            { message: 'in a vendored header', offset: 0, file: 'vendor/v.h' },
          ],
        }),
        diag({
          name: 'bugprone-v',
          message: 'vendored',
          file: 'vendor/v.h',
          offset: 0,
          build: root,
        }),
      ]),
      { root, version: '22.1.8', scope: new Set(['a.cpp']) },
    );
    expect(unplaced).toBe(3);
    const results = log.runs[0]!.results!;
    expect(results).toHaveLength(1);
    expect(results[0]!.relatedLocations).toEqual([
      {
        physicalLocation: {
          artifactLocation: { uri: 'a.cpp' },
          region: { startLine: 2, startColumn: 11 },
        },
        message: { text: "Calling 'get'" },
      },
    ]);
    expect(JSON.stringify(log)).not.toContain('host-secret');
    expect(JSON.stringify(log)).not.toContain('vendor');
  });

  it('reads no output as no diagnostic, and refuses what is not an export', () => {
    expect(
      clangTidyFixesToSarif('', { root: tmp(), version: '22.1.8' }).log.runs[0]!.results,
    ).toEqual([]);
    expect(() => clangTidyFixesToSarif('a: [1', { root: tmp(), version: 'x' })).toThrow();
    expect(() =>
      clangTidyFixesToSarif('Diagnostics: 3\n', { root: tmp(), version: 'x' }),
    ).toThrow();
  });

  it('places three of the fixture diagnostics of fact F12 on fixtures/cpp-basic, one per line', () => {
    const root = path.resolve('fixtures/cpp-basic');
    const text = readFileSync(path.join(root, 'src/shape.cpp'), 'utf8');
    const at = (s: string, from = 0) => Buffer.from(text.slice(0, text.indexOf(s, from))).length;
    const { log } = clangTidyFixesToSarif(
      doc([
        diag({
          name: 'bugprone-use-after-move',
          message: 'm',
          file: 'src/shape.cpp',
          offset: at('label.size()'),
          build: root,
        }),
        diag({
          name: 'clang-analyzer-unix.MismatchedDeallocator',
          message: 'm',
          file: 'src/shape.cpp',
          offset: at('delete counts'),
          build: root,
        }),
        diag({
          name: 'clang-analyzer-core.DivideZero',
          message: 'm',
          file: 'src/shape.cpp',
          offset: at('/ zero'),
          build: root,
        }),
      ]),
      { root, version: '22.1.8' },
    );
    expect(
      log.runs[0]!.results!.map(
        (r) =>
          `${r.ruleId}:${r.locations![0]!.physicalLocation!.region!.startLine}:${r.locations![0]!.physicalLocation!.region!.startColumn}`,
      ),
    ).toEqual([
      'bugprone-use-after-move:27:48',
      'clang-analyzer-unix.MismatchedDeallocator:29:5',
      'clang-analyzer-core.DivideZero:36:18',
    ]);
  });
});
