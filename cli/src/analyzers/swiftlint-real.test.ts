import { existsSync, symlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { engineMapping, parseConfig } from '@qualor/shared';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { describeWithSwiftlint } from '../../test/analyzers';
import { useTempDirs, writeTree } from '../../test/tmp';
import { discoverFiles } from '../discovery/discover';
import { createLogger, silentLogger } from '../log';
import { Warnings } from '../warnings';
import { fileLines, normalizeCaptures } from './normalize';
import { runAnalyzers } from './runner';
import { swiftlintAnalyzer } from './swiftlint';

const tmp = useTempDirs();
const posix = process.platform !== 'win32';
const linux = process.platform === 'linux';
const TIMEOUT = { timeout: 120_000 };

async function lint(root: string, env: NodeJS.ProcessEnv = process.env, lines: string[] = []) {
  const config = parseConfig({ version: 1 });
  const files = discoverFiles({ root, config, warnings: new Warnings(), log: silentLogger });
  const log = createLogger('debug', (t) => lines.push(t));
  const [capture] = await runAnalyzers([swiftlintAnalyzer], { root, config, files, log, env });
  return capture!;
}
type Result = {
  ruleId: string;
  level: string;
  message: { text: string };
  locations: {
    physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number } };
  }[];
};
const results = (sarif: unknown) =>
  (sarif as { runs: { results: Result[] }[] }).runs[0]?.results ?? [];
const uriOf = (r: Result) => r.locations[0]!.physicalLocation.artifactLocation.uri;
const lineOf = (r: Result) => r.locations[0]!.physicalLocation.region.startLine;
/** `line ruleId`, sorted, for one file's results. */
const found = (sarif: unknown) =>
  results(sarif)
    .map((r) => `${uriOf(r)}:${lineOf(r)} ${r.ruleId}`)
    .sort();

/**
 * A SwiftUI screen as Xcode writes one, with no SwiftLint configuration: the indentation Xcode
 * leaves on a blank line (line 13), a to-do marker comment, `Button(action:) { … }`, loop and
 * geometry names, a comment with a long URL, and one genuine finding, a force cast (line 30).
 */
const SWIFTUI = [
  'import SwiftUI',
  '',
  'struct ContentView: View {',
  '    @State private var count = 0',
  '',
  '    // TODO: move the counter into a view model',
  '    var body: some View {',
  '        VStack {',
  '            Button(action: { count += 1 }) {',
  '                Text("Add")',
  '            }',
  '            .padding()',
  '            ',
  '            Text("\\(count)")',
  '        }',
  '    }',
  '}',
  '',
  'func area(x: Double, y: Double) -> Double {',
  '    var total = 0.0',
  '    for i in 0..<3 {',
  '        total += Double(i) * x * y',
  '    }',
  '    return total',
  '}',
  '',
  '// https://developer.apple.com/documentation/swiftui/view/frame(minwidth:idealwidth:maxwidth:minheight:idealheight:maxheight:alignment:)',
  'let anyValue: Any = 1',
  'let doubled = (anyValue as? Int ?? 0) * 2',
  'let forced = anyValue as! Int',
  '',
].join('\n');

/**
 * What SwiftPM and the formatters write (ruling F27): `swift package init`'s Package.swift, with
 * its two trailing commas, and a source with the swift.org header separator, a condition wrapped
 * SwiftFormat's way (`{` on its own line) and a type nested two deep (the TCA/SwiftUI idiom).
 */
const FORMATTED: Record<string, string> = {
  'Package.swift': [
    '// swift-tools-version: 6.0',
    '// The swift-tools-version declares the minimum version of Swift required to build this package.',
    '',
    'import PackageDescription',
    '',
    'let package = Package(',
    '    name: "Feature",',
    '    products: [',
    '        .library(',
    '            name: "Feature",',
    '            targets: ["Feature"]),',
    '    ],',
    '    targets: [',
    '        .target(',
    '            name: "Feature"),',
    '        .testTarget(',
    '            name: "FeatureTests",',
    '            dependencies: ["Feature"]',
    '        ),',
    '    ]',
    ')',
    '',
  ].join('\n'),
  'Sources/Feature/Feature.swift': [
    '//===----------------------------------------------------------------------===//',
    '//',
    '// This source file is part of the Feature open source project',
    '//',
    '//===----------------------------------------------------------------------===//',
    '',
    'enum Feature {',
    '    enum Action {',
    '        enum Alert {',
    '            case confirm',
    '        }',
    '    }',
    '}',
    '',
    'func both(first: Bool, second: Bool) -> Bool {',
    '    if first,',
    '       second',
    '    {',
    '        return true',
    '    }',
    '    return false',
    '}',
    '',
  ].join('\n'),
};
/** The rules the layer quiets on FORMATTED (ruling F27). */
const FORMATTER_RULES = ['comment_spacing', 'nesting', 'opening_brace', 'trailing_comma'];

describeWithSwiftlint()('swiftlint with the real binary (plan 8F)', () => {
  let requests = 0;
  const server = createServer((_req, res) => {
    requests += 1;
    res.end('only_rules: [colon]\n');
  });
  let port = 0;
  beforeAll(async () => {
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as AddressInfo).port;
  });
  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  it(
    'never writes, fetches, expands or reads nested configs a checkout plants',
    TIMEOUT,
    async () => {
      const root = tmp();
      const outside = tmp();
      writeTree(root, {
        '.swiftlint.yml': [
          `write_baseline: ${outside}/root-baseline.json`,
          `cache_path: ${outside}/cache`,
          'check_for_updates: true',
          'strict: true',
          'reporter: html',
          'inclusive_language:',
          '  additional_terms: ["${SWIFT_CI_SECRET_TERM}"]',
          '',
        ].join('\n'),
        'Sources/.swiftlint.yml': `write_baseline: ${outside}/nested-baseline.json\ndisabled_rules: [colon]\n`,
        'Sources/A.swift': 'let s3cr3tValue : Int = 1\n',
      });
      // A CI variable, not a QUALOR_ one (those are stripped for every analyzer anyway).
      const capture = await lint(root, { ...process.env, SWIFT_CI_SECRET_TERM: 's3cr3t' });
      expect(capture.status, capture.reason ?? '').toBe('ok');
      const got = results(capture.sarif);
      // The nested config's `disabled_rules: [colon]` is not read; `strict` is dropped (warning stays).
      expect(got.map((r) => [r.ruleId, r.level])).toContainEqual(['colon', 'warning']);
      // The variable never reaches SwiftLint, so the planted term matches nothing (fact F4: with
      // the variable set, inclusive_language reports `contains the term "s3cr3t"`).
      expect(got.some((r) => r.ruleId === 'inclusive_language')).toBe(false);
      expect(got.some((r) => r.message.text.includes('s3cr3t'))).toBe(false);
      for (const marker of ['root-baseline.json', 'nested-baseline.json', 'cache']) {
        expect(existsSync(path.join(outside, marker)), marker).toBe(false);
      }
      expect(existsSync(path.join(root, '.swiftlint'))).toBe(false);
      // The control: the same rule setting, written out, does report the term.
      writeFileSync(
        path.join(root, '.swiftlint.yml'),
        'inclusive_language:\n  additional_terms: ["s3cr3t"]\n',
      );
      const control = await lint(root);
      expect(results(control.sarif).map((r) => r.ruleId)).toContain('inclusive_language');
    },
  );

  it('skips a parent_config and fetches nothing', TIMEOUT, async () => {
    const root = tmp();
    writeTree(root, {
      '.swiftlint.yml': `parent_config: http://127.0.0.1:${port}/parent.yml\n`,
      'A.swift': 'let a = 1\n',
    });
    const capture = await lint(root);
    expect(capture.status).toBe('skipped');
    expect(capture.reason).toContain('parent_config');
    expect(requests).toBe(0);
  });

  it(
    'lints awkward file names from the copy and maps them to their repository paths; never a link or a line break',
    TIMEOUT,
    async () => {
      const root = tmp();
      const outside = tmp();
      writeTree(root, {
        'Sources/a b#ü.swift': 'let x : Int = 1\n',
        'Sources/-dash.swift': 'let y : Int = 1\n',
        'Sources/$(HOME)${HOME}.swift': 'let z : Int = 1\n',
        'Sources/100%.swift': 'let p : Int = 1\n',
        'Sources/p%41q.swift': 'let q : Int = 1\n',
      });
      writeFileSync(path.join(outside, 'O.swift'), 'let o : Int = 1\n');
      if (posix) {
        symlinkSync(path.join(outside, 'O.swift'), path.join(root, 'Sources/L.swift'));
      }
      if (linux) {
        // A file name, not a directory: discovery skips a directory with a line break in its
        // name (PATH_UNSUPPORTED).
        writeFileSync(path.join(root, 'Sources/new\nline.swift'), 'let n : Int = 1\n');
        // A root-level name with a colon, which a URI reader would take for a scheme.
        writeFileSync(path.join(root, 'a:b.swift'), 'let c : Int = 1\n');
        writeFileSync(path.join(root, 'Sources/ls\u2028x.swift'), 'let s : Int = 1\n');
      }
      const lines: string[] = [];
      const capture = await lint(root, process.env, lines);
      expect(capture.status, capture.reason ?? '').toBe('ok');
      // Through the normaliser, as runScan does: every finding keeps its repository path.
      const known = discoverFiles({
        root,
        config: parseConfig({ version: 1 }),
        warnings: new Warnings(),
        log: silentLogger,
      }).map((f) => f.path);
      const out = normalizeCaptures([{ ...capture, mapping: engineMapping('swiftlint')! }], {
        repoRoot: root,
        readLines: fileLines(root),
        knownPaths: new Set(known),
        log: silentLogger,
      });
      expect(out.warnings).toEqual([]);
      const colon = out.findings.filter((f) => f.ruleId === 'colon');
      expect(colon).toHaveLength(results(capture.sarif).filter((r) => r.ruleId === 'colon').length);
      expect([...new Set(colon.map((f) => f.location?.path))].sort()).toEqual(
        [
          'Sources/$(HOME)${HOME}.swift',
          'Sources/-dash.swift',
          'Sources/100%.swift',
          'Sources/a b#ü.swift',
          'Sources/p%41q.swift',
          ...(linux ? ['a:b.swift'] : []),
        ].sort(),
      );
      if (linux) {
        expect(lines.join('')).toContain(
          'swiftlint: 2 file(s) whose path has a line break were left out',
        );
      }
    },
  );

  it(
    'reports exactly the findings of Verified facts F9 on fixtures/swift-basic (and can record them)',
    TIMEOUT,
    async () => {
      const capture = await lint(path.resolve('fixtures/swift-basic'));
      expect(capture.status, capture.reason ?? '').toBe('ok');
      const got = results(capture.sarif)
        .map((r) => `${uriOf(r)}:${lineOf(r)} ${r.ruleId} ${r.level}`)
        .sort();
      expect(got).toEqual([
        'Sources/App/Store.swift:20 force_cast error',
        'Sources/App/Store.swift:25 force_unwrapping warning',
        'Sources/App/Store.swift:29 duplicate_conditions error',
        'Sources/App/Store.swift:33 duplicate_conditions error',
        'Sources/App/Store.swift:40 line_length warning',
      ]);
      // Task 8 Step 6 records cli/test/analyzer-output/swiftlint/basic.sarif through this hook.
      const record = process.env['QUALOR_RECORD_SWIFTLINT_SARIF'];
      if (record) writeFileSync(record, `${JSON.stringify(capture.sarif, null, 2)}\n`);
    },
  );

  it(
    'quiets the Xcode and SwiftUI noise without a project config and keeps the real finding (ruling F5)',
    TIMEOUT,
    async () => {
      const root = tmp();
      writeTree(root, { 'App/ContentView.swift': SWIFTUI, ...FORMATTED });
      const capture = await lint(root);
      expect(capture.status, capture.reason ?? '').toBe('ok');
      // Nothing from SwiftPM's template or the formatters' output either (ruling F27).
      expect(found(capture.sarif)).toEqual(['App/ContentView.swift:30 force_cast']);
    },
  );

  it(
    'applies SwiftLint’s own defaults, not the layer, when the project has a config (ruling F5)',
    TIMEOUT,
    async () => {
      const root = tmp();
      writeTree(root, {
        'App/ContentView.swift': SWIFTUI,
        ...FORMATTED,
        // A neutral project config: SwiftLint's own line_length, nothing else.
        '.swiftlint.yml': 'line_length: 120\n',
      });
      const capture = await lint(root);
      expect(capture.status, capture.reason ?? '').toBe('ok');
      // Every rule the layer quiets on FORMATTED fires under SwiftLint's own defaults.
      const formatted = results(capture.sarif).filter((r) => Object.hasOwn(FORMATTED, uriOf(r)));
      expect([...new Set(formatted.map((r) => r.ruleId))]).toEqual(
        expect.arrayContaining(FORMATTER_RULES),
      );
      expect(found(capture.sarif).filter((f) => f.startsWith('App/'))).toEqual([
        'App/ContentView.swift:13 trailing_whitespace',
        'App/ContentView.swift:19 identifier_name',
        'App/ContentView.swift:19 identifier_name',
        'App/ContentView.swift:21 identifier_name',
        'App/ContentView.swift:27 line_length',
        'App/ContentView.swift:30 force_cast',
        'App/ContentView.swift:6 todo',
        'App/ContentView.swift:9 multiple_closures_with_trailing_closure',
      ]);
    },
  );

  it(
    'gives a CRLF file the findings and lines of its LF twin, none past its end (ruling F27)',
    TIMEOUT,
    async () => {
      const sample = [
        'import Foundation',
        '',
        'func total(first: Int, second: Int, third: Int) -> Int {',
        '    return first + second + third',
        '}',
        '',
        'let sum = total(first: 1,',
        '                second: 2,',
        '                third: 3)',
        'let label : String = "sum"',
        'let values = [',
        '    total(first: 1, second: 2, third: 3),',
        '    total(first: 4, second: 5, third: 6)',
        ']',
        'let anyValue: Any = sum',
        'let forced = anyValue as! Int',
        '',
      ];
      const root = tmp();
      writeTree(root, {
        'Lf/Sample.swift': sample.join('\n'),
        'Crlf/Sample.swift': sample.join('\r\n'),
      });
      const capture = await lint(root);
      expect(capture.status, capture.reason ?? '').toBe('ok');
      const lf = found(capture.sarif).filter((f) => f.startsWith('Lf/'));
      const crlf = found(capture.sarif).filter((f) => f.startsWith('Crlf/'));
      expect(lf).toEqual(['Lf/Sample.swift:10 colon', 'Lf/Sample.swift:16 force_cast']);
      expect(crlf).toEqual(lf.map((f) => f.replace('Lf/', 'Crlf/')));
      // Through the normaliser: every finding has its snippet, so no message-only hash.
      const out = normalizeCaptures([{ ...capture, mapping: engineMapping('swiftlint')! }], {
        repoRoot: root,
        readLines: fileLines(root),
        knownPaths: new Set(['Lf/Sample.swift', 'Crlf/Sample.swift']),
        log: silentLogger,
      });
      expect(out.warnings).toEqual([]);
      expect(out.findings.every((f) => (f.location?.startLine ?? 0) <= sample.length - 1)).toBe(
        true,
      );
    },
  );

  it(
    'leaves a lone CR as it is: SwiftLint counts it as a line end, Qualor does not (ruling F27, accepted)',
    TIMEOUT,
    async () => {
      const root = tmp();
      // Qualor's line 1 holds `let one = 1\rlet two : Int = 2`; line 2 is `let three : Int = 3`.
      writeTree(root, { 'Cr.swift': 'let one = 1\rlet two : Int = 2\nlet three : Int = 3\n' });
      const capture = await lint(root);
      expect(capture.status, capture.reason ?? '').toBe('ok');
      // SwiftLint's lines 2 and 3: one line late after the CR. Such a file (classic Mac OS line
      // ends) is rare; turning the CR into LF would move Qualor's lines the other way.
      expect(found(capture.sarif)).toEqual(['Cr.swift:2 colon', 'Cr.swift:3 colon']);
    },
  );

  it(
    'warns about unknown rule ids and rule settings SwiftLint could not read (final review minor 9)',
    TIMEOUT,
    async () => {
      const root = tmp();
      writeTree(root, {
        'A.swift': 'let value = 1\n',
        '.swiftlint.yml': 'disabled_rules: [not_a_rule]\nnesting:\n  type_level: foo\n',
      });
      const lines: string[] = [];
      const capture = await lint(root, process.env, lines);
      expect(capture.status, capture.reason ?? '').toBe('ok');
      const warn = lines.filter((l) => l.startsWith('warn: '));
      expect(warn).toContainEqual(
        expect.stringContaining(
          'swiftlint: .swiftlint.yml: SwiftLint does not know the rule ids not_a_rule; it ignores them',
        ),
      );
      expect(warn).toContainEqual(
        expect.stringContaining(
          'swiftlint: .swiftlint.yml: SwiftLint could not read the settings of nesting and uses their defaults',
        ),
      );
    },
  );

  it('lints a thousand files through the list file', TIMEOUT, async () => {
    const root = tmp();
    const files: Record<string, string> = {};
    for (let i = 0; i < 1000; i++) files[`Sources/F${i}.swift`] = `let v${i}value = ${i}\n`;
    writeTree(root, files);
    const capture = await lint(root);
    expect(capture.status, capture.reason ?? '').toBe('ok');
    expect(results(capture.sarif)).toEqual([]);
  });
});
