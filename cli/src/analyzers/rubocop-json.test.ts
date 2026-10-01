import { RUBOCOP_VERSION, rubocopSelection } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { expectedKeys, findingKeys, normalizeRecorded, recorded } from '../../test/analyzers';
import { createLogger } from '../log';
import { rubocopAnalyzer } from './rubocop';
import { rubocopCrashWarnings, rubocopFailureDetail, rubocopJsonToSarif } from './rubocop-json';

const stderr = recorded('rubocop/stderr.json') as Record<string, string>;
const WORK = '/tmp/qualor-rubocop-AbC123';
const offense = (
  cop: string,
  line: number,
  col: number,
  lastCol: number,
  severity = 'warning',
) => ({
  severity,
  message: `${cop} message`,
  cop_name: cop,
  corrected: false,
  correctable: false,
  location: {
    start_line: line,
    start_column: col,
    last_line: line,
    last_column: lastCol,
    length: lastCol - col + 1,
    line,
    column: col,
  },
});
const report = (files: { path: string; offenses: unknown[] }[], version = RUBOCOP_VERSION) => ({
  metadata: { rubocop_version: version, ruby_engine: 'ruby', ruby_version: '4.0.7' },
  files,
  summary: {
    offense_count: 0,
    target_file_count: files.length,
    inspected_file_count: files.length,
  },
});

describe('rubocopJsonToSarif (config.md §6, plan 9B)', () => {
  const cops = new Set(['Lint/UselessAssignment', 'Security/Eval']);

  it('converts offenses of the selected cops, with 1-based columns and exclusive end columns', () => {
    const sarif = rubocopJsonToSarif(
      report([
        {
          path: 'app/a b#c%d.rb',
          offenses: [offense('Lint/UselessAssignment', 4, 3, 8), offense('Security/Eval', 9, 3, 6)],
        },
      ]),
      { version: RUBOCOP_VERSION, cops },
    ) as {
      runs: [
        {
          tool: {
            driver: {
              name: string;
              version: string;
              rules: { id: string; helpUri: string; properties: object }[];
            };
          };
          results: {
            ruleId: string;
            level: string;
            locations: {
              physicalLocation: { artifactLocation: { uri: string }; region: object };
            }[];
          }[];
        },
      ];
    };
    const run = sarif.runs[0];
    expect(run.tool.driver).toMatchObject({ name: 'RuboCop', version: RUBOCOP_VERSION });
    expect(run.tool.driver.rules.map((r) => r.id)).toEqual([
      'Lint/UselessAssignment',
      'Security/Eval',
    ]);
    expect(run.tool.driver.rules[0]).toMatchObject({
      helpUri: 'https://docs.rubocop.org/rubocop/latest/cops_lint.html#lintuselessassignment',
      properties: { department: 'Lint' },
    });
    expect(run.results[0]).toMatchObject({
      ruleId: 'Lint/UselessAssignment',
      level: 'warning',
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: 'app/a%20b%23c%25d.rb' },
            region: { startLine: 4, startColumn: 3, endLine: 4, endColumn: 9 },
          },
        },
      ],
    });
  });

  it('drops Lint/Syntax and cops outside the selection, and counts both at debug level', () => {
    const lines: string[] = [];
    const sarif = rubocopJsonToSarif(
      report([
        { path: 'broken.rb', offenses: [offense('Lint/Syntax', 1, 7, 7, 'fatal')] },
        {
          path: 'b.rb',
          offenses: [
            offense('Metrics/MethodLength', 3, 1, 3, 'convention'),
            offense('Security/Eval', 2, 1, 4),
          ],
        },
      ]),
      { version: RUBOCOP_VERSION, cops, log: createLogger('debug', (t) => lines.push(t)) },
    ) as { runs: [{ results: { ruleId: string }[] }] };
    expect(sarif.runs[0].results.map((r) => r.ruleId)).toEqual(['Security/Eval']);
    expect(lines.join('')).toContain('rubocop: 1 file(s) RuboCop could not parse');
    expect(lines.join('')).toContain('rubocop: 1 offense(s) of cops outside the selection dropped');
  });

  it('drops every file the CLI did not list, with a warning (B9-14 defence in depth)', () => {
    const lines: string[] = [];
    const sarif = rubocopJsonToSarif(
      report([
        { path: '{,/}tmp/x*.rb', offenses: [offense('Security/Eval', 1, 1, 4)] },
        { path: '/tmp/xsecret.rb', offenses: [offense('Security/Eval', 2, 1, 4)] },
        { path: 'tmp/xother.rb', offenses: [] },
      ]),
      {
        version: RUBOCOP_VERSION,
        cops,
        files: new Set(['{,/}tmp/x*.rb']),
        log: createLogger('info', (t) => lines.push(t)),
      },
    ) as {
      runs: [
        { results: { locations: [{ physicalLocation: { artifactLocation: { uri: string } } }] }[] },
      ];
    };
    expect(
      sarif.runs[0].results.map((r) => r.locations[0].physicalLocation.artifactLocation.uri),
    ).toEqual(['%7B%2C/%7Dtmp/x*.rb']);
    expect(lines.join('')).toContain(
      'rubocop: RuboCop reported 2 file(s) Qualor did not give it; their findings were dropped',
    );
  });

  it('refuses a report of another RuboCop version and anything that is not its JSON', () => {
    expect(() =>
      rubocopJsonToSarif(report([], '1.80.0'), { version: RUBOCOP_VERSION, cops }),
    ).toThrow(/1\.80\.0/);
    expect(() => rubocopJsonToSarif({ files: 'x' }, { version: RUBOCOP_VERSION, cops })).toThrow();
  });

  it('never writes an end column before the start column', () => {
    const sarif = rubocopJsonToSarif(
      report([
        {
          path: 'a.rb',
          offenses: [
            {
              ...offense('Security/Eval', 1, 5, 4),
              location: {
                start_line: 1,
                start_column: 5,
                last_line: 1,
                last_column: 0,
                length: 0,
                line: 1,
                column: 5,
              },
            },
          ],
        },
      ]),
      { version: RUBOCOP_VERSION, cops },
    ) as {
      runs: [
        { results: { locations: { physicalLocation: { region: Record<string, number> } }[] }[] },
      ];
    };
    expect(sarif.runs[0].results[0]!.locations[0]!.physicalLocation.region).toEqual({
      startLine: 1,
      startColumn: 5,
      endLine: 1,
    });
  });
});

describe('RuboCop stderr', () => {
  it('names why RuboCop stopped, with the work directory hidden', () => {
    expect(rubocopFailureDetail(stderr['unknownCop']!, WORK)).toBe(
      'Error: unrecognized cop or department Foo/Bar found in <work>/rubocop.yml',
    );
    expect(rubocopFailureDetail(stderr['missingFile']!, WORK)).toBe(
      'Error: No such file or directory: <work>/src/b.rb',
    );
    expect(rubocopFailureDetail(stderr['target']!, WORK)).toBe(
      'RuboCop supports target Ruby versions 3.3 and above with Prism. Specified target Ruby version: 9.9',
    );
    expect(rubocopFailureDetail(stderr['runner']!, WORK)).toContain(
      'rubocop: fatal: Gem::MissingSpecError',
    );
    expect(rubocopFailureDetail('', WORK)).toBeNull();
  });

  it('turns a cop crash into one warning naming the repository path', () => {
    expect(rubocopCrashWarnings(stderr['crash']!, `${WORK}/src`)).toEqual([
      'Lint/Void failed on app/a b.rb (a RuboCop error); that file has no Lint/Void findings',
    ]);
    expect(
      rubocopCrashWarnings(
        'An error occurred while Not/ACop cop was inspecting /x/a.rb:1:0.\n',
        '/x',
      ),
    ).toEqual([]);
    expect(rubocopCrashWarnings('', `${WORK}/src`)).toEqual([]);
  });
});

it('turns the recorded report of fixtures/ruby-basic into its expected findings', () => {
  const sarif = rubocopJsonToSarif(recorded('rubocop/basic.json'), {
    version: RUBOCOP_VERSION,
    cops: new Set(rubocopSelection(['qualor-default'], [])),
  });
  const out = normalizeRecorded(sarif, rubocopAnalyzer, 'ruby-basic');
  expect(out.warnings).toEqual([]);
  expect(findingKeys(out.findings)).toEqual(expectedKeys('ruby-basic', 'rubocop'));
});
