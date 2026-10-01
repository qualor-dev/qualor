import { PHPSTAN_VERSION } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { expectedKeys, findingKeys, normalizeRecorded, recorded } from '../../test/analyzers';
import { createLogger, silentLogger } from '../log';
import { phpstanAnalyzer } from './phpstan';
import { phpstanSarif } from './phpstan-output';

const WORK = '/w/qualor-x';
const INPUT = `${WORK}/src`;
const report = (files: unknown, errors: unknown[] = []) => ({
  totals: { errors: errors.length, file_errors: 0 },
  files,
  errors,
});
const convert = (output: unknown, withDependencies = true, log = silentLogger) =>
  phpstanSarif(output, { input: INPUT, workDir: WORK, version: '2.2.16', withDependencies, log });

describe('phpstanSarif (config.md §6, report-format.md §5)', () => {
  it('turns each message into a warning result on the repository path, with one rule per identifier', () => {
    const sarif = convert(
      report({
        [`${INPUT}/src/Cart.php`]: {
          errors: 2,
          messages: [
            {
              message: 'Undefined variable: $totl',
              line: 31,
              ignorable: true,
              identifier: 'variable.undefined',
            },
            {
              message: 'Function strlen invoked with 2 parameters, 1 required.',
              line: 36,
              ignorable: true,
              identifier: 'arguments.count',
            },
          ],
        },
        [`${INPUT}/a b/#c%d ü.php`]: {
          errors: 1,
          messages: [
            {
              message: 'Undefined variable: $x',
              line: 2,
              ignorable: true,
              identifier: 'variable.undefined',
            },
          ],
        },
      }),
    );
    const run = sarif.runs[0]!;
    expect(run.tool.driver).toMatchObject({ name: 'PHPStan', version: '2.2.16' });
    expect(run.tool.driver.rules?.map((r) => [r.id, r.helpUri])).toEqual([
      ['arguments.count', 'https://phpstan.org/error-identifiers/arguments.count'],
      ['variable.undefined', 'https://phpstan.org/error-identifiers/variable.undefined'],
    ]);
    expect(
      run.results?.map((r) => [
        r.ruleId,
        r.level,
        r.locations?.[0]?.physicalLocation?.artifactLocation?.uri,
        r.locations?.[0]?.physicalLocation?.region?.startLine,
      ]),
    ).toEqual([
      ['variable.undefined', 'warning', 'src/Cart.php', 31],
      ['arguments.count', 'warning', 'src/Cart.php', 36],
      ['variable.undefined', 'warning', 'a%20b/%23c%25d%20%C3%BC.php', 2],
    ]);
  });

  it('drops parse errors, ignore bookkeeping and unknown symbols, and counts them at debug level', () => {
    const lines: string[] = [];
    const messages = [
      'phpstan.parse',
      'ignore.unmatchedLine',
      'class.notFound',
      'staticMethod.notFound',
      'argument.unknown',
      'offsetAccess.notFound',
      'class.noParent',
    ].map((identifier, i) => ({ message: identifier, line: i + 1, ignorable: true, identifier }));
    const keep = (withDependencies: boolean) =>
      convert(
        report({ [`${INPUT}/a.php`]: { errors: 7, messages } }),
        withDependencies,
        createLogger('debug', (t) => lines.push(t)),
      ).runs[0]!.results?.map((r) => r.ruleId);
    expect(keep(true)).toEqual(['offsetAccess.notFound', 'class.noParent']);
    // Without dependencies a parent class PHPStan cannot see is an artefact (config.md §6).
    expect(keep(false)).toEqual(['offsetAccess.notFound']);
    expect(lines.join('')).toContain(
      'phpstan: 2 message(s) that are not findings and 3 unknown-symbol message(s) dropped',
    );
  });

  it("reports a trait's message once, on the trait's file", () => {
    const m = {
      message: 'Undefined variable: $x',
      line: 5,
      ignorable: true,
      identifier: 'variable.undefined',
    };
    const sarif = convert(
      report({
        [`${INPUT}/src/T.php (in context of class App\\A)`]: { errors: 1, messages: [m] },
        [`${INPUT}/src/T.php (in context of class App\\B)`]: { errors: 1, messages: [m] },
      }),
    );
    expect(
      sarif.runs[0]!.results?.map((r) => r.locations?.[0]?.physicalLocation?.artifactLocation?.uri),
    ).toEqual(['src/T.php']);
  });

  it('shows repository paths, never the work directory, in messages', () => {
    const sarif = convert(
      report({
        [`${INPUT}/src/a.php`]: {
          errors: 1,
          messages: [
            {
              message: `Path in require() "${INPUT}/src/missing.php" is not a file or it does not exist; see ${WORK}/phpstan.neon.`,
              line: 3,
              ignorable: true,
              identifier: 'require.fileNotFound',
            },
          ],
        },
      }),
    );
    expect(sarif.runs[0]!.results?.[0]?.message?.text).toBe(
      'Path in require() "src/missing.php" is not a file or it does not exist; see <work>/phpstan.neon.',
    );
    const named = convert(
      report({
        [`${INPUT}/src/a.php`]: {
          errors: 1,
          messages: [
            {
              message: 'Result of method Shop\\Cart::clear() (void) is used.',
              line: 1,
              ignorable: true,
              identifier: 'method.void',
            },
          ],
        },
      }),
    );
    // A PHP name keeps its backslashes.
    expect(named.runs[0]!.results?.[0]?.message?.text).toBe(
      'Result of method Shop\\Cart::clear() (void) is used.',
    );
  });

  it('accepts files: [] and a message without a line; ignores a file outside the copy', () => {
    expect(convert(report([])).runs[0]!.results).toEqual([]);
    const sarif = convert(
      report({
        [`${INPUT}/a.php`]: {
          errors: 1,
          messages: [{ message: 'x', ignorable: true, identifier: 'variable.undefined' }],
        },
        ['/elsewhere/b.php']: {
          errors: 1,
          messages: [{ message: 'y', line: 2, ignorable: true, identifier: 'variable.undefined' }],
        },
      }),
    );
    expect(
      sarif.runs[0]!.results?.map((r) => r.locations?.[0]?.physicalLocation?.region?.startLine),
    ).toEqual([1]);
  });

  it('reads Windows paths too', () => {
    const sarif = phpstanSarif(
      report({
        'C:\\w\\src\\src\\a.php': {
          errors: 1,
          messages: [{ message: 'x', line: 1, ignorable: true, identifier: 'variable.undefined' }],
        },
      }),
      {
        input: 'C:\\w\\src',
        workDir: 'C:\\w',
        version: null,
        withDependencies: true,
        log: silentLogger,
      },
    );
    expect(
      sarif.runs[0]!.results?.[0]?.locations?.[0]?.physicalLocation?.artifactLocation?.uri,
    ).toBe('src/a.php');
  });

  it('refuses anything that is not a PHPStan report', () => {
    expect(() => convert({ runs: [] })).toThrow();
    expect(() => convert(null)).toThrow();
  });

  it("normalises the recorded fixture run into the fixture's phpstan findings", () => {
    const sarif = phpstanSarif(recorded('phpstan/basic.json'), {
      input: '/qualor-work/src',
      workDir: '/qualor-work',
      version: PHPSTAN_VERSION,
      withDependencies: false,
      log: silentLogger,
    });
    expect(findingKeys(normalizeRecorded(sarif, phpstanAnalyzer, 'php-basic').findings)).toEqual(
      expectedKeys('php-basic', 'phpstan'),
    );
  });
});
