import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { resolveBinary } from '../../cli/src/analyzers/binary';
import { describeWithSwiftlint, REQUIRE_ANALYZERS } from '../../cli/test/analyzers';
// @ts-expect-error: a plain ES module of the repository's tooling, without type declarations
import { buildTable, markSourceKit, parseRulesTable, parseSkipped } from './swiftlint-rules.mjs';

const TABLE = 'packages/shared/rules/swiftlint-rules.json';
const swiftlint = resolveBinary('swiftlint', { root: process.cwd(), env: process.env });

describe('swiftlint-rules.mjs', () => {
  it("reads SwiftLint's rules table", () => {
    const text = [
      '+------+',
      '| identifier | opt-in | correctable | enabled in your config | kind | analyzer | uses sourcekit | configuration |',
      '+------+',
      '| colon | no | yes | yes | style | no | no | severity: ... |',
      '| unused_import | yes | yes | no | lint | yes | yes | severity: ... |',
      '+------+',
    ].join('\n');
    expect(parseRulesTable(text)).toEqual({
      colon: {
        kind: 'style',
        optIn: false,
        sourceKit: false,
        analyzer: false,
        enabledByDefault: true,
      },
      unused_import: {
        kind: 'lint',
        optIn: true,
        sourceKit: true,
        analyzer: true,
        enabledByDefault: false,
      },
    });
  });

  it('reads the rules SwiftLint skips for want of SourceKit', () => {
    expect(
      parseSkipped(
        "warning: Skipping enabled rule 'statement_position' because it requires SourceKit and SourceKit access is prohibited.\nwarning: other\n",
      ),
    ).toEqual(['statement_position']);
  });

  it('marks the skipped rules, and fails when the lint names none while the table has some (final review minor 3)', () => {
    const rules = () => ({
      colon: { sourceKit: false },
      statement_position: { sourceKit: false },
      unused_import: { sourceKit: true },
    });
    const skipped =
      "warning: Skipping enabled rule 'statement_position' because it requires SourceKit and SourceKit access is prohibited.\n";
    expect(markSourceKit(rules(), skipped)).toEqual({
      colon: { sourceKit: false },
      statement_position: { sourceKit: true },
      unused_import: { sourceKit: true },
    });
    expect(() => markSourceKit(rules(), 'warning: SourceKit rules are not run\n')).toThrow(
      /named no rule skipped for want of SourceKit, but the table has 1/,
    );
    expect(markSourceKit({ colon: { sourceKit: false } }, '')).toEqual({
      colon: { sourceKit: false },
    });
  });

  it.runIf(REQUIRE_ANALYZERS)(
    'finds swiftlint where QUALOR_REQUIRE_ANALYZERS=1 requires it',
    () => {
      expect(swiftlint, 'swiftlint is not installed (tools/analyzers/install.sh)').not.toBeNull();
    },
  );
});

// Ruling F18: a SwiftLint of another version on a developer machine must not fail the comparison.
describeWithSwiftlint()('the committed table and the installed SwiftLint', () => {
  it('are in step', () => {
    expect(existsSync(TABLE)).toBe(true);
    const committed = JSON.parse(readFileSync(TABLE, 'utf8')) as {
      version: string;
      rules: object;
    };
    // Under QUALOR_REQUIRE_ANALYZERS=1 this runs without a binary too: say so, not a TypeError.
    if (swiftlint === null) throw new Error('swiftlint not found (tools/analyzers/install.sh)');
    const fresh = buildTable(swiftlint);
    expect(committed.version).toBe(fresh.version);
    expect(committed.rules).toEqual(fresh.rules);
  });
});
