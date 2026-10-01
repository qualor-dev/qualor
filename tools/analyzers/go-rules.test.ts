import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { resolveBinary } from '../../cli/src/analyzers/binary';
// @ts-expect-error: a plain ES module of the repository's tooling, without type declarations
import * as rules from './go-rules.mjs';

const { buildTable, parseGosecRules, parseStaticcheckChecks, parseVetAnalyzers } = rules;

const TABLE = 'packages/shared/rules/go-rules.json';
const where = { root: process.cwd(), env: process.env };
const bins = {
  go: resolveBinary('go', where),
  staticcheck: resolveBinary('staticcheck', where),
  gosec: resolveBinary('gosec', where),
};
const installed = Object.values(bins).every((b) => b !== null);
const required = process.env['QUALOR_REQUIRE_ANALYZERS'] === '1';

describe('go-rules.mjs (plan 9C)', () => {
  it("reads staticcheck's, go vet's and gosec's rule lists", () => {
    expect(
      parseStaticcheckChecks(
        'S1000 Use plain channel send\nSA5009 Invalid Printf call\nU1000 Unused code\nnoise\n',
      ),
    ).toEqual(['S1000', 'SA5009', 'U1000']);
    expect(
      parseVetAnalyzers(
        'vet is a tool\n\nRegistered analyzers:\n\n    appends      check …\n    printf       check …\n\nBy default all analyzers are run.\n',
      ),
    ).toEqual(['appends', 'printf']);
    expect(() => parseVetAnalyzers('nothing here')).toThrow(/go tool vet help/);
    expect(
      parseGosecRules(
        'RULES:\n\n\tG101: Look for hardcoded credentials\n\tG401: Detect the usage of MD5\n',
      ),
    ).toEqual(['G101', 'G401']);
  });

  it.runIf(required)(
    'finds go, staticcheck and gosec where QUALOR_REQUIRE_ANALYZERS=1 requires them',
    () => {
      expect(bins, 'install tools/analyzers/install-go.sh').toEqual({
        go: expect.any(String),
        staticcheck: expect.any(String),
        gosec: expect.any(String),
      });
    },
  );

  it.runIf(installed)('keeps the committed table in step with the installed tools', () => {
    expect(existsSync(TABLE)).toBe(true);
    const committed = JSON.parse(readFileSync(TABLE, 'utf8')) as Record<string, unknown>;
    const fresh = buildTable(bins) as Record<string, unknown>;
    for (const key of ['go', 'staticcheck', 'govet', 'gosec'])
      expect(committed[key], key).toEqual(fresh[key]);
  });
});
