import { existsSync, readFileSync } from 'node:fs';
import { FINDSECBUGS_PATTERNS, FINDSECBUGS_VERSION } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { describeWithFindsecbugs, installedFindsecbugs } from '../../cli/test/analyzers';
// @ts-expect-error: a plain ES module of the repository's tooling, without type declarations
import { compareWithTable, findbugsXml, patternIds } from './findsecbugs-patterns.mjs';

const TABLE = 'packages/shared/rules/findsecbugs.json';

describe('findsecbugs-patterns.mjs', () => {
  it("reads the bug pattern ids of a plugin's findbugs.xml, sorted and without duplicates", () => {
    const xml = [
      '<FindbugsPlugin pluginid="x">',
      '  <Detector class="a.B" reports="Z_PATTERN,A_PATTERN"/>',
      '  <BugPattern type="Z_PATTERN" abbrev="Z" category="SECURITY" cweid="89"/>',
      '  <BugPattern abbrev="A" type="A_PATTERN" category="SECURITY"/>',
      '  <BugPattern type="Z_PATTERN" abbrev="Z" category="SECURITY"/>',
      '</FindbugsPlugin>',
    ].join('\n');
    expect(patternIds(xml)).toEqual(['A_PATTERN', 'Z_PATTERN']);
  });

  it('lists ids missing from the table and table ids the jar no longer has', () => {
    expect(compareWithTable(['A', 'B', 'C'], { patterns: { B: {}, C: {}, D: {} } })).toEqual({
      missing: ['A'],
      stale: ['D'],
    });
  });
});

describeWithFindsecbugs()('the committed table and the installed FindSecBugs', () => {
  it('describe the same version and exactly the same patterns', () => {
    const plugin = installedFindsecbugs();
    expect(plugin, 'FindSecBugs is not installed (tools/analyzers/install.sh)').not.toBeNull();
    if (plugin === null) return;
    expect(plugin.version).toBe(FINDSECBUGS_VERSION);
    expect(existsSync(TABLE)).toBe(true);
    const table = JSON.parse(readFileSync(TABLE, 'utf8')) as { patterns: Record<string, unknown> };
    const ids = patternIds(findbugsXml(plugin.jar)) as string[];
    expect(compareWithTable(ids, table)).toEqual({ missing: [], stale: [] });
    expect(ids.length).toBe(FINDSECBUGS_PATTERNS.size);
  });
});
