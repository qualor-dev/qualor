import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ANALYZER_OUTPUT_DIR } from '../../test/analyzers';
import { cppcheckXmlToSarif } from './cppcheck-xml';

const xml = (errors: string) =>
  `<?xml version="1.0" encoding="UTF-8"?>\n<results version="2">\n<cppcheck version="2.22.0"/>\n<errors>\n${errors}\n</errors>\n</results>\n`;

describe('cppcheckXmlToSarif (config.md §6.2, plan 9D)', () => {
  it('makes one result per error, the first location primary, the others related, the CWE a tag', () => {
    const { log, notAnalysed, outside } = cppcheckXmlToSarif(
      xml(`<error id="nullPointerOutOfMemory" severity="warning" msg="null: copy" verbose="v" cwe="476" file0="src/stack.c">
  <location file="src/stack.c" line="23" column="9" info="Null pointer dereference"/>
  <location file="src/stack.c" line="21" column="23" info="Assuming allocation function fails"/>
  <symbol>copy</symbol>
</error>`),
      { version: '2.22.0', base: '/w/src' },
    );
    expect(notAnalysed.size).toBe(0);
    expect(outside).toBe(0);
    const run = log.runs[0]!;
    expect(run.tool.driver).toMatchObject({ name: 'cppcheck', version: '2.22.0' });
    expect(run.tool.driver.rules).toEqual([
      {
        id: 'nullPointerOutOfMemory',
        properties: { cppcheckSeverity: 'warning', tags: ['external/cwe/cwe-476'] },
      },
    ]);
    expect(run.results).toEqual([
      {
        ruleId: 'nullPointerOutOfMemory',
        level: 'warning',
        message: { text: 'null: copy' },
        properties: { cppcheckSeverity: 'warning' },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: 'src/stack.c' },
              region: { startLine: 23, startColumn: 9 },
            },
          },
        ],
        relatedLocations: [
          {
            physicalLocation: {
              artifactLocation: { uri: 'src/stack.c' },
              region: { startLine: 21, startColumn: 23 },
            },
            message: { text: 'Assuming allocation function fails' },
          },
        ],
      },
    ]);
  });

  it('counts analysis errors and information messages instead of reporting them (decision 6)', () => {
    const { log, notAnalysed } = cppcheckXmlToSarif(
      xml(`<error id="syntaxError" severity="error" msg="Unmatched '{'." verbose="x" file0="src/broken.c"><location file="src/broken.c" line="2" column="13"/></error>
<error id="syntaxError" severity="error" msg="x" verbose="x" file0="b.c"><location file="b.c" line="1" column="1"/></error>
<error id="checkersReport" severity="information" msg="Active checkers: 1/2" verbose="x"/>
<error id="somethingNew" severity="debug" msg="x" verbose="x"><location file="a.c" line="1" column="1"/></error>`),
      { version: '2.22.0', base: '/w/src' },
    );
    expect(log.runs[0]!.results).toEqual([]);
    expect([...notAnalysed]).toEqual([
      ['syntaxError', 2],
      ['checkersReport', 1],
      ['somethingNew', 1],
    ]);
  });

  it('rebases paths under the copy, percent-encodes segments, and drops every location outside it (ruling D9-9)', () => {
    const { log, outside } = cppcheckXmlToSarif(
      xml(`<error id="zerodiv" severity="error" msg="Division by zero." verbose="x" cwe="369" file0="x"><location file="/w/src/src/a b#%.cpp" line="3" column="5"/><location file="/usr/include/stdio.h" line="9" column="1" info="from /usr/include/stdio.h"/><location file="src/b.c" line="4" column="1" info="here"/></error>
<error id="zerodiv" severity="error" msg="Division by zero." verbose="x" cwe="369" file0="x"><location file="../../tmp/secret.h" line="2" column="13"/></error>
<error id="nullPointer" severity="error" msg="Null pointer." verbose="x" file0="x"><location file="/w/src" line="2" column="13"/></error>
<error id="unusedFunction" severity="style" msg="no location" verbose="x"/>`),
      { version: '2.22.0', base: '/w/src' },
    );
    const results = log.runs[0]!.results!;
    expect(results.map((r) => r.locations?.[0]?.physicalLocation?.artifactLocation?.uri)).toEqual([
      'src/a%20b%23%25.cpp',
    ]);
    // The related location in a system header is dropped with its note; the in-copy one stays.
    expect(results[0]!.relatedLocations).toEqual([
      {
        physicalLocation: {
          artifactLocation: { uri: 'src/b.c' },
          region: { startLine: 4, startColumn: 1 },
        },
        message: { text: 'here' },
      },
    ]);
    expect(outside).toBe(3);
    expect(JSON.stringify(log)).not.toMatch(/secret|stdio|\/w\/src/);
  });

  it('refuses what is not cppcheck XML', () => {
    expect(() =>
      cppcheckXmlToSarif('<results version="1">', { version: 'x', base: '/w' }),
    ).toThrow();
    expect(() => cppcheckXmlToSarif('not xml', { version: 'x', base: '/w' })).toThrow();
    expect(() =>
      cppcheckXmlToSarif(
        '<!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]><results version="2"><errors><error id="a" severity="error" msg="&e;"/></errors></results>',
        { version: 'x', base: '/w' },
      ),
    ).toThrow();
  });

  it('reads the recorded c-basic run (plan 9D, fact F12)', () => {
    const recorded = readFileSync(path.join(ANALYZER_OUTPUT_DIR, 'cppcheck/basic.xml'), 'utf8');
    const { log, notAnalysed } = cppcheckXmlToSarif(recorded, {
      version: '2.22.0',
      base: '/fixture-root',
    });
    const got = log.runs[0]!.results!.map(
      (r) =>
        `${r.locations![0]!.physicalLocation!.artifactLocation!.uri}:${r.locations![0]!.physicalLocation!.region!.startLine} ${r.ruleId}`,
    ).sort();
    expect(got).toEqual([
      'src/main.c:18 memleak',
      'src/main.c:21 memleak',
      'src/main.c:9 zerodiv',
      'src/stack.c:17 arrayIndexOutOfBounds',
      'src/stack.c:23 nullPointerOutOfMemory',
    ]);
    expect([...notAnalysed]).toEqual([['syntaxError', 1]]);
  });
});
