import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { compareSonarImport, type SonarExpected } from './sonarqube-check';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const base: SonarExpected = {
  profiles: {
    P: {
      skip: null,
      rows: [{ ruleKey: 'eslint:x', active: true, severityOverride: null }],
      pendingReview: [],
      statusOnly: [],
      unmapped: [],
    },
  },
  gates: {
    G: { skip: null, mapped: [{ metric: 'new_issues', operator: 'gt', threshold: 0 }], unmapped: [] },
  },
  statuses: { A: { ruleKey: 'eslint:x', line: 3 }, B: 'unmatched' },
};

describe("the fixture check matches as the server does, with no copy of the server's code", () => {
  it.each(['tools/fixtures/sonarqube-check.ts', 'server/src/issues/status-import.ts'])(
    '%s takes the shared statusMatchItem and builds no matcher view of its own',
    (file) => {
      const source = readFileSync(path.join(root, file), 'utf8');
      expect(source).toContain('statusMatchItem');
      expect(source).not.toMatch(/commentKey\s*:/);
      expect(source).not.toMatch(/function matchItem|const matchItem/);
    },
  );
});

describe('compareSonarImport', () => {
  it('finds no difference in equal plans', () => {
    expect(compareSonarImport(base, structuredClone(base))).toEqual([]);
  });

  it('names each difference', () => {
    const actual = structuredClone(base);
    actual.statuses['A'] = 'unmatched';
    actual.statuses['C'] = 'competitorsUnknown';
    actual.gates['G']!.unmapped.push('x');
    delete actual.profiles['P'];
    expect(compareSonarImport(base, actual)).toEqual([
      'profile P: expected {"skip":null,"rows":[{"ruleKey":"eslint:x","active":true,"severityOverride":null}],"pendingReview":[],"statusOnly":[],"unmapped":[]}, got nothing',
      'gate G: expected {"skip":null,"mapped":[{"metric":"new_issues","operator":"gt","threshold":0}],"unmapped":[]}, got {"skip":null,"mapped":[{"metric":"new_issues","operator":"gt","threshold":0}],"unmapped":["x"]}',
      'status A: expected {"ruleKey":"eslint:x","line":3}, got "unmatched"',
      'status C: expected nothing, got "competitorsUnknown"',
    ]);
  });

  it('does not depend on the order of an object’s keys', () => {
    const actual = structuredClone(base);
    actual.statuses = { A: { line: 3, ruleKey: 'eslint:x' } as never, B: 'unmatched' };
    expect(compareSonarImport(base, actual)).toEqual([]);
  });
});
