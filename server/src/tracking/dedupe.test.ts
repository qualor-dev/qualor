import { enginePriority, rulesEquivalent, sameEngineRank } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { rng } from '../../test/match-harness';
import { budgetMs } from '../../test/perf';
import { planDedupe, type DuplicateChange } from './dedupe';
import type { LiveIssue } from './plan';

const codeUnits = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/**
 * The O(N²)-per-line implementation planDedupe had before the final fix wave (every issue scanned
 * every earlier root with rulesEquivalent), the reference its indexed replacement must agree with.
 * Its sort follows planDedupe's since plan 6A: a curated same-engine primary is walked before the
 * rest of its engine; the scan itself is unchanged and rulesEquivalent knows the pairs.
 */
function referencePlanDedupe(live: readonly LiveIssue[]): DuplicateChange[] {
  const groups = new Map<string, LiveIssue[]>();
  const primaryOf = new Map<string, string | null>();
  for (const issue of live) {
    primaryOf.set(issue.id, null);
    if (issue.path === null || issue.startLine === null) continue;
    const key = `${issue.path}\u0000${issue.startLine}`;
    const group = groups.get(key);
    if (group) group.push(issue);
    else groups.set(key, [issue]);
  }
  for (const group of groups.values()) {
    if (group.length < 2) continue;
    group.sort(
      (a, b) =>
        enginePriority(b.engineId) - enginePriority(a.engineId) ||
        codeUnits(a.engineId, b.engineId) ||
        sameEngineRank(b.ruleKey) - sameEngineRank(a.ruleKey) ||
        codeUnits(a.id, b.id),
    );
    const roots: LiveIssue[] = [];
    for (const issue of group) {
      const self = { key: issue.ruleKey, engineId: issue.engineId, cwe: issue.cwe };
      const primary = roots.find((root) =>
        rulesEquivalent(self, { key: root.ruleKey, engineId: root.engineId, cwe: root.cwe }),
      );
      if (primary) primaryOf.set(issue.id, primary.id);
      else roots.push(issue);
    }
  }
  return live
    .filter((issue) => (primaryOf.get(issue.id) ?? null) !== issue.duplicateOfIssueId)
    .map((issue) => ({ id: issue.id, duplicateOf: primaryOf.get(issue.id) ?? null }));
}

const issue = (id: string, ruleKey: string, cwe: number[], overrides: Partial<LiveIssue> = {}) =>
  ({
    id,
    ruleKey,
    engineId: ruleKey.split(':')[0]!,
    cwe,
    path: 'src/config.ts',
    startLine: 2,
    status: 'open',
    duplicateOfIssueId: null,
    ...overrides,
  }) satisfies LiveIssue;

describe('planDedupe (data-model.md §5.3)', () => {
  it('points the lower-priority engine at the higher one, whatever the input order', () => {
    const semgrep = issue('s', 'semgrep:hardcoded-api-key', [798]);
    const gitleaks = issue('g', 'gitleaks:generic-api-key', []);
    expect(planDedupe([semgrep, gitleaks])).toEqual([{ id: 's', duplicateOf: 'g' }]);
    expect(planDedupe([gitleaks, semgrep])).toEqual([{ id: 's', duplicateOf: 'g' }]);
  });

  it('points every duplicate at the highest-priority root, never at another duplicate', () => {
    const changes = planDedupe([
      issue('e', 'eslint:security/detect-eval', [95]),
      issue('s', 'semgrep:ts-eval', [95]),
      issue('x', 'my-tool:eval', [95]),
    ]);
    expect(changes).toEqual([
      { id: 'e', duplicateOf: 's' },
      { id: 'x', duplicateOf: 's' },
    ]);
  });

  it('breaks priority ties by code-unit order of the id, like writes.ts', () => {
    // 'B' < 'a' in code units; localeCompare puts 'a' first.
    const changes = planDedupe([
      issue('x', 'my-tool:eval', [95]),
      issue('a', 'semgrep:ts-eval', [95]),
      issue('B', 'semgrep:ts-eval-2', [95]),
    ]);
    expect(changes).toEqual([{ id: 'x', duplicateOf: 'B' }]);
  });

  it('leaves different lines, one engine, and unrelated rules alone', () => {
    expect(
      planDedupe([
        issue('g', 'gitleaks:generic-api-key', []),
        issue('s', 'semgrep:hardcoded-api-key', [798], { startLine: 3 }),
        issue('s2', 'semgrep:other-secret', [798], { startLine: 3 }),
        issue('e', 'eslint:no-console', [], { startLine: 3 }),
        issue('f', 'my-tool:x', [798], { path: null, startLine: null }),
      ]),
    ).toEqual([]);
  });

  it('points a FindSecBugs issue at the core SpotBugs issue of a curated pair on its line (plan 6A)', () => {
    const core = issue('z', 'spotbugs:SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE', [89]);
    const fsb = issue('a', 'spotbugs:SQL_INJECTION_JDBC', [89]);
    // 'a' < 'z': without the pair rank, the FindSecBugs issue would be walked first and stay a root.
    expect(planDedupe([core, fsb])).toEqual([{ id: 'a', duplicateOf: 'z' }]);
    expect(planDedupe([fsb, core])).toEqual([{ id: 'a', duplicateOf: 'z' }]);
    // Another rule of the engine with the same CWE stays its own issue.
    expect(planDedupe([fsb, issue('b', 'spotbugs:SQL_INJECTION_SPRING_JDBC', [89])])).toEqual([]);
    // The core rule turned off in the profile: the FindSecBugs issue is a root (and is promoted).
    expect(planDedupe([{ ...fsb, duplicateOfIssueId: 'z' }])).toEqual([
      { id: 'a', duplicateOf: null },
    ]);
    // A higher-priority engine with the CWE wins over both.
    const semgrep = issue('s', 'semgrep:java-sqli', [89]);
    expect(planDedupe([core, fsb, semgrep])).toEqual([
      { id: 'z', duplicateOf: 's' },
      { id: 'a', duplicateOf: 's' },
    ]);
  });

  it("makes Qualor's own rule the one issue of its line, also for engines that share no CWE with it (plan 6B)", () => {
    // Python, the 2026-10-06 merge request: Ruff's S608 carries no CWE.
    expect(
      planDedupe([
        issue('a', 'ruff:S608', []),
        issue('q', 'qualor:python/sql-injection', [89]),
        issue('b', 'ruff:S113', []),
      ]),
    ).toEqual([{ id: 'a', duplicateOf: 'q' }]);
    // Ruff's shell rules S602 and S605 carry no CWE either.
    expect(
      planDedupe([
        issue('a', 'ruff:S602', []),
        issue('q', 'qualor:python/command-injection', [78]),
      ]),
    ).toEqual([{ id: 'a', duplicateOf: 'q' }]);
    expect(
      planDedupe([
        issue('a', 'ruff:S605', []),
        issue('q', 'qualor:python/command-injection', [78]),
      ]),
    ).toEqual([{ id: 'a', duplicateOf: 'q' }]);
    // JavaScript: the SonarJS hotspot and the project's own eslint-plugin-sonarjs finding.
    expect(
      planDedupe([
        issue('a', 'sonarjs:S2077', []),
        issue('b', 'eslint:sonarjs/sql-queries', []),
        issue('q', 'qualor:js/sql-injection', [89]),
      ]),
    ).toEqual([
      { id: 'a', duplicateOf: 'q' },
      { id: 'b', duplicateOf: 'q' },
    ]);
    // Go: gosec's G107 has CWE-88, its taint rule G704 CWE-918.
    expect(
      planDedupe([
        issue('a', 'gosec:G107', [88]),
        issue('b', 'gosec:G704', [918]),
        issue('q', 'qualor:go/ssrf', [918]),
      ]),
    ).toEqual([
      { id: 'a', duplicateOf: 'q' },
      { id: 'b', duplicateOf: 'q' },
    ]);
    // Java: the core SpotBugs rule (CWE-23) is walked before its FindSecBugs duplicate (CWE-22)
    // and would otherwise stay a second root.
    expect(
      planDedupe([
        issue('a', 'spotbugs:PATH_TRAVERSAL_IN', [22]),
        issue('b', 'spotbugs:PT_RELATIVE_PATH_TRAVERSAL', [23]),
        issue('q', 'qualor:java/path-traversal', [22]),
      ]),
    ).toEqual([
      { id: 'a', duplicateOf: 'q' },
      { id: 'b', duplicateOf: 'q' },
    ]);
  });

  it('promotes a duplicate whose primary is gone, and reports only real changes', () => {
    const orphan = issue('s', 'semgrep:hardcoded-api-key', [798], { duplicateOfIssueId: 'g' });
    expect(planDedupe([orphan])).toEqual([{ id: 's', duplicateOf: null }]);
    const settled = issue('s', 'semgrep:hardcoded-api-key', [798], { duplicateOfIssueId: 'g' });
    expect(planDedupe([issue('g', 'gitleaks:generic-api-key', []), settled])).toEqual([]);
  });

  it('agrees with the reference implementation on random issues (differential, 2 000 seeded cases)', () => {
    // Few engines, lines and CWEs, so groups are dense and every tie-break is exercised: equal
    // priorities (two external engines), the curated pair, the gitleaks engine CWE, rules without
    // a CWE, the curated same-engine pair, other same-engine rules (never duplicates), and stale
    // or dangling pointers.
    const ENGINES = ['gitleaks', 'semgrep', 'spotbugs', 'eslint', 'pmd', 'tool-a', 'tool-b'];
    const PAIR = [
      'eslint:no-eval',
      'semgrep:javascript.browser.security.eval-detected.eval-detected',
    ];
    const SAME = [
      'spotbugs:SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE',
      'spotbugs:SQL_INJECTION_JDBC',
    ];
    const random = rng(20260924);
    for (let n = 0; n < 2_000; n++) {
      const count = 1 + random.int(24);
      const live: LiveIssue[] = [];
      for (let i = 0; i < count; i++) {
        const pairRule = random.int(6) === 0 ? PAIR[random.int(2)] : undefined;
        const sameRule =
          pairRule === undefined && random.int(6) === 0 ? SAME[random.int(2)] : undefined;
        const chosen = pairRule ?? sameRule;
        const engineId = chosen ? chosen.split(':')[0]! : ENGINES[random.int(ENGINES.length)]!;
        const cwe = Array.from({ length: random.int(3) }, () => [78, 95, 798, 89][random.int(4)]!);
        const fileless = random.int(10) === 0;
        live.push({
          id: `id-${random.int(1_000)}-${i}`,
          engineId,
          ruleKey: chosen ?? `${engineId}:r${random.int(4)}`,
          cwe,
          path: fileless ? null : ['a.ts', 'b.ts'][random.int(2)]!,
          startLine: fileless ? null : 1 + random.int(3),
          status: 'open',
          duplicateOfIssueId:
            random.int(3) === 0 ? `id-${random.int(1_000)}-${random.int(count)}` : null,
        });
      }
      expect(planDedupe(live), `case ${n}`).toEqual(referencePlanDedupe(live));
    }
  });

  it('dedupes 50 000 issues on one line across two engines in well under a second (I1)', () => {
    // A minified bundle: every finding on line 1. The old per-line scan was O(N²) here (22 s for
    // 20 000 issues), blocking the event loop past the job lease.
    const n = 50_000;
    const live: LiveIssue[] = Array.from({ length: n }, (_, i) => {
      const engineId = i % 2 ? 'semgrep' : 'eslint';
      return issue(
        `00000000-0000-7000-8000-${String(i).padStart(12, '0')}`,
        `${engineId}:r${i}`,
        [],
        {
          engineId,
          path: 'dist/bundle.min.js',
          startLine: 1,
        },
      );
    });
    const started = performance.now();
    const changes = planDedupe(live);
    expect(performance.now() - started).toBeLessThan(budgetMs(1_000));
    expect(changes).toEqual([]);
    // And the same line with every rule sharing one CWE: every eslint issue points at the first
    // semgrep one.
    const shared = live.map((l) => ({ ...l, cwe: [95] }));
    const started2 = performance.now();
    const dups = planDedupe(shared);
    expect(performance.now() - started2).toBeLessThan(budgetMs(1_000));
    expect(dups).toHaveLength(n / 2);
    expect(new Set(dups.map((d) => d.duplicateOf))).toEqual(new Set([shared[1]!.id]));
  });
});
