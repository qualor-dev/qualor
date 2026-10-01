import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { resolveBinary } from '../../cli/src/analyzers/binary';
import { describeWithClangTidy, describeWithCppcheck } from '../../cli/test/analyzers';

// Plan 9D: runs only with the pinned tools (cppcheck 2.22, clang-tidy of the pinned major) or under
// QUALOR_REQUIRE_ANALYZERS=1, so another cppcheck minor (Debian's 2.10 lacks ids 2.22 has) skips.
const cppcheck = resolveBinary('cppcheck', { root: process.cwd(), env: process.env });
const clangTidy = resolveBinary('clang-tidy', { root: process.cwd(), env: process.env });

/** Every `cppcheck:`/`clang-tidy:` key the curated tables name (F11: checked one by one at planning). */
function curatedKeys(engine: string): string[] {
  const keys = new Set<string>();
  const sonar = JSON.parse(readFileSync('packages/shared/rules/sonarqube.json', 'utf8')) as {
    rules: { qualor: string[] }[];
  };
  const eq = JSON.parse(readFileSync('packages/shared/rules/equivalences.json', 'utf8')) as {
    pairs: { rules: string[] }[];
  };
  for (const k of [...sonar.rules.flatMap((r) => r.qualor), ...eq.pairs.flatMap((p) => p.rules)]) {
    if (k.startsWith(`${engine}:`)) keys.add(k.slice(engine.length + 1));
  }
  return [...keys].sort();
}

describeWithCppcheck()(
  'the cppcheck ids of the curated tables exist in the pinned cppcheck (plan 9D)',
  () => {
    it('cppcheck --errorlist has every cppcheck id', () => {
      const list = spawnSync(cppcheck ?? 'cppcheck', ['--errorlist'], {
        encoding: 'utf8',
        maxBuffer: 16 * 1024 * 1024,
      }).stdout;
      const ids = new Set([...list.matchAll(/<error id="([^"]+)"/g)].map((m) => m[1]));
      const keys = curatedKeys('cppcheck');
      expect(keys.length).toBeGreaterThan(20);
      expect(keys.filter((k) => !ids.has(k))).toEqual([]);
    });
  },
);

describeWithClangTidy()(
  'the clang-tidy checks of the curated tables exist in the pinned clang-tidy (plan 9D)',
  () => {
    it('clang-tidy --list-checks has every check that is not a compiler warning', () => {
      const list = spawnSync(clangTidy ?? 'clang-tidy', ['--list-checks', '--checks=*'], {
        encoding: 'utf8',
        maxBuffer: 16 * 1024 * 1024,
      }).stdout;
      const checks = new Set(
        list
          .split('\n')
          .map((l) => l.trim())
          .filter((l) => l !== ''),
      );
      const keys = curatedKeys('clang-tidy').filter((k) => !k.startsWith('clang-diagnostic-'));
      expect(keys.length).toBeGreaterThan(10);
      expect(keys.filter((k) => !checks.has(k))).toEqual([]);
    });
  },
);
