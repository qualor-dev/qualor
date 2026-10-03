import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { ENGINE_MAPPINGS } from '@qualor/shared';
import { expect, it } from 'vitest';
import {
  describeWithQualorRules,
  expectedKeys,
  installedQualorRules,
  qualorRulesPins,
  scanFixtureWith,
} from '../../test/analyzers';
import { commitAll, initRepo } from '../../test/git';
import { useTempDirs } from '../../test/tmp';
import { MAX_ANALYZED_BYTES } from '../discovery/discover';
import { createQualorAnalyzer, qualorAnalyzer, withQualorRules } from './qualor';
import type { Analyzer } from './types';

const tmp = useTempDirs();
const gitRepo = (dir: string) => {
  initRepo(dir);
  commitAll(dir, 'fixture');
};

describeWithQualorRules()(
  "Qualor's security rules on qualor-security (real OpenGrep and pack)",
  () => {
    it('is the pinned pack, made for the pinned OpenGrep, and every rule maps to its manifest kind and severity', () => {
      const pack = installedQualorRules();
      expect(
        pack,
        'the pack is not installed (tools/analyzers/install-qualor-rules.sh)',
      ).not.toBeNull();
      expect(pack!.manifest.version).toBe(qualorRulesPins().version);
      expect(pack!.manifest.opengrep).toBe(qualorRulesPins().opengrep);
      const log = withQualorRules(
        {
          runs: [
            {
              tool: {
                driver: {
                  semanticVersion: pack!.manifest.opengrep,
                  rules: pack!.manifest.rules.map((r) => ({ id: r.id.replace('/', '.') })),
                },
              },
            },
          ],
        },
        pack!.manifest,
      ) as {
        runs: {
          tool: { driver: { rules: { id: string; properties?: Record<string, unknown> }[] } };
        }[];
      };
      pack!.manifest.rules.forEach((r, i) => {
        const rule = log.runs[0]!.tool.driver.rules[i]!;
        expect(rule.id).toBe(r.id);
        expect(ENGINE_MAPPINGS.qualor.rule!(rule as never), r.id).toEqual({
          quality: 'security',
          kind: r.kind,
          defaultSeverity: r.severity,
        });
      });
    });

    it(
      'reports the fixture findings despite .semgrepignore and tests/, and names the pack in the version',
      { timeout: 300_000 },
      async () => {
        const { out, keys } = await scanFixtureWith(
          qualorAnalyzer,
          'qualor-security',
          tmp(),
          gitRepo,
        );
        expect(keys).toEqual(expectedKeys('qualor-security', 'qualor'));
        expect(out.engines[0]?.version).toBe(
          `${qualorRulesPins().opengrep} + qualor-rules ${qualorRulesPins().version}`,
        );
        expect(out.engines[0]?.rules.find((r) => r.id === 'python/sql-injection')).toMatchObject({
          quality: 'security',
          kind: 'issue',
          cwe: [89],
        });
      },
    );

    it('is not hidden by a nosemgrep comment in the checkout', { timeout: 300_000 }, async () => {
      const { keys } = await scanFixtureWith(qualorAnalyzer, 'qualor-security', tmp(), (dir) => {
        const file = path.join(dir, 'python', 'orders.py');
        const lines = readFileSync(file, 'utf8').split('\n');
        lines[11] = `${lines[11]}  # nosemgrep`;
        writeFileSync(file, lines.join('\n'));
        gitRepo(dir);
      });
      expect(keys).toEqual(expectedKeys('qualor-security', 'qualor'));
    });

    it.runIf(process.platform !== 'win32')(
      "ignores the CI's SEMGREP_* variables: same findings, nothing written into the checkout",
      { timeout: 300_000 },
      async () => {
        const root = tmp();
        const { keys } = await scanFixtureWith(qualorAnalyzer, 'qualor-security', root, gitRepo, {
          ...process.env,
          SEMGREP_BASELINE_REF: 'HEAD',
          SEMGREP_BASELINE_COMMIT: 'HEAD',
          SEMGREP_TIMEOUT: '0.001',
          SEMGREP_LOG_FILE: path.join(root, 'opengrep.log'),
        });
        expect(keys).toEqual(expectedKeys('qualor-security', 'qualor'));
        expect(existsSync(path.join(root, 'opengrep.log'))).toBe(false);
      },
    );

    it(
      "covers the fixture with OpenGrep's own file selection when the list does not fit",
      { timeout: 300_000 },
      async () => {
        const fallback = createQualorAnalyzer({ maxTargetArgBytes: 1 });
        const warnings: string[] = [];
        let args: readonly string[] = [];
        // The same analyzer, recording the command it hands the runner and the warnings it logs.
        const recording: Analyzer = {
          ...fallback,
          prepare: async (ctx) => {
            const prep = await fallback.prepare({
              ...ctx,
              log: { ...ctx.log, warn: (m: string) => warnings.push(m) },
            });
            if ('run' in prep) args = prep.run.args;
            return prep;
          },
        };
        const { keys } = await scanFixtureWith(recording, 'qualor-security', tmp(), gitRepo);
        expect(keys).toEqual(expectedKeys('qualor-security', 'qualor'));
        // The fallback ran: no file list, OpenGrep scanned `.` itself.
        expect(args).not.toContain('--');
        expect(args.slice(-4)).toEqual([
          '--max-target-bytes',
          String(MAX_ANALYZED_BYTES),
          '--x-ignore-semgrepignore-files',
          '.',
        ]);
        expect(warnings).toEqual([
          expect.stringMatching(
            /^qualor: \d+ files do not fit one command line; OpenGrep selects the files itself/,
          ),
        ]);
      },
    );
  },
);
