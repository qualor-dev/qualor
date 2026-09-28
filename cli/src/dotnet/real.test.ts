import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { gunzipSync } from 'node:zlib';
import { expect, it } from 'vitest';
import { describeWithDotnet } from '../../test/analyzers';
import { commitAll, initRepo } from '../../test/git';
import { captureIO } from '../../test/io';
import { testParsers } from '../../test/parsers';
import { useTempDirs } from '../../test/tmp';
import { EXIT } from '../errors';
import { silentLogger } from '../log';
import { runDotnetBegin } from './begin';
import { runDotnetEnd } from './end';
import { hookPath, installHook } from './hook';

const tmp = useTempDirs();
const FIXTURE = path.resolve(import.meta.dirname, '../../../fixtures/csharp-basic');

describeWithDotnet()('qualor dotnet with a real build (fixtures/csharp-basic)', () => {
  const dotnet = (cwd: string, env: NodeJS.ProcessEnv) =>
    spawnSync('dotnet', ['build', '--no-incremental', '-nologo', 'Fixture.slnx'], {
      cwd,
      env,
      encoding: 'utf8',
      timeout: 600_000,
    });

  // A real dotnet build (restore, two target frameworks) is slower than vitest's 5 s default,
  // especially alongside every other real-tool test of a full `pnpm test` run (Task 9's Linux
  // check); as generous as the other real-tool suites (pmd.test.ts 180 s, spotbugs.test.ts 300 s).
  it(
    'reports the fixture findings once each, builds despite TreatWarningsAsErrors, and cleans up (Review Focus 1, 3)',
    { timeout: 300_000 },
    async () => {
      const root = tmp();
      cpSync(FIXTURE, root, { recursive: true });
      initRepo(root);
      commitAll(root, 'fixture');
      const env = {
        ...process.env,
        XDG_DATA_HOME: tmp(),
        DOTNET_CLI_TELEMETRY_OPTOUT: '1',
        DOTNET_NOLOGO: '1',
      };
      expect(runDotnetBegin({}, captureIO({ cwd: root, env }).io, silentLogger)).toBe(EXIT.OK);
      const build = dotnet(root, env);
      expect(build.status, build.stdout + build.stderr).toBe(0);
      const out = path.join(tmp(), 'r.json.gz');
      await runDotnetEnd(
        { sarif: [], coverage: [], wait: true, dryRun: true, output: out, projectKey: 'p' },
        captureIO({ cwd: root, env }).io,
        silentLogger,
        { parsers: await testParsers(), baselineClient: null },
      );
      const report = JSON.parse(gunzipSync(readFileSync(out)).toString('utf8'));
      const keys = report.findings
        .filter((f: { engineId: string }) => f.engineId === 'roslyn')
        .map(
          (f: { ruleId: string; location: { path: string; startLine: number } }) =>
            `${f.ruleId}@${f.location.path}:${f.location.startLine}`,
        );
      expect(keys).toContain('CA5351@src/Acme.Store/Hashing.cs:9');
      expect(new Set(keys).size).toBe(keys.length);
      expect(keys.some((k: string) => k.startsWith('CA1822@'))).toBe(false); // #pragma-suppressed
      expect(existsSync(hookPath(path.join(env.XDG_DATA_HOME, 'Microsoft', 'MSBuild')))).toBe(
        false,
      );
      expect(existsSync(path.join(root, '.qualor', 'dotnet'))).toBe(false);
    },
  );

  it(
    'a hook left behind changes no build outside a session (Review Focus 2)',
    { timeout: 300_000 },
    () => {
      const root = tmp();
      cpSync(FIXTURE, root, { recursive: true });
      const env = {
        ...process.env,
        XDG_DATA_HOME: tmp(),
        DOTNET_CLI_TELEMETRY_OPTOUT: '1',
        DOTNET_NOLOGO: '1',
      };
      installHook(path.join(env.XDG_DATA_HOME, 'Microsoft', 'MSBuild'));
      const build = dotnet(root, env);
      // The library sets TreatWarningsAsErrors and has analyzer warnings only inside a session:
      // outside one it builds, and nothing is written below the checkout.
      expect(build.status, build.stdout + build.stderr).toBe(0);
      expect(existsSync(path.join(root, '.qualor'))).toBe(false);
      expect(readdirSync(root)).not.toContain('.qualor');
    },
  );
});
