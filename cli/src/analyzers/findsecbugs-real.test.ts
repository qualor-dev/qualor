import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { expect, it } from 'vitest';
import {
  compileJava,
  describeWithFindsecbugs,
  expectedKeys,
  installedFindsecbugs,
  scanFixtureWith,
} from '../../test/analyzers';
import { useTempDirs } from '../../test/tmp';
import { spotbugsAnalyzer } from './spotbugs';

const tmp = useTempDirs();
const pin = (name: string) =>
  new RegExp(`^${name}=(.+)$`, 'm').exec(readFileSync('tools/analyzers/install.sh', 'utf8'))?.[1];

describeWithFindsecbugs()('FindSecBugs inside SpotBugs on java-security (real SpotBugs)', () => {
  it('finds the plugin where QUALOR_REQUIRE_ANALYZERS=1 requires it', () => {
    expect(installedFindsecbugs()?.version).toBe(pin('FINDSECBUGS_VERSION'));
  });

  it(
    'reports the fixture findings, and names the plugin in the version',
    { timeout: 300_000 },
    async () => {
      const { out, keys } = await scanFixtureWith(
        spotbugsAnalyzer,
        'java-security',
        tmp(),
        compileJava,
      );
      expect(keys).toEqual(expectedKeys('java-security', 'spotbugs'));
      expect(out.engines[0]?.version).toBe(
        `${pin('SPOTBUGS_VERSION')} + FindSecBugs ${pin('FINDSECBUGS_VERSION')}`,
      );
    },
  );

  it.runIf(process.platform !== 'win32')(
    'ignores findsecbugs* variables: nothing written into the checkout, no custom config read (Review Focus 1)',
    { timeout: 300_000 },
    async () => {
      const root = tmp();
      // scanFixtureWith fails unless the engine's status is ok: a bogus custom config file that
      // reached the plugin would make SpotBugs exit 1.
      const { keys } = await scanFixtureWith(spotbugsAnalyzer, 'java-security', root, compileJava, {
        ...process.env,
        findsecbugs_taint_outputconfigs: 'true',
        findsecbugs_taint_customconfigfile: 'does-not-exist.txt',
        'findsecbugs.injection.sources': 'does-not-exist-either.txt',
      });
      expect(existsSync(path.join(root, 'derived-config.txt'))).toBe(false);
      expect(keys).toEqual(expectedKeys('java-security', 'spotbugs'));
    },
  );
});
