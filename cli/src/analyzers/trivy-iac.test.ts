import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { parseConfig } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import {
  describeWithTools,
  fakeContext,
  findingKeys,
  REQUIRE_ANALYZERS,
  type FakeContextOptions,
} from '../../test/analyzers';
import { FIXTURES_DIR } from '../../test/fixtures';
import { useTempDirs, writeTree } from '../../test/tmp';
import { discoverFiles, type ScopeFile } from '../discovery/discover';
import { silentLogger } from '../log';
import { Warnings } from '../warnings';
import { fileLines, normalizeCaptures } from './normalize';
import { deadProxyEnv } from './offline';
import { runAnalyzers } from './runner';
import { skipDirs } from './trivy';
import {
  createTrivyIacAnalyzer,
  DEFAULT_IAC_CHECKS_DIR,
  IAC_CHECKS_EMBEDDED_MESSAGE,
  isIacCandidate,
  trivyIacAnalyzer,
} from './trivy-iac';
import type { AnalyzerContext, Preparation } from './types';

const tmp = useTempDirs();

const scope = (p: string): ScopeFile => ({
  path: p,
  absPath: p,
  language: 'other',
  grammar: null,
  kind: 'main',
  size: 1,
});

/** A checks directory the way install.sh leaves it. */
function checks(version?: string): string {
  const dir = tmp();
  writeTree(dir, { 'policy/content/.keep': '' });
  if (version !== undefined) writeFileSync(path.join(dir, 'version'), version);
  return dir;
}

interface SetupOptions {
  files?: string[];
  env?: Record<string, string>;
  config?: FakeContextOptions['config'];
  binary?: boolean;
}

function setup(o: SetupOptions = {}): { root: string; ctx: AnalyzerContext } {
  const root = tmp();
  const ctx = fakeContext(root, {
    binaries: o.binary === false ? {} : { trivy: '/opt/qualor/bin/trivy' },
    env: o.env ?? {},
    ...(o.config !== undefined && { config: o.config }),
  });
  mkdirSync(ctx.workDir, { recursive: true });
  return { root, ctx: { ...ctx, files: (o.files ?? ['main.tf']).map(scope) } };
}

function runOf(prep: Preparation) {
  if (!('run' in prep)) throw new Error(JSON.stringify(prep));
  return prep.run;
}

const cacheDirOf = (args: readonly string[]) => args[args.indexOf('--cache-dir') + 1];

describe('trivyIacAnalyzer.prepare', () => {
  it('runs the exact command of the constraints', async () => {
    const dir = checks('2.3.0\n');
    const { root, ctx } = setup();
    const run = runOf(await createTrivyIacAnalyzer(dir).prepare(ctx));
    const work = (n: string) => path.join(ctx.workDir, n);
    expect(run.command).toBe('/opt/qualor/bin/trivy');
    expect(run.args).toEqual([
      'fs',
      '--config',
      work('trivy.yaml'),
      '--cache-dir',
      dir,
      '--cache-backend',
      'memory',
      '--skip-check-update',
      '--skip-version-check',
      '--disable-telemetry',
      '--offline-scan',
      '--module-dir',
      work('modules'),
      '--scanners',
      'misconfig',
      '--misconfig-scanners',
      'azure-arm,cloudformation,dockerfile,helm,kubernetes,terraform,terraformplan-json,terraformplan-snapshot',
      '--tf-exclude-downloaded-modules',
      '--ignorefile',
      work('trivyignore'),
      ...skipDirs().flatMap((d) => ['--skip-dirs', d]),
      '--timeout',
      '600s',
      '--format',
      'json',
      '--output',
      work('trivy-iac.json'),
      '--quiet',
      '.',
    ]);
    expect(run.cwd).toBe(root);
    expect(run.sarifPath).toBe(work('trivy-iac.json'));
    expect(run.okExitCodes).toEqual([0]);
    expect(run.version).toBe('checks 2.3.0');
    expect(run.warnings).toBeUndefined();
    expect(readFileSync(work('trivyignore'), 'utf8')).toBe('');
  });

  it('uses the root .trivyignore when there is one', async () => {
    const { root, ctx } = setup();
    writeFileSync(path.join(root, '.trivyignore'), 'AVD-AWS-0086\n');
    const run = runOf(await createTrivyIacAnalyzer(checks()).prepare(ctx));
    expect(run.args[run.args.indexOf('--ignorefile') + 1]).toBe(path.join(root, '.trivyignore'));
  });

  it('adds the dead proxy and GIT_ALLOW_PROTOCOL=file, and drops TRIVY_ and TF_TOKEN_ variables', async () => {
    const { ctx } = setup();
    const run = runOf(await createTrivyIacAnalyzer(checks()).prepare(ctx));
    expect(run.env).toEqual({ ...deadProxyEnv(), GIT_ALLOW_PROTOCOL: 'file' });
    expect(run.dropEnv?.('TRIVY_FOO')).toBe(true);
    expect(run.dropEnv?.('TF_TOKEN_app_terraform_io')).toBe(true);
    for (const name of [
      'AWS_ACCESS_KEY_ID',
      'GOOGLE_APPLICATION_CREDENTIALS',
      'AZURE_CLIENT_SECRET',
      'ARM_CLIENT_SECRET',
    ]) {
      expect(run.dropEnv?.(name), name).toBe(true);
    }
    expect(run.dropEnv?.('PATH')).toBe(false);
  });

  it('names an empty config in workDir, never the repository trivy.yaml', async () => {
    const { root, ctx } = setup();
    writeFileSync(path.join(root, 'trivy.yaml'), 'severity:\n  - CRITICAL\n');
    const run = runOf(await createTrivyIacAnalyzer(checks()).prepare(ctx));
    const config = run.args[run.args.indexOf('--config') + 1] ?? '';
    expect(config).toBe(path.join(ctx.workDir, 'trivy.yaml'));
    expect(config).not.toBe(path.join(root, 'trivy.yaml'));
    expect(readFileSync(config, 'utf8')).toBe('');
    const modules = run.args[run.args.indexOf('--module-dir') + 1] ?? '';
    expect(path.dirname(modules)).toBe(ctx.workDir);
    expect(readdirSync(modules)).toEqual([]);
  });

  it('passes the timeout in seconds', async () => {
    const { ctx } = setup({ config: { analyzers: { 'trivy-iac': { timeoutSeconds: 120 } } } });
    const run = runOf(await createTrivyIacAnalyzer(checks()).prepare(ctx));
    expect(run.args[run.args.indexOf('--timeout') + 1]).toBe('120s');
  });

  it('skips a scope without infrastructure files', async () => {
    const { ctx } = setup({ files: ['src/a.ts', 'README.md'] });
    expect(await createTrivyIacAnalyzer(checks()).prepare(ctx)).toEqual({
      skip: 'no infrastructure files in scope',
    });
  });

  it.each(['Dockerfile.prod', 'app.Dockerfile', 'infra/x.tf.json', 'package.json'])(
    'treats %s as a candidate',
    async (file) => {
      const { ctx } = setup({ files: ['src/a.ts', file] });
      expect('run' in (await createTrivyIacAnalyzer(checks()).prepare(ctx))).toBe(true);
    },
  );

  it('knows the candidate names', () => {
    for (const p of ['a.tf', 'a.tfvars', 'a.yaml', 'a.YML', 'x/Containerfile', 'DOCKERFILE']) {
      expect(isIacCandidate(p), p).toBe(true);
    }
    for (const p of ['a.ts', 'dockerfiles', 'README.md', 'a.hcl', 'Dockerfile.md.ts']) {
      expect(isIacCandidate(p), p).toBe(p === 'Dockerfile.md.ts');
    }
  });

  it('is unavailable without a trivy binary', async () => {
    const { ctx } = setup({ binary: false });
    const prep = await createTrivyIacAnalyzer(checks()).prepare(ctx);
    expect(prep).toEqual({ unavailable: expect.stringContaining('Trivy is not installed') });
  });

  it('reports a .trivyignore over 1 MiB like the trivy analyzer', () => {
    const { root, ctx } = setup();
    writeFileSync(path.join(root, '.trivyignore'), 'x'.repeat(1024 * 1024 + 1));
    const a = createTrivyIacAnalyzer(checks());
    expect(a.checkConfig?.(root, ctx.config, {})).toBe('.trivyignore is larger than 1 MiB');
  });
});

describe('the checks directory', () => {
  it('takes QUALOR_TRIVY_CHECKS_DIR when absolute, outside the repository and complete', async () => {
    const named = checks('2.3.0');
    const { ctx } = setup({ env: { QUALOR_TRIVY_CHECKS_DIR: named } });
    const run = runOf(await createTrivyIacAnalyzer(checks('9.9.9')).prepare(ctx));
    expect(cacheDirOf(run.args)).toBe(named);
    expect(run.warnings).toBeUndefined();
    expect(run.version).toBe('checks 2.3.0');
  });

  it('ignores a named directory inside the repository', async () => {
    const { root, ctx } = setup();
    const inside = path.join(root, 'checks');
    writeTree(inside, { 'policy/content/.keep': '' });
    const dflt = checks('2.3.0');
    const run = runOf(
      await createTrivyIacAnalyzer(dflt).prepare({
        ...ctx,
        env: { QUALOR_TRIVY_CHECKS_DIR: inside },
      }),
    );
    expect(cacheDirOf(run.args)).toBe(dflt);
  });

  it('ignores a relative name', async () => {
    const dflt = checks();
    const { ctx } = setup({ env: { QUALOR_TRIVY_CHECKS_DIR: 'checks' } });
    const run = runOf(await createTrivyIacAnalyzer(dflt).prepare(ctx));
    expect(cacheDirOf(run.args)).toBe(dflt);
  });

  it('falls back to an empty directory in workDir, with the warning, when policy/content is missing', async () => {
    const { ctx } = setup();
    const run = runOf(await createTrivyIacAnalyzer(tmp()).prepare(ctx));
    expect(path.dirname(cacheDirOf(run.args) ?? '')).toBe(ctx.workDir);
    expect(run.warnings).toEqual([
      { code: 'IAC_CHECKS_EMBEDDED', message: IAC_CHECKS_EMBEDDED_MESSAGE, count: 1 },
    ]);
    expect(IAC_CHECKS_EMBEDDED_MESSAGE).toBe(
      "Trivy used its built-in checks (the scanner image's pinned checks were not found); findings can differ from the scanner image.",
    );
    expect(run.version).toBe('embedded checks');
  });

  it('versions the checks from the version file', async () => {
    const { ctx } = setup();
    const known = runOf(await createTrivyIacAnalyzer(checks('2.3.0\n')).prepare(ctx));
    expect(known.version).toBe('checks 2.3.0');
    const unknown = runOf(await createTrivyIacAnalyzer(checks()).prepare(ctx));
    expect(unknown.version).toBe('checks unknown');
    expect(unknown.warnings).toBeUndefined();
  });
});

/** The checks bundle the real tests use: the CI's, else the scanner image's. */
const CHECKS = process.env['QUALOR_TRIVY_CHECKS_DIR'] ?? DEFAULT_IAC_CHECKS_DIR;
const checksInstalled = existsSync(path.join(CHECKS, 'policy', 'content'));

/** Runs the real adapter over `root` the way `qualor scan` does and normalises its findings. */
async function scanTree(root: string) {
  const config = parseConfig({ version: 1 });
  const files = discoverFiles({ root, config, warnings: new Warnings(), log: silentLogger });
  const started = Date.now();
  const [capture] = await runAnalyzers([trivyIacAnalyzer], {
    root,
    config,
    files,
    log: silentLogger,
    env: { ...process.env, QUALOR_TRIVY_CHECKS_DIR: CHECKS },
  });
  const seconds = (Date.now() - started) / 1000;
  if (capture === undefined) throw new Error('no capture');
  const out = normalizeCaptures([capture], {
    repoRoot: root,
    readLines: fileLines(root),
    knownPaths: new Set(files.map((f) => f.path)),
    log: silentLogger,
  });
  return { capture, out, keys: findingKeys(out.findings), seconds };
}

// The filtered trivy-checks bundle comes with the scanner image (install.sh); where it is not
// installed these skip, and QUALOR_REQUIRE_ANALYZERS=1 makes them run, and fail, without it.
describeWithTools(['trivy'])('Trivy IaC on real trees (real Trivy, offline)', () => {
  const when = describe.runIf(REQUIRE_ANALYZERS || checksInstalled) as typeof describe;

  when('with the pinned checks', () => {
    it('needs the checks bundle', () => {
      expect(checksInstalled).toBe(true);
    });

    it(
      'scans the iac-basic fixture, with modules that cannot be fetched, in under 30 s',
      { timeout: 120_000 },
      async () => {
        const root = tmp();
        cpSync(path.join(FIXTURES_DIR, 'iac-basic'), root, { recursive: true });
        const { capture, out, keys, seconds } = await scanTree(root);
        expect(capture.status, capture.reason ?? '').toBe('ok');
        expect(out.engines[0]?.version).toBe('checks 2.3.0');
        expect(out.warnings).toEqual([]);
        for (const file of [
          'terraform/main.tf',
          'cloudformation/bucket.yaml',
          'k8s/deployment.yaml',
          'helm/app/templates/deployment.yaml',
          'docker/Dockerfile',
          'arm/storage.json',
        ]) {
          expect(
            keys.some((k) => k.includes(` ${file}:`)),
            file,
          ).toBe(true);
        }
        expect(keys.some((k) => k.includes(':KCV-'))).toBe(false);
        console.info(`iac-basic: ${keys.length} findings in ${seconds.toFixed(1)} s`);
        expect(seconds).toBeLessThan(30);
      },
    );

    it(
      'ends ok with no finding and no warning on a tree of JSON and YAML without infrastructure',
      { timeout: 120_000 },
      async () => {
        const root = tmp();
        const files: Record<string, string> = {};
        for (let i = 0; i < 200; i++) {
          files[`packages/p${i}/package.json`] =
            `{ "name": "p${i}", "version": "1.0.0", "dependencies": { "left-pad": "^1.3.0" } }\n`;
        }
        for (let i = 0; i < 50; i++)
          files[`config/c${i}.yaml`] = `name: c${i}\nitems:\n  - a\n  - b\n`;
        writeTree(root, files);
        const { capture, out, keys, seconds } = await scanTree(root);
        expect(capture.status, capture.reason ?? '').toBe('ok');
        expect(keys).toEqual([]);
        expect(out.warnings).toEqual([]);
        console.info(`json-only tree: ${seconds.toFixed(1)} s`);
      },
    );

    it('never reads a trivy.yaml of the repository', { timeout: 120_000 }, async () => {
      const plain = tmp();
      cpSync(path.join(FIXTURES_DIR, 'iac-basic'), plain, { recursive: true });
      const before = await scanTree(plain);
      const root = tmp();
      cpSync(path.join(FIXTURES_DIR, 'iac-basic'), root, { recursive: true });
      // Read from the working directory, this would keep only the critical findings.
      writeFileSync(
        path.join(root, 'trivy.yaml'),
        'severity:\n  - CRITICAL\nscan:\n  skip-dirs:\n    - terraform\n',
      );
      const after = await scanTree(root);
      expect(after.capture.status, after.capture.reason ?? '').toBe('ok');
      expect(before.keys.length).toBeGreaterThan(0);
      expect(after.keys.filter((k) => !k.includes(' trivy.yaml:'))).toEqual(before.keys);
    });

    it(
      'honours a .trivyignore that mixes vulnerability and check ids, and an expired entry',
      { timeout: 120_000 },
      async () => {
        const plain = tmp();
        cpSync(path.join(FIXTURES_DIR, 'iac-basic'), plain, { recursive: true });
        const before = await scanTree(plain);
        expect(before.keys.some((k) => k.includes(':AWS-0086 '))).toBe(true);
        expect(before.keys.some((k) => k.includes(':KSV-0001 '))).toBe(true);

        const root = tmp();
        cpSync(path.join(FIXTURES_DIR, 'iac-basic'), root, { recursive: true });
        writeFileSync(
          path.join(root, '.trivyignore'),
          'CVE-2024-0001\nAVD-AWS-0086\nKSV-0001 exp:2000-01-01\n',
        );
        const after = await scanTree(root);
        expect(after.capture.status, after.capture.reason ?? '').toBe('ok');
        expect(after.keys.some((k) => k.includes(':AWS-0086 '))).toBe(false);
        // The KSV-0001 entry expired in 2000: its findings stay.
        const ksv = (keys: string[]) => keys.filter((k) => k.includes(':KSV-0001 '));
        expect(ksv(after.keys)).toEqual(ksv(before.keys));
        expect(ksv(after.keys).length).toBeGreaterThan(0);
      },
    );
  });
});
