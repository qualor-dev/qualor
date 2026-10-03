import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { gunzipSync, gzipSync } from 'node:zlib';
import { parse as parseYaml, type Tags } from 'yaml';
import { describe, expect, it } from 'vitest';
import { finalStage } from './deploy/debian-sources';
import { DEPLOY_LABEL } from './deploy/workspace';

/** GitLab's `!reference [job, key]` tag, kept as { reference: [...] } so it can be asserted on. */
const gitlabTags: Tags = [
  {
    tag: '!reference',
    collection: 'seq',
    default: false,
    resolve: (seq) => ({ reference: seq.toJSON() as unknown }),
  },
];
const parse = (src: string): unknown => parseYaml(src, { customTags: gitlabTags });

const REQUIRED = [
  'lint',
  'typecheck',
  'test',
  'audit',
  'fixtures',
  'cli-binary',
  'ui-e2e',
  'dogfood',
  'helm',
];

/** A GitHub Actions `uses:` pinned to a full commit SHA (the tag goes in a comment). */
const PINNED = /^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/;

interface Workflow {
  on: Record<string, unknown> & { schedule?: { cron: string }[] };
  permissions?: Record<string, string>;
  jobs: Record<
    string,
    {
      'timeout-minutes'?: number;
      permissions?: Record<string, string>;
      steps: {
        id?: string;
        uses?: string;
        run?: string;
        if?: string;
        env?: Record<string, string>;
        with?: unknown;
      }[];
    }
  >;
}

function workflowUses(wf: Workflow): string[] {
  return Object.values(wf.jobs).flatMap((j) =>
    j.steps.flatMap((s) => (s.uses === undefined ? [] : [s.uses])),
  );
}

describe('CI definitions', () => {
  it('GitLab CI defines every required job and runs on MRs and the default branch', () => {
    const ci = parse(readFileSync('.gitlab-ci.yml', 'utf8')) as Record<string, unknown>;
    for (const job of REQUIRED) expect(ci, job).toHaveProperty(job);
    expect(JSON.stringify(ci['workflow'])).toContain('merge_request_event');
  });

  it('GitHub Actions defines every required job for pull_request and push to main', () => {
    const wf = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as {
      on: Record<string, unknown>;
      jobs: Record<string, unknown>;
    };
    for (const job of REQUIRED) expect(wf.jobs, job).toHaveProperty(job);
    expect(wf.on).toHaveProperty('pull_request');
    expect(wf.on).toHaveProperty('push');
  });

  it('pins every GitHub action of every workflow to a full commit SHA', () => {
    const files = readdirSync('.github/workflows').filter((f) => /\.ya?ml$/.test(f));
    expect(files).toEqual(expect.arrayContaining(['ci.yml', 'nightly.yml', 'release.yml']));
    for (const f of files) {
      const wf = parse(readFileSync(`.github/workflows/${f}`, 'utf8')) as Workflow;
      const uses = workflowUses(wf);
      expect(uses.length, f).toBeGreaterThan(0);
      for (const u of uses) expect(u, `${f}: ${u}`).toMatch(PINNED);
    }
  });
});

describe('web UI checks (plan 1F)', () => {
  it('runs the UI unit tests with the coverage run and checks the extracted messages in both CIs', () => {
    const gitlab = parse(readFileSync('.gitlab-ci.yml', 'utf8')) as Record<
      string,
      { script?: string[] }
    >;
    const github = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as Workflow;
    const githubRuns = (job: string) => (github.jobs[job]?.steps ?? []).map((s) => s.run);
    expect(gitlab['test']?.script).toContain('pnpm test:coverage');
    expect(githubRuns('test')).toContain('pnpm test:coverage');
    for (const command of [
      'pnpm --filter @qualor/ui i18n:extract',
      'git diff --exit-code -- ui/src/locale',
    ]) {
      expect(gitlab['lint']?.script, command).toContain(command);
      expect(githubRuns('lint'), command).toContain(command);
    }
    const root = JSON.parse(readFileSync('package.json', 'utf8')) as {
      scripts: Record<string, string>;
    };
    expect(root.scripts['test:coverage']).toBe(
      'vitest run --coverage && pnpm --filter @qualor/ui test',
    );
  });
});

describe('UI end-to-end job (plan 1F)', () => {
  it('runs Playwright with the browser build its pinned version ships, in both CIs', () => {
    const ui = JSON.parse(readFileSync('ui/package.json', 'utf8')) as {
      devDependencies: Record<string, string>;
    };
    const playwright = ui.devDependencies['@playwright/test'];
    expect(playwright).toMatch(/^\d+\.\d+\.\d+$/);
    const gitlab = parse(readFileSync('.gitlab-ci.yml', 'utf8')) as Record<
      string,
      { image?: string; script?: string[]; variables?: Record<string, string> }
    >;
    expect(gitlab['ui-e2e']?.image).toBe(`mcr.microsoft.com/playwright:v${playwright}-noble`);
    expect(gitlab['ui-e2e']?.script).toEqual(['pnpm ui:e2e', 'pnpm ui:screenshots']);
    expect(gitlab['ui-e2e']?.variables?.['QUALOR_TEST_DATABASE_URL']).toMatch(/^postgres:/);
    const github = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as Workflow;
    const runs = (github.jobs['ui-e2e']?.steps ?? []).map((s) => s.run);
    expect(runs).toContain('pnpm --filter @qualor/ui exec playwright install --with-deps chromium');
    expect(runs).toContain('pnpm ui:e2e');
    expect(runs).toContain('pnpm ui:screenshots');
  });

  it('runs the job on Node 22, like every other job (the Playwright image ships another Node)', () => {
    const gitlab = parse(readFileSync('.gitlab-ci.yml', 'utf8')) as Record<
      string,
      { before_script?: unknown[]; variables?: Record<string, string> }
    >;
    const job = gitlab['ui-e2e'];
    expect(job?.variables?.['NODE_VERSION']).toMatch(/^22\.\d+\.\d+$/);
    expect(job?.variables?.['NODE_SHA256']).toMatch(/^[0-9a-f]{64}$/);
    expect(job?.before_script).toContain(
      'echo "${NODE_SHA256}  /tmp/node.tar.gz" | sha256sum -c -',
    );
    expect(job?.before_script).toContain('test "$(node -v)" = "v${NODE_VERSION}"');
    // The install comes before, and does not replace, the default before_script (pnpm install).
    expect(job?.before_script?.at(-1)).toEqual({ reference: ['default', 'before_script'] });
    const github = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as Workflow;
    const setupNode = github.jobs['ui-e2e']?.steps.find(
      (s) => s.uses?.startsWith('actions/setup-node@') === true,
    );
    expect(setupNode?.with).toMatchObject({ 'node-version': 22 });
  });
});

describe('nightly benchmark (CLI step 14)', () => {
  it('runs pnpm bench with the compiled binary on a schedule in both CIs', () => {
    const gitlab = parse(readFileSync('.gitlab-ci.yml', 'utf8')) as Record<string, unknown> & {
      benchmark?: { rules?: { if?: string }[]; script?: string[] };
    };
    expect(JSON.stringify(gitlab['workflow'])).toContain('schedule');
    expect(gitlab.benchmark?.rules?.[0]?.if).toBe('$CI_PIPELINE_SOURCE == "schedule"');
    expect(gitlab.benchmark?.script).toContain('npm install -g bun@1.3.13');
    expect(gitlab.benchmark?.script).toContain('QUALOR_BIN=cli/dist/qualor-linux-x64 pnpm bench');
    const nightly = parse(readFileSync('.github/workflows/nightly.yml', 'utf8')) as Workflow;
    expect(nightly.on.schedule?.[0]?.cron).toBeDefined();
    expect(nightly.permissions).toEqual({ contents: 'read' });
    // A hung run must not hold a runner for GitHub's six-hour default.
    expect(nightly.jobs['benchmark']?.['timeout-minutes']).toBe(30);
    const steps = nightly.jobs['benchmark']?.steps ?? [];
    const bench = steps.find((s) => s.run === 'pnpm bench');
    expect(bench?.env?.['QUALOR_BIN']).toBe('cli/dist/qualor-linux-x64');
    expect(steps.some((s) => s.run === 'pnpm --filter @qualor/cli build linux-x64')).toBe(true);
    // Every action pinned to a full commit SHA; bun pinned to the build version (plan 1B C2).
    const uses = workflowUses(nightly);
    expect(uses.length).toBeGreaterThan(0);
    for (const u of uses) expect(u, u).toMatch(PINNED);
    const bun = steps.find((s) => s.uses?.startsWith('oven-sh/setup-bun@') === true);
    expect(bun?.with).toEqual({ 'bun-version': '1.3.13' });
  });
});

describe('CLI end to end (plan 1D Task 10)', () => {
  it('runs the compiled binary against a real server in both cli-binary jobs', () => {
    const e2e = 'pnpm exec vitest run --project db server/test/cli-e2e.db.test.ts';
    const gitlab = parse(readFileSync('.gitlab-ci.yml', 'utf8')) as Record<
      string,
      { script?: string[]; variables?: Record<string, string> }
    >;
    expect(gitlab['cli-binary']?.script).toContain(`QUALOR_BIN=cli/dist/qualor-linux-x64 ${e2e}`);
    expect(gitlab['cli-binary']?.variables?.['QUALOR_TEST_DATABASE_URL']).toMatch(/^postgres:/);
    const github = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as {
      jobs: Record<string, { steps: { run?: string; env?: Record<string, string> }[] }>;
    };
    const step = github.jobs['cli-binary']?.steps.find((s) => s.run === e2e);
    expect(step?.env?.['QUALOR_BIN']).toBe('cli/dist/qualor-linux-x64');
  });
});

describe('analyzer toolchain (plan 1D)', () => {
  const script = readFileSync('tools/analyzers/install.sh', 'utf8');

  it('pins every tool to an exact version and a SHA-256', () => {
    for (const tool of [
      'PMD',
      'SPOTBUGS',
      'FINDSECBUGS',
      'OPENGREP',
      'GITLEAKS',
      'TRIVY',
      'RUFF',
      'SWIFTLINT',
      'PHPSTAN',
    ]) {
      expect(script, tool).toMatch(new RegExp(`^${tool}_VERSION=\\d+\\.\\d+\\.\\d+$`, 'm'));
      expect(script, tool).toMatch(new RegExp(`^${tool}_SHA256(_X64)?=[0-9a-f]{64}$`, 'm'));
    }
    expect(script).toContain('sha256sum -c');
    expect(script).toContain("--proto '=https' --proto-redir '=https' --tlsv1.2");
    expect(script).not.toMatch(/latest/);
  });

  it('pins detekt by version and SHA-256 and installs its jar only after the check (plan 8E)', () => {
    expect(script).toMatch(/^DETEKT_VERSION=\d+\.\d+\.\d+$/m);
    expect(script).toMatch(/^DETEKT_SHA256=[0-9a-f]{64}$/m);
    expect(script).toContain(
      'https://repo1.maven.org/maven2/io/gitlab/arturbosch/detekt/detekt-cli/$DETEKT_VERSION/detekt-cli-$DETEKT_VERSION-all.jar',
    );
    const fetched = script.indexOf('"$DETEKT_SHA256" detekt.jar');
    expect(fetched).toBeGreaterThan(-1);
    expect(fetched).toBeLessThan(script.indexOf('"$PREFIX/lib/detekt/detekt-cli.jar"'));
  });

  it('pins FindSecBugs and installs it into the SpotBugs home only after the check (plan 6A)', () => {
    expect(script).toMatch(/^FINDSECBUGS_VERSION=\d+\.\d+\.\d+$/m);
    expect(script).toMatch(/^FINDSECBUGS_SHA256=[0-9a-f]{64}$/m);
    const fetchLine =
      'fetch "https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/$FINDSECBUGS_VERSION/findsecbugs-plugin-$FINDSECBUGS_VERSION.jar" "$FINDSECBUGS_SHA256" findsecbugs.jar';
    const installLine =
      'install -m 0644 "$TMP/findsecbugs.jar" "$PREFIX/lib/spotbugs-$SPOTBUGS_VERSION/plugin/findsecbugs-plugin-$FINDSECBUGS_VERSION.jar"';
    expect(script).toContain(fetchLine);
    expect(script).toContain(installLine);
    // Checked before it is installed, and installed after SpotBugs is unpacked: the rm -rf of the
    // SpotBugs home would delete it otherwise.
    const rm = script.indexOf('rm -rf "$PREFIX/lib/spotbugs-$SPOTBUGS_VERSION"');
    const unpack = script.indexOf('tar -xzf "$TMP/spotbugs.tgz"');
    expect(rm).toBeGreaterThan(-1);
    expect(script.indexOf(fetchLine)).toBeLessThan(script.indexOf(installLine));
    expect(rm).toBeLessThan(unpack);
    expect(unpack).toBeLessThan(script.indexOf(installLine));
    // The CLI's table and the image's jar must agree (packages/shared/src/rules/findsecbugs.ts).
    const pinned = /^FINDSECBUGS_VERSION=(.+)$/m.exec(script)?.[1];
    expect(readFileSync('packages/shared/src/rules/findsecbugs.ts', 'utf8')).toContain(
      `export const FINDSECBUGS_VERSION = '${pinned}';`,
    );
    const table = JSON.parse(readFileSync('packages/shared/rules/findsecbugs.json', 'utf8')) as {
      version: string;
    };
    expect(table.version).toBe(pinned);
  });

  it("pins Trivy's vulnerability database by the digest of its layer, checked before it is unpacked (plan 2B)", () => {
    expect(script).toMatch(/^TRIVY_SHA256_ARM64=[0-9a-f]{64}$/m);
    expect(script).toMatch(/^TRIVY_DB_DIGEST=sha256:[0-9a-f]{64}$/m);
    expect(script).toMatch(/^TRIVY_DB_CREATED=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/m);
    // Fetched by digest (never the moving tag `2`), https only, and checked with sha256sum.
    expect(script).toContain('https://ghcr.io/v2/aquasecurity/trivy-db/blobs/$TRIVY_DB_DIGEST');
    expect(script).toContain('"${TRIVY_DB_DIGEST#sha256:}  $TMP/trivy-db.tar.gz" | sha256sum -c -');
    expect(script).not.toMatch(/trivy-db\/manifests|--download-db-only/);
    expect(
      script.indexOf('sha256sum -c - >/dev/null || { echo "checksum mismatch: trivy-db'),
    ).toBeLessThan(script.indexOf('tar -xzf "$TMP/trivy-db.tar.gz"'));
    // Only the two database files are unpacked, readable by the image's user.
    expect(script).toContain('--no-same-owner -C "$PREFIX/share/trivy/db" trivy.db metadata.json');
    const root = JSON.parse(readFileSync('package.json', 'utf8')) as {
      scripts: Record<string, string>;
    };
    expect(root.scripts['trivy-db:pin']).toBe('tsx tools/analyzers/trivy-db-pin.ts');
  });

  it('pins Ruff per architecture and its source archive, and installs only the binary (plan 8C)', () => {
    expect(script).toMatch(/^RUFF_VERSION=\d+\.\d+\.\d+$/m);
    expect(script).toMatch(/^RUFF_SHA256_X64=[0-9a-f]{64}$/m);
    expect(script).toMatch(/^RUFF_SHA256_ARM64=[0-9a-f]{64}$/m);
    expect(script).toMatch(/^RUFF_SOURCE_SHA256=[0-9a-f]{64}$/m);
    expect(script).toContain(
      '"$GH/astral-sh/ruff/releases/download/$RUFF_VERSION/ruff-$RF_ARCH-unknown-linux-gnu.tar.gz" "$RF_SHA" ruff.tgz',
    );
    expect(script).toContain('install -m 0755 "$TMP/ruff" "$PREFIX/bin/ruff"');
    // The CLI's pin and the image's must agree (RUFF_VERSION in packages/shared/src/rules/ruff.ts).
    const shared = readFileSync('packages/shared/src/rules/ruff.ts', 'utf8');
    const pinned = /^RUFF_VERSION=(.+)$/m.exec(script)?.[1];
    expect(shared).toContain(`export const RUFF_VERSION = '${pinned}';`);
  });

  it('pins SwiftLint per architecture and installs only its static binary, checked before unzip (plan 8F)', () => {
    expect(script).toMatch(/^SWIFTLINT_VERSION=\d+\.\d+\.\d+$/m);
    expect(script).toMatch(/^SWIFTLINT_SHA256_X64=[0-9a-f]{64}$/m);
    expect(script).toMatch(/^SWIFTLINT_SHA256_ARM64=[0-9a-f]{64}$/m);
    const fetchLine =
      'fetch "$GH/realm/SwiftLint/releases/download/$SWIFTLINT_VERSION/swiftlint_linux_$SL_ARCH.zip" "$SL_SHA" swiftlint.zip';
    expect(script).toContain(fetchLine);
    // fetch() checks the SHA-256 before anything is unpacked; only swiftlint-static is extracted.
    expect(script.indexOf(fetchLine)).toBeLessThan(
      script.indexOf('unzip -q -o "$TMP/swiftlint.zip" swiftlint-static -d "$TMP"'),
    );
    expect(script).toContain('install -m 0755 "$TMP/swiftlint-static" "$PREFIX/bin/swiftlint"');
    // The zip's dynamically linked `swiftlint` is never unpacked or installed.
    expect(script).not.toContain('"$TMP/swiftlint"');
    // The CLI's pin and the image's must agree (packages/shared/src/rules/swiftlint.ts, Task 6).
    const pinned = /^SWIFTLINT_VERSION=(.+)$/m.exec(script)?.[1];
    const shared = readFileSync('packages/shared/src/rules/swiftlint.ts', 'utf8');
    expect(shared).toContain(`export const SWIFTLINT_VERSION = '${pinned}';`);
  });

  it('pins PHPStan by version and SHA-256 and installs only the phar, nothing next to it (plan 9A)', () => {
    expect(script).toMatch(/^PHPSTAN_VERSION=\d+\.\d+\.\d+$/m);
    expect(script).toMatch(/^PHPSTAN_SHA256=[0-9a-f]{64}$/m);
    // The identifiers table of this version (tools/analyzers/phpstan-identifiers.mjs reads it; ruling A9-10).
    expect(script).toMatch(
      /^PHPSTAN_VERSION=.+\nPHPSTAN_SHA256=.+\nPHPSTAN_IDENTIFIERS_SHA256=[0-9a-f]{64}$/m,
    );
    expect(script).toContain(
      'fetch "$GH/phpstan/phpstan/releases/download/$PHPSTAN_VERSION/phpstan.phar" "$PHPSTAN_SHA256" phpstan.phar',
    );
    expect(script).toContain(
      'install -m 0644 "$TMP/phpstan.phar" "$PREFIX/lib/phpstan/phpstan.phar"',
    );
    // PHPStan loads a native extension found in <phar dir>/turbo-ext/ (fact P4): never install one.
    expect(script).not.toMatch(/turbo-ext|phpstan_turbo/);
    // The CLI's pin and the image's must agree (PHPSTAN_VERSION in packages/shared/src/rules/phpstan.ts).
    const shared = readFileSync('packages/shared/src/rules/phpstan.ts', 'utf8');
    const pinned = /^PHPSTAN_VERSION=(.+)$/m.exec(script)?.[1];
    expect(shared).toContain(`export const PHPSTAN_VERSION = '${pinned}';`);
  });

  it('gives PHPStan a php in every job that requires the analyzers, and in both images (plan 9A)', () => {
    // The scanner image's final stage is the one pin of Debian's PHP (php<major.minor>-cli); every
    // other place that installs PHP must name the same version (ruling A9-10: no '8.2' literal here).
    const phpCli = finalStage(readFileSync('deploy/scanner/Dockerfile', 'utf8')).aptPackages.filter(
      (p) => /^php\d+\.\d+-cli$/.test(p),
    );
    expect(phpCli).toHaveLength(1);
    const phpMinor = /^php(\d+\.\d+)-cli$/.exec(phpCli[0]!)![1]!;
    const aptLine = new RegExp(
      `--no-install-recommends [^\\n]*\\bphp${phpMinor.replace('.', '\\.')}-cli\\b`,
    );
    const github = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as Workflow;
    for (const job of ['test', 'fixtures', 'cli-binary']) {
      const steps = github.jobs[job]?.steps ?? [];
      const setup = steps.find((s) => s.uses?.startsWith('shivammathur/setup-php@') === true);
      expect(setup?.uses, job).toMatch(PINNED);
      const options = setup?.with as Record<string, unknown> | undefined;
      expect(String(options?.['php-version']), job).toBe(phpMinor);
      expect(options?.['tools'], job).toBe('none');
      // php must be there before the tests that require it run.
      const require = steps.findIndex((s) => s.env?.['QUALOR_REQUIRE_ANALYZERS'] === '1');
      expect(steps.indexOf(setup!), job).toBeLessThan(require);
    }
    const gitlab = parse(readFileSync('.gitlab-ci.yml', 'utf8')) as Record<
      string,
      { before_script?: unknown[] } | undefined
    >;
    const analyzersApt = String(gitlab['.analyzers']?.before_script?.[0]);
    expect(analyzersApt).toMatch(/apt-get install /);
    expect(analyzersApt).toMatch(aptLine);
    expect(readFileSync('tools/analyzers/Dockerfile', 'utf8')).toMatch(aptLine);
  });

  it('installs the toolchain (Ruff included) in every job that requires the analyzers (plan 8C)', () => {
    const github = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as Workflow;
    for (const [name, job] of Object.entries(github.jobs)) {
      if (!job.steps.some((s) => s.env?.['QUALOR_REQUIRE_ANALYZERS'] === '1')) continue;
      expect(
        job.steps.some((s) => s.run?.endsWith('sh tools/analyzers/install.sh') === true),
        name,
      ).toBe(true);
    }
    const gitlab = parse(readFileSync('.gitlab-ci.yml', 'utf8')) as Record<
      string,
      | { extends?: string; variables?: Record<string, string>; before_script?: unknown[] }
      | undefined
    >;
    const template = gitlab['.analyzers'];
    expect(template?.before_script).toContain('sh tools/analyzers/install.sh');
    expect(template?.variables?.['QUALOR_REQUIRE_ANALYZERS']).toBe('1');
    // A job's variables as GitLab resolves them: the template's under its own (`extends`).
    const requiring: string[] = [];
    for (const [name, job] of Object.entries(gitlab)) {
      if (name.startsWith('.') || job === undefined || typeof job !== 'object') continue;
      const inherited = job.extends === '.analyzers' ? template?.variables : undefined;
      const variables = { ...inherited, ...job.variables };
      if (variables['QUALOR_REQUIRE_ANALYZERS'] !== '1') continue;
      requiring.push(name);
      // Requiring the analyzers without the template would run without install.sh.
      expect(job.extends, name).toBe('.analyzers');
      expect(job.before_script, `${name} must not replace the template's before_script`).toBe(
        undefined,
      );
    }
    expect(requiring).toEqual(expect.arrayContaining(['test', 'fixtures', 'cli-binary']));
    expect(script.indexOf('"$PREFIX/bin/ruff"')).toBeGreaterThan(0);
    expect(script.indexOf('"$PREFIX/bin/swiftlint"')).toBeGreaterThan(0);
  });

  it('installs the toolchain and requires it in the test, fixtures and cli-binary jobs', () => {
    const gitlab = parse(readFileSync('.gitlab-ci.yml', 'utf8')) as Record<
      string,
      { extends?: string; variables?: Record<string, string>; before_script?: unknown[] }
    >;
    expect(gitlab['.analyzers']?.before_script).toContain('sh tools/analyzers/install.sh');
    expect(gitlab['.analyzers']?.variables?.['QUALOR_REQUIRE_ANALYZERS']).toBe('1');
    // The template extends, not replaces, the default before_script (corepack, pnpm install).
    expect(gitlab['.analyzers']?.before_script).toContainEqual({
      reference: ['default', 'before_script'],
    });
    expect(gitlab['default']?.before_script).toContain('pnpm install --frozen-lockfile');
    for (const job of ['test', 'fixtures', 'cli-binary']) {
      expect(gitlab[job]?.extends, job).toBe('.analyzers');
    }
    const github = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as {
      jobs: Record<
        string,
        {
          steps: {
            uses?: string;
            run?: string;
            env?: Record<string, string>;
            with?: Record<string, unknown>;
          }[];
        }
      >;
    };
    for (const job of ['test', 'fixtures', 'cli-binary']) {
      const steps = github.jobs[job]?.steps ?? [];
      // An exact JDK 17 (fix round 2), not whatever `17` resolves to on the day.
      const java = steps.find((s) => s.uses?.startsWith('actions/setup-java@') === true);
      expect(String(java?.with?.['java-version']), job).toMatch(/^17\.\d+\.\d+\+\d+$/);
      expect(
        steps.some(
          (s) =>
            s.run === 'sudo --preserve-env=QUALOR_DOWNLOAD_CACHE sh tools/analyzers/install.sh',
        ),
        job,
      ).toBe(true);
      expect(
        steps.some((s) => s.env?.['QUALOR_REQUIRE_ANALYZERS'] === '1'),
        job,
      ).toBe(true);
    }
  });
});

describe('install-dotnet.sh (plan 2D, ruling D11)', () => {
  const script = readFileSync('tools/analyzers/install-dotnet.sh', 'utf8');

  it('pins both SDKs per architecture by SHA-512 and Roslynator by SHA-256', () => {
    expect(script).toMatch(/^DOTNET8_VERSION=8\.0\.\d+$/m);
    expect(script).toMatch(/^DOTNET10_VERSION=10\.0\.\d+$/m);
    for (const v of [
      'DOTNET8_SHA512_X64',
      'DOTNET8_SHA512_ARM64',
      'DOTNET10_SHA512_X64',
      'DOTNET10_SHA512_ARM64',
    ]) {
      expect(script).toMatch(new RegExp(`^${v}=[0-9a-f]{128}$`, 'm'));
    }
    expect(script).toMatch(/^ROSLYNATOR_VERSION=\d+\.\d+\.\d+$/m);
    expect(script).toMatch(/^ROSLYNATOR_SHA256=[0-9a-f]{64}$/m);
    expect(script).toMatch(/^SONARANALYZER_VERSION=9\.32\.0\.97167$/m);
    expect(script).toMatch(
      /^SONARANALYZER_SHA256=17c7fd6230597a4c08a30226e8b29f8e8c2a982ca12d4b9315021c8c41150cf8$/m,
    );
  });

  it('checks every download before unpacking it, over https only', () => {
    expect(script).toContain("--proto '=https'");
    expect(script.indexOf('sha512sum -c -')).toBeLessThan(script.indexOf('tar -xzf'));
    // 'unzip' alone would match the apt package name installed earlier in the script; the actual
    // unpack invocation is 'unzip -q'.
    expect(script.indexOf('sha256sum -c -')).toBeLessThan(script.indexOf('unzip -q'));
  });

  it('runs in every job that requires the analyzers, alongside install.sh', () => {
    const github = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as Workflow;
    for (const [name, job] of Object.entries(github.jobs)) {
      const requiresAnalyzers = job.steps.some((s) => s.env?.['QUALOR_REQUIRE_ANALYZERS'] === '1');
      if (!requiresAnalyzers) continue;
      expect(
        job.steps.some((s) => s.run?.endsWith('sh tools/analyzers/install-dotnet.sh') === true),
        name,
      ).toBe(true);
    }
  });
});

describe('install-sonarjs.sh (plan 8A/8B, controller ruling 14)', () => {
  const script = readFileSync('tools/analyzers/install-sonarjs.sh', 'utf8');

  it('reads the SONARJS_* pins from install.sh instead of duplicating them, and hardcodes no "latest"', () => {
    expect(script).toContain('grep -E \'^SONARJS_[A-Z0-9_]+=\' "$INSTALL_SH"');
    expect(script).not.toMatch(/^SONARJS_VERSION=/m);
    expect(script).not.toMatch(/^SONARJS_COMMIT=/m);
    expect(script).not.toMatch(/^SONARJS_SOURCE_SHA256=/m);
    expect(script).not.toMatch(/latest/);
  });

  it('checks the SonarJS source archive against its pinned SHA-256 before it is unpacked, over https only', () => {
    expect(script).toContain("--proto '=https' --proto-redir '=https' --tlsv1.2");
    expect(script.indexOf('sha256sum -c -')).toBeLessThan(script.indexOf('tar -xzf'));
    // Only the rule metadata directory is extracted, like the recipe it replaced.
    expect(script).toContain(
      "'*/sonar-plugin/javascript-checks/src/main/resources/org/sonar/l10n/javascript/rules/javascript/S*.json'",
    );
  });

  it('checks the installed plugin version against the pin and uses the ambient npm >= 10, never a fetched one', () => {
    expect(script).toContain('$SONARJS_VERSION');
    expect(script).toContain('[ "${npm_major:-0}" -ge 10 ]');
    expect(script).toContain('(cd "$DEST" && npm ci --omit=dev --ignore-scripts');
    expect(script).not.toMatch(/npx|npm@|NPM_FALLBACK/);
  });

  it('runs in every job that requires the analyzers, alongside install.sh and install-dotnet.sh (GitHub)', () => {
    const github = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as Workflow;
    for (const [name, job] of Object.entries(github.jobs)) {
      const requiresAnalyzers = job.steps.some((s) => s.env?.['QUALOR_REQUIRE_ANALYZERS'] === '1');
      if (!requiresAnalyzers) continue;
      expect(
        job.steps.some((s) => s.run?.endsWith('sh tools/analyzers/install-sonarjs.sh') === true),
        name,
      ).toBe(true);
      // install-sonarjs.sh runs unprivileged (actions/setup-node's node/npm stay on PATH; sudo's
      // secure_path would hide them), after root hands it just /opt/qualor/sonarjs.
      const install = job.steps.findIndex(
        (s) => s.run?.endsWith('sh tools/analyzers/install-sonarjs.sh') === true,
      );
      expect(job.steps[install - 1]?.run, name).toContain(
        'chown -R "$(id -u):$(id -g)" /opt/qualor/sonarjs',
      );
    }
  });

  it("runs in GitLab's shared .analyzers template, after install.sh and before every job's own before_script", () => {
    const gitlab = parse(readFileSync('.gitlab-ci.yml', 'utf8')) as Record<
      string,
      { before_script?: unknown[] }
    >;
    const before = gitlab['.analyzers']?.before_script ?? [];
    expect(before).toContain('sh tools/analyzers/install-sonarjs.sh');
    expect(before.indexOf('sh tools/analyzers/install.sh')).toBeLessThan(
      before.indexOf('sh tools/analyzers/install-sonarjs.sh'),
    );
  });

  it("runs the pass's own tests (run.test.ts) where it is installed and required", () => {
    // run.test.ts finds the pass in /opt/qualor/sonarjs and fails instead of skipping under
    // QUALOR_REQUIRE_ANALYZERS=1, so its security and licence tests run in both test jobs.
    const github = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as Workflow;
    const steps = github.jobs['test']?.steps ?? [];
    const install = steps.findIndex(
      (s) => s.run?.endsWith('sh tools/analyzers/install-sonarjs.sh') === true,
    );
    const tests = steps.findIndex((s) => s.run === 'pnpm test:coverage');
    expect(install).toBeGreaterThanOrEqual(0);
    expect(tests).toBeGreaterThan(install);
    expect(steps[tests]?.env?.['QUALOR_REQUIRE_ANALYZERS']).toBe('1');
    const gitlab = parse(readFileSync('.gitlab-ci.yml', 'utf8')) as Record<
      string,
      { extends?: string; script?: string[]; variables?: Record<string, string> }
    >;
    expect(gitlab['test']?.extends).toBe('.analyzers');
    expect(gitlab['test']?.script).toContain('pnpm test:coverage');
    expect(gitlab['test']?.variables?.['QUALOR_REQUIRE_ANALYZERS']).toBe('1');
  });
});

describe('install-weblint.sh (plan 8D)', () => {
  const script = readFileSync('tools/analyzers/install-weblint.sh', 'utf8');

  it('installs from the lockfile without scripts, with the ambient npm, and downloads nothing else', () => {
    expect(script).toContain('(cd "$DEST" && npm ci --omit=dev --ignore-scripts');
    expect(script).toContain('[ "${npm_major:-0}" -ge 10 ]');
    expect(script).not.toMatch(/npx|npm@|curl|wget|latest/);
  });

  it('copies only the runtime files, never the tests or dev scripts', () => {
    expect(script).toContain(
      'package.json package-lock.json bundled.mjs files.mjs stylelint.mjs htmlhint.mjs',
    );
    expect(script).not.toMatch(/run\.test\.ts|licences\.mjs/);
  });

  it('pins every dependency exactly and locks each package by sha512', () => {
    const pkg = JSON.parse(readFileSync('tools/analyzers/weblint/package.json', 'utf8')) as {
      dependencies: Record<string, string>;
    };
    for (const [name, version] of Object.entries(pkg.dependencies))
      expect(version, name).toMatch(/^\d+\.\d+\.\d+$/);
    const lock = JSON.parse(readFileSync('tools/analyzers/weblint/package-lock.json', 'utf8')) as {
      packages: Record<string, { integrity?: string }>;
    };
    for (const [where, entry] of Object.entries(lock.packages)) {
      if (where === '') continue;
      expect(entry.integrity, where).toMatch(/^sha512-/);
    }
  });

  it('runs in every GitHub job that requires the analyzers, unprivileged after a chown', () => {
    const github = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as Workflow;
    for (const [name, job] of Object.entries(github.jobs)) {
      if (!job.steps.some((s) => s.env?.['QUALOR_REQUIRE_ANALYZERS'] === '1')) continue;
      const install = job.steps.findIndex(
        (s) => s.run?.endsWith('sh tools/analyzers/install-weblint.sh') === true,
      );
      expect(install, name).toBeGreaterThan(0);
      expect(job.steps[install - 1]?.run, name).toContain(
        'chown -R "$(id -u):$(id -g)" /opt/qualor/weblint',
      );
      const uses = job.steps.findIndex((s) => s.env?.['QUALOR_REQUIRE_ANALYZERS'] === '1');
      expect(uses, name).toBeGreaterThan(install);
    }
  });

  it("runs in GitLab's shared .analyzers template after install.sh", () => {
    const gitlab = parse(readFileSync('.gitlab-ci.yml', 'utf8')) as Record<
      string,
      { before_script?: unknown[] }
    >;
    const before = gitlab['.analyzers']?.before_script ?? [];
    expect(before).toContain('sh tools/analyzers/install-weblint.sh');
    expect(before.indexOf('sh tools/analyzers/install.sh')).toBeLessThan(
      before.indexOf('sh tools/analyzers/install-weblint.sh'),
    );
  });

  it('is installed by both images', () => {
    for (const file of ['deploy/scanner/Dockerfile', 'tools/analyzers/Dockerfile'])
      expect(readFileSync(file, 'utf8'), file).toMatch(/sh \/tmp\/install-weblint\.sh/);
  });
});

describe('install-go.sh (plan 9C)', () => {
  const script = readFileSync('tools/analyzers/install-go.sh', 'utf8');
  const pin = (name: string) => new RegExp(`^${name}=(.+)$`, 'm').exec(script)?.[1];

  it('pins Go, staticcheck and gosec per architecture and checks each before it is unpacked', () => {
    for (const tool of ['GO', 'STATICCHECK', 'GOSEC']) {
      expect(pin(`${tool}_VERSION`), tool).toMatch(/^\d+\.\d+\.\d+$/);
      expect(pin(`${tool}_SHA256_X64`), tool).toMatch(/^[0-9a-f]{64}$/);
      expect(pin(`${tool}_SHA256_ARM64`), tool).toMatch(/^[0-9a-f]{64}$/);
    }
    for (const [fetchLine, unpack] of [
      [
        'fetch "https://go.dev/dl/go$GO_VERSION.linux-$GO_ARCH.tar.gz" "$GO_SHA" go.tgz',
        'tar -xzf "$TMP/go.tgz"',
      ],
      [
        'fetch "$GH/dominikh/go-tools/releases/download/$STATICCHECK_VERSION/staticcheck_linux_$GO_ARCH.tar.gz" "$SC_SHA" staticcheck.tgz',
        'tar -xzf "$TMP/staticcheck.tgz"',
      ],
      [
        'fetch "$GH/securego/gosec/releases/download/v$GOSEC_VERSION/gosec_${GOSEC_VERSION}_linux_$GO_ARCH.tar.gz" "$GS_SHA" gosec.tgz',
        'tar -xzf "$TMP/gosec.tgz"',
      ],
    ] as const) {
      expect(script).toContain(fetchLine);
      expect(script.indexOf(fetchLine)).toBeLessThan(script.indexOf(unpack));
    }
    expect(script).toContain('sha256sum -c -');
    expect(script).not.toMatch(/go (get|install|mod)|latest|npx|wget/);
  });

  it('agrees with the versions the CLI runs (packages/shared/src/rules/golang.ts)', () => {
    const shared = readFileSync('packages/shared/src/rules/golang.ts', 'utf8');
    expect(shared).toContain(`export const GO_VERSION = '${pin('GO_VERSION')}';`);
    expect(shared).toContain(`export const STATICCHECK_VERSION = '${pin('STATICCHECK_VERSION')}';`);
    expect(shared).toContain(`export const GOSEC_VERSION = '${pin('GOSEC_VERSION')}';`);
  });

  it('trims the Go distribution but keeps pkg/ and src/cmd, links go and gofmt, installs the runner', () => {
    expect(script).toContain('rm -rf api doc misc test lib/wasm');
    expect(script).not.toMatch(/rm -rf[^\n]*\b(pkg|src\/cmd)\b/);
    expect(script).toContain('ln -sf ../lib/go/bin/go "$PREFIX/bin/go"');
    expect(script).toContain('install -m 0644 "$SRC/run.mjs" "$PREFIX/go/run.mjs"');
  });

  it('runs in every GitHub job that requires the analyzers, with /opt/qualor/bin first on PATH', () => {
    const github = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as Workflow;
    for (const [name, job] of Object.entries(github.jobs)) {
      const uses = job.steps.findIndex((s) => s.env?.['QUALOR_REQUIRE_ANALYZERS'] === '1');
      if (uses < 0) continue;
      const install = job.steps.findIndex((s) => s.run === 'sudo sh tools/analyzers/install-go.sh');
      const onPath = job.steps.findIndex((s) => s.run === 'echo /opt/qualor/bin >> "$GITHUB_PATH"');
      expect(install, name).toBeGreaterThan(0);
      expect(onPath, name).toBeGreaterThan(install);
      expect(uses, name).toBeGreaterThan(onPath);
    }
  });

  it("runs in GitLab's shared .analyzers template after install.sh", () => {
    const gitlab = parse(readFileSync('.gitlab-ci.yml', 'utf8')) as Record<
      string,
      { before_script?: unknown[] }
    >;
    const before = gitlab['.analyzers']?.before_script ?? [];
    expect(before).toContain('sh tools/analyzers/install-go.sh');
    expect(before.indexOf('sh tools/analyzers/install.sh')).toBeLessThan(
      before.indexOf('sh tools/analyzers/install-go.sh'),
    );
  });

  it('is installed by both images', () => {
    for (const file of ['deploy/scanner/Dockerfile', 'tools/analyzers/Dockerfile'])
      expect(readFileSync(file, 'utf8'), file).toMatch(/sh \/tmp\/install-go\.sh/);
  });
});

describe('install-cppcheck.sh (plan 9D)', () => {
  const script = readFileSync('tools/analyzers/install-cppcheck.sh', 'utf8');

  it('pins cppcheck by version and the SHA-256 of its tag archive, checked before tar', () => {
    expect(script).toMatch(/^CPPCHECK_VERSION=\d+\.\d+\.\d+$/m);
    expect(script).toMatch(/^CPPCHECK_SHA256=[0-9a-f]{64}$/m);
    const check = 'echo "$CPPCHECK_SHA256  $TMP/cppcheck.tar.gz" | sha256sum -c -';
    expect(script).toContain(check);
    expect(script.indexOf(check)).toBeLessThan(script.indexOf('tar -xzf "$TMP/cppcheck.tar.gz"'));
    expect(script).toContain(
      '"https://github.com/cppcheck-opensource/cppcheck/archive/refs/tags/$CPPCHECK_VERSION.tar.gz"',
    );
    const pinned = /^CPPCHECK_VERSION=(.+)$/m.exec(script)?.[1];
    expect(readFileSync('packages/shared/src/rules/cfamily.ts', 'utf8')).toContain(
      `export const CPPCHECK_VERSION = '${pinned}';`,
    );
  });

  it('builds only the cppcheck target and installs no addon, rule or report script', () => {
    // The comments name what the script leaves out ("no addons", "`make install` would …"):
    // only its commands count here.
    const code = script
      .split('\n')
      .filter((l) => !l.trimStart().startsWith('#'))
      .join('\n');
    expect(code).toContain('MATCHCOMPILER=yes');
    expect(code).toMatch(/^make -C "\$TMP\/src" [^\n]* cppcheck >\/dev\/null$/m);
    expect(code).not.toMatch(/HAVE_RULES=yes|addons|htmlreport|make install|curl[^\n]*\| *sh/);
    expect(code).toContain('cp -R "$TMP/src/cfg" "$TMP/src/platforms" "$FILESDIR/"');
    // cppcheck prints `Cppcheck X.Y` for some .0 releases: the check compares major.minor, the
    // rule of cppcheckVersionSupported.
    expect(code).toContain(
      '"Cppcheck ${CPPCHECK_VERSION%.*}" | "Cppcheck ${CPPCHECK_VERSION%.*}."*)',
    );
  });

  it('runs in every GitHub job that requires the analyzers, before the tests', () => {
    const github = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as Workflow;
    for (const [name, job] of Object.entries(github.jobs)) {
      const uses = job.steps.findIndex((s) => s.env?.['QUALOR_REQUIRE_ANALYZERS'] === '1');
      if (uses === -1) continue;
      const install = job.steps.findIndex(
        (s) => s.run === 'sudo sh tools/analyzers/install-cppcheck.sh',
      );
      expect(install, name).toBeGreaterThan(0);
      expect(uses, name).toBeGreaterThan(install);
    }
  });

  it("runs in GitLab's shared .analyzers template, and in both images", () => {
    const gitlab = parse(readFileSync('.gitlab-ci.yml', 'utf8')) as Record<
      string,
      { before_script?: unknown[] }
    >;
    expect(gitlab['.analyzers']?.before_script ?? []).toContain(
      'sh tools/analyzers/install-cppcheck.sh',
    );
    for (const file of ['deploy/scanner/Dockerfile', 'tools/analyzers/Dockerfile']) {
      expect(readFileSync(file, 'utf8'), file).toMatch(/sh \/tmp\/install-cppcheck\.sh/);
    }
  });
});

describe('install-clang-tidy.sh (plan 9D, CI and the toolbox only)', () => {
  const script = readFileSync('tools/analyzers/install-clang-tidy.sh', 'utf8');

  it('pins the PyPI wheel per architecture, checked before unzip, and installs only the binary and its headers', () => {
    expect(script).toMatch(/^CLANG_TIDY_VERSION=\d+\.\d+\.\d+$/m);
    expect(script).toMatch(/^CLANG_TIDY_SHA256_X64=[0-9a-f]{64}$/m);
    expect(script).toMatch(/^CLANG_TIDY_SHA256_ARM64=[0-9a-f]{64}$/m);
    // Each wheel's full PyPI URL is pinned beside its SHA-256 and must name the pinned version, so
    // a bump of CLANG_TIDY_VERSION alone cannot leave a stale URL behind.
    const version = /^CLANG_TIDY_VERSION=(.+)$/m.exec(script)?.[1] ?? '';
    for (const arch of ['X64', 'ARM64']) {
      const url = new RegExp(`^CLANG_TIDY_URL_${arch}=(\\S+)$`, 'm').exec(script)?.[1] ?? '';
      expect(url, arch).toMatch(
        /^https:\/\/files\.pythonhosted\.org\/packages\/[0-9a-f]+\/[0-9a-f]+\/[0-9a-f]+\/clang_tidy-/,
      );
      expect(url, arch).toContain(`/clang_tidy-${version}-py2.py3-none-manylinux_`);
      expect(url, arch).not.toContain('$');
    }
    const check = 'echo "$CT_SHA  $TMP/clang-tidy.whl" | sha256sum -c -';
    expect(script).toContain(check);
    expect(script.indexOf(check)).toBeLessThan(script.indexOf('unzip -q "$TMP/clang-tidy.whl"'));
    expect(script).toContain("'clang_tidy/data/bin/clang-tidy' 'clang_tidy/data/lib/*'");
    expect(script).not.toMatch(/pip install|run-clang-tidy|clang-apply-replacements/);
  });

  it('is never installed by the scanner image (decision 2), but by the toolbox and every analyzers job', () => {
    expect(readFileSync('deploy/scanner/Dockerfile', 'utf8')).not.toMatch(/clang-tidy/);
    expect(readFileSync('tools/analyzers/Dockerfile', 'utf8')).toMatch(
      /sh \/tmp\/install-clang-tidy\.sh/,
    );
    const github = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as Workflow;
    for (const [name, job] of Object.entries(github.jobs)) {
      const uses = job.steps.findIndex((s) => s.env?.['QUALOR_REQUIRE_ANALYZERS'] === '1');
      if (uses === -1) continue;
      const install = job.steps.findIndex(
        (s) => s.run === 'sudo sh tools/analyzers/install-clang-tidy.sh',
      );
      expect(install, name).toBeGreaterThan(0);
      expect(uses, name).toBeGreaterThan(install);
    }
    const gitlab = parse(readFileSync('.gitlab-ci.yml', 'utf8')) as Record<
      string,
      { before_script?: unknown[] }
    >;
    expect(gitlab['.analyzers']?.before_script ?? []).toContain(
      'sh tools/analyzers/install-clang-tidy.sh',
    );
  });
});

describe('the qualor rules pack (plan 6B-1)', () => {
  const script = readFileSync('tools/analyzers/install.sh', 'utf8');
  const installer = readFileSync('tools/analyzers/install-qualor-rules.sh', 'utf8');
  const RULES_URL =
    'https://github.com/qualor-dev/qualor-rules/releases/download/v$QUALOR_RULES_VERSION/qualor-rules-$QUALOR_RULES_VERSION.tar.gz';

  it('pins the pack by version and SHA-256 in install.sh, and its URL only once it is published', () => {
    expect(script).toMatch(/^QUALOR_RULES_VERSION=\d{4}\.([1-9]|1[0-2])\.(0|[1-9]\d*)$/m);
    expect(script).toMatch(/^QUALOR_RULES_SHA256=[0-9a-f]{64}$/m);
    const url = /^QUALOR_RULES_URL=(.*)$/m.exec(script)?.[1];
    expect(['', RULES_URL]).toContain(url);
    // The installer reads the pins from install.sh and never carries its own.
    expect(installer).toContain(
      'eval "$(grep -E \'^QUALOR_RULES_(VERSION|SHA256|URL)=\' "$INSTALL_SH")"',
    );
    expect(installer).not.toMatch(/^QUALOR_RULES_(VERSION|SHA256|URL)=/m);
  });

  it('checks the archive against the pin before it unpacks it, over https only', () => {
    const check = installer.indexOf('sha256sum -c -');
    expect(check).toBeGreaterThan(-1);
    expect(check).toBeLessThan(installer.indexOf('tar -xzf'));
    expect(installer).toContain("--proto '=https' --proto-redir '=https' --tlsv1.2");
    expect(installer).toContain('--no-same-owner');
    // Without a pack it skips, unless a build requires one: the failure comes before the skip.
    const required = installer.indexOf('if [ "$REQUIRED" = 1 ]');
    expect(required).toBeGreaterThan(-1);
    expect(installer.indexOf('exit 1', required)).toBeLessThan(
      installer.indexOf('exit 0', required),
    );
  });

  /** The tar archive with one more entry: `rules/js/odd.yml`, a symbolic link to `../../LICENSE` or a FIFO. */
  function withOddEntry(archive: Buffer, kind: 'symlink' | 'fifo'): Buffer {
    let end = archive.length;
    while (end >= 512 && archive.subarray(end - 512, end).every((b) => b === 0)) end -= 512;
    const header = Buffer.alloc(512);
    header.write('rules/js/odd.yml', 0, 'latin1');
    header.write('0000644\0', 100, 'latin1');
    header.write('0000000\0', 108, 'latin1');
    header.write('0000000\0', 116, 'latin1');
    header.write('00000000000\0', 124, 'latin1');
    header.write('00000000000\0', 136, 'latin1');
    header.write('        ', 148, 'latin1');
    header.write(kind === 'symlink' ? '2' : '6', 156, 'latin1');
    if (kind === 'symlink') header.write('../../LICENSE', 157, 'latin1');
    header.write('ustar\0' + '00', 257, 'latin1');
    const sum = header.reduce((n, b) => n + b, 0);
    header.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 'latin1');
    return gzipSync(Buffer.concat([archive.subarray(0, end), header, Buffer.alloc(1024)]));
  }

  /** A synthetic pack (no real rule text) with the layout of a release, and install.sh pins for it. */
  function fixture(
    opts: { sha?: string; url?: string; manifestVersion?: string; entry?: 'symlink' | 'fifo' } = {},
  ) {
    const dir = mkdtempSync(path.join(tmpdir(), 'qualor-rules-'));
    const posix = (p: string) => p.replace(/\\/g, '/');
    const pack = path.join(dir, 'pack');
    mkdirSync(path.join(pack, 'rules', 'js'), { recursive: true });
    writeFileSync(
      path.join(pack, 'manifest.json'),
      `{\n  "version": "${opts.manifestVersion ?? '2026.10.0'}",\n  "rules": []\n}\n`,
    );
    writeFileSync(path.join(pack, 'LICENSE'), 'synthetic licence\n');
    writeFileSync(path.join(pack, 'NOTICE'), 'synthetic notice\n');
    writeFileSync(path.join(pack, 'rules', 'js', 'synthetic.yml'), 'rules: []\n');
    const src = path.join(dir, 'src');
    mkdirSync(src);
    // Relative paths: GNU tar reads "C:" in an absolute Windows path as a remote host.
    const archive = path.join(src, 'qualor-rules-2026.10.0.tar.gz');
    const tar = spawnSync('sh', ['-c', 'tar -czf ../src/qualor-rules-2026.10.0.tar.gz .'], {
      cwd: pack,
      encoding: 'utf8',
    });
    expect(tar.status, tar.stderr).toBe(0);
    if (opts.entry) {
      // Written by hand: on Windows `ln -s` and tar's extraction of a link make a copy.
      writeFileSync(archive, withOddEntry(gunzipSync(readFileSync(archive)), opts.entry));
    }
    const sha = opts.sha ?? createHash('sha256').update(readFileSync(archive)).digest('hex');
    writeFileSync(
      path.join(dir, 'install.sh'),
      `QUALOR_RULES_VERSION=2026.10.0\nQUALOR_RULES_SHA256=${sha}\nQUALOR_RULES_URL=${opts.url ?? ''}\n`,
    );
    const empty = path.join(dir, 'empty');
    mkdirSync(empty);
    const run = (env: Record<string, string>) =>
      spawnSync('sh', [path.resolve('tools/analyzers/install-qualor-rules.sh')], {
        encoding: 'utf8',
        env: {
          ...process.env,
          QUALOR_INSTALL_SH: posix(path.join(dir, 'install.sh')),
          QUALOR_TOOLS: posix(path.join(dir, 'prefix')),
          QUALOR_RULES_SRC: posix(src),
          ...env,
        },
      });
    return {
      run,
      empty: posix(empty),
      prefix: path.join(dir, 'prefix'),
      clean: () => rmSync(dir, { recursive: true, force: true }),
    };
  }
  const hasSh = spawnSync('sh', ['-c', 'true']).status === 0;

  it.skipIf(!hasSh)(
    'skips with a message when there is no pack, and fails when one is required',
    () => {
      const f = fixture();
      try {
        const skipped = f.run({ QUALOR_RULES_SRC: f.empty, QUALOR_RULES_REQUIRED: '0' });
        expect(skipped.status, skipped.stderr).toBe(0);
        expect(skipped.stdout).toContain('is not published yet');
        expect(skipped.stdout).toContain('skipped');
        expect(existsSync(path.join(f.prefix, 'rules', 'qualor'))).toBe(false);
        const required = f.run({ QUALOR_RULES_SRC: f.empty, QUALOR_RULES_REQUIRED: '1' });
        expect(required.status).toBe(1);
        expect(required.stderr).toContain('(QUALOR_RULES_REQUIRED=1)');
        expect(existsSync(path.join(f.prefix, 'rules', 'qualor'))).toBe(false);
      } finally {
        f.clean();
      }
    },
  );

  it.skipIf(!hasSh)('installs a pack that matches the pin, with its licence files', () => {
    const f = fixture();
    try {
      const done = f.run({});
      expect(done.status, done.stderr).toBe(0);
      const dest = path.join(f.prefix, 'rules', 'qualor');
      for (const file of [
        'manifest.json',
        'LICENSE',
        'NOTICE',
        path.join('rules', 'js', 'synthetic.yml'),
      ])
        expect(existsSync(path.join(dest, file)), file).toBe(true);
      for (const file of ['LICENSE', 'NOTICE'])
        expect(existsSync(path.join(f.prefix, 'licenses', 'qualor-rules', file)), file).toBe(true);
    } finally {
      f.clean();
    }
  });

  it.skipIf(!hasSh)(
    'refuses a pack that does not match the pin, whether or not one is required',
    () => {
      const f = fixture({ sha: 'f'.repeat(64) });
      try {
        for (const required of ['0', '1']) {
          const done = f.run({ QUALOR_RULES_REQUIRED: required });
          expect(done.status, required).toBe(1);
          expect(done.stderr).toContain('checksum mismatch');
          expect(existsSync(path.join(f.prefix, 'rules', 'qualor'))).toBe(false);
        }
      } finally {
        f.clean();
      }
    },
  );

  // Tar extraction on Windows turns a symbolic link into a copy, so the link is tested elsewhere.
  it.skipIf(!hasSh)(
    'refuses a pack with an entry that is not a regular file or a directory',
    () => {
      for (const entry of ['fifo', 'symlink'] as const) {
        if (entry === 'symlink' && process.platform === 'win32') continue;
        const f = fixture({ entry });
        try {
          const done = f.run({});
          expect(done.status, `${entry}: ${done.stdout}`).toBe(1);
          expect(done.stderr, entry).toContain('not a regular file or a directory');
          expect(existsSync(path.join(f.prefix, 'rules', 'qualor')), entry).toBe(false);
        } finally {
          f.clean();
        }
      }
    },
  );

  it.skipIf(!hasSh)('compares the manifest version literally, not as a pattern', () => {
    // The pinned 2026.10.0 would match 2026x10y0 as a regular expression.
    const f = fixture({ manifestVersion: '2026x10y0' });
    try {
      const done = f.run({});
      expect(done.status, done.stdout).toBe(1);
      expect(done.stderr).toContain('is not version 2026.10.0');
      expect(existsSync(path.join(f.prefix, 'rules', 'qualor'))).toBe(false);
    } finally {
      f.clean();
    }
  });

  it('runs in every job that requires the analyzers, in both CIs', () => {
    const github = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as Workflow;
    for (const [name, job] of Object.entries(github.jobs)) {
      if (!job.steps.some((s) => s.env?.['QUALOR_REQUIRE_ANALYZERS'] === '1')) continue;
      const steps = job.steps;
      const install = steps.findIndex(
        (s) => s.run === 'sudo sh tools/analyzers/install-qualor-rules.sh',
      );
      expect(install, name).toBeGreaterThan(
        steps.findIndex((s) => s.run?.endsWith('sh tools/analyzers/install.sh') === true),
      );
      expect(install, name).toBeLessThan(
        steps.findIndex((s) => s.env?.['QUALOR_REQUIRE_ANALYZERS'] === '1'),
      );
      // CI never requires the pack; the tests require it once QUALOR_RULES_URL is set.
      expect(JSON.stringify(steps[install]), name).not.toContain('QUALOR_RULES_REQUIRED');
    }
    const gitlab = parse(readFileSync('.gitlab-ci.yml', 'utf8')) as Record<
      string,
      { before_script?: unknown[] } | undefined
    >;
    const before = gitlab['.analyzers']?.before_script ?? [];
    expect(before.indexOf('sh tools/analyzers/install-qualor-rules.sh')).toBeGreaterThan(
      before.indexOf('sh tools/analyzers/install.sh'),
    );
  });

  it('installs it in both images', () => {
    const scanner = readFileSync('deploy/scanner/Dockerfile', 'utf8');
    expect(scanner).toContain('ARG QUALOR_RULES_REQUIRED=0');
    expect(scanner).toContain('COPY tools/analyzers/qualor-rules/ /tmp/qualor-rules/');
    expect(scanner).toContain(
      'QUALOR_RULES_REQUIRED="$QUALOR_RULES_REQUIRED" sh /tmp/install-qualor-rules.sh',
    );
    // In the tools stage, after install.sh (whose pins it reads from /tmp/install.sh).
    expect(scanner.indexOf('sh /tmp/install-qualor-rules.sh')).toBeGreaterThan(
      scanner.indexOf('RUN sh /tmp/install.sh'),
    );
    expect(scanner.indexOf('sh /tmp/install-qualor-rules.sh')).toBeLessThan(
      scanner.lastIndexOf('\nFROM '),
    );
    const toolbox = readFileSync('tools/analyzers/Dockerfile', 'utf8');
    expect(toolbox).toContain('COPY qualor-rules/ /tmp/qualor-rules/');
    expect(toolbox).toContain('sh /tmp/install-qualor-rules.sh');
  });

  it('never commits a pack into this repository (the rules are not MIT)', () => {
    // Tracked and untracked-but-not-ignored files: the README alone, whether or not it is staged
    // yet, and never a tarball (the drop directory is git-ignored).
    const files = spawnSync(
      'git',
      ['ls-files', '-co', '--exclude-standard', 'tools/analyzers/qualor-rules'],
      { encoding: 'utf8' },
    );
    expect(files.stdout.trim().split('\n')).toEqual(['tools/analyzers/qualor-rules/README.md']);
    // Everything in the drop directory is ignored but its README.
    const ignore = readFileSync('.gitignore', 'utf8');
    expect(ignore).toMatch(/^\/tools\/analyzers\/qualor-rules\/\*$/m);
    expect(ignore).toMatch(/^!\/tools\/analyzers\/qualor-rules\/README\.md$/m);
  });
});

describe("the CI cache of Trivy's downloads (plan 2B)", () => {
  const script = readFileSync('tools/analyzers/install.sh', 'utf8');
  const pin = (name: string) => new RegExp(`^${name}=(.*)$`, 'm').exec(script)?.[1];

  it('keeps the release archive and the database layer by checksum, checked on every use', () => {
    expect(script).toContain('CACHE="${QUALOR_DOWNLOAD_CACHE:-}"');
    // A cached file is used only when its SHA-256 matches the pin, else it is dropped and fetched.
    expect(script).toContain('from_cache "$TV_SHA" trivy.tgz ||');
    expect(script).toContain('from_cache "${TRIVY_DB_DIGEST#sha256:}" trivy-db.tar.gz');
    // The database is checked after the cache or the download alike, before it is unpacked.
    const check = script.indexOf(
      '"${TRIVY_DB_DIGEST#sha256:}  $TMP/trivy-db.tar.gz" | sha256sum -c -',
    );
    expect(script.indexOf('from_cache "${TRIVY_DB_DIGEST#sha256:}"')).toBeLessThan(check);
    expect(check).toBeLessThan(script.indexOf('to_cache "${TRIVY_DB_DIGEST#sha256:}"'));
    // Only the current pins stay in the cache.
    expect(script).toContain('! -name "$TV_SHA" ! -name "${TRIVY_DB_DIGEST#sha256:}" -delete');
  });

  it('keys the GitLab cache on TRIVY_DB_DIGEST, next to the pnpm store', () => {
    const gitlab = parse(readFileSync('.gitlab-ci.yml', 'utf8')) as Record<
      string,
      { variables?: Record<string, string>; cache?: unknown }
    >;
    const analyzers = gitlab['.analyzers'];
    expect(`sha256:${analyzers?.variables?.['QUALOR_TRIVY_DB_SHA256'] ?? ''}`).toBe(
      pin('TRIVY_DB_DIGEST'),
    );
    expect(analyzers?.variables?.['QUALOR_DOWNLOAD_CACHE']).toBe('.tmp/downloads');
    expect(analyzers?.cache).toEqual([
      gitlab['default']?.cache,
      { key: 'trivy-db-$QUALOR_TRIVY_DB_SHA256', paths: ['.tmp/downloads'] },
    ]);
  });

  it('keys the GitHub cache on the Trivy version and TRIVY_DB_DIGEST, read from install.sh', () => {
    const github = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as Workflow;
    const dir = '${{ runner.temp }}/qualor-downloads';
    for (const job of ['test', 'fixtures', 'cli-binary']) {
      const steps = github.jobs[job]?.steps ?? [];
      const at = (p: (s: (typeof steps)[number]) => boolean) => steps.findIndex(p);
      const pins = at((s) => s.id === 'trivy-pins');
      expect(steps[pins]?.run, job).toContain('s/^TRIVY_VERSION=//p');
      expect(steps[pins]?.run, job).toContain('s/^TRIVY_DB_DIGEST=sha256://p');
      const cache = at((s) => s.uses?.startsWith('actions/cache@') === true);
      expect(steps[cache]?.uses, job).toMatch(PINNED);
      expect(steps[cache]?.with, job).toEqual({
        path: dir,
        key: '${{ steps.trivy-pins.outputs.key }}',
      });
      const install = at((s) => s.run?.endsWith('sh tools/analyzers/install.sh') === true);
      expect(steps[install]?.env, job).toEqual({ QUALOR_DOWNLOAD_CACHE: dir });
      expect(pins, job).toBeLessThan(cache);
      expect(cache, job).toBeLessThan(install);
    }
  });
});

describe('Bun smoke checks of the shipped runtime (plan 1D)', () => {
  it('runs the process, upload and autoload smoke binaries in both cli-binary jobs', () => {
    const gitlab = parse(readFileSync('.gitlab-ci.yml', 'utf8')) as Record<
      string,
      { script?: unknown[] }
    >;
    const github = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as {
      jobs: Record<string, { steps: { run?: string }[] }>;
    };
    for (const smoke of ['smoke:process', 'smoke:upload', 'smoke:autoload']) {
      const command = `pnpm --filter @qualor/cli ${smoke}`;
      expect(gitlab['cli-binary']?.script, smoke).toContain(command);
      expect(
        github.jobs['cli-binary']?.steps.some((s) => s.run === command),
        smoke,
      ).toBe(true);
    }
  });
});

describe('dogfood job (plan 1G, brief rule 4)', () => {
  const gitlab = parse(readFileSync('.gitlab-ci.yml', 'utf8')) as Record<
    string,
    {
      image?: string;
      needs?: string[];
      services?: { name: string }[];
      variables?: Record<string, string>;
      script?: string[];
      before_script?: string[];
      after_script?: string[];
      artifacts?: { paths?: string[] };
    }
  >;
  const github = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as Workflow & {
    jobs: Record<string, { needs?: string[] }>;
  };

  it('builds both images, runs the compose smoke test and scans the repository with the gate', () => {
    const builds = [
      'docker build -f deploy/server/Dockerfile -t qualor/server:dev .',
      'docker build -f deploy/scanner/Dockerfile -t qualor/scanner:dev .',
      'pnpm deploy:smoke',
    ];
    const gl = gitlab['dogfood'];
    for (const command of builds) expect(gl?.script, command).toContain(command);
    expect(gl?.script?.at(-1)).toContain('pnpm dogfood --base "$CI_MERGE_REQUEST_DIFF_BASE_SHA"');
    expect(gl?.needs).toEqual(['test']);
    expect(gl?.variables?.['GIT_DEPTH']).toBe(0);
    const ghRuns = (github.jobs['dogfood']?.steps ?? []).map((s) => s.run);
    for (const command of builds) expect(ghRuns, command).toContain(command);
    expect(ghRuns.some((r) => r?.startsWith('pnpm dogfood --base HEAD^1 --mr'))).toBe(true);
    expect(github.jobs['dogfood']?.needs).toEqual(['test']);
  });

  it('hands the coverage of the test job to the scan in both CIs', () => {
    expect(gitlab['test']?.artifacts?.paths).toContain('coverage/lcov.info');
    const upload = github.jobs['test']?.steps.find((s) =>
      s.uses?.startsWith('actions/upload-artifact@'),
    );
    expect(upload?.with).toMatchObject({ name: 'coverage', path: 'coverage/lcov.info' });
  });

  it('pins the Docker-in-Docker images of the GitLab job by digest', () => {
    const images = [
      gitlab['dogfood']?.image ?? '',
      ...(gitlab['dogfood']?.services ?? []).map((s) => s.name),
    ];
    expect(images).toHaveLength(2);
    for (const image of images)
      expect(image, image).toMatch(/^docker:[\d.]+-\w+@sha256:[0-9a-f]{64}$/);
  });

  it('tears the stacks and the checkout volume down even when the job fails or is cancelled', () => {
    const steps = github.jobs['dogfood']?.steps ?? [];
    const last = steps.at(-1);
    expect(last?.if).toBe('always()');
    expect(last?.run).toBe('sh tools/deploy/teardown.sh');
    expect(gitlab['dogfood']?.after_script).toEqual(['sh tools/deploy/teardown.sh']);
    const script = readFileSync('tools/deploy/teardown.sh', 'utf8');
    // The scanner and Node containers, the checkout volumes and the pnpm store.
    expect(script).toContain(`--filter label=${DEPLOY_LABEL}`);
    // The stacks' containers, networks and database volumes, by their qualor-* project names
    // only: never every compose project on the host (a self-hosted runner may run others).
    expect(script).toContain("grep '^qualor-'");
    expect(script).toContain('label=com.docker.compose.project=$project');
    expect(script).not.toMatch(/--filter label=com\.docker\.compose\.project \|/);
  });

  it('installs pnpm in the GitLab dogfood job through a pinned corepack (packageManager)', () => {
    const before = gitlab['dogfood']?.before_script ?? [];
    expect(before).toContain('corepack enable');
    expect(before.some((l) => /^npm install -g corepack@\d+\.\d+\.\d+$/.test(l))).toBe(true);
    expect(before.some((l) => l.includes('npm install -g pnpm'))).toBe(false);
  });
});

describe('release engineering jobs (plan 4A)', () => {
  it('runs the chart and release tool tests in both CIs, through Docker on GitHub and directly on GitLab', () => {
    const wf = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as Workflow;
    const gh = wf.jobs['helm']?.steps.map((s) => s.run ?? '') ?? [];
    expect(gh).toContain('pnpm release:test');
    expect(wf.jobs['helm']?.steps.some((s) => s.uses?.startsWith('oven-sh/setup-bun@'))).toBe(true);
    const gl = (
      parse(readFileSync('.gitlab-ci.yml', 'utf8')) as Record<
        string,
        { variables?: Record<string, string>; script?: string[]; before_script?: unknown[] }
      >
    )['helm'];
    expect(gl?.variables?.['QUALOR_TOOLBOX']).toBe('direct');
    expect(JSON.stringify(gl?.before_script)).toContain('sh tools/release/install-tools.sh');
    expect(gl?.script).toContain('pnpm helm:test');
  });

  it('runs the k3s smoke test on GitHub Actions only, after building the server image', () => {
    const wf = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as Workflow;
    const runs = wf.jobs['helm-smoke']?.steps.map((s) => s.run ?? '') ?? [];
    expect(runs).toContain('pnpm helm:smoke');
    expect(
      runs.indexOf('docker build -f deploy/server/Dockerfile -t qualor/server:dev .'),
    ).toBeLessThan(runs.indexOf('pnpm helm:smoke'));
    expect(readFileSync('.gitlab-ci.yml', 'utf8')).not.toContain('helm:smoke');
  });

  it('gives both GitHub jobs read-only contents, no secrets and a timeout', () => {
    const text = readFileSync('.github/workflows/ci.yml', 'utf8');
    const wf = parse(text) as Workflow;
    expect(wf.permissions).toEqual({ contents: 'read' });
    for (const job of ['helm', 'helm-smoke']) {
      expect(wf.jobs[job]?.permissions, job).toEqual({ contents: 'read' });
      expect(wf.jobs[job]?.['timeout-minutes'], job).toBeGreaterThan(0);
      expect(JSON.stringify(wf.jobs[job]), job).not.toMatch(/secrets\./);
    }
  });
});

describe('install-rubocop.sh (plan 9B)', () => {
  const script = readFileSync('tools/analyzers/install-rubocop.sh', 'utf8');
  const lock = readFileSync('tools/analyzers/rubocop/gems.lock', 'utf8');
  const entries = lock.split('\n').filter((l) => l.trim() !== '' && !l.startsWith('#'));

  it("pins Ruby's source and every gem by SHA-256, checked before use, and resolves nothing online", () => {
    expect(script).toMatch(/^RUBY_VERSION=\d+\.\d+\.\d+$/m);
    expect(script).toMatch(/^RUBY_SHA256=[0-9a-f]{64}$/m);
    expect(script).toMatch(/^RUBOCOP_VERSION=\d+\.\d+\.\d+$/m);
    expect(script).toContain(
      'fetch "https://cache.ruby-lang.org/pub/ruby/${RUBY_VERSION%.*}/ruby-$RUBY_VERSION.tar.gz" "$RUBY_SHA256" ruby.tar.gz',
    );
    expect(script).toContain(
      'fetch "https://rubygems.org/downloads/$name-$version.gem" "$sha" "$name-$version.gem"',
    );
    expect(script).toContain('install --local --ignore-dependencies --no-document');
    expect(script).not.toMatch(/bundle install|--source|latest|wget/);
    expect(entries.length).toBeGreaterThanOrEqual(13);
    for (const e of entries) expect(e, e).toMatch(/^[a-z][a-z0-9_-]* \d+(\.\d+)+ [0-9a-f]{64}$/);
    const pinned = /^RUBOCOP_VERSION=(.+)$/m.exec(script)?.[1] ?? '';
    expect(entries.some((e) => e.startsWith(`rubocop ${pinned} `))).toBe(true);
  });

  it('pins the .gem files it takes the default gems’ licence files from (B9-15)', () => {
    const licenceLock = readFileSync('tools/analyzers/rubocop/licence-gems.lock', 'utf8')
      .split('\n')
      .filter((l) => l.trim() !== '' && !l.startsWith('#'));
    expect(licenceLock.map((e) => e.split(' ')[0])).toEqual(
      expect.arrayContaining(['prism', 'syntax_suggest']),
    );
    for (const e of licenceLock)
      expect(e, e).toMatch(/^[a-z][a-z0-9_-]* \d+(\.\d+)+ [0-9a-f]{64}$/);
    expect(script).toContain(
      'fetch "https://rubygems.org/downloads/$name-$version.gem" "$sha" "licence/$name-$version.gem"',
    );
    expect(script).toContain('done <"$SRC/licence-gems.lock"');
    for (const file of ['deploy/scanner/Dockerfile', 'tools/analyzers/Dockerfile'])
      expect(readFileSync(file, 'utf8'), file).toMatch(/rubocop\/licence-gems\.lock/);
  });

  it('pins the same RuboCop as the CLI (packages/shared/src/rules/rubocop.ts)', () => {
    const pinned = /^RUBOCOP_VERSION=(.+)$/m.exec(script)?.[1];
    expect(readFileSync('packages/shared/src/rules/rubocop.ts', 'utf8')).toContain(
      `export const RUBOCOP_VERSION = '${pinned}';`,
    );
  });

  it('runs in every GitHub job that requires the analyzers, before the tests', () => {
    const github = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as Workflow;
    for (const [name, job] of Object.entries(github.jobs)) {
      if (!job.steps.some((s) => s.env?.['QUALOR_REQUIRE_ANALYZERS'] === '1')) continue;
      const install = job.steps.findIndex(
        (s) => s.run?.endsWith('sudo sh tools/analyzers/install-rubocop.sh') === true,
      );
      expect(install, name).toBeGreaterThan(0);
      const uses = job.steps.findIndex((s) => s.env?.['QUALOR_REQUIRE_ANALYZERS'] === '1');
      expect(uses, name).toBeGreaterThan(install);
    }
  });

  it("runs in GitLab's shared .analyzers template after install.sh", () => {
    const gitlab = parse(readFileSync('.gitlab-ci.yml', 'utf8')) as Record<
      string,
      { before_script?: unknown[] }
    >;
    const before = gitlab['.analyzers']?.before_script ?? [];
    expect(before).toContain('sh tools/analyzers/install-rubocop.sh');
    expect(before.indexOf('sh tools/analyzers/install.sh')).toBeLessThan(
      before.indexOf('sh tools/analyzers/install-rubocop.sh'),
    );
  });

  it('is installed by both images, and the scanner image has the libyaml its Ruby links', () => {
    for (const file of ['deploy/scanner/Dockerfile', 'tools/analyzers/Dockerfile'])
      expect(readFileSync(file, 'utf8'), file).toMatch(/sh \/tmp\/install-rubocop\.sh/);
    expect(readFileSync('deploy/scanner/Dockerfile', 'utf8')).toMatch(
      /apt-get install -y --no-install-recommends [^\n]*\blibyaml-0-2\b/,
    );
  });
});
