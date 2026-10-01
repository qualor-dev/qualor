import { readdirSync, readFileSync } from 'node:fs';
import { parse as parseYaml, type Tags } from 'yaml';
import { describe, expect, it } from 'vitest';
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
    for (const tool of ['PMD', 'SPOTBUGS', 'OPENGREP', 'GITLEAKS', 'TRIVY', 'RUFF', 'SWIFTLINT']) {
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
