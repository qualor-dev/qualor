import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';

/**
 * Plan 3A Task 17 (import-sonarqube.md §17.1): the live SonarQube check reads a production
 * organisation, so `pnpm test` and CI must never collect it. It exists as a vitest project only
 * when both of its variables are set, and only `pnpm sonar:live` names that project.
 */
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const LIVE_FILE = 'cli/test/sonar-live.live.test.ts';
const LLM_LIVE_FILE = 'tools/llm/ollama.live.test.ts';
const REVIEW_LIVE_FILE = 'tools/review/review.live.test.ts';
/** Every variable of every live check, stubbed empty unless a case sets it. */
const VARS = [
  'QUALOR_LIVE_SONAR_URL',
  'QUALOR_LIVE_SONAR_TOKEN',
  'QUALOR_LIVE_SONAR_ORG',
  'QUALOR_LIVE_LLM_URL',
  'QUALOR_LIVE_LLM_MODEL',
  'QUALOR_LIVE_REVIEW_URL',
  'QUALOR_LIVE_REVIEW_MODEL',
  'QUALOR_LIVE_JIRA_SITE_URL',
  'QUALOR_LIVE_JIRA_TOKEN',
  'QUALOR_LIVE_JIRA_PROJECT',
  'QUALOR_LIVE_AZURE_ENV_FILES',
  'QUALOR_RELEASE_TOOLS',
];

interface Project {
  test: { name: string; include?: string[]; exclude?: string[] };
}

const ARGV = process.argv;

/** The projects with these variables and, when given, this command line (after `vitest`). */
async function projects(env: Record<string, string>, args?: string[]): Promise<Project[]> {
  for (const v of VARS) vi.stubEnv(v, env[v] ?? '');
  process.argv = args === undefined ? ARGV : [ARGV[0] ?? 'node', 'vitest', ...args];
  vi.resetModules();
  const config = (await import('../vitest.config')).default as {
    test: { projects: Project[] };
  };
  return config.test.projects;
}

afterEach(() => {
  process.argv = ARGV;
  vi.unstubAllEnvs();
  vi.resetModules();
});

describe('the live SonarQube check is never collected by pnpm test or CI', () => {
  it('is a project only with both the URL and the token set', async () => {
    const names = (ps: Project[]) => ps.map((p) => p.test.name);
    expect(names(await projects({}))).not.toContain('sonar-live');
    expect(names(await projects({ QUALOR_LIVE_SONAR_URL: 'https://sonar.invalid' }))).not.toContain(
      'sonar-live',
    );
    expect(names(await projects({ QUALOR_LIVE_SONAR_TOKEN: 'x' }))).not.toContain('sonar-live');
    const on = await projects({
      QUALOR_LIVE_SONAR_URL: 'https://sonar.invalid',
      QUALOR_LIVE_SONAR_TOKEN: 'x',
    });
    const live = on.find((p) => p.test.name === 'sonar-live');
    expect(live?.test.include).toEqual([LIVE_FILE]);
  });

  it('is excluded from every other project', async () => {
    for (const p of await projects({})) {
      const include = p.test.include ?? [];
      // Only the unit project's pattern could match the file; it excludes every *.live.test.ts.
      if (include.includes('**/*.test.ts')) expect(p.test.exclude).toContain('**/*.live.test.ts');
      else for (const pattern of include) expect(pattern).not.toMatch(/^(\*\*|cli)\//);
    }
    expect(LIVE_FILE.endsWith('.live.test.ts')).toBe(true);
  });

  it('runs only through pnpm sonar:live, which no CI job calls', () => {
    const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')) as {
      scripts: Record<string, string>;
    };
    expect(pkg.scripts['sonar:live']).toBe('vitest run --project sonar-live');
    for (const [name, script] of Object.entries(pkg.scripts)) {
      if (name !== 'sonar:live') expect(script, name).not.toMatch(/sonar-live|sonar:live/);
    }
    const ci = [
      path.join(root, '.gitlab-ci.yml'),
      ...readdirSync(path.join(root, '.github', 'workflows')).map((f) =>
        path.join(root, '.github', 'workflows', f),
      ),
    ];
    for (const file of ci) {
      const text = readFileSync(file, 'utf8');
      expect(text, file).not.toMatch(/QUALOR_LIVE_SONAR|sonar-live|sonar:live/);
    }
  });
});

/**
 * Plan 3B Task 20 (llm.md §17): the live check against a local Ollama sends prompts to a model, so
 * `pnpm test` and CI must never collect it either. Its project exists only with both
 * `QUALOR_LIVE_LLM_URL` and `QUALOR_LIVE_LLM_MODEL`, and only `pnpm llm:live` names it.
 */
describe('the live LLM check is never collected by pnpm test or CI', () => {
  it('is a project only with both the URL and the model set', async () => {
    const names = (ps: Project[]) => ps.map((p) => p.test.name);
    expect(names(await projects({}))).not.toContain('llm-live');
    expect(
      names(await projects({ QUALOR_LIVE_LLM_URL: 'http://localhost:11434/v1' })),
    ).not.toContain('llm-live');
    expect(names(await projects({ QUALOR_LIVE_LLM_MODEL: 'm' }))).not.toContain('llm-live');
    const on = await projects({
      QUALOR_LIVE_LLM_URL: 'http://localhost:11434/v1',
      QUALOR_LIVE_LLM_MODEL: 'm',
    });
    const live = on.find((p) => p.test.name === 'llm-live');
    expect(live?.test.include).toEqual([LLM_LIVE_FILE]);
    // Setting the LLM variables adds no other project, and the SonarQube one stays off.
    expect(names(on)).not.toContain('sonar-live');
  });

  it('is excluded from every other project, and no pattern elsewhere reaches tools/llm', async () => {
    for (const p of await projects({})) {
      const include = p.test.include ?? [];
      if (include.includes('**/*.test.ts')) expect(p.test.exclude).toContain('**/*.live.test.ts');
      else for (const pattern of include) expect(pattern).not.toMatch(/^(\*\*|tools)\//);
    }
    expect(LLM_LIVE_FILE.endsWith('.live.test.ts')).toBe(true);
  });

  it('runs only through pnpm llm:live, which no CI job calls', () => {
    const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')) as {
      scripts: Record<string, string>;
    };
    expect(pkg.scripts['llm:live']).toBe('vitest run --project llm-live');
    for (const [name, script] of Object.entries(pkg.scripts)) {
      if (name !== 'llm:live') expect(script, name).not.toMatch(/llm-live|llm:live/);
    }
    const ci = [
      path.join(root, '.gitlab-ci.yml'),
      ...readdirSync(path.join(root, '.github', 'workflows')).map((f) =>
        path.join(root, '.github', 'workflows', f),
      ),
    ];
    for (const file of ci) {
      const text = readFileSync(file, 'utf8');
      expect(text, file).not.toMatch(/QUALOR_LIVE_LLM|llm-live|llm:live/);
    }
  });
});

/**
 * Plan 6I-3 Task 14 (spec §12): the live evaluation of the AI review sends the evaluation set to a
 * real provider, which costs money, so `pnpm test` and CI must never collect it either. Its project
 * exists only with both `QUALOR_LIVE_REVIEW_URL` and `QUALOR_LIVE_REVIEW_MODEL`, and only
 * `pnpm review:live` names it.
 */
describe('the live AI review evaluation is never collected by pnpm test or CI', () => {
  it('the review-live project exists only with both variables and no CI file mentions it', async () => {
    const names = (ps: Project[]) => ps.map((p) => p.test.name);
    const url = { QUALOR_LIVE_REVIEW_URL: 'https://llm.invalid/v1' };
    const model = { QUALOR_LIVE_REVIEW_MODEL: 'm' };
    expect(names(await projects({}))).not.toContain('review-live');
    expect(names(await projects(url))).not.toContain('review-live');
    expect(names(await projects(model))).not.toContain('review-live');
    const on = await projects({ ...url, ...model });
    expect(on.find((p) => p.test.name === 'review-live')?.test.include).toEqual([REVIEW_LIVE_FILE]);
    // Setting its variables adds no other live project.
    expect(names(on)).not.toContain('llm-live');
    expect(names(on)).not.toContain('sonar-live');

    // The unit project, whose pattern matches every *.test.ts, leaves the file out, and no other
    // project's pattern reaches tools/review.
    expect(REVIEW_LIVE_FILE.endsWith('.live.test.ts')).toBe(true);
    for (const p of await projects({})) {
      const include = p.test.include ?? [];
      if (include.includes('**/*.test.ts')) expect(p.test.exclude).toContain('**/*.live.test.ts');
      else for (const pattern of include) expect(pattern).not.toMatch(/^(\*\*|tools)\//);
    }

    // Only the script that names the project runs it, and no CI file names the project, the
    // script or a variable.
    const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')) as {
      scripts: Record<string, string>;
    };
    expect(pkg.scripts['review:live']).toBe('vitest run --project review-live');
    for (const [name, script] of Object.entries(pkg.scripts)) {
      if (name !== 'review:live') expect(script, name).not.toMatch(/review-live|review:live/);
    }
    const ci = [
      path.join(root, '.gitlab-ci.yml'),
      ...readdirSync(path.join(root, '.github', 'workflows')).map((f) =>
        path.join(root, '.github', 'workflows', f),
      ),
    ];
    for (const file of ci) {
      const text = readFileSync(file, 'utf8');
      expect(text, file).not.toMatch(/QUALOR_LIVE_REVIEW|review-live|review:live/);
    }
  });
});

describe('release tool tests (plan 4A, ruling RE5)', () => {
  it('are never collected by pnpm test, only when QUALOR_RELEASE_TOOLS=1', async () => {
    const plain = await projects({});
    expect(plain.map((p) => p.test.name)).not.toContain('release-tools');
    const unit = plain.find((p) => p.test.name === 'unit');
    expect(unit?.test.exclude).toEqual(
      expect.arrayContaining(['**/*.helm.test.ts', '**/*.tools.test.ts']),
    );
    const withTools = await projects({ QUALOR_RELEASE_TOOLS: '1' });
    expect(withTools.find((p) => p.test.name === 'release-tools')?.test.include).toEqual([
      'tools/**/*.helm.test.ts',
      'tools/**/*.tools.test.ts',
    ]);
  });

  it('run only through pnpm helm:test and pnpm release:test', () => {
    const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')) as {
      scripts: Record<string, string>;
    };
    expect(pkg.scripts['helm:test']).toBe('tsx tools/release/test-tools.ts tools/helm');
    expect(pkg.scripts['release:test']).toBe('tsx tools/release/test-tools.ts');
  });
});

/**
 * Plan 4D Task 20 (sso-scim.md §19.4): the live check starts Keycloak and a licensed server in
 * Docker, so `pnpm test` and CI must never collect it. Its project exists only when the command
 * line names it (`pnpm sso:keycloak` runs `vitest run --project keycloak`); the unit project,
 * whose pattern matches every `*.test.ts`, excludes its file by name.
 */
describe('the live Keycloak check is never collected by pnpm test or CI', () => {
  const KEYCLOAK_FILE = 'tools/sso/keycloak.test.ts';

  it('is a project only when the command line names it', async () => {
    const names = (ps: Project[]) => ps.map((p) => p.test.name);
    expect(names(await projects({}, ['run']))).not.toContain('keycloak');
    expect(names(await projects({}, []))).not.toContain('keycloak');
    expect(names(await projects({}, ['run', '--project', 'unit']))).not.toContain('keycloak');
    expect(names(await projects({}, ['run', 'keycloak']))).not.toContain('keycloak');
    for (const args of [
      ['run', '--project', 'keycloak'],
      ['run', '--project=keycloak'],
    ]) {
      const on = await projects({}, args);
      expect(on.find((p) => p.test.name === 'keycloak')?.test.include).toEqual([KEYCLOAK_FILE]);
    }
  });

  it('is excluded from the unit project, and no other pattern reaches tools/sso', async () => {
    for (const p of await projects({}, ['run'])) {
      const include = p.test.include ?? [];
      if (include.includes('**/*.test.ts')) expect(p.test.exclude).toContain(KEYCLOAK_FILE);
      else for (const pattern of include) expect(pattern).not.toMatch(/^(\*\*|tools)\//);
    }
  });

  it('runs only through pnpm sso:keycloak, which no CI job calls', () => {
    const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')) as {
      scripts: Record<string, string>;
    };
    expect(pkg.scripts['sso:keycloak']).toBe('vitest run --project keycloak');
    for (const [name, script] of Object.entries(pkg.scripts)) {
      if (name !== 'sso:keycloak') expect(script, name).not.toMatch(/keycloak/);
    }
    const ci = [
      path.join(root, '.gitlab-ci.yml'),
      ...readdirSync(path.join(root, '.github', 'workflows')).map((f) =>
        path.join(root, '.github', 'workflows', f),
      ),
    ];
    for (const file of ci) {
      const text = readFileSync(file, 'utf8');
      expect(text, file).not.toMatch(/sso:keycloak|--project[ =]keycloak/);
    }
  });
});

/**
 * 0.16 Jira (spec §9): the live check creates issues in a real Jira site, so `pnpm test` and CI
 * must never collect it, even with its variables set. Its project exists only when the command
 * line names it (`pnpm jira:live` runs `vitest run --project jira-live`).
 */
describe('the live Jira check is never collected by pnpm test or CI', () => {
  const JIRA_LIVE_FILE = 'server/src/jira/live.live.test.ts';
  const SET = {
    QUALOR_LIVE_JIRA_SITE_URL: 'https://x.atlassian.net',
    QUALOR_LIVE_JIRA_TOKEN: 'x',
    QUALOR_LIVE_JIRA_PROJECT: 'KEY',
  };

  it('is a project only when the command line names it, whatever variables are set', async () => {
    const names = (ps: Project[]) => ps.map((p) => p.test.name);
    expect(names(await projects({}))).not.toContain('jira-live');
    expect(names(await projects(SET))).not.toContain('jira-live');
    expect(names(await projects(SET, []))).not.toContain('jira-live');
    expect(names(await projects(SET, ['run']))).not.toContain('jira-live');
    expect(names(await projects(SET, ['run', 'jira-live']))).not.toContain('jira-live');
    for (const args of [
      ['run', '--project', 'jira-live'],
      ['run', '--project=jira-live'],
    ]) {
      const on = await projects({}, args);
      expect(on.find((p) => p.test.name === 'jira-live')?.test.include).toEqual([JIRA_LIVE_FILE]);
    }
  });

  it('is excluded from the unit project, and no other pattern reaches it', async () => {
    expect(JIRA_LIVE_FILE.endsWith('.live.test.ts')).toBe(true);
    for (const p of await projects(SET, ['run'])) {
      const include = p.test.include ?? [];
      if (include.includes('**/*.test.ts')) expect(p.test.exclude).toContain('**/*.live.test.ts');
      else for (const pattern of include) expect(pattern).not.toContain('live');
    }
  });

  it('runs only through pnpm jira:live, which no CI job calls', () => {
    const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')) as {
      scripts: Record<string, string>;
    };
    expect(pkg.scripts['jira:live']).toBe('vitest run --project jira-live');
    for (const [name, script] of Object.entries(pkg.scripts)) {
      if (name !== 'jira:live') expect(script, name).not.toMatch(/jira-live|jira:live/);
    }
    const ci = [
      path.join(root, '.gitlab-ci.yml'),
      ...readdirSync(path.join(root, '.github', 'workflows')).map((f) =>
        path.join(root, '.github', 'workflows', f),
      ),
    ];
    for (const file of ci) {
      const text = readFileSync(file, 'utf8');
      expect(text, file).not.toMatch(/QUALOR_LIVE_JIRA|jira-live|jira:live/);
    }
  });
});

/**
 * 0.16 fix MRs (spec §9, R26): the live checks of the fix adapters run real package managers
 * against the public registries, so `pnpm test` and CI must never collect them. Their project
 * exists only when the command line names it (`pnpm fix:live` runs `vitest run --project fix-live`).
 */
describe('the live fix adapter checks are never collected by pnpm test or CI', () => {
  const FIX_LIVE_FILES = 'cli/src/fix/**/*.live.test.ts';

  it('are a project only when the command line names it', async () => {
    const names = (ps: Project[]) => ps.map((p) => p.test.name);
    expect(names(await projects({}))).not.toContain('fix-live');
    expect(names(await projects({}, []))).not.toContain('fix-live');
    expect(names(await projects({}, ['run']))).not.toContain('fix-live');
    expect(names(await projects({}, ['run', '--project', 'unit']))).not.toContain('fix-live');
    expect(names(await projects({}, ['run', 'fix-live']))).not.toContain('fix-live');
    for (const args of [
      ['run', '--project', 'fix-live'],
      ['run', '--project=fix-live'],
    ]) {
      const on = await projects({}, args);
      expect(on.find((p) => p.test.name === 'fix-live')?.test.include).toEqual([FIX_LIVE_FILES]);
    }
  });

  it('are excluded from the unit project, and no other pattern reaches them', async () => {
    for (const p of await projects({}, ['run'])) {
      const include = p.test.include ?? [];
      if (include.includes('**/*.test.ts')) expect(p.test.exclude).toContain('**/*.live.test.ts');
      else for (const pattern of include) expect(pattern).not.toMatch(/^(\*\*|cli)\//);
    }
  });

  it('run only through pnpm fix:live, which no CI job calls', () => {
    const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')) as {
      scripts: Record<string, string>;
    };
    expect(pkg.scripts['fix:live']).toBe('vitest run --project fix-live');
    for (const [name, script] of Object.entries(pkg.scripts)) {
      if (name !== 'fix:live') expect(script, name).not.toMatch(/fix-live|fix:live/);
    }
    const ci = [
      path.join(root, '.gitlab-ci.yml'),
      ...readdirSync(path.join(root, '.github', 'workflows')).map((f) =>
        path.join(root, '.github', 'workflows', f),
      ),
    ];
    for (const file of ci) {
      const text = readFileSync(file, 'utf8');
      expect(text, file).not.toMatch(/fix-live|fix:live/);
    }
  });
});

/**
 * Azure DevOps connection: the live check reads a real organisation with real credentials, so
 * `pnpm test` and CI must never collect it, even with its variable set. Its project exists only
 * when the variable is set and the command line names it (`pnpm azure:live`).
 */
describe('the live Azure DevOps check is never collected by pnpm test or CI', () => {
  const AZURE_LIVE_FILE = 'server/src/scm/azure/live.live.test.ts';
  const SET = { QUALOR_LIVE_AZURE_ENV_FILES: 'a.env;b.env' };
  const NAMED = ['run', '--project', 'azure-live'];

  it('is a project only with the variable set and the command line naming it', async () => {
    const names = (ps: Project[]) => ps.map((p) => p.test.name);
    expect(names(await projects({}))).not.toContain('azure-live');
    expect(names(await projects(SET))).not.toContain('azure-live');
    expect(names(await projects(SET, []))).not.toContain('azure-live');
    expect(names(await projects(SET, ['run']))).not.toContain('azure-live');
    expect(names(await projects(SET, ['run', 'azure-live']))).not.toContain('azure-live');
    expect(names(await projects({}, NAMED))).not.toContain('azure-live');
    for (const args of [NAMED, ['run', '--project=azure-live']]) {
      const on = await projects(SET, args);
      expect(on.find((p) => p.test.name === 'azure-live')?.test.include).toEqual([AZURE_LIVE_FILE]);
    }
  });

  it('is excluded from the unit project, and no other pattern reaches it', async () => {
    expect(AZURE_LIVE_FILE.endsWith('.live.test.ts')).toBe(true);
    for (const p of await projects(SET, ['run'])) {
      const include = p.test.include ?? [];
      if (include.includes('**/*.test.ts')) expect(p.test.exclude).toContain('**/*.live.test.ts');
      else for (const pattern of include) expect(pattern).not.toContain('live');
    }
  });

  it('runs only through pnpm azure:live, which no CI job calls', () => {
    const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')) as {
      scripts: Record<string, string>;
    };
    expect(pkg.scripts['azure:live']).toBe('vitest run --project azure-live');
    for (const [name, script] of Object.entries(pkg.scripts)) {
      if (name !== 'azure:live') expect(script, name).not.toMatch(/azure-live|azure:live/);
    }
    const ci = [
      path.join(root, '.gitlab-ci.yml'),
      ...readdirSync(path.join(root, '.github', 'workflows')).map((f) =>
        path.join(root, '.github', 'workflows', f),
      ),
    ];
    for (const file of ci) {
      const text = readFileSync(file, 'utf8');
      expect(text, file).not.toMatch(/QUALOR_LIVE_AZURE|azure-live|azure:live/);
    }
  });
});
