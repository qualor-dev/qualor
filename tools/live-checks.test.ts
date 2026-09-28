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
/** Every variable of every live check, stubbed empty unless a case sets it. */
const VARS = [
  'QUALOR_LIVE_SONAR_URL',
  'QUALOR_LIVE_SONAR_TOKEN',
  'QUALOR_LIVE_SONAR_ORG',
  'QUALOR_LIVE_LLM_URL',
  'QUALOR_LIVE_LLM_MODEL',
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
