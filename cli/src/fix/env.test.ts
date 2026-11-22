import { describe, expect, it } from 'vitest';
import { FIX_DROPPED_ENV, fixJobSecrets, fixToolEnv } from './env';

// Test secrets are assembled at runtime, so the repository's own gitleaks pass finds none here.
const NPM_SECRET = ['npm', 'S3CR3T', 'v4lue'].join('_');

const DROPPED = [
  'QUALOR_TOKEN',
  'QUALOR_URL',
  'QUALOR_PROJECT_KEY',
  'QUALOR_TOKEN_FILE',
  'QUALOR_CA_FILE',
  'CI_JOB_TOKEN',
  'GITHUB_TOKEN',
  'ACTIONS_RUNTIME_TOKEN',
  'ACTIONS_ID_TOKEN_REQUEST_URL',
  'ACTIONS_CACHE_URL',
];

describe('fixToolEnv (B9)', () => {
  it('drops each Qualor and CI job credential', () => {
    const env = Object.fromEntries(DROPPED.map((name) => [name, `value-of-${name}`]));
    const out = fixToolEnv({ ...env, PATH: '/usr/bin' });
    for (const name of DROPPED) expect(out, name).not.toHaveProperty(name);
    expect(Object.values(out).join('\n')).not.toContain('value-of-');
  });

  it('passes registry credentials, PATH and HOME to the package managers', () => {
    const out = fixToolEnv({
      NPM_TOKEN: NPM_SECRET,
      PATH: '/usr/local/bin:/usr/bin',
      HOME: '/home/ci',
      GOPROXY: 'https://proxy.golang.org',
      npm_config_registry: 'https://registry.example/',
      CI: 'true',
    });
    expect(out).toEqual({
      NPM_TOKEN: NPM_SECRET,
      PATH: '/usr/local/bin:/usr/bin',
      HOME: '/home/ci',
      GOPROXY: 'https://proxy.golang.org',
      npm_config_registry: 'https://registry.example/',
      CI: 'true',
    });
  });

  it('matches names whatever their case (Windows names are case-insensitive) and skips unset values', () => {
    const out = fixToolEnv({
      Qualor_Token: 'x',
      github_token: 'y',
      Actions_Foo: 'z',
      UNSET: undefined,
    });
    expect(out).toEqual({});
  });

  it('drops whole names: the QUALOR_ and ACTIONS_ prefixes and the listed names, not look-alikes', () => {
    expect(FIX_DROPPED_ENV.test('QUALOR_ANYTHING')).toBe(true);
    expect(FIX_DROPPED_ENV.test('ACTIONS_STEP_DEBUG')).toBe(true);
    expect(FIX_DROPPED_ENV.test('MY_GITHUB_TOKEN')).toBe(false);
    expect(FIX_DROPPED_ENV.test('CI_JOB_JWT_V2')).toBe(true);
    expect(fixToolEnv({ MY_GITHUB_TOKEN: 'kept' })).toEqual({ MY_GITHUB_TOKEN: 'kept' });
  });
});

describe('fixToolEnv: the CI job credentials (ruling T12b)', () => {
  it('drops every CI_, GITHUB_ and RUNNER_ name with TOKEN, PASSWORD, SECRET, JWT or KEY, in any case', () => {
    const dropped = [
      'CI_REGISTRY_PASSWORD',
      'CI_DEPENDENCY_PROXY_PASSWORD',
      'CI_DEPLOY_PASSWORD',
      'CI_JOB_JWT',
      'CI_JOB_JWT_V2',
      'CI_JOB_JWT_V1',
      'CI_BUILD_TOKEN',
      'CI_SERVER_TLS_KEY_FILE',
      'CI_SOME_SECRET',
      'ci_registry_password',
      'GITHUB_APP_PRIVATE_KEY',
      'GITHUB_PAT_TOKEN',
      'RUNNER_TOKEN',
      'RUNNER_SECRET_X',
      'Runner_Jwt',
    ];
    const out = fixToolEnv(Object.fromEntries(dropped.map((name) => [name, `value-of-${name}`])));
    for (const name of dropped) expect(out, name).not.toHaveProperty(name);
  });

  it('keeps the other CI names and the registry credentials', () => {
    const kept = {
      CI: 'true',
      CI_PROJECT_DIR: '/builds/acme/app',
      CI_COMMIT_SHA: 'a'.repeat(40),
      GITHUB_SHA: 'b'.repeat(40),
      GITHUB_WORKSPACE: '/home/runner/work',
      RUNNER_TEMP: '/home/runner/work/_temp',
      NPM_TOKEN: NPM_SECRET,
      npm_config__auth: 'abc',
      MY_CI_TOKEN: 'kept-as-registry-config',
    };
    expect(fixToolEnv(kept)).toEqual(kept);
  });
});

describe('fixJobSecrets (B9, I1, ruling T12b)', () => {
  const TOKEN = ['qlr', 'prj', 'T0KEN', 'value'].join('_');

  it('scrubs the token, the secret-named values and the values of the dropped CI variables', () => {
    const { scrub } = fixJobSecrets(
      {
        NPM_TOKEN: NPM_SECRET,
        CI_JOB_JWT: 'jwt-header.payload.sig',
        ACTIONS_RUNTIME_URL: 'https://pipelines.actions.example/x',
        QUALOR_PROJECT_KEY: 'core',
        QUALOR_URL: 'https://qualor.example',
        PATH: '/usr/bin',
      },
      TOKEN,
    );
    expect(scrub).toEqual(
      expect.arrayContaining([
        TOKEN,
        NPM_SECRET,
        'jwt-header.payload.sig',
        'https://pipelines.actions.example/x',
      ]),
    );
    expect(scrub).not.toContain('core');
    expect(scrub).not.toContain('https://qualor.example');
    expect(scrub).not.toContain('/usr/bin');
  });

  it('counts as credentials only the token and secret-like values of 8 characters or more', () => {
    const { credentials } = fixJobSecrets(
      {
        NPM_TOKEN: NPM_SECRET,
        YARN_NPM_ALWAYS_AUTH: 'true',
        NPM_CONFIG_ALWAYS_AUTH: 'false',
        SOME_KEY: '12345678',
        SHORT_TOKEN: 'abc1234',
        QUALOR_PROJECT_KEY: 'core-project',
        CI_REGISTRY_PASSWORD: 'registry-pw-1',
      },
      TOKEN,
    );
    expect(credentials.toSorted()).toEqual([NPM_SECRET, TOKEN, 'registry-pw-1'].toSorted());
  });
});

describe('fixToolEnv and fixJobSecrets: the Azure Pipelines credentials', () => {
  const TOKEN = ['qlr', 'prj', 'T0KEN', 'azure'].join('_');
  const AZURE_SECRETS: Record<string, string> = {
    SYSTEM_ACCESSTOKEN: ['sys', 'S3CR3T', 'v4lue', '1'].join('_'),
    AZURE_DEVOPS_EXT_PAT: ['azd', 'S3CR3T', 'v4lue', '2'].join('_'),
    SECRET_QUALOR_TOKEN: ['sec', 'S3CR3T', 'v4lue', '3'].join('_'),
    AGENT_JOBACCESSTOKEN: ['agt', 'S3CR3T', 'v4lue', '4'].join('_'),
    VSTS_AGENT_INPUT_TOKEN: ['vsts', 'S3CR3T', 'v4lue', '5'].join('_'),
    ENDPOINT_AUTH_PARAMETER_X_PASSWORD: ['ep', 'S3CR3T', 'v4lue', '6'].join('_'),
  };
  const AZURE_KEPT: Record<string, string> = {
    SYSTEM_TEAMPROJECT: 'acme',
    BUILD_SOURCEBRANCH: 'refs/heads/main',
    AGENT_TEMPDIRECTORY: '/agent/_temp',
  };

  it('drops each Azure credential variable and scrubs its value', () => {
    const env = { ...AZURE_SECRETS, ...AZURE_KEPT };
    const out = fixToolEnv(env);
    for (const name of Object.keys(AZURE_SECRETS)) expect(out, name).not.toHaveProperty(name);
    expect(out).toEqual(AZURE_KEPT);
    const { scrub } = fixJobSecrets(env, TOKEN);
    expect(scrub).toEqual(expect.arrayContaining(Object.values(AZURE_SECRETS)));
    for (const value of Object.values(AZURE_KEPT)) expect(scrub).not.toContain(value);
  });
});
