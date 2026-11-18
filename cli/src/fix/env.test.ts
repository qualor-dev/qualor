import { describe, expect, it } from 'vitest';
import { FIX_DROPPED_ENV, fixToolEnv } from './env';

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

  it('drops whole names only: a prefix rule for QUALOR_ and ACTIONS_, exact names otherwise', () => {
    expect(FIX_DROPPED_ENV.test('QUALOR_ANYTHING')).toBe(true);
    expect(FIX_DROPPED_ENV.test('ACTIONS_STEP_DEBUG')).toBe(true);
    expect(FIX_DROPPED_ENV.test('MY_GITHUB_TOKEN')).toBe(false);
    expect(FIX_DROPPED_ENV.test('CI_JOB_TOKEN_X')).toBe(false);
    expect(fixToolEnv({ MY_GITHUB_TOKEN: 'kept' })).toEqual({ MY_GITHUB_TOKEN: 'kept' });
  });
});
