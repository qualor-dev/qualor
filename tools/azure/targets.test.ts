import { afterEach, describe, expect, it, vi } from 'vitest';
import { loadEnvFiles, loadTarget } from './targets.js';

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('loadTarget', () => {
  it('builds the services target from the environment, choosing the credential kind', () => {
    vi.stubEnv('AZURE_PROBE_SERVICES_URL', 'https://dev.example.invalid/org');
    vi.stubEnv('AZURE_PROBE_SERVICES_PAT', 'pat1');
    vi.stubEnv('AZURE_PROBE_SERVICES_USER_PAT', 'pat2');
    vi.stubEnv('AZURE_PROBE_TENANT_ID', 'tn');
    vi.stubEnv('AZURE_PROBE_CLIENT_ID', 'cl');
    vi.stubEnv('AZURE_PROBE_CLIENT_SECRET', 'sec');
    vi.stubEnv('AZURE_PROBE_HOOK_BASE', 'https://hooks.example.invalid');
    vi.stubEnv('AZURE_PROBE_RECORDER_SECRET', 'rec');
    vi.stubEnv('AZURE_PROBE_PROJECT', 'demo-project');
    const t = loadTarget('services');
    expect(t.baseUrl).toBe('https://dev.example.invalid/org');
    expect(t.project).toBe('demo-project');
    expect(t.auth).toEqual({ kind: 'pat', pat: 'pat1' });
    expect(t.userAuth).toEqual({ kind: 'pat', pat: 'pat2' });
    expect(t.readerAuth).toBeUndefined();
    expect(t.recorderSecret).toBe('rec');
    expect(t.hookBase).toBe('https://hooks.example.invalid');
    expect(loadTarget('services', { auth: 'secret' }).auth).toEqual({
      kind: 'secret',
      tenantId: 'tn',
      clientId: 'cl',
      secret: 'sec',
    });
  });

  it('names the missing variable', () => {
    vi.stubEnv('AZURE_PROBE_HOOK_BASE', 'https://h.example.invalid');
    vi.stubEnv('AZURE_PROBE_RECORDER_SECRET', 'r');
    vi.stubEnv('AZURE_PROBE_PROJECT', '');
    expect(() => loadTarget('server')).toThrow(/AZURE_PROBE_PROJECT/);
    vi.stubEnv('AZURE_PROBE_PROJECT', 'demo-project');
    vi.stubEnv('AZURE_PROBE_SERVER_URL', '');
    expect(() => loadTarget('server')).toThrow(/AZURE_PROBE_SERVER_URL/);
  });
});

describe('loadEnvFiles', () => {
  it('throws a clear error when AZURE_PROBE_ENV_FILES is unset', () => {
    vi.stubEnv('AZURE_PROBE_ENV_FILES', '');
    expect(() => loadEnvFiles()).toThrow(/AZURE_PROBE_ENV_FILES/);
  });

  it('throws when a listed file is missing', () => {
    vi.stubEnv('AZURE_PROBE_ENV_FILES', 'Z:/nope/missing.env');
    expect(() => loadEnvFiles()).toThrow(/missing\.env/);
  });
});
