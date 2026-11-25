import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { loadEnvFiles, loadTarget, qualorIdentityAuth } from './targets.js';

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

describe('qualorIdentityAuth', () => {
  it("builds the weaker identities' credentials; Server has no minimal PAT", () => {
    vi.stubEnv('AZURE_PROBE_TENANT_ID', 'tn');
    vi.stubEnv('AZURE_PROBE_CONTRIBUTOR_TENANT_ID', '');
    vi.stubEnv('AZURE_PROBE_CONTRIBUTOR_CLIENT_ID', 'ccl');
    vi.stubEnv('AZURE_PROBE_CONTRIBUTOR_CLIENT_SECRET', 'csec');
    vi.stubEnv('AZURE_PROBE_MINIMAL_PAT', 'mpat');
    vi.stubEnv('AZURE_PROBE_SERVER_USER_PAT', 'upat');
    expect(qualorIdentityAuth('services', 'contributor')).toEqual({
      kind: 'secret',
      tenantId: 'tn',
      clientId: 'ccl',
      secret: 'csec',
    });
    vi.stubEnv('AZURE_PROBE_CONTRIBUTOR_TENANT_ID', 'tn2');
    expect(qualorIdentityAuth('services', 'contributor')).toMatchObject({ tenantId: 'tn2' });
    expect(qualorIdentityAuth('services', 'minimal-pat')).toEqual({ kind: 'pat', pat: 'mpat' });
    expect(qualorIdentityAuth('server', 'contributor')).toEqual({ kind: 'pat', pat: 'upat' });
    expect(() => qualorIdentityAuth('server', 'minimal-pat')).toThrow(/services only/);
    vi.stubEnv('AZURE_PROBE_MINIMAL_PAT', '');
    expect(() => qualorIdentityAuth('services', 'minimal-pat')).toThrow(/AZURE_PROBE_MINIMAL_PAT/);
  });
});

describe('loadEnvFiles', () => {
  it('throws a clear error when AZURE_PROBE_ENV_FILES is unset', () => {
    vi.stubEnv('AZURE_PROBE_ENV_FILES', '');
    expect(() => loadEnvFiles()).toThrow(/AZURE_PROBE_ENV_FILES/);
  });

  it('keeps the first value of a key: an env file listed first wins (the bench lists bench-2022.env first)', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'probe-env-'));
    try {
      writeFileSync(path.join(dir, 'first.env'), `AZURE_PROBE_TEST_ORDER_ONLY=first\n`);
      writeFileSync(path.join(dir, 'second.env'), `AZURE_PROBE_TEST_ORDER_ONLY=second\n`);
      vi.stubEnv(
        'AZURE_PROBE_ENV_FILES',
        `${path.join(dir, 'first.env')};${path.join(dir, 'second.env')}`,
      );
      loadEnvFiles();
      expect(process.env['AZURE_PROBE_TEST_ORDER_ONLY']).toBe('first');
    } finally {
      delete process.env['AZURE_PROBE_TEST_ORDER_ONLY'];
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('throws when a listed file is missing', () => {
    vi.stubEnv('AZURE_PROBE_ENV_FILES', 'Z:/nope/missing.env');
    expect(() => loadEnvFiles()).toThrow(/missing\.env/);
  });
});
