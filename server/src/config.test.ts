import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig } from './config';

const base = {
  DATABASE_URL: 'postgres://q:q@localhost:5432/qualor',
  QUALOR_SECRET_KEY: 'k'.repeat(32),
};

function problems(env: Record<string, string | undefined>): string[] {
  try {
    loadConfig(env);
  } catch (err) {
    if (err instanceof ConfigError) return err.problems;
    throw err;
  }
  return [];
}

describe('loadConfig', () => {
  it('applies the documented defaults', () => {
    expect(loadConfig(base)).toEqual({
      databaseUrl: base.DATABASE_URL,
      embedded: { dataDir: resolve('/var/lib/qualor'), postgresDir: resolve('/opt/postgresql') },
      secretKey: 'k'.repeat(32),
      host: '0.0.0.0',
      port: 8080,
      logLevel: 'info',
      trustProxy: false,
      bootstrapAdmin: { username: 'admin', password: undefined },
      sessionTtlHours: 168,
      upload: { maxCompressedBytes: 52_428_800, maxDecompressedBytes: 524_288_000 },
      workerConcurrency: 1,
      requestTimeoutMs: 300_000,
      maxConcurrentUploads: 4,
      uiDir: null,
      publicUrl: null,
      scmInternalHosts: new Set(),
      llmInternalHosts: new Set(),
      ssoInternalHosts: new Set(),
      forcePasswordSignIn: false,
      license: { text: null, file: null },
      pluginPaths: [],
      demoUser: null,
      telemetry: { enabled: true, url: 'https://qualor.dev/api/telemetry' },
    });
  });

  it('QUALOR_TELEMETRY: on by default, off with false/0/off/no, anything else stops the boot', () => {
    expect(loadConfig(base).telemetry.enabled).toBe(true);
    for (const on of ['true', 'TRUE', '1', 'on', 'yes', '', ' ']) {
      expect(loadConfig({ ...base, QUALOR_TELEMETRY: on }).telemetry.enabled).toBe(true);
    }
    for (const off of ['false', 'False', ' 0 ', 'off', 'NO']) {
      expect(loadConfig({ ...base, QUALOR_TELEMETRY: off }).telemetry.enabled).toBe(false);
    }
    expect(problems({ ...base, QUALOR_TELEMETRY: 'disabled' })).toEqual([
      'QUALOR_TELEMETRY: QUALOR_TELEMETRY must be true or false',
    ]);
  });

  it('QUALOR_TELEMETRY_URL: an http(s) URL, default qualor.dev', () => {
    expect(loadConfig(base).telemetry.url).toBe('https://qualor.dev/api/telemetry');
    expect(
      loadConfig({ ...base, QUALOR_TELEMETRY_URL: 'http://127.0.0.1:4000/t' }).telemetry.url,
    ).toBe('http://127.0.0.1:4000/t');
    expect(problems({ ...base, QUALOR_TELEMETRY_URL: 'ftp://x' })).toEqual([
      'QUALOR_TELEMETRY_URL: must be an http or https URL',
    ]);
  });

  it('reads QUALOR_PUBLIC_URL and QUALOR_SCM_INTERNAL_HOSTS (scm.md §2)', () => {
    const c = loadConfig({
      ...base,
      QUALOR_PUBLIC_URL: 'https://qualor.example.com/q/',
      QUALOR_SCM_INTERNAL_HOSTS: 'GitLab.corp, 10.0.0.5',
    });
    expect(c.publicUrl).toBe('https://qualor.example.com/q');
    expect([...c.scmInternalHosts]).toEqual(['gitlab.corp', '10.0.0.5']);
    expect(loadConfig({ ...base, QUALOR_PUBLIC_URL: ' ' }).publicUrl).toBeNull();
    expect(problems({ ...base, QUALOR_PUBLIC_URL: 'ftp://x' })).toEqual([
      'QUALOR_PUBLIC_URL: must be an http or https URL without credentials, query or fragment',
    ]);
    expect(problems({ ...base, QUALOR_PUBLIC_URL: 'https://x/?a=1' })).toHaveLength(1);
    expect(problems({ ...base, QUALOR_SCM_INTERNAL_HOSTS: 'a/b' })).toEqual([
      'QUALOR_SCM_INTERNAL_HOSTS: "a/b" is not a host name or IP address',
    ]);
  });

  it('reads QUALOR_LLM_INTERNAL_HOSTS like the SCM list (llm.md §4)', () => {
    const c = loadConfig({ ...base, QUALOR_LLM_INTERNAL_HOSTS: 'Ollama:11434, localhost:11434' });
    expect([...c.llmInternalHosts]).toEqual(['ollama:11434', 'localhost:11434']);
    expect(problems({ ...base, QUALOR_LLM_INTERNAL_HOSTS: 'a b' })).toEqual([
      'QUALOR_LLM_INTERNAL_HOSTS: "a b" is not a host name or IP address',
    ]);
    expect([
      ...loadConfig({ ...base, QUALOR_SCM_INTERNAL_HOSTS: 'ollama:11434' }).llmInternalHosts,
    ]).toEqual([]);
  });

  it('resolves QUALOR_UI_DIR to an absolute path and treats an empty value as unset', () => {
    expect(loadConfig({ ...base, QUALOR_UI_DIR: 'ui/dist' }).uiDir).toBe(resolve('ui/dist'));
    expect(loadConfig({ ...base, QUALOR_UI_DIR: '  ' }).uiDir).toBeNull();
  });

  it('requires QUALOR_SECRET_KEY', () => {
    expect(problems({}).map((p) => p.split(':')[0])).toEqual(['QUALOR_SECRET_KEY']);
  });

  it('uses the embedded PostgreSQL without DATABASE_URL, or with an empty one (embedded-postgres.md §2)', () => {
    const rest = { QUALOR_SECRET_KEY: base.QUALOR_SECRET_KEY };
    for (const env of [rest, { ...base, DATABASE_URL: '' }, { ...base, DATABASE_URL: '  ' }]) {
      expect(loadConfig(env).databaseUrl).toBeNull();
    }
    expect(loadConfig(base).databaseUrl).toBe(base.DATABASE_URL);
  });

  it('takes absolute embedded directories and refuses relative ones (embedded-postgres.md §3)', () => {
    const config = loadConfig({ ...base, QUALOR_DATA_DIR: '/data/q', QUALOR_POSTGRES_DIR: '/pg' });
    expect(config.embedded).toEqual({ dataDir: resolve('/data/q'), postgresDir: resolve('/pg') });
    expect(loadConfig({ ...base, QUALOR_DATA_DIR: '' }).embedded.dataDir).toBe(
      resolve('/var/lib/qualor'),
    );
    expect(problems({ ...base, QUALOR_DATA_DIR: 'data', QUALOR_POSTGRES_DIR: './pg' })).toEqual([
      expect.stringContaining('QUALOR_DATA_DIR'),
      expect.stringContaining('QUALOR_POSTGRES_DIR'),
    ]);
  });

  it('parses numbers from strings', () => {
    const c = loadConfig({
      ...base,
      PORT: '9000',
      QUALOR_TRUST_PROXY: '2',
      QUALOR_WORKER_CONCURRENCY: '4',
      QUALOR_REQUEST_TIMEOUT_MS: '60000',
      QUALOR_MAX_CONCURRENT_UPLOADS: '8',
    });
    expect([
      c.port,
      c.trustProxy,
      c.workerConcurrency,
      c.requestTimeoutMs,
      c.maxConcurrentUploads,
    ]).toEqual([9000, 2, 4, 60_000, 8]);
  });

  describe('QUALOR_TRUST_PROXY', () => {
    const trustProxy = (value: string | undefined) =>
      loadConfig({ ...base, QUALOR_TRUST_PROXY: value }).trustProxy;

    it('is off when unset or empty', () => {
      expect(trustProxy(undefined)).toBe(false);
      expect(trustProxy('')).toBe(false);
    });

    it('accepts a hop count (integer >= 1)', () => {
      expect(trustProxy('1')).toBe(1);
      expect(trustProxy(' 3 ')).toBe(3);
    });

    it('accepts a comma-separated list of IPs, CIDRs and proxy-addr presets', () => {
      expect(trustProxy('10.0.0.1, 192.168.0.0/16,::1 ,fd00::/8, loopback')).toEqual([
        '10.0.0.1',
        '192.168.0.0/16',
        '::1',
        'fd00::/8',
        'loopback',
      ]);
    });

    it('rejects true/false (trusting every hop lets any client spoof its address), 0 and junk', () => {
      for (const value of [
        'true',
        'false',
        '0',
        '-1',
        '1.5',
        '10.0.0.1/33',
        'proxy.local',
        '1,,2',
      ]) {
        expect(problems({ ...base, QUALOR_TRUST_PROXY: value }), value).toEqual([
          expect.stringContaining('QUALOR_TRUST_PROXY'),
        ]);
      }
    });
  });

  it('rejects a non-postgres URL, a short secret and a bad port', () => {
    const found = problems({
      DATABASE_URL: 'mysql://x',
      QUALOR_SECRET_KEY: 'short',
      PORT: '70000',
    });
    expect(found.map((p) => p.split(':')[0])).toEqual([
      'DATABASE_URL',
      'QUALOR_SECRET_KEY',
      'PORT',
    ]);
  });

  it('rejects a request timeout of 0 (S11: that would disable the timeout entirely)', () => {
    expect(problems({ ...base, QUALOR_REQUEST_TIMEOUT_MS: '0' })).toEqual([
      expect.stringContaining('QUALOR_REQUEST_TIMEOUT_MS'),
    ]);
  });

  it('caps QUALOR_UPLOAD_MAX_DECOMPRESSED_BYTES at 500 MiB regardless of what is configured (ruling S13 #3)', () => {
    const MiB = 1024 * 1024;
    expect(
      problems({ ...base, QUALOR_UPLOAD_MAX_DECOMPRESSED_BYTES: String(500 * MiB + 1) }),
    ).toEqual([expect.stringContaining('QUALOR_UPLOAD_MAX_DECOMPRESSED_BYTES')]);
    expect(
      loadConfig({ ...base, QUALOR_UPLOAD_MAX_DECOMPRESSED_BYTES: String(500 * MiB) }).upload
        .maxDecompressedBytes,
    ).toBe(500 * MiB);
  });

  it('never echoes secret values in its errors', () => {
    const secret = 'too-short-secret';
    const password = 'shortpw';
    const message = problems({
      ...base,
      QUALOR_SECRET_KEY: secret,
      QUALOR_BOOTSTRAP_ADMIN_PASSWORD: password,
    }).join('\n');
    expect(message).toContain('QUALOR_SECRET_KEY');
    expect(message).toContain('QUALOR_BOOTSTRAP_ADMIN_PASSWORD');
    expect(message).not.toContain(secret);
    expect(message).not.toContain(password);
  });
});

describe('licence and plugin variables (enterprise.md §6, api.md §4.1)', () => {
  it('defaults to no licence and no plugins', () => {
    const config = loadConfig(base);
    expect(config.license).toEqual({ text: null, file: null });
    expect(config.pluginPaths).toEqual([]);
  });

  it('reads QUALOR_LICENSE as text and QUALOR_LICENSE_FILE as an absolute path', () => {
    expect(loadConfig({ ...base, QUALOR_LICENSE: '  QLK1.x.y.z \n' }).license.text).toBe(
      'QLK1.x.y.z',
    );
    expect(
      loadConfig({ ...base, QUALOR_LICENSE_FILE: '/run/secrets/qualor-license' }).license.file,
    ).toBe(resolve('/run/secrets/qualor-license'));
  });

  it('refuses both licence variables at once, naming both', () => {
    expect(() => loadConfig({ ...base, QUALOR_LICENSE: 'a', QUALOR_LICENSE_FILE: '/x' })).toThrow(
      /QUALOR_LICENSE.*QUALOR_LICENSE_FILE/s,
    );
  });

  it('never echoes the key text when it refuses both variables', () => {
    const key = 'QLK1.test-a.secret-payload.secret-signature';
    const message = problems({ ...base, QUALOR_LICENSE: key, QUALOR_LICENSE_FILE: '/x' }).join(
      '\n',
    );
    expect(message).toContain('QUALOR_LICENSE_FILE');
    expect(message).not.toContain('secret-payload');
  });

  it('treats an empty variable as unset', () => {
    expect(loadConfig({ ...base, QUALOR_LICENSE: '', QUALOR_LICENSE_FILE: ' ' }).license).toEqual({
      text: null,
      file: null,
    });
  });

  it('parses QUALOR_PLUGIN_PATHS: absolute .js/.mjs paths, at most 8', () => {
    const abs = resolve('/app/enterprise/plugin.js');
    expect(loadConfig({ ...base, QUALOR_PLUGIN_PATHS: ` ${abs} , ` }).pluginPaths).toEqual([abs]);
    expect(() => loadConfig({ ...base, QUALOR_PLUGIN_PATHS: 'relative/plugin.js' })).toThrow(
      /QUALOR_PLUGIN_PATHS/,
    );
    expect(() => loadConfig({ ...base, QUALOR_PLUGIN_PATHS: resolve('/x/plugin.ts') })).toThrow(
      /QUALOR_PLUGIN_PATHS/,
    );
    const nine = Array.from({ length: 9 }, (_, i) => resolve(`/p/${i}.js`)).join(',');
    expect(() => loadConfig({ ...base, QUALOR_PLUGIN_PATHS: nine })).toThrow(/QUALOR_PLUGIN_PATHS/);
  });
});

describe('SSO variables (sso-scim.md §10.4, §14)', () => {
  it('reads QUALOR_SSO_INTERNAL_HOSTS like the SCM list', () => {
    const config = loadConfig({
      ...base,
      QUALOR_SSO_INTERNAL_HOSTS: 'Keycloak.corp:8443, 127.0.0.1:18080',
    });
    expect([...config.ssoInternalHosts].sort()).toEqual(['127.0.0.1:18080', 'keycloak.corp:8443']);
  });

  it.each([
    [undefined, false],
    ['', false],
    ['false', false],
    ['true', true],
  ])('QUALOR_FORCE_PASSWORD_SIGN_IN=%s is %s', (value, expected) => {
    expect(loadConfig({ ...base, QUALOR_FORCE_PASSWORD_SIGN_IN: value }).forcePasswordSignIn).toBe(
      expected,
    );
  });

  it.each(['TRUE', '1', 'yes', 'on'])(
    'stops the boot on QUALOR_FORCE_PASSWORD_SIGN_IN=%s, naming it',
    (value) => {
      expect(() => loadConfig({ ...base, QUALOR_FORCE_PASSWORD_SIGN_IN: value })).toThrow(
        /QUALOR_FORCE_PASSWORD_SIGN_IN/,
      );
    },
  );
});

describe('QUALOR_DEMO_USER', () => {
  it('is off when unset or blank', () => {
    expect(loadConfig(base).demoUser).toBeNull();
    expect(loadConfig({ ...base, QUALOR_DEMO_USER: '  ' }).demoUser).toBeNull();
  });

  it('reads a username, trimmed', () => {
    expect(loadConfig({ ...base, QUALOR_DEMO_USER: ' guest ' }).demoUser).toBe('guest');
  });

  it('refuses what is not a username', () => {
    expect(() => loadConfig({ ...base, QUALOR_DEMO_USER: 'no spaces' })).toThrow(
      /QUALOR_DEMO_USER/,
    );
  });

  it('refuses the bootstrap administrator', () => {
    expect(() => loadConfig({ ...base, QUALOR_DEMO_USER: 'admin' })).toThrow(
      /QUALOR_DEMO_USER: must not be the bootstrap administrator/,
    );
  });
});
