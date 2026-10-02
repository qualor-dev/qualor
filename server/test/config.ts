import type { Config } from '../src/config';

const MiB = 1024 * 1024;

export function testConfig(overrides: Partial<Config> = {}): Config {
  return {
    databaseUrl: 'postgres://unused@127.0.0.1:1/unused',
    embedded: { dataDir: '/var/lib/qualor', postgresDir: '/opt/postgresql' },
    secretKey: 'test-secret-key-that-is-at-least-32-characters',
    host: '127.0.0.1',
    port: 0,
    logLevel: 'silent',
    trustProxy: false,
    bootstrapAdmin: { username: 'admin', password: undefined },
    sessionTtlHours: 168,
    upload: { maxCompressedBytes: 50 * MiB, maxDecompressedBytes: 500 * MiB },
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
    ...overrides,
  };
}
