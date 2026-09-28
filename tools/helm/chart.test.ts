import { readFileSync } from 'node:fs';
import { Ajv } from 'ajv';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

const CHART = 'deploy/helm/qualor';
const schema = JSON.parse(readFileSync(`${CHART}/values.schema.json`, 'utf8')) as object;
const defaults = parse(readFileSync(`${CHART}/values.yaml`, 'utf8')) as Record<string, unknown>;
const validate = new Ajv({ allErrors: true, strict: false }).compile(schema);

/** Deep merge of plain objects, arrays and scalars replaced, as Helm merges values files. */
function merge(a: unknown, b: unknown): unknown {
  if (typeof a !== 'object' || a === null || Array.isArray(a)) return b;
  if (typeof b !== 'object' || b === null || Array.isArray(b)) return b;
  const out: Record<string, unknown> = { ...(a as Record<string, unknown>) };
  for (const [k, v] of Object.entries(b)) out[k] = merge(out[k], v);
  return out;
}
const withValues = (over: unknown): unknown => merge(defaults, over);
const ok = (values: unknown): boolean => validate(values) === true;

describe('Chart.yaml (release.md §6.1, ruling RE6)', () => {
  it('is a v2 application chart named qualor whose version equals its appVersion', () => {
    const chart = parse(readFileSync(`${CHART}/Chart.yaml`, 'utf8')) as Record<string, string>;
    expect(chart).toMatchObject({
      apiVersion: 'v2',
      name: 'qualor',
      type: 'application',
      kubeVersion: '>=1.29.0-0',
    });
    expect(chart['version']).toBe(chart['appVersion']);
  });
});

describe('values.schema.json (release.md §6.3)', () => {
  it('accepts the defaults and every ci/ values file', () => {
    expect(ok(defaults), JSON.stringify(validate.errors)).toBe(true);
    for (const mode of ['embedded', 'external', 'bundled']) {
      const file = parse(readFileSync(`${CHART}/ci/${mode}-values.yaml`, 'utf8')) as unknown;
      expect(ok(withValues(file)), `${mode}: ${JSON.stringify(validate.errors)}`).toBe(true);
    }
  });

  it('accepts the global values Helm passes to every chart', () => {
    expect(ok(withValues({ global: {} })), JSON.stringify(validate.errors)).toBe(true);
  });

  it.each([
    ['an unknown top-level key', { replicas: 2 }],
    ['an unknown nested key', { image: { name: 'x' } }],
    ['an unknown database mode', { database: { mode: 'sqlite' } }],
    ['a digest that is not sha256', { image: { digest: 'md5:abc' } }],
    ['a short digest', { image: { digest: 'sha256:abc' } }],
    ['a secret key under 32 characters', { secrets: { secretKey: 'short' } }],
    [
      'a bootstrap password under 12 characters',
      { secrets: { bootstrapAdminPassword: 'elevenchars' } },
    ],
    ['a non-hex bundled password', { database: { bundled: { password: 'not hex at all!' } } }],
    ['trustProxy "true" (the server rejects it)', { config: { trustProxy: 'true' } }],
    ['a log level the server does not know', { config: { logLevel: 'trace' } }],
    ['replicaCount 0', { replicaCount: 0 }],
    ['a nodePort outside 30000-32767', { service: { type: 'NodePort', nodePort: 8080 } }],
    ['a worker concurrency of 0', { config: { workerConcurrency: 0 } }],
    // release.md §2 and install-server.md: never latest, for the server or the bundled PostgreSQL.
    ['the server tag latest', { image: { tag: 'latest' } }],
    ['the server tag Latest', { image: { tag: 'Latest' } }],
    ['the bundled PostgreSQL tag latest', { database: { bundled: { image: { tag: 'latest' } } } }],
    ['a non-object global', { global: 'x' }],
    // The server's own bounds (server/src/config.ts), so the pod never fails at start-up.
    ['a worker concurrency over 32', { config: { workerConcurrency: 33 } }],
    ['a trustProxy hop count of 0', { config: { trustProxy: '0' } }],
    ['a trustProxy hop count over 100', { config: { trustProxy: '101' } }],
    ['a trustProxy that is no address list', { config: { trustProxy: 'my proxy' } }],
    ['a trustProxy list with an empty entry', { config: { trustProxy: '10.0.0.1,,10.0.0.2' } }],
    ['a trustProxy address that is no IP', { config: { trustProxy: '10x0x0x1' } }],
    ['a username with a space', { config: { bootstrapAdminUsername: 'the admin' } }],
    ['a username over 64 characters', { config: { bootstrapAdminUsername: 'a'.repeat(65) } }],
    ['an empty CA key', { database: { external: { caKey: '' } } }],
    ['a CA key with a slash', { database: { external: { caKey: '../ca.crt' } } }],
    ['a non-boolean networkPolicy.enabled', { networkPolicy: { enabled: 'yes' } }],
    ['a forcePasswordSignIn that is not a boolean', { config: { forcePasswordSignIn: 'true' } }],
    ['an unknown networkPolicy key', { networkPolicy: { enabled: true, deny: true } }],
    ['networkPolicy.ingressFrom that is not a list', { networkPolicy: { ingressFrom: {} } }],
  ])('rejects %s', (_what, over) => {
    expect(ok(withValues(over))).toBe(false);
  });

  it.each([
    ['a trustProxy hop count of 1', { config: { trustProxy: '1' } }],
    ['a trustProxy hop count of 100', { config: { trustProxy: '100' } }],
    [
      'a trustProxy list of addresses, CIDRs and presets',
      { config: { trustProxy: '10.0.0.0/8, 192.168.1.10,fd00::/8, loopback' } },
    ],
    ['a worker concurrency of 32', { config: { workerConcurrency: 32 } }],
    [
      'single sign-on settings',
      { config: { ssoInternalHosts: 'keycloak.corp:8443', forcePasswordSignIn: true } },
    ],
    [
      'a username of 64 allowed characters',
      { config: { bootstrapAdminUsername: 'a._-Z9'.repeat(10) + 'abcd' } },
    ],
    [
      'an external database with a private CA',
      {
        database: {
          mode: 'external',
          external: { existingSecret: 'db', caSecret: 'db-ca', caKey: 'root.pem' },
        },
      },
    ],
    [
      'a NetworkPolicy with peers and egress rules',
      {
        networkPolicy: {
          enabled: true,
          ingressFrom: [
            {
              namespaceSelector: {
                matchLabels: { 'kubernetes.io/metadata.name': 'ingress-nginx' },
              },
            },
          ],
          egress: [
            { to: [{ ipBlock: { cidr: '10.0.0.0/8' } }], ports: [{ port: 443, protocol: 'TCP' }] },
          ],
        },
      },
    ],
  ])('accepts %s', (_what, over) => {
    expect(ok(withValues(over)), JSON.stringify(validate.errors)).toBe(true);
  });

  it('pins the bundled PostgreSQL by the digest deploy/docker-compose.yml uses', () => {
    const compose = readFileSync('deploy/docker-compose.yml', 'utf8');
    const pinned = /image: (postgres:[^@\s]+)@(sha256:[0-9a-f]{64})/.exec(compose);
    const pg = (defaults['database'] as { bundled: { image: Record<string, string> } }).bundled
      .image;
    expect(`${pg['repository']}:${pg['tag']}`).toBe(pinned?.[1]);
    expect(pg['digest']).toBe(pinned?.[2]);
  });

  it('defaults to the embedded database, one replica, no secrets and qualor/server at the app version', () => {
    expect(defaults).toMatchObject({
      image: { repository: 'qualor/server', tag: '', digest: '' },
      replicaCount: 1,
      database: { mode: 'embedded' },
      secrets: { existingSecret: '', secretKey: '', bootstrapAdminPassword: '' },
      networkPolicy: { enabled: false, ingressFrom: [], egress: [] },
    });
  });

  it('gives the bundled PostgreSQL requests and a memory limit by default', () => {
    expect(defaults).toMatchObject({
      database: {
        external: { caSecret: '', caKey: 'ca.crt' },
        bundled: {
          resources: { requests: { cpu: '100m', memory: '256Mi' }, limits: { memory: '1Gi' } },
        },
      },
    });
  });
});
