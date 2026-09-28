import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import {
  CHART_DIR,
  helmLint,
  helmNotes,
  helmTemplate,
  podSpecs,
  type K8sObject,
  type RenderResult,
} from './render';

const chart = parse(readFileSync(`${CHART_DIR}/Chart.yaml`, 'utf8')) as { appVersion: string };
const appVersion = chart.appVersion;
const MODES = ['embedded', 'external', 'bundled'] as const;

function render(files: string[], over: Record<string, unknown> = {}): K8sObject[] {
  const r: RenderResult = helmTemplate(files, over);
  if (!r.ok) throw new Error(r.error);
  return r.objects;
}
const kinds = (objects: K8sObject[]): string[] =>
  objects.map((o) => `${o.kind}/${o.metadata.name}`).sort();
function find(objects: K8sObject[], kind: string, name: string): K8sObject {
  const o = objects.find((x) => x.kind === kind && x.metadata.name === name);
  if (!o) throw new Error(`no ${kind}/${name} in ${kinds(objects).join(', ')}`);
  return o;
}
const server = (o: K8sObject) => o.spec?.template?.spec.containers.find((c) => c.name === 'server');
const env = (o: K8sObject, name: string) => server(o)?.env?.find((e) => e.name === name);
const EMBEDDED = ['ci/embedded-values.yaml'];

describe('helm lint (release.md §15 item 3)', () => {
  it.each(MODES)('passes --strict with ci/%s-values.yaml', (mode) => {
    const r = helmLint(`ci/${mode}-values.yaml`);
    expect(r.code, r.stdout + r.stderr).toBe(0);
  });
});

describe('database modes (release.md §6.2)', () => {
  it('embedded: one StatefulSet with its data claim, kept on uninstall, and an empty DATABASE_URL', () => {
    const objects = render(EMBEDDED);
    expect(kinds(objects)).toEqual([
      'Pod/qualor-test-ready',
      'Secret/qualor-secrets',
      'Service/qualor',
      'Service/qualor-headless',
      'ServiceAccount/qualor',
      'StatefulSet/qualor',
    ]);
    const sts = find(objects, 'StatefulSet', 'qualor');
    expect(sts.spec?.replicas).toBe(1);
    expect(sts.spec?.serviceName).toBe('qualor-headless');
    expect(sts.spec?.persistentVolumeClaimRetentionPolicy).toEqual({
      whenDeleted: 'Retain',
      whenScaled: 'Retain',
    });
    expect(sts.spec?.volumeClaimTemplates?.[0]?.metadata.name).toBe('data');
    expect(sts.spec?.volumeClaimTemplates?.[0]?.spec.resources.requests.storage).toBe('10Gi');
    expect(env(sts, 'DATABASE_URL')).toEqual({ name: 'DATABASE_URL', value: '' });
    expect(server(sts)?.volumeMounts).toContainEqual({
      name: 'data',
      mountPath: '/var/lib/qualor',
    });
  });

  it('external: a Deployment with DATABASE_URL from the named Secret, and no Secret of its own', () => {
    const objects = render(['ci/external-values.yaml']);
    const dep = find(objects, 'Deployment', 'qualor');
    expect(dep.spec?.replicas).toBe(2);
    expect(env(dep, 'DATABASE_URL')?.valueFrom?.secretKeyRef).toEqual({
      name: 'qualor-database',
      key: 'DATABASE_URL',
    });
    expect(env(dep, 'QUALOR_SECRET_KEY')?.valueFrom?.secretKeyRef).toEqual({
      name: 'qualor-secrets',
      key: 'QUALOR_SECRET_KEY',
    });
    expect(objects.some((o) => o.kind === 'Secret' || o.kind === 'StatefulSet')).toBe(false);
    expect(env(dep, 'QUALOR_PUBLIC_URL')?.value).toBe('https://qualor.example.test');
    expect(env(dep, 'QUALOR_TRUST_PROXY')?.value).toBe('1');
    // An empty setting is not set at all (the server's defaults apply).
    expect(env(dep, 'QUALOR_SCM_INTERNAL_HOSTS')).toBeUndefined();
    expect(env(dep, 'QUALOR_SSO_INTERNAL_HOSTS')).toBeUndefined();
    expect(env(dep, 'QUALOR_FORCE_PASSWORD_SIGN_IN')).toBeUndefined();
    expect(server(dep)?.volumeMounts?.some((m) => m.mountPath === '/var/lib/qualor')).toBe(false);
  });

  it('single sign-on: ssoInternalHosts and forcePasswordSignIn become their variables', () => {
    const sts = find(
      render(EMBEDDED, {
        config: { ssoInternalHosts: 'keycloak.corp:8443', forcePasswordSignIn: true },
      }),
      'StatefulSet',
      'qualor',
    );
    expect(env(sts, 'QUALOR_SSO_INTERNAL_HOSTS')?.value).toBe('keycloak.corp:8443');
    expect(env(sts, 'QUALOR_FORCE_PASSWORD_SIGN_IN')?.value).toBe('true');
  });

  it('bundled: PostgreSQL pinned by digest, and DATABASE_URL built from its password after it', () => {
    const objects = render(['ci/bundled-values.yaml']);
    const pg = find(objects, 'StatefulSet', 'qualor-postgres');
    expect(pg.spec?.template?.spec.containers[0]?.image).toBe(
      'postgres:18.6-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873',
    );
    find(objects, 'Service', 'qualor-postgres');
    find(objects, 'Secret', 'qualor-postgres');
    const dep = find(objects, 'Deployment', 'qualor');
    const names = server(dep)?.env?.map((e) => e.name) ?? [];
    expect(names.indexOf('POSTGRES_PASSWORD')).toBeGreaterThan(-1);
    expect(names.indexOf('POSTGRES_PASSWORD')).toBeLessThan(names.indexOf('DATABASE_URL'));
    expect(env(dep, 'DATABASE_URL')?.value).toBe(
      'postgres://qualor:$(POSTGRES_PASSWORD)@qualor-postgres:5432/qualor',
    );
    const ingress = JSON.stringify(find(objects, 'Ingress', 'qualor').spec);
    expect(ingress).toContain('qualor.example.test');
    expect(ingress).toContain('qualor-tls');
  });
});

describe('security (release.md §6.4)', () => {
  it.each(MODES)('%s: every pod and container is locked down', (mode) => {
    const pods = podSpecs(render([`ci/${mode}-values.yaml`]));
    expect(pods.length).toBeGreaterThan(0);
    for (const { owner, spec } of pods) {
      expect(spec.automountServiceAccountToken, owner).toBe(false);
      expect(spec.enableServiceLinks, owner).toBe(false);
      expect(spec.securityContext, owner).toMatchObject({
        runAsNonRoot: true,
        seccompProfile: { type: 'RuntimeDefault' },
      });
      const tmp = spec.volumes?.find((v) => v.name === 'tmp');
      expect(tmp?.emptyDir?.sizeLimit, owner).toMatch(/^\d+Mi$/);
      for (const c of [...(spec.initContainers ?? []), ...spec.containers]) {
        expect(c.securityContext, `${owner} ${c.name}`).toEqual({
          allowPrivilegeEscalation: false,
          readOnlyRootFilesystem: true,
          capabilities: { drop: ['ALL'] },
        });
        expect(c.volumeMounts, `${owner} ${c.name}`).toContainEqual({
          name: 'tmp',
          mountPath: '/tmp',
        });
      }
    }
  });

  it('keeps the pod name stable and does not re-chown the data volume on every mount', () => {
    const sts = find(render(EMBEDDED), 'StatefulSet', 'qualor');
    expect(sts.kind).toBe('StatefulSet');
    expect(sts.spec?.template?.spec.securityContext).toMatchObject({
      runAsUser: 65532,
      runAsGroup: 65532,
      fsGroup: 65532,
      fsGroupChangePolicy: 'OnRootMismatch',
    });
  });

  it('probes /readyz at start-up for up to 150 s, then /readyz and /healthz, and waits 60 s on stop', () => {
    const sts = find(render(EMBEDDED), 'StatefulSet', 'qualor');
    const c = server(sts);
    expect(c?.startupProbe).toMatchObject({
      httpGet: { path: '/readyz' },
      periodSeconds: 5,
      failureThreshold: 30,
    });
    expect(c?.readinessProbe?.httpGet?.path).toBe('/readyz');
    expect(c?.livenessProbe?.httpGet?.path).toBe('/healthz');
    expect(sts.spec?.template?.spec.terminationGracePeriodSeconds).toBe(60);
  });
});

describe('images (release.md §6.3, ruling RE6)', () => {
  it('uses qualor/server at the app version by default, and repository@digest when a digest is set', () => {
    expect(server(find(render(EMBEDDED), 'StatefulSet', 'qualor'))?.image).toBe(
      `qualor/server:${appVersion}`,
    );
    const digest = `sha256:${'b'.repeat(64)}`;
    const pinned = render(EMBEDDED, { image: { digest, tag: 'ignored' } });
    expect(server(find(pinned, 'StatefulSet', 'qualor'))?.image).toBe(`qualor/server@${digest}`);
  });

  it('never renders a latest tag or an unpinned third-party image', () => {
    for (const mode of MODES) {
      const pods = podSpecs(render([`ci/${mode}-values.yaml`]));
      expect(pods.length, mode).toBeGreaterThan(0);
      for (const { spec } of pods) {
        for (const c of [...(spec.initContainers ?? []), ...spec.containers]) {
          expect(c.image).not.toMatch(/:latest(@|$)/);
          if (!c.image.startsWith('qualor/server'))
            expect(c.image).toMatch(/@sha256:[0-9a-f]{64}$/);
        }
      }
    }
  });
});

describe('secrets (release.md §6.4)', () => {
  it('restarts the pods when a chart-managed secret changes', () => {
    const sum = (o: K8sObject) => o.spec?.template?.metadata?.annotations?.['checksum/secret'];
    const a = find(render(EMBEDDED), 'StatefulSet', 'qualor');
    const other = { secrets: { secretKey: 'another-value-another-value-another-value' } };
    const b = find(render(EMBEDDED, other), 'StatefulSet', 'qualor');
    expect(sum(a)).toMatch(/^[0-9a-f]{64}$/);
    expect(sum(b)).not.toBe(sum(a));
  });
});

describe('render-time checks (release.md §6.5)', () => {
  function fails(files: string[], over: Record<string, unknown>): string {
    const r = helmTemplate(files, over);
    if (r.ok) throw new Error('rendered, but should have failed');
    return r.error;
  }

  it('fails embedded mode with more than one replica, naming external mode', () => {
    expect(fails(EMBEDDED, { replicaCount: 3 })).toContain(
      'database.mode=embedded runs one server per volume: set replicaCount to 1, or use database.mode=external',
    );
  });

  it('fails without secrets', () => {
    expect(fails([], {})).toContain(
      'set secrets.existingSecret, or both secrets.secretKey (32+ characters) and secrets.bootstrapAdminPassword (12+)',
    );
  });

  it('fails external mode without its database Secret', () => {
    expect(fails(EMBEDDED, { database: { mode: 'external' } })).toContain(
      'database.mode=external needs database.external.existingSecret (a Secret holding DATABASE_URL)',
    );
  });

  it('fails bundled mode without a password', () => {
    expect(fails(EMBEDDED, { database: { mode: 'bundled' } })).toContain(
      'database.mode=bundled needs database.bundled.existingSecret or database.bundled.password (hex)',
    );
  });

  it('fails an ingress without a host', () => {
    expect(fails(EMBEDDED, { ingress: { enabled: true } })).toContain(
      'ingress.enabled needs ingress.host',
    );
  });

  it('lets Helm enforce values.schema.json', () => {
    expect(fails(EMBEDDED, { config: { trustProxy: 'true' } })).toMatch(/schema/i);
  });
});

describe('the test hook (release.md §6.6)', () => {
  it('fetches /readyz of the Service from the server image', () => {
    const pod = find(render(EMBEDDED), 'Pod', 'qualor-test-ready');
    expect(pod.metadata.annotations?.['helm.sh/hook']).toBe('test');
    const c = pod.spec?.containers?.[0];
    expect(c?.image).toBe(`qualor/server:${appVersion}`);
    expect(c?.command?.join(' ')).toContain("fetch('http://qualor:8080/readyz')");
  });
});

describe('Helm global values (the Task 2 probe)', () => {
  it('renders with the global key Helm passes to every chart', () => {
    expect(kinds(render(EMBEDDED, { global: { imageRegistry: 'x' } }))).toContain(
      'StatefulSet/qualor',
    );
  });
});

describe('image refusals (release.md §2, §5)', () => {
  function fails(over: Record<string, unknown>, flags: string[] = []): string {
    const r = helmTemplate(EMBEDDED, over, flags);
    if (r.ok) throw new Error('rendered, but should have failed');
    return r.error;
  }
  const SKIP = ['--skip-schema-validation'];

  it('refuses a latest tag through the schema, and in the template when the schema is skipped', () => {
    expect(fails({ image: { tag: 'latest' } })).toMatch(/schema/i);
    expect(fails({ image: { tag: 'latest' } }, SKIP)).toContain(
      'image.tag latest is refused: set a release version, or image.digest',
    );
    expect(fails({ image: { tag: 'LATEST' } }, SKIP)).toContain('image.tag latest is refused');
    const bundled = {
      database: {
        mode: 'bundled',
        bundled: { password: 'a'.repeat(32), image: { tag: 'latest' } },
      },
    };
    expect(fails(bundled)).toMatch(/schema/i);
    expect(fails(bundled, SKIP)).toContain('database.bundled.image.tag latest is refused');
  });

  it('refuses the bundled PostgreSQL without its digest, and a malformed server digest', () => {
    expect(
      fails({
        database: { mode: 'bundled', bundled: { password: 'a'.repeat(32), image: { digest: '' } } },
      }),
    ).toContain('database.bundled.image.digest must pin the bundled PostgreSQL (sha256:<64 hex>)');
    expect(fails({ image: { digest: 'sha256:abc' } }, SKIP)).toContain(
      'image.digest must be sha256:<64 hex>',
    );
  });
});

describe('secrets never in plain text (release.md §6.4)', () => {
  const SECRET_KEY = 'not-a-secret-not-a-secret-not-a-secret';
  const PASSWORD = 'not-a-password';
  const BUNDLED = 'a'.repeat(32);

  it.each(MODES)(
    '%s: no ConfigMap, and no rendered object holds a secret value in clear',
    (mode) => {
      const objects = render([`ci/${mode}-values.yaml`]);
      expect(objects.length).toBeGreaterThan(0);
      expect(objects.some((o) => o.kind === 'ConfigMap')).toBe(false);
      const text = JSON.stringify(objects);
      for (const secret of [SECRET_KEY, PASSWORD, BUNDLED]) expect(text).not.toContain(secret);
      for (const s of objects.filter((o) => o.kind === 'Secret')) {
        // Only base64 `data`, never `stringData`.
        expect(Object.keys(s)).not.toContain('stringData');
      }
    },
  );

  it.each(MODES)('%s: NOTES.txt names no secret value', (mode) => {
    const notes = helmNotes([`ci/${mode}-values.yaml`]);
    expect(notes).toContain('bootstrap password');
    for (const secret of [SECRET_KEY, PASSWORD, BUNDLED]) {
      expect(notes).not.toContain(secret);
      expect(notes).not.toContain(Buffer.from(secret).toString('base64'));
    }
  });

  it('never mounts the service account token, on the pods or the ServiceAccount', () => {
    const sa = find(render(EMBEDDED), 'ServiceAccount', 'qualor') as K8sObject & {
      automountServiceAccountToken?: boolean;
    };
    expect(sa.automountServiceAccountToken).toBe(false);
  });
});

describe('fix wave: the bundled PostgreSQL (release.md §6.2, §6.4)', () => {
  const objects = render(['ci/bundled-values.yaml']);
  const pgImage =
    'postgres:18.6-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873';

  it('governs the StatefulSet with a headless Service', () => {
    const svc = find(objects, 'Service', 'qualor-postgres');
    expect(svc.spec?.['clusterIP']).toBe('None');
    expect(find(objects, 'StatefulSet', 'qualor-postgres').spec?.serviceName).toBe(
      'qualor-postgres',
    );
  });

  it('gives PostgreSQL a start-up and a liveness probe, and requests with a memory limit', () => {
    const c = find(objects, 'StatefulSet', 'qualor-postgres').spec?.template?.spec.containers[0];
    expect(c?.startupProbe?.exec?.command).toContain('pg_isready');
    expect(c?.startupProbe).toMatchObject({ periodSeconds: 5, failureThreshold: 60 });
    expect(c?.livenessProbe?.exec?.command).toContain('pg_isready');
    expect(c?.livenessProbe).toMatchObject({ periodSeconds: 20, failureThreshold: 6 });
    expect(c?.resources).toEqual({
      requests: { cpu: '100m', memory: '256Mi' },
      limits: { memory: '1Gi' },
    });
  });

  it('starts the server only once PostgreSQL answers, instead of crash-looping', () => {
    const spec = find(objects, 'Deployment', 'qualor').spec?.template?.spec;
    expect(spec?.initContainers?.map((c) => c.name)).toEqual(['wait-for-postgres']);
    const wait = spec?.initContainers?.[0];
    expect(wait?.image).toBe(pgImage);
    const script = [...(wait?.command ?? []), ...(wait?.args ?? [])].join(' ');
    expect(script).toContain('pg_isready -h qualor-postgres -p 5432');
    expect(script).toMatch(/until .* do sleep 2; done/);
    expect(wait?.resources?.limits?.['memory']).toBeDefined();
    for (const mode of ['embedded', 'external']) {
      const other = render([`ci/${mode}-values.yaml`]);
      const w = other.find((o) => o.kind === 'StatefulSet' || o.kind === 'Deployment');
      expect(w?.spec?.template?.spec.initContainers, mode).toBeUndefined();
    }
  });

  it('restarts the servers when the chart-managed PostgreSQL password changes', () => {
    const sum = (o: K8sObject) => o.spec?.template?.metadata?.annotations?.['checksum/secret'];
    const other = render(['ci/bundled-values.yaml'], {
      database: { bundled: { password: 'b'.repeat(32) } },
    });
    expect(sum(find(other, 'Deployment', 'qualor'))).not.toBe(
      sum(find(objects, 'Deployment', 'qualor')),
    );
  });
});

describe('fix wave: the test hook (release.md §6.6)', () => {
  it('has requests, a memory limit and its own component label', () => {
    const pod = find(render(EMBEDDED), 'Pod', 'qualor-test-ready');
    expect(pod.metadata.labels?.['app.kubernetes.io/component']).toBe('test');
    expect(pod.spec?.containers?.[0]?.resources).toEqual({
      requests: { cpu: '10m', memory: '32Mi' },
      limits: { memory: '128Mi' },
    });
  });
});

describe('fix wave: names (release.md §6.1)', () => {
  it('cuts the full name to 43 characters, so every StatefulSet name fits 52', () => {
    const release = `r${'x'.repeat(52)}`;
    const r = helmTemplate(['ci/bundled-values.yaml'], {}, [], release);
    if (!r.ok) throw new Error(r.error);
    const sts = r.objects.filter((o) => o.kind === 'StatefulSet');
    expect(sts.map((o) => o.metadata.name)).toEqual([`${release.slice(0, 43)}-postgres`]);
    for (const o of r.objects) expect(o.metadata.name.length, o.metadata.name).toBeLessThan(64);
  });
});

describe('fix wave: NOTES.txt', () => {
  it('shows https only when the ingress has TLS', () => {
    const host = 'qualor.example.test';
    const tls = helmNotes(['ci/bundled-values.yaml']);
    expect(tls).toContain(`https://${host}`);
    const plain = helmNotes(['ci/bundled-values.yaml'], { ingress: { tls: { secretName: '' } } });
    expect(plain).toContain(`http://${host}`);
    expect(plain).not.toContain(`https://${host}`);
  });
});

describe('fix wave: a private CA for the external database (release.md §6.2)', () => {
  const EXTERNAL = ['ci/external-values.yaml'];
  const ca = { database: { external: { caSecret: 'db-ca', caKey: 'root.pem' } } };

  it('mounts only the CA key, read-only, and points NODE_EXTRA_CA_CERTS at it', () => {
    const dep = find(render(EXTERNAL, ca), 'Deployment', 'qualor');
    const spec = dep.spec?.template?.spec;
    expect(spec?.volumes).toContainEqual({
      name: 'database-ca',
      secret: { secretName: 'db-ca', items: [{ key: 'root.pem', path: 'ca.crt' }] },
    });
    expect(server(dep)?.volumeMounts).toContainEqual({
      name: 'database-ca',
      mountPath: '/etc/qualor/database-ca',
      readOnly: true,
    });
    expect(env(dep, 'NODE_EXTRA_CA_CERTS')).toEqual({
      name: 'NODE_EXTRA_CA_CERTS',
      value: '/etc/qualor/database-ca/ca.crt',
    });
  });

  it('adds nothing without a CA Secret', () => {
    const dep = find(render(EXTERNAL), 'Deployment', 'qualor');
    expect(env(dep, 'NODE_EXTRA_CA_CERTS')).toBeUndefined();
    expect(dep.spec?.template?.spec.volumes?.map((v) => v.name)).toEqual(['tmp']);
  });
});

describe('fix wave: more render-time checks (release.md §6.5)', () => {
  const SKIP = ['--skip-schema-validation'];
  function fails(files: string[], over: Record<string, unknown>, flags: string[] = []): string {
    const r = helmTemplate(files, over, flags);
    if (r.ok) throw new Error('rendered, but should have failed');
    return r.error;
  }

  it('refuses an unknown database mode even without the schema', () => {
    expect(fails(EMBEDDED, { database: { mode: 'sqlite' } }, SKIP)).toContain(
      'database.mode must be embedded, external or bundled',
    );
  });

  it('refuses a CA Secret outside external mode, and a second NODE_EXTRA_CA_CERTS', () => {
    expect(fails(EMBEDDED, { database: { external: { caSecret: 'db-ca' } } })).toContain(
      'database.external.caSecret needs database.mode=external',
    );
    expect(
      fails(['ci/external-values.yaml'], {
        database: { external: { caSecret: 'db-ca' } },
        extraEnv: [{ name: 'NODE_EXTRA_CA_CERTS', value: '/x.pem' }],
      }),
    ).toContain('database.external.caSecret sets NODE_EXTRA_CA_CERTS: remove it from extraEnv');
  });

  it('refuses short secrets and a non-hex bundled password even without the schema', () => {
    const message = 'secrets.secretKey needs 32+ characters and secrets.bootstrapAdminPassword 12+';
    expect(fails(EMBEDDED, { secrets: { secretKey: 'short' } }, SKIP)).toContain(message);
    expect(fails(EMBEDDED, { secrets: { bootstrapAdminPassword: 'eleven-char' } }, SKIP)).toContain(
      message,
    );
    const bundled = { database: { mode: 'bundled', bundled: { password: 'not hex, not hex!' } } };
    expect(fails(EMBEDDED, bundled, SKIP)).toContain(
      'database.bundled.password must be hex (it goes into a URL)',
    );
  });
});

describe('fix wave: NetworkPolicy (ruling R-NP, release.md §6.4)', () => {
  interface Rule {
    from?: object[];
    to?: object[];
    ports?: { port: number | string; protocol?: string }[];
  }
  interface Policy {
    podSelector: { matchLabels: Record<string, string> };
    policyTypes: string[];
    ingress?: Rule[];
    egress?: Rule[];
  }
  const policy = (objects: K8sObject[], name: string) =>
    find(objects, 'NetworkPolicy', name).spec as unknown as Policy;
  const labels = (component: string) => ({
    podSelector: {
      matchLabels: {
        'app.kubernetes.io/name': 'qualor',
        'app.kubernetes.io/instance': 'qualor',
        'app.kubernetes.io/component': component,
      },
    },
  });
  const ON = { networkPolicy: { enabled: true } };

  it.each(MODES)('%s: renders no NetworkPolicy by default', (mode) => {
    expect(render([`ci/${mode}-values.yaml`]).some((o) => o.kind === 'NetworkPolicy')).toBe(false);
  });

  it('embedded: the server accepts only its port, from anywhere, and keeps its egress', () => {
    const objects = render(EMBEDDED, ON);
    expect(objects.filter((o) => o.kind === 'NetworkPolicy')).toHaveLength(1);
    const p = policy(objects, 'qualor');
    expect(p.podSelector).toEqual(labels('server').podSelector);
    expect(p.policyTypes).toEqual(['Ingress']);
    expect(p.ingress).toEqual([{ ports: [{ port: 8080, protocol: 'TCP' }] }]);
  });

  it('bundled: PostgreSQL accepts only the release’s servers, on 5432, and has no egress', () => {
    const p = policy(render(['ci/bundled-values.yaml'], ON), 'qualor-postgres');
    expect(p.podSelector).toEqual(labels('postgres').podSelector);
    expect(p.policyTypes).toEqual(['Ingress', 'Egress']);
    expect(p.ingress).toEqual([
      { from: [labels('server')], ports: [{ port: 5432, protocol: 'TCP' }] },
    ]);
    expect(p.egress ?? []).toEqual([]);
  });

  it('limits the sources to ingressFrom, and always lets the release’s test pod in', () => {
    const peer = { namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'nginx' } } };
    const over = { networkPolicy: { enabled: true, ingressFrom: [peer] } };
    expect(policy(render(EMBEDDED, over), 'qualor').ingress).toEqual([
      { from: [peer, labels('test')], ports: [{ port: 8080, protocol: 'TCP' }] },
    ]);
  });

  it('with egress rules, allows only DNS, the bundled PostgreSQL and those rules', () => {
    const rule = { to: [{ ipBlock: { cidr: '10.0.0.0/8' } }], ports: [{ port: 443 }] };
    const over = { networkPolicy: { enabled: true, egress: [rule] } };
    const dns = {
      ports: [
        { port: 53, protocol: 'UDP' },
        { port: 53, protocol: 'TCP' },
      ],
    };
    const pg = { to: [labels('postgres')], ports: [{ port: 5432, protocol: 'TCP' }] };
    const bundled = policy(render(['ci/bundled-values.yaml'], over), 'qualor');
    expect(bundled.policyTypes).toEqual(['Ingress', 'Egress']);
    expect(bundled.egress).toEqual([dns, pg, rule]);
    expect(policy(render(EMBEDDED, over), 'qualor').egress).toEqual([dns, rule]);
  });
});
