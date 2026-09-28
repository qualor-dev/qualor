import { describe, expect, it } from 'vitest';
import {
  BACKUP_COMMAND,
  checkIsolation,
  k3sRunArgs,
  K3S_IMAGE,
  NAMESPACE_LABELS,
  netCheckOverrides,
  NODE_PORT,
  parseReach,
  parseShellProbe,
  RESTRICTED_CONTAINER,
  restoreOverrides,
  smokeValues,
  splitImage,
} from './smoke';

const secrets = { secretKey: 'k'.repeat(64), password: 'p'.repeat(24), pgPassword: 'a'.repeat(32) };
const image = { repository: 'qualor/server', tag: 'dev' };

describe('helm smoke (release.md §15 item 4, ruling RE2)', () => {
  it('runs a digest-pinned k3s, publishing only the node port on 127.0.0.1', () => {
    expect(K3S_IMAGE).toMatch(/^rancher\/k3s:v1\.37\.0-k3s1@sha256:[0-9a-f]{64}$/);
    const args = k3sRunArgs('qualor-helm-smoke-ab', 41234);
    expect(args).toContain(`127.0.0.1:41234:${NODE_PORT}`);
    expect(args.filter((a) => a === '-p')).toHaveLength(1);
    expect(args).toContain('--disable=traefik');
    expect(args.indexOf(K3S_IMAGE)).toBeGreaterThan(args.indexOf('--privileged'));
  });

  it('splits an image reference', () => {
    expect(splitImage('qualor/server:dev')).toEqual({ repository: 'qualor/server', tag: 'dev' });
    expect(splitImage('127.0.0.1:5000/qualor/server:1.0.0')).toEqual({
      repository: '127.0.0.1:5000/qualor/server',
      tag: '1.0.0',
    });
  });

  it('restores in a one-off pod on the data claim, as the server user, with the restore command', () => {
    const o = JSON.parse(restoreOverrides('qualor/server:1.0.0')) as {
      spec: { securityContext: object; volumes: object[]; containers: Record<string, unknown>[] };
    };
    expect(o.spec.securityContext).toMatchObject({ runAsUser: 65532, fsGroup: 65532 });
    // Found by the smoke: the default (Always) re-chowns the claim recursively and leaves the
    // cluster group-writable (2770), which PostgreSQL refuses, for the restore and every start after.
    expect(o.spec.securityContext).toMatchObject({ fsGroupChangePolicy: 'OnRootMismatch' });
    expect(o.spec.volumes).toContainEqual({
      name: 'data',
      persistentVolumeClaim: { claimName: 'data-qualor-0' },
    });
    expect(o.spec.containers[0]).toMatchObject({
      image: 'qualor/server:1.0.0',
      args: ['restore'],
      stdin: true,
    });
    expect(restoreOverrides('x')).not.toContain("'"); // it goes inside single quotes in a shell
    expect(BACKUP_COMMAND).toBe(
      '/opt/postgresql/bin/pg_dump -h /var/lib/qualor/run -U qualor -Fc qualor',
    );
  });

  it('never pulls the server image, and exposes it on the node port', () => {
    expect(smokeValues('embedded', image, secrets)).toMatchObject({
      image: { repository: 'qualor/server', tag: 'dev', pullPolicy: 'Never' },
      service: { type: 'NodePort', nodePort: NODE_PORT },
      database: { mode: 'embedded' },
      networkPolicy: { enabled: true },
    });
    expect(smokeValues('bundled', image, secrets)).toMatchObject({
      replicaCount: 2,
      database: { mode: 'bundled', bundled: { password: 'a'.repeat(32) } },
      networkPolicy: { enabled: true },
    });
  });

  it('gives the restore pod the secret key, which main.js restore needs to load its configuration', () => {
    const o = JSON.parse(
      restoreOverrides('qualor/server:1.0.0', 'Never', 'data-q-0', 'q-secrets'),
    ) as {
      spec: { volumes: object[]; containers: Record<string, unknown>[] };
    };
    expect(o.spec.volumes).toContainEqual({
      name: 'data',
      persistentVolumeClaim: { claimName: 'data-q-0' },
    });
    expect(o.spec.containers[0]).toMatchObject({
      imagePullPolicy: 'Never',
      env: [
        {
          name: 'QUALOR_SECRET_KEY',
          valueFrom: { secretKeyRef: { name: 'q-secrets', key: 'QUALOR_SECRET_KEY' } },
        },
      ],
    });
  });

  it('refuses a container whose security settings are not in force', () => {
    const ok = {
      uid: 70,
      gid: 70,
      capEff: '0000000000000000',
      noNewPrivs: '1',
      root: 'EACCES',
      rootMount: 'ro,relatime',
    };
    expect(() => checkIsolation('pg', ok, 70)).not.toThrow();
    expect(() => checkIsolation('pg', { ...ok, uid: 0 }, 70)).toThrow('pg: runs as 0:70');
    expect(() => checkIsolation('pg', { ...ok, capEff: '00000000a80425fb' }, 70)).toThrow(
      'capabilities',
    );
    expect(() => checkIsolation('pg', { ...ok, noNewPrivs: '0' }, 70)).toThrow(
      'may gain privileges',
    );
    expect(() => checkIsolation('pg', { ...ok, root: 'writable' }, 70)).toThrow('root filesystem');
    expect(() =>
      checkIsolation('s', { ...ok, uid: 65532, gid: 65532, root: 'EROFS' }, 65532),
    ).not.toThrow();
  });

  it('accepts a read-only root only when the kernel says so: EROFS, or ro in the mount options of /', () => {
    const base = { uid: 70, gid: 70, capEff: '0000000000000000', noNewPrivs: '1' };
    expect(() =>
      checkIsolation('pg', { ...base, root: 'EROFS', rootMount: 'rw' }, 70),
    ).not.toThrow();
    expect(() =>
      checkIsolation('pg', { ...base, root: 'EACCES', rootMount: 'ro,relatime' }, 70),
    ).not.toThrow();
    // Final review I-3: EACCES only says / belongs to root; the filesystem may well be writable.
    expect(() =>
      checkIsolation('pg', { ...base, root: 'EACCES', rootMount: 'rw,relatime' }, 70),
    ).toThrow(
      'pg: its root filesystem is not proven read-only (write EACCES, / mounted rw,relatime)',
    );
    expect(() => checkIsolation('pg', { ...base, root: 'EACCES', rootMount: '' }, 70)).toThrow(
      'not proven read-only',
    );
    // "ro" must be a whole option, not a substring of another one.
    expect(() =>
      checkIsolation('pg', { ...base, root: 'EACCES', rootMount: 'rw,errors=remount-ro' }, 70),
    ).toThrow('not proven read-only');
  });

  it("reads the bundled PostgreSQL's probe line", () => {
    expect(
      parseShellProbe(
        'uid=70 gid=70 capEff=0000000000000000 noNewPrivs=1 root=EROFS rootMount=ro,relatime\n',
      ),
    ).toEqual({
      uid: 70,
      gid: 70,
      capEff: '0000000000000000',
      noNewPrivs: '1',
      root: 'EROFS',
      rootMount: 'ro,relatime',
    });
  });

  it('installs into namespaces that enforce the restricted Pod Security Standard', () => {
    expect(NAMESPACE_LABELS).toEqual([
      'pod-security.kubernetes.io/enforce=restricted',
      'pod-security.kubernetes.io/warn=restricted',
    ]);
  });

  it('gives the restore pod the full restricted security settings and a /tmp', () => {
    const o = JSON.parse(restoreOverrides('qualor/server:1.0.0')) as {
      spec: {
        enableServiceLinks: boolean;
        automountServiceAccountToken: boolean;
        volumes: object[];
        containers: { securityContext: object; volumeMounts: object[] }[];
      };
    };
    expect(o.spec.enableServiceLinks).toBe(false);
    expect(o.spec.automountServiceAccountToken).toBe(false);
    expect(o.spec.containers[0]?.securityContext).toEqual({
      allowPrivilegeEscalation: false,
      readOnlyRootFilesystem: true,
      capabilities: { drop: ['ALL'] },
    });
    expect(RESTRICTED_CONTAINER).toEqual(o.spec.containers[0]?.securityContext);
    expect(o.spec.volumes).toContainEqual({ name: 'tmp', emptyDir: { sizeLimit: '64Mi' } });
    expect(o.spec.containers[0]?.volumeMounts).toEqual([
      { name: 'data', mountPath: '/var/lib/qualor' },
      { name: 'tmp', mountPath: '/tmp' },
    ]);
  });

  it('checks the NetworkPolicy from a pod without the server labels, under the restricted standard', () => {
    const o = JSON.parse(netCheckOverrides('qualor/server:dev', 'qualor-postgres')) as {
      metadata: { labels: Record<string, string> };
      spec: {
        securityContext: object;
        containers: {
          image: string;
          imagePullPolicy: string;
          command: string[];
          securityContext: object;
        }[];
      };
    };
    expect(o.metadata.labels).toEqual({ 'qualor-smoke': 'netcheck' });
    expect(o.spec.securityContext).toMatchObject({
      runAsNonRoot: true,
      seccompProfile: { type: 'RuntimeDefault' },
    });
    const c = o.spec.containers[0];
    expect(c).toMatchObject({ image: 'qualor/server:dev', imagePullPolicy: 'Never' });
    expect(c?.securityContext).toEqual(RESTRICTED_CONTAINER);
    expect(c?.command.join(' ')).toContain("connect(5432,'qualor-postgres')");
  });

  it('reads the reachability line among kubectl output', () => {
    expect(parseReach('open\npod "x" deleted\n')).toBe('open');
    expect(parseReach("If you don't see a command prompt\nblocked\n")).toBe('blocked');
    expect(parseReach('ECONNREFUSED\n')).toBe('ECONNREFUSED');
    expect(parseReach('nothing here')).toBe('');
  });
});
