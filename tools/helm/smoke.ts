import { randomBytes } from 'node:crypto';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { Api, freePort, must, REPO_ROOT, run, SERVER_IMAGE, waitReady } from '../deploy/stack';
import { buildToolbox, runTool, SMOKE_CONTAINER_PREFIX } from '../release/toolbox';

/**
 * `pnpm helm:smoke` (release.md §15 item 4, ruling RE2): installs deploy/helm/qualor on k3s in
 * one privileged Docker container. Embedded mode: ready, `helm test`, sign-in, a project that
 * survives a deleted pod, pg_dump through kubectl exec and a restore that brings back exactly the
 * dumped state, the data claim kept after uninstall. Bundled mode: two replicas, ready,
 * `helm test`, sign-in, and the NetworkPolicy keeps a pod without the server's labels away from
 * PostgreSQL. In both, the namespaces enforce the restricted Pod Security Standard, and the
 * chart's security settings are checked inside the running containers (user, a read-only root
 * proven by the kernel, no capabilities, no new privileges), the bundled PostgreSQL included
 * (release.md §6.8). The cluster container is always removed. Needs a built qualor/server:dev
 * (QUALOR_SERVER_IMAGE). Uses no kube context of this machine: kubectl runs inside the k3s
 * container, Helm gets the copied kubeconfig.
 */
export const K3S_IMAGE =
  'rancher/k3s:v1.37.0-k3s1@sha256:d33b1973401a60410681d66c007f5c3a51d565a7c03608904764aef3321fee4d';
export const NODE_PORT = 30080;
const WORK = path.join(REPO_ROOT, '.tmp', 'helm-smoke');
const KUBECONFIG = '/work/.tmp/helm-smoke/kubeconfig';

export interface SmokeSecrets {
  secretKey: string;
  password: string;
  pgPassword: string;
}

export function k3sRunArgs(name: string, hostPort: number): string[] {
  return [
    'run',
    '-d',
    '--privileged',
    '--name',
    name,
    '--tmpfs',
    '/run',
    '--tmpfs',
    '/var/run',
    '-p',
    `127.0.0.1:${hostPort}:${NODE_PORT}`,
    K3S_IMAGE,
    'server',
    '--disable=traefik',
    '--disable=metrics-server',
    '--write-kubeconfig-mode=644',
  ];
}

export function splitImage(ref: string): { repository: string; tag: string } {
  const i = ref.lastIndexOf(':');
  if (i <= ref.lastIndexOf('/')) return { repository: ref, tag: 'latest' };
  return { repository: ref.slice(0, i), tag: ref.slice(i + 1) };
}

export function smokeValues(
  mode: 'embedded' | 'bundled',
  image: { repository: string; tag: string },
  s: SmokeSecrets,
): Record<string, unknown> {
  const common = {
    image: { ...image, pullPolicy: 'Never' },
    service: { type: 'NodePort', nodePort: NODE_PORT },
    secrets: { secretKey: s.secretKey, bootstrapAdminPassword: s.password },
    resources: { requests: { cpu: '100m', memory: '512Mi' }, limits: { memory: '2Gi' } },
  };
  if (mode === 'embedded') {
    return {
      ...common,
      database: { mode: 'embedded' },
      persistence: { size: '1Gi' },
      networkPolicy: { enabled: true },
    };
  }
  return {
    ...common,
    replicaCount: 2,
    database: {
      mode: 'bundled',
      bundled: { password: s.pgPassword, persistence: { size: '1Gi' } },
    },
    networkPolicy: { enabled: true },
  };
}

/** release.md §6.8: the cluster refuses any pod that does not meet the restricted standard. */
export const NAMESPACE_LABELS = [
  'pod-security.kubernetes.io/enforce=restricted',
  'pod-security.kubernetes.io/warn=restricted',
] as const;

/** The chart's pod and container settings (qualor.podSecurity, qualor.containerSecurity). */
const RESTRICTED_POD = {
  runAsNonRoot: true,
  runAsUser: 65532,
  runAsGroup: 65532,
  fsGroup: 65532,
  fsGroupChangePolicy: 'OnRootMismatch',
  seccompProfile: { type: 'RuntimeDefault' },
};
export const RESTRICTED_CONTAINER = {
  allowPrivilegeEscalation: false,
  readOnlyRootFilesystem: true,
  capabilities: { drop: ['ALL'] },
};
const TMP_VOLUME = { name: 'tmp', emptyDir: { sizeLimit: '64Mi' } };

/** install-server.md, Kubernetes: the backup command, run with `kubectl exec qualor-0 --`. */
export const BACKUP_COMMAND =
  '/opt/postgresql/bin/pg_dump -h /var/lib/qualor/run -U qualor -Fc qualor';

/**
 * install-server.md, Kubernetes: the one-off restore pod (embedded-postgres.md §6) on the data
 * claim, while the StatefulSet is scaled to 0. The guide prints the same JSON. `main.js restore`
 * loads the server's configuration first, so the pod gets QUALOR_SECRET_KEY from the release's
 * Secret (`<release>-secrets`, or secrets.existingSecret). Its pod security is the chart's
 * (qualor.podSecurity): without `fsGroupChangePolicy: OnRootMismatch` the kubelet re-chowns the
 * claim recursively and leaves the cluster group-writable, which PostgreSQL refuses. Its container
 * settings are the chart's too, with a `/tmp`, so a restricted namespace admits it.
 */
export function restoreOverrides(
  image: string,
  pullPolicy = 'IfNotPresent',
  claim = 'data-qualor-0',
  secret = 'qualor-secrets',
): string {
  return JSON.stringify({
    spec: {
      automountServiceAccountToken: false,
      enableServiceLinks: false,
      securityContext: RESTRICTED_POD,
      volumes: [{ name: 'data', persistentVolumeClaim: { claimName: claim } }, TMP_VOLUME],
      containers: [
        {
          name: 'qualor-restore',
          image,
          imagePullPolicy: pullPolicy,
          args: ['restore'],
          stdin: true,
          stdinOnce: true,
          env: [
            {
              name: 'QUALOR_SECRET_KEY',
              valueFrom: { secretKeyRef: { name: secret, key: 'QUALOR_SECRET_KEY' } },
            },
          ],
          securityContext: RESTRICTED_CONTAINER,
          volumeMounts: [
            { name: 'data', mountPath: '/var/lib/qualor' },
            { name: 'tmp', mountPath: '/tmp' },
          ],
        },
      ],
    },
  });
}

/**
 * A TCP connection to `host:5432` from Node, as one line: `open`, `blocked` (no answer within
 * 5 s, what a NetworkPolicy drop looks like) or the error code.
 */
export function reachScript(host: string): string {
  return [
    `const s=require('node:net').connect(5432,'${host}');s.setTimeout(5000);`,
    "s.on('connect',()=>{console.log('open');process.exit(0)});",
    "s.on('timeout',()=>{console.log('blocked');process.exit(0)});",
    "s.on('error',(e)=>{console.log(e.code||'error');process.exit(0)})",
  ].join('');
}

/**
 * release.md §6.8: a one-off pod from the server image, without the server's labels, that tries
 * the bundled PostgreSQL. The NetworkPolicy must keep it out. It meets the restricted standard.
 */
export function netCheckOverrides(image: string, host: string): string {
  return JSON.stringify({
    metadata: { labels: { 'qualor-smoke': 'netcheck' } },
    spec: {
      automountServiceAccountToken: false,
      enableServiceLinks: false,
      securityContext: RESTRICTED_POD,
      volumes: [TMP_VOLUME],
      containers: [
        {
          name: 'netcheck',
          image,
          imagePullPolicy: 'Never',
          command: ['/usr/local/bin/node', '-e', reachScript(host)],
          securityContext: RESTRICTED_CONTAINER,
          volumeMounts: [{ name: 'tmp', mountPath: '/tmp' }],
        },
      ],
    },
  });
}

/** The reachability line (`open`, `blocked` or an error code) among kubectl's own output. */
export function parseReach(output: string): string {
  return (
    output
      .split(/\r?\n/)
      .map((l) => l.trim())
      .find((l) => l === 'open' || l === 'blocked' || /^E[A-Z]+$/.test(l)) ?? ''
  );
}

/**
 * Run with `kubectl exec <server pod> -- /usr/local/bin/node -e` (the image has no shell): what
 * the container really runs with, as one JSON line. `root` is how a write to `/` ends (`writable`
 * or the error code), `rootMount` the mount options of `/` in /proc/self/mountinfo (its last
 * mount there, the one in force).
 */
const SERVER_PROBE = [
  "const fs=require('node:fs');",
  "const st=fs.readFileSync('/proc/self/status','utf8');",
  "const f=(k)=>(new RegExp('^'+k+':\\\\s*(\\\\S+)','m').exec(st)||[])[1];",
  "let root='writable';try{fs.writeFileSync('/qualor-probe','x')}catch(e){root=e.code}",
  "let rootMount='';for(const l of fs.readFileSync('/proc/self/mountinfo','utf8').split('\\n')){",
  "const p=l.split(' ');if(p[4]==='/')rootMount=p[5]}",
  'console.log(JSON.stringify({uid:process.getuid(),gid:process.getgid(),',
  "capEff:f('CapEff'),noNewPrivs:f('NoNewPrivs'),root,rootMount}))",
].join('');

/** The same facts from the bundled PostgreSQL's container, which has a shell (busybox). */
export const POSTGRES_PROBE =
  'w=$(touch /qualor-probe 2>&1) && w=writable; case "$w" in writable) ;;' +
  ' *Read-only*) w=EROFS ;; *denied*) w=EACCES ;; *) w=other ;; esac;' +
  " echo uid=$(id -u) gid=$(id -g) capEff=$(awk '/^CapEff/{print $2}' /proc/self/status)" +
  " noNewPrivs=$(awk '/^NoNewPrivs/{print $2}' /proc/self/status)" +
  ' root=$w rootMount=$(awk \'$5=="/"{o=$6} END{print o}\' /proc/self/mountinfo)';

export interface Isolation {
  uid: number;
  gid: number;
  capEff: string;
  noNewPrivs: string;
  /** How a write to `/` ended: `writable`, or its error code (`EROFS`, `EACCES`, …). */
  root: string;
  /** The mount options of `/` (`ro,relatime`), or empty when there is no such line. */
  rootMount: string;
}

/** Throws unless the probe shows the chart's settings (release.md §6) in force. */
export function checkIsolation(what: string, got: Isolation, uid: number): void {
  const problems: string[] = [];
  if (got.uid !== uid || got.gid !== uid) problems.push(`runs as ${got.uid}:${got.gid}`);
  if (!/^0+$/.test(got.capEff)) problems.push(`has capabilities ${got.capEff}`);
  if (got.noNewPrivs !== '1') problems.push('may gain privileges');
  if (got.root === 'writable') problems.push('can write its root filesystem');
  // Final review I-3: EACCES only says / belongs to root. The kernel's EROFS, or ro among the
  // mount options of /, proves the filesystem itself is read-only.
  else if (got.root !== 'EROFS' && !got.rootMount.split(',').includes('ro')) {
    problems.push(
      `its root filesystem is not proven read-only (write ${got.root}, / mounted ${got.rootMount || 'nowhere'})`,
    );
  }
  if (problems.length > 0) throw new Error(`${what}: ${problems.join(', ')}`);
}

/** Parses POSTGRES_PROBE's `key=value` line. */
export function parseShellProbe(line: string): Isolation {
  const v = Object.fromEntries(
    line
      .trim()
      .split(/\s+/)
      .map((kv) => kv.split('=', 2) as [string, string]),
  );
  return {
    uid: Number(v['uid']),
    gid: Number(v['gid']),
    capEff: v['capEff'] ?? '',
    noNewPrivs: v['noNewPrivs'] ?? '',
    root: v['root'] ?? '',
    rootMount: v['rootMount'] ?? '',
  };
}

async function until(check: () => boolean, timeoutMs: number, what: string): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!check()) {
    if (Date.now() > deadline) throw new Error(`${what} not ready after ${timeoutMs / 1000} s`);
    await new Promise((r) => setTimeout(r, 3_000));
  }
}

/** 404 for a project that must not exist; any other answer is an error. */
async function expectMissing(base: string, api: Api, id: string): Promise<void> {
  try {
    await api.json('GET', `/api/v0/projects/${id}`);
  } catch (error) {
    if (error instanceof Error && error.message.includes('status 404')) return;
    throw error;
  }
  throw new Error(`${base}: the project ${id}, created after the backup, survived the restore`);
}

async function main(): Promise<void> {
  must(
    run('docker', ['image', 'inspect', SERVER_IMAGE]),
    `${SERVER_IMAGE} is missing: build it first (docker build -f deploy/server/Dockerfile -t ${SERVER_IMAGE} .)`,
  );
  buildToolbox();
  const name = `${SMOKE_CONTAINER_PREFIX}${randomBytes(4).toString('hex')}`;
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const image = splitImage(SERVER_IMAGE);
  const secrets: SmokeSecrets = {
    secretKey: randomBytes(32).toString('hex'),
    password: randomBytes(12).toString('hex'),
    pgPassword: randomBytes(16).toString('hex'),
  };
  const stop = (): void => {
    run('docker', ['rm', '-f', '-v', name]);
  };
  const onSignal = (): void => {
    stop();
    process.exit(130);
  };
  process.once('SIGINT', onSignal);
  process.once('SIGTERM', onSignal);
  rmSync(WORK, { recursive: true, force: true });
  mkdirSync(WORK, { recursive: true });
  const kubectl = (args: string[]) =>
    must(run('docker', ['exec', name, 'kubectl', ...args]), `kubectl ${args.join(' ')}`);
  const helm = (args: string[]) =>
    must(
      runTool('helm', args, { network: `container:${name}`, env: { KUBECONFIG } }),
      `helm ${args.slice(0, 2).join(' ')}`,
    );
  const values = (file: string, v: Record<string, unknown>): string => {
    writeFileSync(path.join(WORK, file), JSON.stringify(v));
    return `/work/.tmp/helm-smoke/${file}`;
  };
  const serverIsolation = (ns: string, pod: string): void => {
    const out = kubectl([
      '-n',
      ns,
      'exec',
      pod,
      '-c',
      'server',
      '--',
      '/usr/local/bin/node',
      '-e',
      SERVER_PROBE,
    ]);
    checkIsolation(`${ns}/${pod}`, JSON.parse(out.stdout.trim()) as Isolation, 65532);
  };
  /** release.md §6.8: every namespace enforces the restricted Pod Security Standard. */
  const namespace = (ns: string): void => {
    kubectl(['create', 'namespace', ns]);
    kubectl(['label', 'namespace', ns, ...NAMESPACE_LABELS]);
  };
  const chart = '/work/deploy/helm/qualor';
  try {
    must(run('docker', k3sRunArgs(name, port)), 'start k3s');
    await until(
      () =>
        run('docker', ['exec', name, 'kubectl', 'get', 'nodes', '--no-headers']).stdout.includes(
          ' Ready',
        ),
      180_000,
      'the k3s node',
    );
    must(run('docker', ['save', '-o', path.join(WORK, 'server.tar'), SERVER_IMAGE]), 'docker save');
    must(
      run('docker', ['cp', path.join(WORK, 'server.tar'), `${name}:/tmp/server.tar`]),
      'docker cp',
    );
    must(run('docker', ['exec', name, 'ctr', 'images', 'import', '/tmp/server.tar']), 'ctr import');
    run('docker', ['exec', name, 'rm', '-f', '/tmp/server.tar']);
    must(
      run('docker', ['cp', `${name}:/etc/rancher/k3s/k3s.yaml`, path.join(WORK, 'kubeconfig')]),
      'copy the kubeconfig',
    );

    // Embedded mode.
    namespace('embedded');
    const embedded = values('embedded.json', smokeValues('embedded', image, secrets));
    helm([
      'install',
      'qualor',
      chart,
      '-n',
      'embedded',
      '-f',
      embedded,
      '--wait',
      '--timeout',
      '10m',
    ]);
    helm(['test', 'qualor', '-n', 'embedded', '--timeout', '5m']);
    await waitReady(base, 120_000);
    serverIsolation('embedded', 'qualor-0');
    const api = new Api(base);
    await api.login('admin', secrets.password);
    const project = await api.createProject('smoke/helm', 'Helm smoke');
    kubectl(['-n', 'embedded', 'delete', 'pod', 'qualor-0', '--wait=true']);
    const ready = [
      'exec',
      name,
      'kubectl',
      '-n',
      'embedded',
      'get',
      'pod',
      'qualor-0',
      '-o',
      'jsonpath={.status.containerStatuses[0].ready}',
    ];
    await until(() => run('docker', ready).stdout === 'true', 300_000, 'the restarted qualor-0');
    await waitReady(base, 120_000);
    const again = new Api(base);
    await again.login('admin', secrets.password);
    await again.json('GET', `/api/v0/projects/${project.id}`);
    // Backup and restore exactly as install-server.md's Kubernetes section shows them. The dump
    // stays inside the k3s container: `run` passes text, and a dump is binary.
    const sh = (script: string) =>
      must(run('docker', ['exec', name, 'sh', '-c', script]), script.slice(0, 80));
    sh(
      `kubectl -n embedded exec qualor-0 -- ${BACKUP_COMMAND} > /tmp/qualor.dump && head -c 5 /tmp/qualor.dump | grep -q PGDMP`,
    );
    // A project created after the dump must be gone after the restore: the data comes back from
    // the dump, not from the volume it was restored onto.
    const later = await again.createProject('smoke/after-backup', 'After the backup');
    kubectl(['-n', 'embedded', 'scale', 'statefulset/qualor', '--replicas=0']);
    await until(
      () =>
        run('docker', ['exec', name, 'kubectl', '-n', 'embedded', 'get', 'pod', 'qualor-0'])
          .code !== 0,
      180_000,
      'qualor-0 stopping',
    );
    sh(
      `kubectl -n embedded run qualor-restore --rm -i --restart=Never --image=${SERVER_IMAGE} --overrides='${restoreOverrides(SERVER_IMAGE, 'Never')}' < /tmp/qualor.dump`,
    );
    kubectl(['-n', 'embedded', 'scale', 'statefulset/qualor', '--replicas=1']);
    await until(
      () => run('docker', ready).stdout === 'true',
      300_000,
      'qualor-0 after the restore',
    );
    await waitReady(base, 120_000);
    const restored = new Api(base);
    await restored.login('admin', secrets.password);
    await restored.json('GET', `/api/v0/projects/${project.id}`);
    await expectMissing(base, restored, later.id);
    helm(['uninstall', 'qualor', '-n', 'embedded', '--wait']);
    kubectl(['-n', 'embedded', 'get', 'pvc', 'data-qualor-0']);
    process.stdout.write(
      'embedded: installed, tested, restarted with its data, backed up and restored, uninstalled with its claim kept\n',
    );

    // Bundled mode, two replicas.
    namespace('bundled');
    const bundled = values('bundled.json', smokeValues('bundled', image, secrets));
    helm([
      'install',
      'qualor',
      chart,
      '-n',
      'bundled',
      '-f',
      bundled,
      '--wait',
      '--timeout',
      '15m',
    ]);
    helm(['test', 'qualor', '-n', 'bundled', '--timeout', '5m']);
    await waitReady(base, 120_000);
    const pods = kubectl([
      '-n',
      'bundled',
      'get',
      'pods',
      '-l',
      'app.kubernetes.io/component=server',
      '--field-selector=status.phase=Running',
      '-o',
      'jsonpath={.items[*].metadata.name}',
    ])
      .stdout.trim()
      .split(/\s+/)
      .filter((p) => p !== '');
    if (pods.length !== 2) throw new Error(`bundled: ${pods.length} running servers, expected 2`);
    for (const pod of pods) serverIsolation('bundled', pod);
    const pg = kubectl([
      '-n',
      'bundled',
      'exec',
      'qualor-postgres-0',
      '--',
      'sh',
      '-c',
      POSTGRES_PROBE,
    ]);
    checkIsolation('bundled/qualor-postgres-0', parseShellProbe(pg.stdout), 70);
    // Ruling R-NP: a server reaches PostgreSQL, a pod without the server's labels does not.
    const fromServer = parseReach(
      kubectl([
        '-n',
        'bundled',
        'exec',
        pods[0] ?? '',
        '-c',
        'server',
        '--',
        '/usr/local/bin/node',
        '-e',
        reachScript('qualor-postgres'),
      ]).stdout,
    );
    if (fromServer !== 'open')
      throw new Error(`bundled: a server reaching PostgreSQL got ${fromServer || 'no answer'}`);
    const fromOther = parseReach(
      kubectl([
        '-n',
        'bundled',
        'run',
        'qualor-netcheck',
        '--rm',
        '--attach',
        '--quiet',
        '--restart=Never',
        `--image=${SERVER_IMAGE}`,
        `--overrides=${netCheckOverrides(SERVER_IMAGE, 'qualor-postgres')}`,
      ]).stdout,
    );
    if (fromOther === 'open' || fromOther === '') {
      throw new Error(
        `bundled: the NetworkPolicy let a pod without the server's labels reach PostgreSQL (${fromOther || 'no result'})`,
      );
    }
    await new Api(base).login('admin', secrets.password);
    process.stdout.write(
      'security: restricted namespaces; the servers run as 65532 and the bundled PostgreSQL as 70, with a read-only root (EROFS or ro), no capabilities and no new privileges; PostgreSQL answers the servers only\n',
    );
    process.stdout.write('bundled: 2 replicas installed, tested, signed in\nhelm smoke passed\n');
  } finally {
    stop();
    rmSync(path.join(WORK, 'server.tar'), { force: true });
  }
}

if (process.argv[1]?.endsWith('smoke.ts')) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
