import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { Api, run } from './stack';

/**
 * `pnpm deploy:embedded-check [image]`: runs a
 * built qualor/server image (default `qualor/server:dev`) without DATABASE_URL and checks the
 * embedded PostgreSQL end to end: health and a sign-in on a fresh volume, data kept across a
 * restart, a second container refused on the same volume, a backup with pg_dump through exec,
 * `restore` of that backup into a fresh volume, and a broken file that `restore` refuses without
 * touching that data. Everything it creates is removed afterwards.
 */
const PORT_A = 18_190;
const PORT_B = 18_191;
const suffix = randomBytes(4).toString('hex');
const VOLUME = `qualor-embedded-check-${suffix}`;
const RESTORED = `qualor-embedded-check-restored-${suffix}`;
const containers: string[] = [];
const secret = randomBytes(32).toString('hex');
const password = randomBytes(16).toString('hex');

const failures: string[] = [];
const check = (ok: boolean, what: string): void => {
  process.stdout.write(`${ok ? 'ok  ' : 'FAIL'} ${what}\n`);
  if (!ok) failures.push(what);
};

function docker(args: string[], input?: Buffer): { code: number; stdout: Buffer; stderr: string } {
  const r = spawnSync('docker', args, { input, maxBuffer: 512 * 1024 * 1024 });
  if (r.error) throw r.error;
  return { code: r.status ?? 1, stdout: r.stdout, stderr: r.stderr.toString('utf8') };
}

function start(image: string, name: string, volume: string, port: number): void {
  containers.push(name);
  const r = run('docker', [
    'run',
    '-d',
    '--name',
    name,
    '-p',
    `127.0.0.1:${port}:8080`,
    '-v',
    `${volume}:/var/lib/qualor`,
    '--read-only',
    '--tmpfs',
    '/tmp',
    '--cap-drop',
    'ALL',
    '--security-opt',
    'no-new-privileges:true',
    '-e',
    `QUALOR_SECRET_KEY=${secret}`,
    '-e',
    `QUALOR_BOOTSTRAP_ADMIN_PASSWORD=${password}`,
    image,
  ]);
  if (r.code !== 0) throw new Error(`docker run ${name}: ${r.stderr}`);
}

async function ready(port: number): Promise<boolean> {
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    const status = await fetch(`http://127.0.0.1:${port}/readyz`, {
      signal: AbortSignal.timeout(5_000),
    })
      .then((r) => r.status)
      .catch(() => 0);
    if (status === 200) return true;
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  return false;
}

async function projectKeys(port: number): Promise<string[]> {
  const api = new Api(`http://127.0.0.1:${port}`);
  await api.login('admin', password);
  const orgs = await api.json<{ items: { id: string }[] }>('GET', '/api/v0/organizations');
  const projects = await api.json<{ items: { key: string }[] }>(
    'GET',
    `/api/v0/projects?organizationId=${orgs.items[0]?.id ?? ''}`,
  );
  return projects.items.map((p) => p.key);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length > 1 || args[0]?.startsWith('-'))
    throw new Error('usage: pnpm deploy:embedded-check [image]');
  const image = args[0] ?? 'qualor/server:dev';

  start(image, `qualor-embedded-a-${suffix}`, VOLUME, PORT_A);
  check(await ready(PORT_A), 'a fresh volume becomes ready without DATABASE_URL');
  const api = new Api(`http://127.0.0.1:${PORT_A}`);
  await api.login('admin', password);
  await api.createProject('embedded/check', 'Embedded check');
  check(
    (await projectKeys(PORT_A)).includes('embedded/check'),
    'the admin signs in and creates a project',
  );

  const restart = run('docker', ['restart', '-t', '40', `qualor-embedded-a-${suffix}`]);
  check(restart.code === 0 && (await ready(PORT_A)), 'the server restarts on the same volume');
  check((await projectKeys(PORT_A)).includes('embedded/check'), 'the data survives the restart');

  const second = docker([
    'run',
    '--rm',
    '-v',
    `${VOLUME}:/var/lib/qualor`,
    '-e',
    `QUALOR_SECRET_KEY=${secret}`,
    image,
  ]);
  check(
    second.code !== 0 &&
      /another Qualor server .* one server per data directory/.test(
        second.stderr + second.stdout.toString('utf8'),
      ),
    `a second container on the same volume is refused (exit ${second.code})`,
  );

  const dump = docker([
    'exec',
    `qualor-embedded-a-${suffix}`,
    '/opt/postgresql/bin/pg_dump',
    '-h',
    '/var/lib/qualor/run',
    '-U',
    'qualor',
    '-Fc',
    'qualor',
  ]);
  check(
    dump.code === 0 && dump.stdout.subarray(0, 5).toString('latin1') === 'PGDMP',
    `pg_dump through exec writes a backup (${dump.stdout.length} bytes)`,
  );

  const refused = docker(
    [
      'run',
      '--rm',
      '-i',
      '-v',
      `${VOLUME}:/var/lib/qualor`,
      '-e',
      `QUALOR_SECRET_KEY=${secret}`,
      image,
      'restore',
    ],
    dump.stdout,
  );
  check(refused.code !== 0, 'restore is refused while a server holds the volume');

  const restore = docker(
    [
      'run',
      '--rm',
      '-i',
      '-v',
      `${RESTORED}:/var/lib/qualor`,
      '-e',
      `QUALOR_SECRET_KEY=${secret}`,
      image,
      'restore',
    ],
    dump.stdout,
  );
  check(
    restore.code === 0,
    `restore into a fresh volume succeeds${restore.code === 0 ? '' : `:\n${restore.stderr.slice(-2000)}`}`,
  );
  // A file that is not a dump (an empty, truncated or wrong backup) must leave the data as it was.
  const broken = docker(
    [
      'run',
      '--rm',
      '-i',
      '-v',
      `${RESTORED}:/var/lib/qualor`,
      '-e',
      `QUALOR_SECRET_KEY=${secret}`,
      image,
      'restore',
    ],
    Buffer.from('this is not a pg_dump archive\n'),
  );
  check(
    broken.code !== 0 && /the existing database was not changed/.test(broken.stderr),
    `restore of a broken file fails and keeps the data (exit ${broken.code})`,
  );
  start(image, `qualor-embedded-b-${suffix}`, RESTORED, PORT_B);
  check(
    (await ready(PORT_B)) && (await projectKeys(PORT_B)).includes('embedded/check'),
    'the restored volume holds the data',
  );

  const external = docker(
    [
      'run',
      '--rm',
      '-i',
      '-e',
      'DATABASE_URL=postgres://x@127.0.0.1:1/x',
      '-e',
      `QUALOR_SECRET_KEY=${secret}`,
      image,
      'restore',
    ],
    Buffer.from(''),
  );
  check(
    external.code === 1 && /embedded database only/.test(external.stderr),
    'restore refuses external mode',
  );
}

function cleanUp(): void {
  for (const name of containers) run('docker', ['rm', '-f', name]);
  run('docker', ['volume', 'rm', '-f', VOLUME, RESTORED]);
}

main()
  .catch((error: unknown) => {
    failures.push(error instanceof Error ? error.message : String(error));
    process.stderr.write(`${failures.at(-1)}\n`);
  })
  .finally(() => {
    cleanUp();
    process.stdout.write(
      failures.length === 0
        ? 'embedded PostgreSQL: all checks passed\n'
        : `${failures.length} check(s) failed\n`,
    );
    process.exitCode = failures.length === 0 ? 0 : 1;
  });
