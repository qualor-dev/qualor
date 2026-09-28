import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import net from 'node:net';
import type { TestProject } from 'vitest/node';

declare module 'vitest' {
  export interface ProvidedContext {
    gitlabUrl: string;
    gitlabRootToken: string;
  }
}

/**
 * The opt-in real-GitLab check (`pnpm gitlab:real`, scm.md §11): GitLab CE in Docker, pinned, on
 * a loopback port, with no DNS inside the container (`--dns 127.0.0.1`) and Service Ping and the
 * version check off, so it contacts nothing outside the machine. Never part of `pnpm test`: the
 * image is about 1.5 GB to download, 4 GB on disk, takes several minutes to start and about 4 GB
 * of memory. `QUALOR_GITLAB_URL` and `QUALOR_GITLAB_TOKEN` (an admin's `api` token) use an
 * instance that is already running instead. The image is pinned by digest (the multi-platform
 * index of the 19.3.3-ce.0 tag), so a re-tagged image cannot change what the check runs.
 */
export const GITLAB_IMAGE =
  'gitlab/gitlab-ce:19.3.3-ce.0@sha256:8c6ede6b1334738123feba0d248e81a14fc3db7065dc6e1f0a753c0d0332fee8';
const BOOT_TIMEOUT_MS = 15 * 60_000;

function docker(...args: string[]): string {
  return execFileSync('docker', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).trim();
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as net.AddressInfo).port;
      server.close(() => resolve(port));
    });
  });
}

async function waitForRails(url: string): Promise<void> {
  const deadline = Date.now() + BOOT_TIMEOUT_MS;
  while (Date.now() < deadline) {
    try {
      // Unauthenticated: 401 once Rails answers (502 while it boots).
      const res = await fetch(`${url}/api/v4/version`, { signal: AbortSignal.timeout(5_000) });
      if (res.status === 401 || res.status === 200) return;
    } catch {
      // Not listening yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 5_000));
  }
  throw new Error(`GitLab did not start within ${BOOT_TIMEOUT_MS / 60_000} minutes`);
}

export default async function setup(project: TestProject): Promise<() => Promise<void>> {
  const given = process.env['QUALOR_GITLAB_URL'];
  if (given) {
    const token = process.env['QUALOR_GITLAB_TOKEN'];
    if (!token) throw new Error('QUALOR_GITLAB_URL needs QUALOR_GITLAB_TOKEN (an admin api token)');
    project.provide('gitlabUrl', given.replace(/\/+$/, ''));
    project.provide('gitlabRootToken', token);
    return async () => undefined;
  }
  const port = await freePort();
  const url = `http://127.0.0.1:${port}`;
  const name = `qualor-gitlab-real-${randomBytes(4).toString('hex')}`;
  const token = `glpat-${randomBytes(15).toString('hex')}`;
  const omnibus = [
    `external_url '${url}'`,
    "gitlab_rails['usage_ping_enabled'] = false",
    "gitlab_rails['initial_root_password'] = '" + randomBytes(18).toString('hex') + "'",
    "prometheus_monitoring['enable'] = false",
    "registry['enable'] = false",
    "gitlab_kas['enable'] = false",
    "letsencrypt['enable'] = false",
    "puma['worker_processes'] = 0",
    "sidekiq['concurrency'] = 5",
  ].join('; ');
  docker(
    'run',
    '-d',
    '--name',
    name,
    '--label',
    'qualor.deploy=gitlab-real',
    '--dns',
    '127.0.0.1',
    '--shm-size',
    '256m',
    '-p',
    `127.0.0.1:${port}:${port}`,
    '-e',
    `GITLAB_OMNIBUS_CONFIG=${omnibus}`,
    GITLAB_IMAGE,
  );
  const stop = async () => {
    try {
      docker('rm', '-f', '-v', name);
    } catch {
      // Already gone.
    }
  };
  try {
    await waitForRails(url);
    // An admin token for the check, and nothing that phones home.
    docker(
      'exec',
      name,
      'gitlab-rails',
      'runner',
      [
        'ApplicationSetting.current.update!(usage_ping_enabled: false, version_check_enabled: false)',
        "u = User.find_by_username('root')",
        `t = u.personal_access_tokens.create!(scopes: ['api'], name: 'qualor-check', expires_at: 2.days.from_now)`,
        `t.set_token('${token}')`,
        't.save!',
      ].join('; '),
    );
  } catch (err) {
    await stop();
    throw err;
  }
  project.provide('gitlabUrl', url);
  project.provide('gitlabRootToken', token);
  return stop;
}
