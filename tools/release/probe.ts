import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { must, REPO_ROOT, run, secret } from '../deploy/stack';
import { buildToolbox, runTool, toWork } from './toolbox';

/**
 * `pnpm release:tools` (plan 4A Task 2): builds qualor-release-tools:local and proves the
 * assumptions of release.md §7.2 and ruling RE2 on this machine: the tools start with no
 * network, cosign signs and verifies a blob with a throwaway key and no network, and a k3s
 * container becomes Ready. Prints the exact cosign flags that worked. It refuses direct mode
 * (QUALOR_TOOLBOX=direct): there the tools run with the CI job's own network, so "offline" would
 * be unproven.
 */
const K3S_IMAGE =
  'rancher/k3s:v1.37.0-k3s1@sha256:d33b1973401a60410681d66c007f5c3a51d565a7c03608904764aef3321fee4d';
const SIGN = ['--tlog-upload=false', '--use-signing-config=false'];
const VERIFY = ['--insecure-ignore-tlog=true'];

async function main(): Promise<void> {
  if (process.env['QUALOR_TOOLBOX'] === 'direct') {
    throw new Error(
      'release:tools proves offline operation only in the toolbox image; unset QUALOR_TOOLBOX=direct (release.md §9)',
    );
  }
  buildToolbox();
  for (const [tool, args] of [
    ['helm', ['version', '--short']],
    ['cosign', ['version']],
    ['syft', ['version']],
  ] as const) {
    process.stdout.write(`${must(runTool(tool, args), `${tool} version`).stdout.split('\n')[0]}\n`);
  }
  const dir = path.join(REPO_ROOT, '.tmp', 'release-probe');
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  try {
    writeFileSync(path.join(dir, 'blob.txt'), 'probe\n');
    const env = { COSIGN_PASSWORD: secret() };
    must(
      runTool('cosign', ['generate-key-pair'], { workdir: toWork(dir), env }),
      'generate-key-pair',
    );
    const w = toWork(dir);
    must(
      runTool(
        'cosign',
        [
          'sign-blob',
          '--yes',
          '--key',
          `${w}/cosign.key`,
          '--bundle',
          `${w}/blob.bundle`,
          ...SIGN,
          `${w}/blob.txt`,
        ],
        { env },
      ),
      `cosign sign-blob ${SIGN.join(' ')}`,
    );
    must(
      runTool('cosign', [
        'verify-blob',
        '--key',
        `${w}/cosign.pub`,
        '--bundle',
        `${w}/blob.bundle`,
        ...VERIFY,
        `${w}/blob.txt`,
      ]),
      `cosign verify-blob ${VERIFY.join(' ')}`,
    );
    process.stdout.write(`cosign offline: sign ${SIGN.join(' ')}; verify ${VERIFY.join(' ')}\n`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  const name = 'qualor-helm-smoke-probe';
  run('docker', ['rm', '-f', name]);
  try {
    must(
      run('docker', [
        'run',
        '-d',
        '--privileged',
        '--name',
        name,
        '--tmpfs',
        '/run',
        '--tmpfs',
        '/var/run',
        K3S_IMAGE,
        'server',
        '--disable=traefik',
        '--disable=metrics-server',
      ]),
      'start k3s',
    );
    const deadline = Date.now() + 180_000;
    while (
      !run('docker', ['exec', name, 'kubectl', 'get', 'nodes', '--no-headers']).stdout.includes(
        ' Ready',
      )
    ) {
      if (Date.now() > deadline) throw new Error('k3s did not become Ready in 180 s');
      await new Promise((r) => setTimeout(r, 3_000));
    }
    process.stdout.write('k3s in Docker: Ready\n');
  } finally {
    run('docker', ['rm', '-f', '-v', name]);
  }
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
