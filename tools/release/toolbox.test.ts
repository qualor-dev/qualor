import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { REPO_ROOT } from '../deploy/stack';
import {
  assertInternalNetwork,
  directEnv,
  DRY_RUN_NETWORK_PREFIX,
  hostUser,
  mapWorkPaths,
  SMOKE_CONTAINER_PREFIX,
  TOOLBOX_IMAGE,
  toolboxArgs,
  toWork,
} from './toolbox';

const script = readFileSync('tools/release/install-tools.sh', 'utf8');
const dockerfile = readFileSync('tools/release/Dockerfile', 'utf8');
const pin = (name: string): string => new RegExp(`^${name}=(.+)$`, 'm').exec(script)?.[1] ?? '';

describe('install-tools.sh (release.md §9)', () => {
  it('pins Helm 4.3.0, cosign 3.1.3 and Syft 1.52.0 by SHA-256 for both architectures', () => {
    expect(pin('HELM_VERSION')).toBe('4.3.0');
    expect(pin('COSIGN_VERSION')).toBe('3.1.3');
    expect(pin('SYFT_VERSION')).toBe('1.52.0');
    for (const tool of ['HELM', 'COSIGN', 'SYFT']) {
      for (const arch of ['X64', 'ARM64']) {
        expect(pin(`${tool}_SHA256_${arch}`), `${tool} ${arch}`).toMatch(/^[0-9a-f]{64}$/);
      }
    }
  });

  it('downloads over https only and checks every file before using it', () => {
    expect(script).toContain("--proto '=https' --proto-redir '=https'");
    expect(script).toMatch(/sha256sum -c -/);
    expect(script).not.toMatch(/http:\/\//);
    // Every fetch names a SHA-256 variable, and nothing is piped into a shell.
    for (const line of script.split('\n').filter((l) => l.startsWith('fetch '))) {
      expect(line).toMatch(/\$[A-Z_]*SHA/);
    }
    // `\b`: `| sha256sum -c -` (required above) is a checksum check, not a shell.
    expect(script).not.toMatch(/\|\s*(ba)?sh\b/);
  });

  it('downloads exactly the three tools, each through fetch, and nothing else', () => {
    expect(script.split('\n').filter((l) => l.startsWith('fetch '))).toHaveLength(3);
    // curl appears only inside fetch(); wget never.
    const body = /^fetch\(\) \{[^\n]*\n([\s\S]*?)\n\}/m.exec(script)?.[1] ?? '';
    expect(body).toContain('curl ');
    expect(script.replace(body, '')).not.toMatch(/\bcurl\b|\bwget\b/);
  });

  it('names the independent check and the exact signer identities (release.md §9)', () => {
    const check = readFileSync('tools/release/check-pins.py', 'utf8');
    const wrapper = readFileSync('tools/release/check-pins.sh', 'utf8');
    const reqs = readFileSync('tools/release/check-pins.requirements.txt', 'utf8');
    expect(script).toContain('tools/release/check-pins.sh');
    expect(script).toContain('keyless@projectsigstore.iam.gserviceaccount.com');
    expect(check).toContain('COSIGN_IDENTITY = "keyless@projectsigstore.iam.gserviceaccount.com"');
    expect(check).toContain('COSIGN_ISSUER = "https://accounts.google.com"');
    expect(check).toContain(
      'SYFT_IDENTITY = "https://github.com/anchore/syft/.github/workflows/release.yaml@refs/heads/main"',
    );
    // Exact identities through sigstore-python, never a regular expression or the toolbox's cosign.
    expect(`${script}\n${check}`).not.toMatch(/identity-regexp|cosign verify/);
    // A throwaway python image pinned by digest, and every package pinned by hash.
    expect(wrapper).toMatch(/python:[\d.]+-slim@sha256:[0-9a-f]{64}/);
    expect(wrapper).toContain('--require-hashes');
    const blocks = reqs.split(/\n(?=[a-z0-9-]+==)/).filter((b) => /^[a-z0-9-]+==/.test(b));
    expect(blocks.map((b) => b.split(' ')[0])).toContain('sigstore==4.5.0');
    for (const block of blocks) {
      expect(block, block.split('\n')[0]).toMatch(/--hash=sha256:[0-9a-f]{64}/);
    }
  });

  it('is built on the digest-pinned Node base of the other Dockerfiles, and turns off update checks', () => {
    const from = /^FROM (\S+)/m.exec(dockerfile)?.[1];
    const analyzers = /^FROM (\S+)/m.exec(readFileSync('tools/analyzers/Dockerfile', 'utf8'))?.[1];
    expect(from).toMatch(/@sha256:[0-9a-f]{64}$/);
    expect(from).toBe(analyzers);
    expect(dockerfile).toContain('SYFT_CHECK_FOR_APP_UPDATE=false');
    expect(dockerfile).toContain('HOME=/tmp');
  });
});

describe('toolboxArgs (release.md §9)', () => {
  it('runs a tool with no network, a read-only root, no capabilities and the repository at /work', () => {
    const args = toolboxArgs('helm', ['version']);
    expect(args.slice(0, 2)).toEqual(['run', '--rm']);
    expect(args.join(' ')).toContain('--network none');
    for (const flag of ['--read-only', '--cap-drop', 'ALL', 'no-new-privileges']) {
      expect(args).toContain(flag);
    }
    expect(args.slice(-3)).toEqual([TOOLBOX_IMAGE, 'helm', 'version']);
  });

  it('mounts the repository read-only, and only its .tmp writable', () => {
    const args = toolboxArgs('helm', ['version']);
    const mounts = args.filter((_, i) => args[i - 1] === '--mount');
    expect(mounts).toEqual([
      `type=bind,source=${REPO_ROOT},target=/work,readonly`,
      `type=bind,source=${path.join(REPO_ROOT, '.tmp')},target=/work/.tmp`,
    ]);
  });

  it('adds the extra mounts, the working directory and the default user', () => {
    const args = toolboxArgs('syft', ['version'], {
      mounts: [
        { source: '/a', target: '/in', readOnly: true },
        { source: '/b', target: '/out' },
      ],
      workdir: '/work/.tmp/x',
    });
    const joined = args.join(' ');
    expect(joined).toContain('--mount type=bind,source=/a,target=/in,readonly');
    expect(joined).toContain('--mount type=bind,source=/b,target=/out -w');
    expect(joined).toContain('-w /work/.tmp/x');
    expect(toolboxArgs('helm', []).join(' ')).toContain('-w /work ');
    const user = hostUser();
    if (user === undefined) expect(args).not.toContain('--user');
    else expect(joined).toContain(`--user ${user}`);
  });

  it('passes secrets by name and container-only values as NAME=value, never a secret by value', () => {
    const args = toolboxArgs('cosign', ['version'], {
      env: { COSIGN_PASSWORD: 'p' },
      plainEnv: { DOCKER_CONFIG: '/work/.tmp/docker' },
    });
    const joined = args.join(' ');
    expect(joined).toContain('-e COSIGN_PASSWORD ');
    expect(joined).not.toContain('COSIGN_PASSWORD=');
    expect(joined).toContain('-e DOCKER_CONFIG=/work/.tmp/docker ');
    for (const name of ['COSIGN_PASSWORD', 'GH_TOKEN', 'MY_SECRET', 'COSIGN_PRIVATE_KEY']) {
      expect(() => toolboxArgs('cosign', [], { plainEnv: { [name]: 'x' } }), name).toThrow(
        /looks like a secret/,
      );
    }
  });

  it('accepts only the dry-run network and the smoke cluster, unless publishing', () => {
    expect(() =>
      toolboxArgs('cosign', [], { network: `${DRY_RUN_NETWORK_PREFIX}ab12` }),
    ).not.toThrow();
    expect(() =>
      toolboxArgs('helm', [], { network: `container:${SMOKE_CONTAINER_PREFIX}ab12` }),
    ).not.toThrow();
    for (const network of ['bridge', 'host', 'default', 'container:other']) {
      expect(() => toolboxArgs('cosign', [], { network }), network).toThrow(/network/);
    }
    expect(() =>
      toolboxArgs('cosign', [], { network: 'bridge', allowPublishNetwork: true }),
    ).not.toThrow();
  });

  it('allows each network only to the tools that need it', () => {
    const dryRun = `${DRY_RUN_NETWORK_PREFIX}ab12`;
    const smoke = `container:${SMOKE_CONTAINER_PREFIX}ab12`;
    for (const tool of ['helm', 'cosign', 'syft'] as const) {
      expect(() => toolboxArgs(tool, [], { network: dryRun }), tool).not.toThrow();
    }
    for (const tool of ['cosign', 'syft'] as const) {
      expect(() => toolboxArgs(tool, [], { network: smoke }), tool).toThrow(
        new RegExp(`${tool} may not use`),
      );
    }
  });

  it('refuses the publish network without the flag, for Syft, and any other network with it', () => {
    for (const tool of ['helm', 'cosign'] as const) {
      expect(() => toolboxArgs(tool, [], { network: 'bridge' }), tool).toThrow(
        /only for release:publish/,
      );
    }
    expect(() => toolboxArgs('syft', [], { network: 'bridge', allowPublishNetwork: true })).toThrow(
      /syft may not use/,
    );
    for (const network of ['host', 'default', 'container:other', 'qualor-other']) {
      expect(
        () => toolboxArgs('cosign', [], { network, allowPublishNetwork: true }),
        network,
      ).toThrow(/is not allowed/);
    }
  });

  it('requires a dry-run network to be --internal', () => {
    const calls: string[][] = [];
    const docker =
      (stdout: string, code = 0) =>
      (command: string, args: readonly string[]) => {
        calls.push([command, ...args]);
        return { code, stdout, stderr: '' };
      };
    const net = `${DRY_RUN_NETWORK_PREFIX}ab12`;
    expect(() => assertInternalNetwork(net, docker('true\n'))).not.toThrow();
    expect(calls[0]).toEqual(['docker', 'network', 'inspect', '--format', '{{.Internal}}', net]);
    expect(() => assertInternalNetwork(net, docker('false\n'))).toThrow(/not an --internal/);
    expect(() => assertInternalNetwork(net, docker('', 1))).toThrow(/not an --internal/);
  });

  it('passes variables by name only, so no value is on the command line', () => {
    const args = toolboxArgs('cosign', ['sign-blob'], { env: { COSIGN_PASSWORD: 'p4ss-value' } });
    expect(args).toContain('COSIGN_PASSWORD');
    expect(args.join(' ')).not.toContain('p4ss-value');
  });

  it('runs as the given user', () => {
    expect(toolboxArgs('syft', [], { user: '1001:127' }).join(' ')).toContain('--user 1001:127');
  });
});

describe('paths', () => {
  it('maps a host path inside the repository to /work, and refuses one outside', () => {
    expect(toWork(path.join(REPO_ROOT, '.tmp', 'release', '1.0.0'))).toBe(
      '/work/.tmp/release/1.0.0',
    );
    expect(() => toWork(path.resolve(REPO_ROOT, '..', 'elsewhere'))).toThrow(
      /outside the repository/,
    );
    expect(() => toWork(path.resolve(REPO_ROOT, '..'))).toThrow(/outside the repository/);
    expect(toWork(REPO_ROOT)).toBe('/work');
    // A name that merely starts with ".." is still inside.
    expect(toWork(path.join(REPO_ROOT, '..foo', 'x'))).toBe('/work/..foo/x');
  });

  it("does not pass the host's KUBECONFIG or DOCKER_CONFIG in direct mode, unless named", () => {
    expect(directEnv()).toEqual({ KUBECONFIG: undefined, DOCKER_CONFIG: undefined });
    expect(directEnv({ KUBECONFIG: '/k', COSIGN_PASSWORD: 'x' })).toEqual({
      KUBECONFIG: '/k',
      DOCKER_CONFIG: undefined,
      COSIGN_PASSWORD: 'x',
    });
  });

  it('maps /work paths back for direct mode, also after "="', () => {
    expect(
      mapWorkPaths(['-f', '/work/a.yaml', 'spdx-json=/work/b.json', '/workx'], '/repo'),
    ).toEqual(['-f', '/repo/a.yaml', 'spdx-json=/repo/b.json', '/workx']);
  });
});
