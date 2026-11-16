import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';

// 0.16 IaC (Q-L180): the trivy-checks bundle that install.sh unpacks loses its KCV checks (they
// quote CIS Benchmark text) and its specs/ directory before it is installed.

const SCRIPT = path.resolve('tools/analyzers/filter-trivy-checks.sh');
const installSh = readFileSync('tools/analyzers/install.sh', 'utf8');
const tmps: string[] = [];
afterAll(() => {
  for (const dir of tmps) rmSync(dir, { recursive: true, force: true });
});

const rego = (id: string, longId: string) =>
  `# METADATA\n# title: "t"\n# custom:\n#   id: ${id}\n#   long_id: ${longId}\n#   aliases:\n#     - AVD-${id}\npackage builtin.x\n`;

function fakeBundle(): string {
  const root = mkdtempSync(path.join(tmpdir(), 'qualor-checks-'));
  tmps.push(root);
  const write = (rel: string, text: string) => {
    mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    writeFileSync(path.join(root, rel), text);
  };
  write('policies/kubernetes/policies/a.rego', rego('KCV-0001', 'kubernetes-cis-1'));
  write('policies/kubernetes/policies/b.rego', rego('KSV-0001', 'kubernetes-ksv-1'));
  write('policies/docker/policies/c.rego', rego('DS-0002', 'dockerfile-ds-2'));
  // A long_id that mentions KCV must not make a check go: only the `id:` line counts.
  write('policies/cloud/policies/d.rego', rego('AWS-0001', 'KCV-0001-lookalike'));
  write('policies/kubernetes/lib/kubernetes.rego', 'package lib.kubernetes\n');
  write('specs/compliance/x.yaml', 'spec:\n  id: k8s-cis-1.23\n');
  write('commands/config/node.yaml', 'a: b\n');
  return root;
}

const run = (dir: string) => spawnSync('sh', [SCRIPT, dir], { encoding: 'utf8' });

describe('filter-trivy-checks.sh', () => {
  it('removes KCV checks and specs, and keeps every other check, lib and command', () => {
    const root = fakeBundle();
    const result = run(root);
    expect(result.stderr).toBe('');
    expect(result.status).toBe(0);
    expect(existsSync(path.join(root, 'policies/kubernetes/policies/a.rego'))).toBe(false);
    expect(existsSync(path.join(root, 'specs'))).toBe(false);
    for (const kept of [
      'policies/kubernetes/policies/b.rego',
      'policies/docker/policies/c.rego',
      'policies/cloud/policies/d.rego',
      'policies/kubernetes/lib/kubernetes.rego',
      'commands/config/node.yaml',
    ]) {
      expect(existsSync(path.join(root, kept)), kept).toBe(true);
    }
  });

  it('is idempotent and fails on a directory that is not a bundle', () => {
    const root = fakeBundle();
    expect(run(root).status).toBe(0);
    expect(run(root).status).toBe(0);
    const empty = mkdtempSync(path.join(tmpdir(), 'qualor-checks-'));
    tmps.push(empty);
    const bad = run(empty);
    expect(bad.status).toBe(1);
    expect(bad.stderr).toContain('no trivy-checks bundle');
  });
});

describe('the trivy-checks pins of install.sh', () => {
  it('pins 2.3.0 by a 64-hex layer digest and filters before it installs', () => {
    expect(installSh).toMatch(/^TRIVY_CHECKS_VERSION=2\.3\.0$/m);
    expect(installSh).toMatch(/^TRIVY_CHECKS_DIGEST=sha256:[0-9a-f]{64}$/m);
    expect(installSh).toContain(
      'https://ghcr.io/v2/aquasecurity/trivy-checks/blobs/$TRIVY_CHECKS_DIGEST',
    );
    expect(installSh).toContain(
      '"${TRIVY_CHECKS_DIGEST#sha256:}  $TMP/trivy-checks.tar.gz" | sha256sum -c -',
    );
    expect(installSh).toContain('filter-trivy-checks.sh');
    expect(installSh).toContain('$PREFIX/share/trivy-iac/version');
    expect(
      installSh.indexOf('sha256sum -c - >/dev/null || { echo "checksum mismatch: trivy-checks'),
    ).toBeLessThan(installSh.indexOf('tar -xzf "$TMP/trivy-checks.tar.gz"'));
  });
});
