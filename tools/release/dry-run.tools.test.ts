import { randomBytes } from 'node:crypto';
import { existsSync, readdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { must, REPO_ROOT, run } from '../deploy/stack';
import { hostTarget } from './binary';
import { dryRun, packageChart, parseDryRunArgs, workDir } from './dry-run';
import { readManifest } from './manifest';
import { runTool, toWork } from './toolbox';
import { cosignVerifier, verifyRelease } from './verify';
import { currentVersion } from './version';

const scratch = path.join(REPO_ROOT, '.tmp', 'release-test', randomBytes(4).toString('hex'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const packagedDigest = (tgz: string): unknown =>
  (
    parse(must(runTool('helm', ['show', 'values', toWork(tgz)]), 'helm show').stdout) as {
      image: { digest: unknown };
    }
  ).image.digest;

describe('pnpm release:dry-run --skip-images (release.md §15 item 6)', () => {
  it('produces a signed, verifiable release directory and leaves no key and no registry', async () => {
    const v = currentVersion();
    const target = hostTarget() ?? 'linux-x64';
    // A scratch output root: the test never touches .tmp/release/ (release.md §10).
    const root = path.join(scratch, 'dry-run');
    const dir = await dryRun(
      parseDryRunArgs(['--skip-images', '--skip-cli-sources', '--targets', target], v),
      root,
    );
    expect(dir).toBe(path.join(root, 'release', v.text));
    const files = readdirSync(dir).sort();
    expect(files).toEqual([
      'SHA256SUMS',
      'SHA256SUMS.bundle',
      'cli',
      'cosign.pub',
      'helm',
      'release-manifest.json',
      'release-notes.md',
      'sbom',
    ]);
    expect(existsSync(path.join(dir, 'helm', `qualor-${v.text}.tgz`))).toBe(true);
    expect(existsSync(path.join(dir, 'sbom', 'cli.spdx.json'))).toBe(true);
    const m = readManifest(dir);
    expect(m).toMatchObject({
      version: v.text,
      dryRun: true,
      cliSources: false,
      images: [],
      targets: [target],
    });
    expect(m.files).not.toContain('SHA256SUMS');
    expect(m.files.some((f) => f.includes('cli-deps'))).toBe(false);
    // Without images there is no digest to pin: the package keeps the tag (ruling RE6).
    expect(packagedDigest(path.join(dir, 'helm', `qualor-${v.text}.tgz`))).toBe('');
    expect(await verifyRelease(dir, path.join(dir, 'cosign.pub'), cosignVerifier)).toEqual([]);
    expect(existsSync(workDir(v, root))).toBe(false);
    expect(
      run('docker', ['ps', '-a', '--filter', 'name=qualor-release-registry', '-q']).stdout.trim(),
    ).toBe('');
  });
});

describe('the packaged chart (ruling R-DIGEST)', () => {
  it('pins the server image by the digest the registry reported, and lints with it', () => {
    const v = currentVersion();
    const digest = `sha256:${randomBytes(32).toString('hex')}`;
    const file = packageChart(v, path.join(scratch, 'release'), path.join(scratch, 'work'), digest);
    expect(file).toBe(`helm/qualor-${v.text}.tgz`);
    const tgz = path.join(scratch, 'release', file);
    expect(packagedDigest(tgz)).toBe(digest);
    const rendered = must(
      runTool('helm', [
        'template',
        'qualor',
        toWork(tgz),
        '-f',
        '/work/deploy/helm/qualor/ci/embedded-values.yaml',
      ]),
      'helm template',
    ).stdout;
    expect(rendered).toContain(`image: "qualor/server@${digest}"`);
    expect(rendered).not.toContain('image: "qualor/server:');
    // The chart in the repository is unchanged (ruling RE6): the tag, no digest.
    expect(run('git', ['diff', '--quiet', '--', 'deploy/helm/qualor']).code).toBe(0);
  });
});
