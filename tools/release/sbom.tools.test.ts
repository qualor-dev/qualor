import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { must, REPO_ROOT, run } from '../deploy/stack';
import {
  CLI_SBOM_NAME,
  cliDepsArgs,
  cliSbomArgs,
  pnpmCommand,
  spdxProblems,
  syftArgs,
} from './sbom';
import { runTool, toWork } from './toolbox';

const dir = path.join(REPO_ROOT, '.tmp', 'release-test', randomBytes(4).toString('hex'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const packagesOf = (file: string): string[] =>
  (JSON.parse(readFileSync(file, 'utf8')) as { packages: { name: string }[] }).packages.map(
    (p) => p.name,
  );

describe('Syft with no network (release.md §8)', () => {
  it('writes an SPDX 2.3 SBOM of a directory', () => {
    mkdirSync(dir, { recursive: true });
    const out = path.join(dir, 'ts-basic.spdx.json');
    const r = runTool('syft', syftArgs('dir:/work/fixtures/ts-basic', toWork(out)));
    expect(r.code, r.stderr).toBe(0);
    expect(spdxProblems(readFileSync(out, 'utf8'))).toEqual([]);
  });

  it('lists the npm packages of the CLI production install, and nothing from its tests', () => {
    const deps = path.join(dir, 'cli-deps');
    const pnpm = pnpmCommand();
    must(run(pnpm.command, [...pnpm.args, ...cliDepsArgs(deps)]), 'pnpm deploy @qualor/cli');
    const out = path.join(dir, 'cli.spdx.json');
    const r = runTool('syft', cliSbomArgs(toWork(deps), toWork(out), '0.0.0-test'));
    expect(r.code, r.stderr).toBe(0);
    expect(spdxProblems(readFileSync(out, 'utf8'))).toEqual([]);
    // --source-name/--source-version: the document is named after the binary (release.md §8).
    const doc = JSON.parse(readFileSync(out, 'utf8')) as { name: string };
    expect(doc.name).toBe(CLI_SBOM_NAME);
    const cliPackage = JSON.parse(readFileSync('cli/package.json', 'utf8')) as {
      dependencies: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const names = packagesOf(out);
    for (const dependency of Object.keys(cliPackage.dependencies)) {
      expect(names, dependency).toContain(dependency);
    }
    for (const dev of Object.keys(cliPackage.devDependencies ?? {})) {
      expect(names, dev).not.toContain(dev);
    }
    // cli/test's fixtures (a Maven project, a web app) are not part of the binary.
    expect(names).not.toContain('junit');
    expect(names).not.toContain('deps-web');

    // The control: on the same node_modules, the default directory catalogers read lock files
    // only, and miss them all. (The deploy directory's root holds the workspace's lockfile.)
    const plain = path.join(dir, 'cli-plain.spdx.json');
    expect(runTool('syft', syftArgs(`dir:${toWork(deps)}/node_modules`, toWork(plain))).code).toBe(
      0,
    );
    expect(packagesOf(plain)).not.toContain('zod');
  }, 120_000);
});
