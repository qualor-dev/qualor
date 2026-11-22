import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, rmSync } from 'node:fs';
import path from 'node:path';

/**
 * Stages vss-extension.json, overview.md, images/ and the built tasks/ into dist-ext/ and packs
 * them into a VSIX with tfx (run through node, so it behaves the same on Windows and Linux).
 * Arguments: `--output-path <dir>` (default ../../../.tmp/azure) and `--overrides-file <json>`
 * (for example dev-overrides.json: the private qualor-dev extension for a bench install).
 */
const root = path.resolve(__dirname, '..');

function option(args: readonly string[], name: string): string | undefined {
  const at = args.indexOf(name);
  return at >= 0 ? args[at + 1] : undefined;
}

function main(): void {
  const args = process.argv.slice(2);
  const out = path.resolve(root, option(args, '--output-path') ?? '../../../.tmp/azure');
  const overrides = option(args, '--overrides-file');
  const stage = path.join(root, 'dist-ext');
  rmSync(stage, { recursive: true, force: true });
  mkdirSync(stage, { recursive: true });
  cpSync(path.join(root, 'vss-extension.json'), path.join(stage, 'vss-extension.json'));
  cpSync(path.join(root, 'overview.md'), path.join(stage, 'overview.md'));
  cpSync(path.join(root, 'images'), path.join(stage, 'images'), { recursive: true });
  cpSync(path.join(root, 'dist', 'tasks'), path.join(stage, 'tasks'), { recursive: true });
  mkdirSync(out, { recursive: true });

  const tfx = require.resolve('tfx-cli/_build/tfx-cli.js', { paths: [root] });
  const tfxArgs = [
    tfx,
    'extension',
    'create',
    '--root',
    stage,
    '--manifest-globs',
    'vss-extension.json',
    '--output-path',
    out + path.sep,
  ];
  if (overrides !== undefined) tfxArgs.push('--overrides-file', path.resolve(root, overrides));
  const run = spawnSync(process.execPath, tfxArgs, { cwd: root, stdio: 'inherit' });
  if (run.status !== 0) process.exit(run.status ?? 1);
}

main();
