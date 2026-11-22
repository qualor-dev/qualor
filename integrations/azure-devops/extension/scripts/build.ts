import { copyFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { build } from 'esbuild';

/**
 * Builds the task into dist/: tasks/qualor/index.js (src/index.ts with azure-pipelines-task-lib
 * bundled in, so the task needs no node_modules), its task.json and its icon. The agent runs it
 * with Node 24 or Node 20 (task.json `execution`).
 */
const root = path.resolve(__dirname, '..');
const task = path.join(root, 'dist', 'tasks', 'qualor');

async function main(): Promise<void> {
  rmSync(path.join(root, 'dist'), { recursive: true, force: true });
  await build({
    absWorkingDir: root,
    entryPoints: ['tasks/qualor/src/index.ts'],
    outfile: path.join(task, 'index.js'),
    bundle: true,
    platform: 'node',
    target: 'node20',
    format: 'cjs',
    minify: false,
    logLevel: 'warning',
  });
  copyFileSync(path.join(root, 'tasks', 'qualor', 'task.json'), path.join(task, 'task.json'));
  copyFileSync(path.join(root, 'images', 'icon.png'), path.join(task, 'icon.png'));
  process.stdout.write('built dist/tasks/qualor\n');
}

main().catch((err: unknown) => {
  process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
});
