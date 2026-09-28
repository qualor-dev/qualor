import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { REPO_ROOT } from '../deploy/stack';

const TSX = path.join(REPO_ROOT, 'node_modules', 'tsx', 'dist', 'cli.mjs');
const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

/** Runs `then` in a child process that has registered a key directory with keys.ts. */
function child(then: string): { dir: string; status: number | null } {
  const dir = path.join(
    REPO_ROOT,
    '.tmp',
    'release-test',
    `keys-${randomBytes(4).toString('hex')}`,
  );
  dirs.push(dir);
  mkdirSync(dir, { recursive: true });
  writeFileSync(path.join(dir, 'cosign.key'), 'not a real key');
  const script = path.join(dir, '..', `${path.basename(dir)}.ts`);
  dirs.push(script);
  writeFileSync(
    script,
    `import { trackKeyDir } from ${JSON.stringify(pathToFileURL(path.join(REPO_ROOT, 'tools', 'release', 'keys.ts')).href)};\n` +
      `trackKeyDir(${JSON.stringify(dir)});\n${then}\n`,
  );
  const r = spawnSync(process.execPath, [TSX, script], { cwd: REPO_ROOT, encoding: 'utf8' });
  if (r.status === 1) throw new Error(r.stderr);
  return { dir, status: r.status };
}

describe('throwaway keys are removed however the process ends (release.md §7.3, §10)', () => {
  it('on exit', () => {
    const { dir, status } = child('process.exit(3);');
    expect(status).toBe(3);
    expect(existsSync(dir)).toBe(false);
  });

  it('on SIGINT and SIGTERM, exiting 130 when nothing else handles the signal', () => {
    for (const signal of ['SIGINT', 'SIGTERM']) {
      const { dir, status } = child(
        `process.emit(${JSON.stringify(signal)}, ${JSON.stringify(signal)}); setTimeout(() => {}, 5000);`,
      );
      expect(status, signal).toBe(130);
      expect(existsSync(dir), signal).toBe(false);
    }
  });

  it('leaves the exit to another handler of the signal (the dry run)', () => {
    const { dir, status } = child(
      "process.on('SIGINT', () => process.exit(7)); process.emit('SIGINT', 'SIGINT');",
    );
    expect(status).toBe(7);
    expect(existsSync(dir)).toBe(false);
  });
});
