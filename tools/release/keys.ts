import { randomBytes } from 'node:crypto';
import { mkdirSync, rmSync } from 'node:fs';
import { must } from '../deploy/stack';
import { runTool, toWork } from './toolbox';

/**
 * The throwaway key pair of the dry run and the tests (release.md §7.3): generated under .tmp/
 * (git-ignored) with a random password, which reaches cosign by variable name only, and removed
 * afterwards. Never a real release key.
 */
export interface Keys {
  hostDir: string;
  /** Paths inside the toolbox. */
  key: string;
  pub: string;
  password: string;
}

/**
 * Every key directory this process created and has not removed yet. They are removed when the
 * process exits, and on SIGINT and SIGTERM, whoever the caller is (release.md §10), so an
 * interrupted test or probe does not leave a private key behind.
 */
const live = new Set<string>();
let hooked = false;

export function liveKeyDirs(): string[] {
  return [...live];
}

export function removeLiveKeys(): void {
  for (const dir of live) rmSync(dir, { recursive: true, force: true });
  live.clear();
}

function onSignal(signal: NodeJS.Signals): void {
  removeLiveKeys();
  // Alone, this handler would swallow the signal; with others (the dry run's), they decide.
  if (process.listenerCount(signal) === 1) process.exit(130);
}

/** Registers `dir` for removal on exit, SIGINT and SIGTERM. */
export function trackKeyDir(dir: string): void {
  live.add(dir);
  if (hooked) return;
  hooked = true;
  process.on('exit', removeLiveKeys);
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);
}

export function generateKeys(hostDir: string): Keys {
  // toWork first: a directory outside the repository is refused before anything is written.
  const dir = toWork(hostDir);
  trackKeyDir(hostDir);
  mkdirSync(hostDir, { recursive: true });
  const password = randomBytes(24).toString('hex');
  try {
    must(
      runTool('cosign', ['generate-key-pair'], {
        workdir: dir,
        env: { COSIGN_PASSWORD: password },
      }),
      'cosign generate-key-pair',
    );
  } catch (error) {
    removeKeys({ hostDir });
    throw error;
  }
  return { hostDir, key: `${dir}/cosign.key`, pub: `${dir}/cosign.pub`, password };
}

export function removeKeys(k: Pick<Keys, 'hostDir'>): void {
  rmSync(k.hostDir, { recursive: true, force: true });
  live.delete(k.hostDir);
}
