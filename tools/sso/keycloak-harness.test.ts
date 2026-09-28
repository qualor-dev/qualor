import { existsSync, readFileSync, statSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { type Runner, startKeycloak } from './keycloak';

/**
 * Plan 4D Task 20, fix round 1: the Keycloak harness never puts the bootstrap admin's password on
 * a command line, so a failed `docker run` (whose execFile error repeats the whole command line in
 * its message and `cmd`) cannot print it. A fake runner stands in for Docker: no container runs.
 */
describe('startKeycloak keeps the bootstrap admin password off every command line', () => {
  it('a failing docker run: the error, the arguments and the output hold no password; the directory is removed', async () => {
    const calls: string[][] = [];
    let password = '';
    let envFile = '';
    let envMode = 0;
    const run: Runner = async (file, args) => {
      calls.push([file, ...args]);
      if (args[0] === 'run') {
        envFile = args[args.indexOf('--env-file') + 1] ?? '';
        const text = readFileSync(envFile, 'utf8');
        password = /^KC_BOOTSTRAP_ADMIN_PASSWORD=(.+)$/m.exec(text)?.[1] ?? '';
        envMode = statSync(envFile).mode & 0o777;
        // What execFile rejects with: the command line in the message and in `cmd`.
        const cmd = [file, ...args].join(' ');
        throw Object.assign(new Error(`Command failed: ${cmd}\nUnable to find image`), {
          cmd,
          code: 125,
          stdout: '',
          stderr: 'Unable to find image',
        });
      }
      return { stdout: '', stderr: '' };
    };

    const error = await startKeycloak({ realm: 'qualor', clients: [] }, { run }).then(
      () => null,
      (err: unknown) => err as Error & { cmd?: string },
    );

    expect(error).toBeInstanceOf(Error);
    expect(password.length).toBeGreaterThanOrEqual(20);
    expect(error?.message).not.toContain(password);
    expect(error?.cmd ?? '').not.toContain(password);
    expect(calls.flat().join(' ')).not.toContain(password);
    expect(calls.flat().join(' ')).not.toMatch(/KC_BOOTSTRAP_ADMIN_PASSWORD/);
    if (process.platform !== 'win32') expect(envMode).toBe(0o600);
    // The failed start removed the container (by name) and the directory with the env file.
    expect(
      calls.some((c) => c[1] === 'rm' && c[2] === '-f' && c[3]?.startsWith('qualor-kc-')),
    ).toBe(true);
    expect(envFile).not.toBe('');
    expect(existsSync(envFile)).toBe(false);
  });

  it('mounts only the realm subdirectory, never the directory holding the env file', async () => {
    let mount = '';
    let envFile = '';
    const run: Runner = async (_file, args) => {
      if (args[0] === 'run') {
        mount = args[args.indexOf('--mount') + 1] ?? '';
        envFile = args[args.indexOf('--env-file') + 1] ?? '';
        throw new Error('stop here');
      }
      return { stdout: '', stderr: '' };
    };
    await expect(startKeycloak({ realm: 'qualor', clients: [] }, { run })).rejects.toThrow(
      'stop here',
    );
    const source = /source=([^,]+),/.exec(mount)?.[1] ?? '';
    expect(source).toMatch(/[\\/]realm$/);
    expect(envFile.startsWith(source)).toBe(false);
  });
});
