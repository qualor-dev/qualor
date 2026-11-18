import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach } from 'vitest';
import { createToolRunner } from '../../src/fix/runner';
import { silentLogger } from '../../src/log';
import { GIT_TEST_ENV } from '../git';

/** The test process's own Go settings and profile folders, replaced for every `go` call. */
const REPLACED = /^(GO\w*|HOME|USERPROFILE|APPDATA|LOCALAPPDATA|XDG_\w+)$/i;

/** How long `go clean -modcache` may take. */
const CLEAN_MS = 120_000;

/**
 * The Go adapter tests' environment (R27): call once per test file, at its top level, like
 * `useTempDirs`. The function it returns gives `go` its own home, profile folders (`APPDATA`,
 * `XDG_*`), `GOENV=off`, `GOPATH`, `GOCACHE` and `GOMODCACHE` in a new temporary folder, so
 * nothing of this machine's Go setup plays a part, plus `vars` (`GOPROXY`, `GOSUMDB`, `GOFLAGS`).
 * After each test the folder goes: first `go clean -modcache` (go makes the module cache
 * read-only, which a plain removal cannot undo on Linux), then the folder itself.
 */
export function useGoTestEnv(): (vars: Record<string, string>) => Record<string, string> {
  const homes: { dir: string; env: Record<string, string> }[] = [];
  afterEach(async () => {
    for (const home of homes.splice(0)) {
      const go = createToolRunner({ env: home.env, root: home.dir, log: silentLogger });
      await go('go', ['clean', '-modcache'], { cwd: home.dir, timeoutMs: CLEAN_MS }).catch(
        () => null,
      );
      rmSync(home.dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
    }
  });
  return (vars) => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-fix-go-home-'));
    const at = (name: string) => path.join(dir, name);
    const inherited = Object.entries(GIT_TEST_ENV).filter(
      (entry): entry is [string, string] => entry[1] !== undefined && !REPLACED.test(entry[0]),
    );
    const env = {
      ...Object.fromEntries(inherited),
      HOME: dir,
      USERPROFILE: dir,
      APPDATA: at('AppData'),
      LOCALAPPDATA: at('LocalAppData'),
      XDG_CONFIG_HOME: at('config'),
      XDG_CACHE_HOME: at('cache'),
      GOENV: 'off',
      GOPATH: at('gopath'),
      GOCACHE: at('gocache'),
      GOMODCACHE: at('gomodcache'),
      ...vars,
    };
    homes.push({ dir, env });
    return env;
  };
}
