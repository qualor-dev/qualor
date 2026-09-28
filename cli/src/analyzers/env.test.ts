import { symlinkSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { useTempDirs } from '../../test/tmp';
import { confineAnalyzerEnv, mergeAnalyzerEnv, sanitizeAnalyzerEnv } from './env';

describe('sanitizeAnalyzerEnv', () => {
  it('strips QUALOR_TOKEN, QUALOR_TOKEN_FILE and other QUALOR_*-secret-looking vars, keeping the rest', () => {
    const out = sanitizeAnalyzerEnv({
      PATH: '/usr/bin',
      HOME: '/home/qualor',
      QUALOR_TOKEN: 'super-secret',
      QUALOR_TOKEN_FILE: '/etc/qualor/token',
      QUALOR_URL: 'https://qualor.example.com',
      QUALOR_PROJECT_KEY: 'my-project',
      QUALOR_SERVER_API_KEY: 'also-secret',
      CI: 'true',
      undef: undefined,
    });
    expect(out).toEqual({
      PATH: '/usr/bin',
      HOME: '/home/qualor',
      QUALOR_URL: 'https://qualor.example.com',
      QUALOR_PROJECT_KEY: 'my-project',
      CI: 'true',
    });
  });

  it('leaves non-QUALOR_ secret-looking names alone (scoped to QUALOR_*, ruling: fix-round finding 3)', () => {
    const out = sanitizeAnalyzerEnv({ GITHUB_TOKEN: 'x', CI_JOB_TOKEN: 'y' });
    expect(out).toEqual({ GITHUB_TOKEN: 'x', CI_JOB_TOKEN: 'y' });
  });

  it('matches QUALOR_* names case-insensitively on Windows, but case-sensitively elsewhere (fix-round-2 finding 6)', () => {
    const mixedCase = {
      Path: 'C:\\Windows',
      qualor_token: 'super-secret',
      Qualor_Token_File: 'C:\\token.txt',
      QuAlOr_OtHeR_sEcReT: 'also-secret',
      SAFE_VAR: 'kept',
    };
    expect(sanitizeAnalyzerEnv(mixedCase, { platform: 'win32' })).toEqual({
      Path: 'C:\\Windows',
      SAFE_VAR: 'kept',
    });
    // On POSIX these lower/mixed-case names are simply different, unrelated variables.
    expect(sanitizeAnalyzerEnv(mixedCase, { platform: 'linux' })).toEqual(mixedCase);
  });
});

describe('confineAnalyzerEnv', () => {
  const tmp = useTempDirs();

  it('drops relative, empty and in-repository PATH and CLASSPATH entries (ruling V3)', () => {
    const root = tmp();
    const outside = tmp();
    const d = path.delimiter;
    const inRepo = path.join(root, 'bin');
    const out = confineAnalyzerEnv(
      {
        PATH: [
          'bin',
          '',
          inRepo,
          outside,
          '.',
          path.join(root, '..', path.basename(root), 'x'),
        ].join(d),
        CLASSPATH: ['.', path.join(root, 'lib', 'a.jar'), outside].join(d),
        HOME: root,
      },
      root,
    );
    expect(out).toEqual({ PATH: outside, CLASSPATH: outside, HOME: root });
  });

  it('removes the variable when no entry is left, so an empty PATH never means the working directory', () => {
    const root = tmp();
    expect(
      confineAnalyzerEnv({ PATH: `bin${path.delimiter}.`, CLASSPATH: '.', X: '1' }, root),
    ).toEqual({ X: '1' });
  });

  it.runIf(process.platform === 'win32')(
    'matches Path and classpath case-insensitively on Windows',
    () => {
      const root = tmp();
      const outside = tmp();
      expect(
        confineAnalyzerEnv({ Path: `bin;${outside}`, classpath: `.;${outside}` }, root),
      ).toEqual({ Path: outside, classpath: outside });
    },
  );

  it.runIf(process.platform !== 'win32')(
    'follows symlinks: an outside link into the repository is dropped',
    () => {
      const root = tmp();
      const outside = tmp();
      const link = path.join(outside, 'link');
      symlinkSync(root, link);
      expect(confineAnalyzerEnv({ PATH: [link, outside].join(':') }, root)).toEqual({
        PATH: outside,
      });
    },
  );
});

describe('confineAnalyzerEnv: dynamic loader variables (fix round 1 of tasks 3-4)', () => {
  const tmp2 = useTempDirs();

  it.runIf(process.platform !== 'win32')(
    'drops empty, relative and in-repository library path, preload and audit entries',
    () => {
      const root = tmp2();
      const outside = tmp2();
      const lib = path.join(outside, 'libx.so');
      const inRepo = path.join(root, 'evil.so');
      const out = confineAnalyzerEnv(
        {
          LD_LIBRARY_PATH: `:lib:${path.join(root, 'lib')}:${outside}:`,
          DYLD_LIBRARY_PATH: `.:${outside}`,
          DYLD_FALLBACK_LIBRARY_PATH: `${root}`,
          LD_PRELOAD: `evil.so ${inRepo}:${lib} libc.so.6 ./rel.so:sub/rel.so`,
          LD_AUDIT: `${inRepo}:${lib}`,
          OTHER: ':x',
        },
        root,
      );
      expect(out).toEqual({
        LD_LIBRARY_PATH: outside,
        DYLD_LIBRARY_PATH: outside,
        // A bare name is looked up by the loader in the (confined) library path and the system
        // directories, never the working directory; a relative path with a slash is.
        LD_PRELOAD: `evil.so:${lib}:libc.so.6`,
        LD_AUDIT: lib,
        OTHER: ':x',
      });
    },
  );

  it.runIf(process.platform !== 'win32')(
    'splits LD_LIBRARY_PATH on semicolons too, as the dynamic loader does',
    () => {
      const root = tmp2();
      const outside = tmp2();
      expect(
        confineAnalyzerEnv({ LD_LIBRARY_PATH: `${outside};lib;${root}:.;${outside}` }, root),
      ).toEqual({ LD_LIBRARY_PATH: `${outside}:${outside}` });
    },
  );
});

describe('confineAnalyzerEnv: Python variables (Semgrep is a Python program)', () => {
  const tmp3 = useTempDirs();

  it('drops empty, relative and in-repository PYTHONPATH entries, keeping the rest', () => {
    const root = tmp3();
    const outside = tmp3();
    const d = path.delimiter;
    expect(
      confineAnalyzerEnv(
        { PYTHONPATH: ['', '.', 'lib', path.join(root, 'py'), outside].join(d) },
        root,
      ),
    ).toEqual({ PYTHONPATH: outside });
    expect(confineAnalyzerEnv({ PYTHONPATH: `${d}.` }, root)).toEqual({});
  });

  it('keeps PYTHONHOME, PYTHONSTARTUP, PYTHONUSERBASE, PYTHONPYCACHEPREFIX and PYTHONEXECUTABLE only when absolute and outside the repository', () => {
    const root = tmp3();
    const outside = tmp3();
    const names = [
      'PYTHONHOME',
      'PYTHONSTARTUP',
      'PYTHONUSERBASE',
      'PYTHONPYCACHEPREFIX',
      'PYTHONEXECUTABLE',
    ];
    for (const bad of ['', '.', 'py', root, path.join(root, 'py')]) {
      const env = Object.fromEntries(names.map((n) => [n, bad]));
      expect(confineAnalyzerEnv({ ...env, X: '1' }, root), bad).toEqual({ X: '1' });
    }
    const good = Object.fromEntries(names.map((n) => [n, outside]));
    expect(confineAnalyzerEnv(good, root)).toEqual(good);
    // PYTHONHOME may name prefix and exec_prefix; one entry in the repository drops it all.
    const d = path.delimiter;
    expect(confineAnalyzerEnv({ PYTHONHOME: `${outside}${d}${root}` }, root)).toEqual({});
  });

  it.runIf(process.platform === 'win32')(
    'matches Python names case-insensitively on Windows',
    () => {
      const root = tmp3();
      expect(confineAnalyzerEnv({ PythonPath: '.', pythonhome: root }, root)).toEqual({});
    },
  );
});

describe('confineAnalyzerEnv: JAVA_HOME', () => {
  const tmp4 = useTempDirs();

  it('keeps JAVA_HOME only when absolute and outside the repository (the PMD launcher runs its java)', () => {
    const root = tmp4();
    const outside = tmp4();
    for (const bad of ['', 'jdk', root, path.join(root, 'jdk')]) {
      expect(confineAnalyzerEnv({ JAVA_HOME: bad, X: '1' }, root), bad).toEqual({ X: '1' });
    }
    expect(confineAnalyzerEnv({ JAVA_HOME: outside }, root)).toEqual({ JAVA_HOME: outside });
  });
});

describe('mergeAnalyzerEnv', () => {
  it('lets an adapter variable replace the parent one, case-insensitively on Windows only', () => {
    const parent = { Http_Proxy: 'http://ci:3128', PATH: '/usr/bin', X: undefined };
    const extra = { HTTP_PROXY: 'http://127.0.0.1:9' };
    expect(mergeAnalyzerEnv(parent, extra, 'win32')).toEqual({
      PATH: '/usr/bin',
      X: undefined,
      HTTP_PROXY: 'http://127.0.0.1:9',
    });
    expect(mergeAnalyzerEnv(parent, extra, 'linux')).toEqual({
      Http_Proxy: 'http://ci:3128',
      PATH: '/usr/bin',
      X: undefined,
      HTTP_PROXY: 'http://127.0.0.1:9',
    });
    expect(mergeAnalyzerEnv(parent, undefined, 'win32')).toEqual(parent);
  });
});
