import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { brotliDecompressSync, gunzipSync } from 'node:zlib';
import { afterEach, describe, expect, it } from 'vitest';
import { loadUiAssets, preferredEncoding, UiAssetsError } from './ui';

const dirs: string[] = [];
async function uiDir(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'qualor-ui-'));
  dirs.push(dir);
  for (const [name, content] of Object.entries(files)) {
    await mkdir(join(dir, name, '..'), { recursive: true });
    await writeFile(join(dir, name), content);
  }
  return dir;
}
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

describe('loadUiAssets', () => {
  it('keys files by URL path, keeps index.html apart and marks hashed names immutable', async () => {
    const script = 'console.log(1);'.repeat(100);
    const dir = await uiDir({
      'index.html': '<app-root ngCspNonce="__QUALOR_CSP_NONCE__"></app-root>',
      'main-4BUTXKQY.js': script,
      'media/logo.svg': '<svg/>',
      'favicon.ico': 'x',
    });
    const assets = await loadUiAssets(dir);
    expect(assets.index).toContain('__QUALOR_CSP_NONCE__');
    expect([...assets.files.keys()].sort()).toEqual([
      '/favicon.ico',
      '/main-4BUTXKQY.js',
      '/media/logo.svg',
    ]);
    const main = assets.files.get('/main-4BUTXKQY.js')!;
    expect(main).toMatchObject({ contentType: 'text/javascript; charset=utf-8', immutable: true });
    expect(brotliDecompressSync(main.br!).toString()).toBe(script);
    expect(gunzipSync(main.gzip!).toString()).toBe(script);
    expect(main.etag).toMatch(/^"[\w-]{27}"$/);
    // Small files are not compressed; unhashed names are revalidated.
    expect(assets.files.get('/media/logo.svg')).toMatchObject({
      contentType: 'image/svg+xml',
      immutable: false,
      br: null,
      gzip: null,
    });
  });

  it('fails with a UiAssetsError for a missing directory or one without index.html', async () => {
    await expect(loadUiAssets(join(tmpdir(), 'qualor-ui-does-not-exist'))).rejects.toThrow(
      UiAssetsError,
    );
    const dir = await uiDir({ 'main.js': '1' });
    await expect(loadUiAssets(dir)).rejects.toThrow(/has no index\.html/);
  });

  it.skipIf(process.platform === 'win32')('skips symbolic links', async () => {
    const outside = await uiDir({ 'secret.txt': 'do not serve' });
    const dir = await uiDir({ 'index.html': '<html></html>' });
    await symlink(join(outside, 'secret.txt'), join(dir, 'secret.txt'));
    expect((await loadUiAssets(dir)).files.size).toBe(0);
  });

  it('skips linked directories (a junction on Windows) and never follows them', async () => {
    const outside = await uiDir({ 'secret.txt': 'do not serve' });
    const dir = await uiDir({ 'index.html': '<html></html>' });
    await symlink(outside, join(dir, 'linked'), 'junction');
    expect((await loadUiAssets(dir)).files.size).toBe(0);
  });

  it('accepts a QUALOR_UI_DIR that is itself a link (a junction on Windows)', async () => {
    const real = await uiDir({ 'index.html': '<html></html>', 'ok.txt': 'fine' });
    const parent = await uiDir({});
    await symlink(real, join(parent, 'current'), 'junction');
    expect([...(await loadUiAssets(join(parent, 'current'))).files.keys()]).toEqual(['/ok.txt']);
  });

  it('refuses a directory nested too deep or with too many entries, skipped ones included', async () => {
    const deep = await uiDir({ 'index.html': '<html></html>', 'a/b/c/d.txt': 'x' });
    await expect(loadUiAssets(deep, { maxDepth: 2 })).rejects.toThrow(/nests deeper than 2/);
    expect((await loadUiAssets(deep, { maxDepth: 3 })).files.size).toBe(1);
    const hidden = await uiDir({ 'index.html': '<html></html>', '.a': '', '.b': '', '.c': '' });
    await expect(loadUiAssets(hidden, { maxEntries: 3 })).rejects.toThrow(/more than 3 entries/);
  });

  it('marks only Angular output names immutable', async () => {
    const dir = await uiDir({
      'index.html': '<html></html>',
      'polyfills-ABCDEFGH.js': '1',
      'styles-5INURTSO.css': '1',
      'media/logo-ABCDEFGH.svg': '1',
      'favicon-ABCDEFGH.ico': '1',
      'assets/app-ABCDEFGH.js': '1',
      'chunk-ABCDEFGH.txt': '1',
      // Angular 22 (esbuild) hashes in mixed case with - and _:
      'chunk-7S2tK-6Y.js': '1',
      'chunk-BHOaG_M8.js': '1',
      'main-DSibPB6J.js': '1',
      'media/inter-Ab_9-xYz.woff2': '1',
      // Not a hash: wrong length, or a character outside [A-Za-z0-9_-].
      'chunk-7S2tK-6.js': '1',
      'chunk-7S2tK.6Y.js': '1',
      'chunk-7S2tK-6Yz.js': '1',
    });
    const immutable = [...(await loadUiAssets(dir)).files]
      .filter(([, file]) => file.immutable)
      .map(([path]) => path)
      .sort();
    expect(immutable).toEqual([
      '/chunk-7S2tK-6Y.js',
      '/chunk-BHOaG_M8.js',
      '/main-DSibPB6J.js',
      '/media/inter-Ab_9-xYz.woff2',
      '/media/logo-ABCDEFGH.svg',
      '/polyfills-ABCDEFGH.js',
      '/styles-5INURTSO.css',
    ]);
  });

  it('skips hidden files and directories (.env, .git)', async () => {
    const dir = await uiDir({
      'index.html': '<html></html>',
      '.env': 'SECRET=1',
      '.git/config': '[core]',
      'media/.DS_Store': 'x',
      'ok.txt': 'fine',
    });
    expect([...(await loadUiAssets(dir)).files.keys()]).toEqual(['/ok.txt']);
  });

  it('refuses a directory with too many files or bytes, before reading an oversized file', async () => {
    const dir = await uiDir({ 'index.html': '<html></html>', 'a.js': '1', 'b.js': '2' });
    await expect(loadUiAssets(dir, { maxFiles: 2, maxBytes: 1024 })).rejects.toThrow(
      /more than 2 files/,
    );
    const big = await uiDir({ 'index.html': '<html></html>', 'big.js': 'x'.repeat(2000) });
    await expect(loadUiAssets(big, { maxFiles: 10, maxBytes: 1024 })).rejects.toThrow(
      /more than 1024 bytes/,
    );
  });

  it('gives each extension its content type and unknown ones application/octet-stream', async () => {
    const dir = await uiDir({
      'index.html': '<html></html>',
      'styles-5INURTSO.css': 'a{}',
      'chunk-Q2PBAB7W.mjs': '1',
      'manifest.webmanifest': '{}',
      'font.woff2': 'x',
      'data.bin': 'x',
      'UPPER.PNG': 'x',
    });
    const types = Object.fromEntries(
      [...(await loadUiAssets(dir)).files].map(([path, file]) => [path, file.contentType]),
    );
    expect(types).toEqual({
      '/styles-5INURTSO.css': 'text/css; charset=utf-8',
      '/chunk-Q2PBAB7W.mjs': 'text/javascript; charset=utf-8',
      '/manifest.webmanifest': 'application/manifest+json',
      '/font.woff2': 'font/woff2',
      '/data.bin': 'application/octet-stream',
      '/UPPER.PNG': 'image/png',
    });
  });
});

describe('preferredEncoding', () => {
  it('prefers br, then gzip, and honours q=0', () => {
    expect(preferredEncoding('gzip, deflate, br, zstd')).toBe('br');
    expect(preferredEncoding('gzip')).toBe('gzip');
    expect(preferredEncoding('br;q=0, gzip;q=0.5')).toBe('gzip');
    expect(preferredEncoding('identity')).toBeNull();
    expect(preferredEncoding(undefined)).toBeNull();
  });

  it('refuses both at q=0 (also written 0.0 or with spaces) and ignores unknown tokens', () => {
    expect(preferredEncoding('br;q=0.0, gzip ; q=0')).toBeNull();
    expect(preferredEncoding('BR')).toBe('br');
    expect(preferredEncoding('xbr, gzipx')).toBeNull();
    expect(preferredEncoding('*')).toBeNull();
  });

  it('treats an invalid, negative, empty or out-of-range q as 0', () => {
    expect(preferredEncoding('br;q=-1, gzip')).toBe('gzip');
    expect(preferredEncoding('br;q=abc, gzip')).toBe('gzip');
    expect(preferredEncoding('br;q=, gzip')).toBe('gzip');
    expect(preferredEncoding('br;q=2, gzip;q=1')).toBe('gzip');
    expect(preferredEncoding('br;q=0.001')).toBe('br');
  });
});
