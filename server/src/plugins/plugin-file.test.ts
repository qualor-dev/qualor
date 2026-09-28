import { mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { checkPluginFile, type PluginFileSystem } from './loader';

const SERVER_UID = 1000;

/** A fake POSIX file system: `files` maps a path to its mode and owner, `links` to a target. */
function posix(
  files: Record<string, { mode: number; uid: number; dir?: boolean }>,
  links: Record<string, string> = {},
): PluginFileSystem & { realpath: ReturnType<typeof vi.fn> } {
  return {
    realpath: vi.fn(async (p: string) => {
      const target = links[p] ?? p;
      if (!files[target]) throw new Error('ENOENT');
      return target;
    }),
    stat: async (p: string) => {
      const f = files[p];
      if (!f) throw new Error('ENOENT');
      return { isFile: () => !f.dir, mode: f.mode, uid: f.uid };
    },
    platform: 'linux',
    uid: SERVER_UID,
  };
}

const dir = (mode = 0o755, uid = 0) => ({ mode, uid, dir: true });
const file = (mode = 0o644, uid = 0) => ({ mode, uid });

describe('checkPluginFile (enterprise.md §10.1.1, ruling R-PLUGINPATH)', () => {
  it('accepts a root-owned read-only file in a root-owned directory', async () => {
    const fs = posix({ '/app/enterprise': dir(), '/app/enterprise/plugin.js': file() });
    expect(await checkPluginFile('/app/enterprise/plugin.js', fs)).toEqual({
      ok: true,
      realPath: '/app/enterprise/plugin.js',
    });
  });

  it("accepts a file owned by the server's own user", async () => {
    const fs = posix({
      '/srv/plugins': dir(0o755, SERVER_UID),
      '/srv/plugins/p.mjs': file(0o600, SERVER_UID),
    });
    expect(await checkPluginFile('/srv/plugins/p.mjs', fs)).toMatchObject({ ok: true });
  });

  it('follows a symbolic link (a ConfigMap mount) and answers the resolved path', async () => {
    const fs = posix(
      { '/etc/qualor/..data': dir(), '/etc/qualor/..data/plugin.js': file() },
      { '/etc/qualor/plugin.js': '/etc/qualor/..data/plugin.js' },
    );
    expect(await checkPluginFile('/etc/qualor/plugin.js', fs)).toEqual({
      ok: true,
      realPath: '/etc/qualor/..data/plugin.js',
    });
  });

  it.each([
    ['a UNC path', '\\\\server\\share\\plugin.js'],
    ['a UNC path with slashes', '//server/share/plugin.js'],
    ['a Win32 long path', '\\\\?\\C:\\plugins\\plugin.js'],
    ['a Win32 device path', '\\\\.\\C:\\plugins\\plugin.js'],
    ['a relative path', 'plugins/plugin.js'],
  ])('refuses %s before resolving it', async (_what, p) => {
    const fs = posix({});
    const result = await checkPluginFile(p, fs);
    expect(result.ok).toBe(false);
    expect(fs.realpath).not.toHaveBeenCalled();
  });

  it('refuses a link that resolves to a UNC path', async () => {
    const fs = posix(
      { '//server/share/plugin.js': file(), '//server/share': dir() },
      { '/app/plugin.js': '//server/share/plugin.js' },
    );
    expect(await checkPluginFile('/app/plugin.js', fs)).toMatchObject({
      ok: false,
      reason: expect.stringMatching(/UNC/),
    });
  });

  it.each([
    ['a missing file', {}, {}, /does not exist/],
    ['a directory', { '/p': dir(), '/p/x.js': dir() }, {}, /not a regular file/],
    [
      'a link to another kind of file',
      { '/p': dir(), '/p/x.txt': file() },
      { '/p/x.js': '/p/x.txt' },
      /\.js or \.mjs/,
    ],
    [
      'a group-writable file',
      { '/p': dir(), '/p/x.js': file(0o664) },
      {},
      /writable by group or others/,
    ],
    [
      'a world-writable file',
      { '/p': dir(), '/p/x.js': file(0o646) },
      {},
      /writable by group or others/,
    ],
    [
      'a file of another user',
      { '/p': dir(), '/p/x.js': file(0o644, 1234) },
      {},
      /not owned by root/,
    ],
    [
      'a world-writable directory',
      { '/p': dir(0o777), '/p/x.js': file() },
      {},
      /directory is writable/,
    ],
    [
      'a sticky world-writable directory',
      { '/p': dir(0o1777), '/p/x.js': file() },
      {},
      /directory is writable/,
    ],
    [
      'a directory of another user',
      { '/p': dir(0o755, 1234), '/p/x.js': file() },
      {},
      /directory is not owned/,
    ],
  ] as const)('refuses %s', async (_what, files, links, reason) => {
    const result = await checkPluginFile('/p/x.js', posix({ ...files }, { ...links }));
    expect(result).toMatchObject({ ok: false, reason: expect.stringMatching(reason) });
  });

  it('checks no owner or mode on Windows', async () => {
    const fs = {
      ...posix({ 'C:\\p': dir(0o777, 5), 'C:\\p\\x.js': file(0o666, 5) }),
      platform: 'win32' as const,
    };
    expect(await checkPluginFile('C:\\p\\x.js', fs)).toMatchObject({ ok: true });
  });

  describe('on the real file system', () => {
    const tmp = mkdtempSync(path.join(tmpdir(), 'qualor-plugin-file-'));
    afterAll(() => rmSync(tmp, { recursive: true, force: true }));

    it('accepts a file this process wrote, and refuses a missing one', async () => {
      const plugin = path.join(tmp, 'plugin.js');
      writeFileSync(plugin, 'export default {};\n', { mode: 0o644 });
      expect(await checkPluginFile(plugin)).toEqual({
        ok: true,
        realPath: realpathSync.native(plugin),
      });
      expect(await checkPluginFile(path.join(tmp, 'missing.js'))).toMatchObject({ ok: false });
    });
  });
});
