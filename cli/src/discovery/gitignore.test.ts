import { mkdirSync, symlinkSync } from 'node:fs';
import type * as NodeFs from 'node:fs';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useTempDirs, writeTree } from '../../test/tmp';
import { Warnings } from '../warnings';
import { MAX_IGNORE_FILE_BYTES, readIgnoreLayer } from './gitignore';

const tmp = useTempDirs();

describe('readIgnoreLayer', () => {
  it('reads the rules of a plain ignore file', () => {
    const root = tmp();
    writeTree(root, { '.gitignore': 'dist/\n' });
    const warnings = new Warnings();
    const layer = readIgnoreLayer(path.join(root, '.gitignore'), '', warnings);
    expect(layer?.rules.ignores('dist/x.js')).toBe(true);
    expect(warnings.list()).toEqual([]);
  });

  it('returns null without a warning when the file does not exist', () => {
    const root = tmp();
    const warnings = new Warnings();
    expect(readIgnoreLayer(path.join(root, '.gitignore'), '', warnings)).toBeNull();
    expect(warnings.list()).toEqual([]);
  });

  it('never follows a symlink or junction, even one pointing outside the repo (root .gitignore)', () => {
    const root = tmp();
    const outside = tmp();
    writeTree(outside, { secret: 'this must never be read\n' });
    // A junction needs no privileges on Windows; on Linux the type argument is ignored, so this
    // is a plain symlink there too. Either way `.gitignore` itself is now a symlink, which lstat
    // (never stat/existsSync) must report without ever resolving the link.
    symlinkSync(outside, path.join(root, '.gitignore'), 'junction');
    const warnings = new Warnings();
    expect(readIgnoreLayer(path.join(root, '.gitignore'), '', warnings)).toBeNull();
    expect(warnings.list()).toContainEqual(
      expect.objectContaining({ code: 'SYMLINK_SKIPPED', count: 1 }),
    );
  });

  it('never follows a symlink or junction for a nested .gitignore', () => {
    const root = tmp();
    const outside = tmp();
    writeTree(outside, { secret: 'this must never be read\n' });
    mkdirSync(path.join(root, 'src'));
    symlinkSync(outside, path.join(root, 'src', '.gitignore'), 'junction');
    const warnings = new Warnings();
    expect(readIgnoreLayer(path.join(root, 'src', '.gitignore'), 'src', warnings)).toBeNull();
    expect(warnings.list()).toContainEqual(
      expect.objectContaining({ code: 'SYMLINK_SKIPPED', count: 1 }),
    );
  });

  it('skips a non-regular file (here: a directory named .gitignore) with a warning', () => {
    const root = tmp();
    mkdirSync(path.join(root, '.gitignore'));
    const warnings = new Warnings();
    expect(readIgnoreLayer(path.join(root, '.gitignore'), '', warnings)).toBeNull();
    expect(warnings.list()).toContainEqual(
      expect.objectContaining({ code: 'GITIGNORE_UNREADABLE' }),
    );
  });

  it('skips a .gitignore larger than the size cap, without reading it in full, with a warning', () => {
    const root = tmp();
    writeTree(root, { '.gitignore': 'x'.repeat(MAX_IGNORE_FILE_BYTES + 1) });
    const warnings = new Warnings();
    expect(readIgnoreLayer(path.join(root, '.gitignore'), '', warnings)).toBeNull();
    expect(warnings.list()).toContainEqual(
      expect.objectContaining({ code: 'GITIGNORE_UNREADABLE' }),
    );
  });

  it('reads a file exactly at the size cap', () => {
    const root = tmp();
    writeTree(root, { '.gitignore': `${'x'.repeat(MAX_IGNORE_FILE_BYTES - 1)}\n` });
    const warnings = new Warnings();
    expect(readIgnoreLayer(path.join(root, '.gitignore'), '', warnings)).not.toBeNull();
    expect(warnings.list()).toEqual([]);
  });
});

/**
 * Real symlinks/junctions exercise the whole stack, but the security-critical branch — "lstat
 * says this is a symlink, so never call readFileSync on it" — must hold on every platform this
 * runs on, independent of whatever symlink privileges happen to be available. This stubs
 * `node:fs` directly so the branch is covered even where the tests above could not construct a
 * real symlink.
 */
describe('readIgnoreLayer (lstat stubbed)', () => {
  // The module cache must be cleared before each dynamic import below picks up its mock, not just
  // after: the very first import in this describe block would otherwise still resolve to the
  // (unmocked) instance of './gitignore' already cached by the static import at the top of this
  // file.
  beforeEach(() => {
    vi.resetModules();
  });
  afterEach(() => {
    vi.doUnmock('node:fs');
    vi.resetModules();
  });

  it('skips and warns on any lstat result reporting a symbolic link, and never reads it', async () => {
    const readFileSync = vi.fn();
    vi.doMock('node:fs', async (importOriginal) => {
      const actual = await importOriginal<typeof NodeFs>();
      return {
        ...actual,
        lstatSync: () => ({ isSymbolicLink: () => true, isFile: () => false, size: 0 }),
        readFileSync,
      };
    });
    const stubbed = await import('./gitignore');
    const warnings = new Warnings();
    expect(stubbed.readIgnoreLayer('/anywhere/.gitignore', '', warnings)).toBeNull();
    expect(warnings.list()).toContainEqual(expect.objectContaining({ code: 'SYMLINK_SKIPPED' }));
    expect(readFileSync).not.toHaveBeenCalled();
  });

  it('skips and warns on any lstat result reporting a non-regular file, and never reads it', async () => {
    const readFileSync = vi.fn();
    vi.doMock('node:fs', async (importOriginal) => {
      const actual = await importOriginal<typeof NodeFs>();
      return {
        ...actual,
        lstatSync: () => ({ isSymbolicLink: () => false, isFile: () => false, size: 0 }),
        readFileSync,
      };
    });
    const stubbed = await import('./gitignore');
    const warnings = new Warnings();
    expect(stubbed.readIgnoreLayer('/anywhere/.gitignore', '', warnings)).toBeNull();
    expect(warnings.list()).toContainEqual(
      expect.objectContaining({ code: 'GITIGNORE_UNREADABLE' }),
    );
    expect(readFileSync).not.toHaveBeenCalled();
  });
});
