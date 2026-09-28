import * as fs from 'node:fs';
import type { Dirent } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import { useTempDirs } from '../../test/tmp';
import { resolveConfigs } from './semgrep';

// readdirSync is replaced by a pass-through spy, so one test can hand the rule-file search a
// directory listing in a known order (a real directory's order depends on the file system).
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof fs>();
  return { ...actual, readdirSync: vi.fn(actual.readdirSync) };
});

const tmp = useTempDirs();

function entry(name: string): Dirent {
  return { name, isDirectory: () => false } as Dirent;
}

describe('the qualor-default rule-file search', () => {
  it('stops at its bound of 10 000 entries, also inside one directory', () => {
    const root = tmp();
    const pack = tmp();
    const listing = Array.from({ length: 10_000 }, (_, i) => entry(`notes-${i}.txt`));
    listing.push(entry('rules.yml'));
    vi.mocked(fs.readdirSync).mockImplementationOnce(
      (() => listing) as unknown as typeof fs.readdirSync,
    );
    // The rule file is entry 10 001: past the bound, so the directory counts as holding none.
    expect(resolveConfigs(root, ['qualor-default'], pack)).toEqual({
      skip: 'the qualor/scanner image ships no Semgrep rules yet; set analyzers.semgrep.configs to local rule files',
    });
  });

  it('finds a rule file within the bound', () => {
    const root = tmp();
    const pack = tmp();
    const listing = [entry('README.md'), entry('rules.yml')];
    vi.mocked(fs.readdirSync).mockImplementationOnce(
      (() => listing) as unknown as typeof fs.readdirSync,
    );
    expect(resolveConfigs(root, ['qualor-default'], pack)).toEqual([pack]);
  });
});
