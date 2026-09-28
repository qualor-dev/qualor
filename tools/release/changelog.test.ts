import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { changelogSection, releaseNotes } from './changelog';

const md = [
  '# Changelog',
  '',
  '## [Unreleased]',
  '',
  '- next',
  '',
  '## [1.1.0] - 2026-10-01',
  '',
  '### Fixed',
  '- one',
  '',
  '## [1.0.0] - 2026-09-30',
  '',
  '- first',
  '',
].join('\n');

describe('CHANGELOG.md (release.md §2)', () => {
  it('returns the section of one version, without its heading', () => {
    expect(changelogSection(md, '1.1.0')).toBe('### Fixed\n- one');
    expect(changelogSection(md, '1.0.0')).toBe('- first');
    expect(changelogSection(md, '1.0')).toBeNull();
  });

  it('falls back to Unreleased only when allowed (the dry run), never for publishing', () => {
    expect(releaseNotes(md, '1.2.0', { allowUnreleased: true })).toEqual({
      notes: '- next',
      fromUnreleased: true,
    });
    expect(() => releaseNotes(md, '1.2.0', { allowUnreleased: false })).toThrow(
      'CHANGELOG.md has no "## [1.2.0] - YYYY-MM-DD" section',
    );
  });

  it('refuses a version heading without a real date, and an empty section', () => {
    const notes =
      (text: string, version = '2.0.0', allowUnreleased = false) =>
      () =>
        releaseNotes(text, version, { allowUnreleased });
    for (const heading of ['## [2.0.0]', '## [2.0.0] - soon', '## [2.0.0] - 2026-02-30']) {
      expect(notes(`${heading}\n\n- a\n`), heading).toThrow(
        /must read "## \[2\.0\.0\] - YYYY-MM-DD"/,
      );
    }
    expect(notes('## [2.0.0] - 2026-10-02\n\n## [1.0.0] - 2026-09-30\n- x\n')).toThrow(
      /section of 2\.0\.0 is empty/,
    );
    expect(notes('## [Unreleased]\n\n## [1.0.0] - 2026-09-30\n- x\n', '2.0.0', true)).toThrow(
      /Unreleased section is empty/,
    );
    expect(
      releaseNotes('## [2.0.0] - 2026-10-02\n- a\n', '2.0.0', { allowUnreleased: false }),
    ).toEqual({ notes: '- a', fromUnreleased: false });
  });

  it('the repository has a changelog with an Unreleased section', () => {
    expect(changelogSection(readFileSync('CHANGELOG.md', 'utf8'), 'Unreleased')).not.toBeNull();
  });
});
