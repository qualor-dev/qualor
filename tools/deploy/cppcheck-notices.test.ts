import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const script = readFileSync('tools/analyzers/install-cppcheck.sh', 'utf8');
const version = /^CPPCHECK_VERSION=(.+)$/m.exec(script)?.[1] ?? '';
const sha = /^CPPCHECK_SHA256=(.+)$/m.exec(script)?.[1] ?? '';

/** What the cppcheck binary compiles in besides its own code (fact F2), as headed in the licence file. */
export const CPPCHECK_BUNDLED = ['simplecpp', 'tinyxml2', 'picojson'] as const;

describe('cppcheck licence and source (plan 9D, decision 1)', () => {
  it('ships the GPL text and the licences of what the binary compiles in', () => {
    const text = readFileSync('deploy/scanner/licenses/CPPCHECK-LICENSE.txt', 'utf8');
    expect(text).toContain('GNU GENERAL PUBLIC LICENSE');
    expect(text).toContain('Version 3, 29 June 2007');
    for (const name of CPPCHECK_BUNDLED) expect(text).toMatch(new RegExp(`^---- ${name} \\(`, 'm'));
    expect(text).toContain('BSD Zero Clause License');
    expect(text).toContain('Copyright 2011-2014 Kazuho Oku');
  });

  it('pins the exact archive the image builds as corresponding source', () => {
    const manifest = JSON.parse(readFileSync('deploy/scanner/sources.json', 'utf8')) as {
      sources: {
        component: string;
        componentVersion: string;
        sha256: string;
        licence: string;
        fetch: { url?: string };
      }[];
    };
    const entry = manifest.sources.find((s) => s.component === 'cppcheck');
    expect(entry).toMatchObject({
      componentVersion: version,
      sha256: sha,
      licence: 'GPL-3.0-or-later',
    });
    expect(entry?.fetch.url).toBe(
      `https://github.com/cppcheck-opensource/cppcheck/archive/refs/tags/${version}.tar.gz`,
    );
  });

  // Task 12 writes NOTICE.md and turns this into `it` (with the check that the docs name no
  // other cppcheck version than the pin).
  it.todo('NOTICE.md names cppcheck, its licence file and its source');
});
