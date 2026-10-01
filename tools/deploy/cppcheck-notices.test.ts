import { readdirSync, readFileSync } from 'node:fs';
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

  it('NOTICE.md names cppcheck, its licence file and its source', () => {
    const notice = readFileSync('deploy/scanner/NOTICE.md', 'utf8');
    const row = notice.split('\n').find((l) => /^\| cppcheck/.test(l)) ?? '';
    expect(row.split('|').map((c) => c.trim())[2]).toBe(version);
    expect(notice).toContain('GPL-3.0-or-later');
    expect(notice).toContain('CPPCHECK-LICENSE.txt');
    expect(notice).toContain(`https://github.com/cppcheck-opensource/cppcheck/tree/${version}`);
    expect(notice).toContain('qualor/scanner-sources');
    expect(notice).toContain('tree-sitter-c 0.24.1');
    expect(notice).toContain('tree-sitter-cpp 0.23.4');
  });

  it('names no other cppcheck version than the pinned one in the docs (CHANGELOG history aside)', () => {
    const docs = [
      'README.md',
      'deploy/README.md',
      'deploy/scanner/NOTICE.md',
      ...readdirSync('deploy/dockerhub')
        .filter((f) => f.endsWith('.md'))
        .map((f) => `deploy/dockerhub/${f}`),
      ...readdirSync('docs/guide')
        .filter((f) => f.endsWith('.md'))
        .map((f) => `docs/guide/${f}`),
    ];
    const named: string[] = [];
    for (const file of docs) {
      for (const m of readFileSync(file, 'utf8').matchAll(/cppcheck\W{0,4}(\d+\.\d+\.\d+)/gi)) {
        named.push(`${file}: ${m[1]}`);
      }
    }
    expect(named.length).toBeGreaterThan(0);
    expect(named.filter((n) => !n.endsWith(`: ${version}`))).toEqual([]);
  });
});
