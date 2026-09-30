import { readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { VERSION } from '@qualor/shared';

const FILES = [
  'README.md',
  ...readdirSync('docs/guide')
    .filter((f) => f.endsWith('.md'))
    .map((f) => 'docs/guide/' + f),
];
/** The major tag 1 (not released yet), a floating 0, or latest: image tag, component version, QUALOR_VERSION. */
const WRONG =
  /qualor\/(server|scanner|scanner-dotnet):(1|0|latest)\b(?![.\d])|qualor\/qualor@(1|0)\b(?![.\d])|image-tag: '(1|0)'|QUALOR_VERSION=(1|0)\b(?![.\d])/;

describe('the guide uses the 0.x tags', () => {
  it.each(FILES)('%s names no major tag 1, no floating 0 and no latest', (f) => {
    const hits = readFileSync(f, 'utf8')
      .split('\n')
      .filter((l) => WRONG.test(l));
    expect(hits).toEqual([]);
  });

  it('install-server.md explains the 0.x tags', () => {
    const text = readFileSync('docs/guide/install-server.md', 'utf8');
    expect(text).toContain('there is no `0` tag');
    // The examples use the minor tag of the release the guide describes.
    expect(text).toContain(`QUALOR_VERSION=${VERSION.split('.').slice(0, 2).join('.')}`);
  });
});
