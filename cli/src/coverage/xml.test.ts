import { readFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import { FIXTURES_DIR } from '../../test/fixtures';
import { useTempDirs, writeTree } from '../../test/tmp';
import { parseXmlFile } from './xml';

const tmp = useTempDirs();

async function names(file: string): Promise<string[]> {
  const out: string[] = [];
  await parseXmlFile(file, { open: (name, _attrs, parents) => out.push([...parents, name].join('>')) });
  return out;
}

describe('parseXmlFile', () => {
  it('parses a report with an external DOCTYPE without loading the DTD', async () => {
    const seen = await names(path.join(FIXTURES_DIR, 'java-basic', 'reports', 'jacoco.xml'));
    expect(seen.slice(0, 3)).toEqual(['report', 'report>package', 'report>package>sourcefile']);
  });

  it('rejects external entities without reading the file they name', async () => {
    const root = tmp();
    writeTree(root, { 'secret.txt': 'TOP-SECRET-VALUE' });
    const target = pathToFileURL(path.join(root, 'secret.txt')).href;
    writeTree(root, {
      'xxe.xml': `<?xml version="1.0"?><!DOCTYPE c [<!ENTITY xxe SYSTEM "${target}">]><coverage>&xxe;</coverage>`,
    });
    const texts: string[] = [];
    await expect(
      parseXmlFile(path.join(root, 'xxe.xml'), { open: () => undefined, text: (t) => texts.push(t) }),
    ).rejects.toThrow(/undefined entity/);
    expect(texts.join('')).not.toContain('TOP-SECRET-VALUE');
    expect(readFileSync(path.join(root, 'secret.txt'), 'utf8')).toBe('TOP-SECRET-VALUE');
  });

  it('rejects entity expansion bombs and absurd nesting', async () => {
    const root = tmp();
    writeTree(root, {
      'lol.xml':
        '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]><l>&b;</l>',
      'deep.xml': `${'<d>'.repeat(300)}${'</d>'.repeat(300)}`,
      'broken.xml': '<coverage><class filename="a.ts">',
    });
    await expect(names(path.join(root, 'lol.xml'))).rejects.toThrow(/undefined entity/);
    await expect(names(path.join(root, 'deep.xml'))).rejects.toThrow(/nesting deeper than 256/);
    await expect(names(path.join(root, 'broken.xml'))).rejects.toThrow();
  });
});
