import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

const SRC = import.meta.dirname;

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return sourceFiles(path);
    return entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts') ? [path] : [];
  });
}

describe('server module layering', () => {
  it('keeps route modules as leaves: nothing outside routes/ imports them but app wiring', () => {
    const offenders = sourceFiles(SRC)
      .map((file) => relative(SRC, file).replaceAll('\\', '/'))
      .filter((file) => !file.startsWith('routes/') && file !== 'app.ts')
      .filter((file) => /from '(\.\.\/)+routes\//.test(readFileSync(join(SRC, file), 'utf8')));
    expect(offenders).toEqual([]);
  });
});
