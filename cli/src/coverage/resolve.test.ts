import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ancestorDirs, PathResolver, repoRelativeDir } from './resolve';

const ROOT = path.resolve('/work/app');
const KNOWN = [
  'src/math.ts',
  'src/main/java/com/acme/Calculator.java',
  'a/util.ts',
  'b/util.ts',
  'src/helper.ts',
  'packages/web/src/index.ts',
  'packages/api/src/index.ts',
  'pkg/math2.ts',
  'other/math2.ts',
  'dir with space/\u00fc.ts',
];

function resolver(prefixes: string[] = []) {
  return new PathResolver(ROOT, KNOWN, prefixes);
}

describe('PathResolver', () => {
  it('accepts repo-relative, ./-prefixed and absolute-inside-root paths', () => {
    const r = resolver();
    expect(r.resolve('src/math.ts', [''])).toEqual({ path: 'src/math.ts' });
    expect(r.resolve('./src/math.ts', [''])).toEqual({ path: 'src/math.ts' });
    expect(r.resolve(path.join(ROOT, 'src', 'math.ts'), [''])).toEqual({ path: 'src/math.ts' });
    expect(r.resolve(`file://${path.join(ROOT, 'src', 'math.ts').replaceAll('\\', '/')}`, [''])).toEqual({
      path: 'src/math.ts',
    });
  });

  it('matches paths written on another machine by whole suffix', () => {
    const r = resolver();
    expect(r.resolve('/builds/acme/app/src/math.ts', [''])).toEqual({ path: 'src/math.ts' });
    expect(r.resolve('C:\\agent\\_work\\1\\s\\src\\math.ts', [''])).toEqual({ path: 'src/math.ts' });
    expect(r.resolve('com/acme/Calculator.java', [''])).toEqual({
      path: 'src/main/java/com/acme/Calculator.java',
    });
  });

  it('never attaches coverage to a file whose directory conflicts or is ambiguous', () => {
    const r = resolver();
    expect(r.resolve('/x/lib/helper.ts', [''])).toEqual({ unresolved: 'not-found' });
    expect(r.resolve('util.ts', [''])).toEqual({ unresolved: 'ambiguous' });
    expect(r.resolve('src/index.ts', [''])).toEqual({ unresolved: 'ambiguous' });
    expect(r.resolve('../../etc/passwd', [''])).toEqual({ unresolved: 'not-found' });
    expect(r.resolve('', [''])).toEqual({ unresolved: 'not-found' });
  });

  it('resolves monorepo package paths through the report directory ancestors', () => {
    const r = resolver();
    const bases = ancestorDirs('packages/web/coverage');
    expect(bases).toEqual(['packages/web/coverage', 'packages/web', 'packages', '']);
    expect(r.resolve('src/index.ts', bases)).toEqual({ path: 'packages/web/src/index.ts' });
  });

  it('strips or prepends configured path prefixes', () => {
    expect(resolver(['/builds/acme/app']).resolve('/builds/acme/app/pkg/math2.ts', [''])).toEqual({
      path: 'pkg/math2.ts',
    });
    expect(resolver().resolve('math2.ts', [''])).toEqual({ unresolved: 'ambiguous' });
    expect(resolver(['pkg']).resolve('math2.ts', [''])).toEqual({ path: 'pkg/math2.ts' });
  });

  it('normalises decomposed unicode in report paths', () => {
    expect(resolver().resolve('dir with space/u\u0308.ts', [''])).toEqual({ path: 'dir with space/\u00fc.ts' });
  });
});

describe('repoRelativeDir', () => {
  it('returns the report directory inside the root, or null outside', () => {
    expect(repoRelativeDir(ROOT, path.join(ROOT, 'coverage', 'lcov.info'))).toBe('coverage');
    expect(repoRelativeDir(ROOT, path.join(ROOT, 'lcov.info'))).toBe('');
    expect(repoRelativeDir(ROOT, path.resolve('/elsewhere/lcov.info'))).toBeNull();
    expect(ancestorDirs(null)).toEqual(['']);
  });
});
