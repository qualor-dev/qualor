import { describe, expect, it } from 'vitest';
import { detectLanguage } from './languages';

describe('detectLanguage', () => {
  it('maps extensions to languages and grammars', () => {
    expect(detectLanguage('src/a.ts', 'auto')).toEqual({
      language: 'typescript',
      grammar: 'typescript',
    });
    expect(detectLanguage('src/a.d.mts', 'auto').grammar).toBe('typescript');
    expect(detectLanguage('src/A.TSX', 'auto')).toEqual({ language: 'typescript', grammar: 'tsx' });
    expect(detectLanguage('a.cjs', 'auto')).toEqual({
      language: 'javascript',
      grammar: 'javascript',
    });
    expect(detectLanguage('a.jsx', 'auto').grammar).toBe('javascript');
    expect(detectLanguage('src/Main.java', 'auto')).toEqual({ language: 'java', grammar: 'java' });
    expect(detectLanguage('src/Acme/Store.cs', 'auto')).toEqual({
      language: 'csharp',
      grammar: 'csharp',
    });
    expect(detectLanguage('Store.CS', 'auto').language).toBe('csharp');
    for (const p of ['build.csx', 'Pages/Index.razor', 'Views/Home.cshtml']) {
      expect(detectLanguage(p, 'auto')).toEqual({ language: 'other', grammar: null });
    }
  });

  it('treats unknown extensions, dotfiles and extension-less files as other', () => {
    for (const p of ['README.md', 'Makefile', '.eslintrc', 'dir.ts/file', 'a.ts.bak']) {
      expect(detectLanguage(p, 'auto')).toEqual({ language: 'other', grammar: null });
    }
  });

  it('honours an explicit languages list', () => {
    expect(detectLanguage('a.ts', ['java'])).toEqual({ language: 'other', grammar: null });
    expect(detectLanguage('A.java', ['java']).language).toBe('java');
    expect(detectLanguage('A.cs', ['java']).language).toBe('other');
  });
});
