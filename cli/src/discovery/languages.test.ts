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
    expect(detectLanguage('app/store.py', 'auto')).toEqual({
      language: 'python',
      grammar: 'python',
    });
    expect(detectLanguage('APP.PY', 'auto').language).toBe('python');
    for (const p of ['stubs/a.pyi', 'gui.pyw', 'nb/analysis.ipynb', 'setup.cfg']) {
      expect(detectLanguage(p, 'auto')).toEqual({ language: 'other', grammar: null });
    }
    expect(detectLanguage('a.py', ['java']).language).toBe('other');
    expect(detectLanguage('store/store.go', 'auto')).toEqual({ language: 'go', grammar: 'go' });
    expect(detectLanguage('cmd/MAIN.GO', 'auto').language).toBe('go');
    for (const p of ['go.mod', 'go.sum', 'go.work', 'a.gox']) {
      expect(detectLanguage(p, 'auto')).toEqual({ language: 'other', grammar: null });
    }
    expect(detectLanguage('a.go', ['java']).language).toBe('other');
  });

  it('treats unknown extensions, dotfiles and extension-less files as other', () => {
    for (const p of ['README.md', 'Makefile', '.eslintrc', 'dir.ts/file', 'a.ts.bak']) {
      expect(detectLanguage(p, 'auto')).toEqual({ language: 'other', grammar: null });
    }
  });

  it('detects HTML and CSS; SCSS is css without a grammar; Less stays other (plan 8D)', () => {
    expect(detectLanguage('site/index.html', 'auto')).toEqual({
      language: 'html',
      grammar: 'html',
    });
    expect(detectLanguage('old/page.HTM', 'auto')).toEqual({ language: 'html', grammar: 'html' });
    expect(detectLanguage('src/a.css', 'auto')).toEqual({ language: 'css', grammar: 'css' });
    expect(detectLanguage('src/b.scss', 'auto')).toEqual({ language: 'css', grammar: null });
    expect(detectLanguage('src/c.less', 'auto')).toEqual({ language: 'other', grammar: null });
    expect(detectLanguage('src/d.sass', 'auto')).toEqual({ language: 'other', grammar: null });
    expect(detectLanguage('src/a.css', ['typescript'])).toEqual({
      language: 'other',
      grammar: null,
    });
  });

  it('maps .kt and .kts to kotlin (phase 8E)', () => {
    expect(detectLanguage('src/main/kotlin/App.kt', 'auto')).toEqual({
      language: 'kotlin',
      grammar: 'kotlin',
    });
    expect(detectLanguage('build.gradle.kts', 'auto')).toEqual({
      language: 'kotlin',
      grammar: 'kotlin',
    });
    expect(detectLanguage('App.KT', 'auto').language).toBe('kotlin');
    expect(detectLanguage('App.kt', ['java'])).toEqual({ language: 'other', grammar: null });
    expect(detectLanguage('App.ktm', 'auto')).toEqual({ language: 'other', grammar: null });
  });

  it('maps .swift to swift (plan 8F)', () => {
    expect(detectLanguage('Sources/App/Store.swift', 'auto')).toEqual({
      language: 'swift',
      grammar: 'swift',
    });
    expect(detectLanguage('Package.SWIFT', 'auto').language).toBe('swift');
    for (const p of ['App.xcodeproj/project.pbxproj', 'Podfile', 'a.swiftinterface']) {
      expect(detectLanguage(p, 'auto')).toEqual({ language: 'other', grammar: null });
    }
    expect(detectLanguage('a.swift', ['java']).language).toBe('other');
  });

  it('honours an explicit languages list', () => {
    expect(detectLanguage('a.ts', ['java'])).toEqual({ language: 'other', grammar: null });
    expect(detectLanguage('A.java', ['java']).language).toBe('java');
    expect(detectLanguage('A.cs', ['java']).language).toBe('other');
  });
});
