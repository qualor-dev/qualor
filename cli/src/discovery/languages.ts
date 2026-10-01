import type { Language, QualorConfig } from '@qualor/shared';
import type { GrammarId } from '../parse/grammars';

export interface LanguageInfo {
  language: Language;
  grammar: GrammarId | null;
}

const OTHER: LanguageInfo = { language: 'other', grammar: null };
const TS: LanguageInfo = { language: 'typescript', grammar: 'typescript' };
const TSX: LanguageInfo = { language: 'typescript', grammar: 'tsx' };
const JS: LanguageInfo = { language: 'javascript', grammar: 'javascript' };
const JAVA: LanguageInfo = { language: 'java', grammar: 'java' };
const CSHARP: LanguageInfo = { language: 'csharp', grammar: 'csharp' };
const PYTHON: LanguageInfo = { language: 'python', grammar: 'python' };
const HTML: LanguageInfo = { language: 'html', grammar: 'html' };
const CSS: LanguageInfo = { language: 'css', grammar: 'css' };
const KOTLIN: LanguageInfo = { language: 'kotlin', grammar: 'kotlin' };
const SWIFT: LanguageInfo = { language: 'swift', grammar: 'swift' };
const C: LanguageInfo = { language: 'c', grammar: 'c' };
const CPP: LanguageInfo = { language: 'cpp', grammar: 'cpp' };
/** SCSS is linted as CSS (stylelint with postcss-scss) but has no grammar: no metrics, no duplication. */
const SCSS: LanguageInfo = { language: 'css', grammar: null };

const BY_EXTENSION = new Map<string, LanguageInfo>([
  ['.ts', TS],
  ['.mts', TS],
  ['.cts', TS],
  ['.tsx', TSX],
  ['.js', JS],
  ['.mjs', JS],
  ['.cjs', JS],
  ['.jsx', JS],
  ['.java', JAVA],
  ['.cs', CSHARP],
  ['.py', PYTHON],
  ['.html', HTML],
  ['.htm', HTML],
  ['.css', CSS],
  ['.scss', SCSS],
  ['.kt', KOTLIN],
  ['.kts', KOTLIN],
  ['.swift', SWIFT],
  // `.h` is handled apart: see detectLanguage and resolveCHeaders.
  ['.c', C],
  ['.cc', CPP],
  ['.cpp', CPP],
  ['.cxx', CPP],
  ['.c++', CPP],
  ['.hpp', CPP],
  ['.hh', CPP],
  ['.hxx', CPP],
  ['.h++', CPP],
  ['.ipp', CPP],
]);

/** A `.h` file, whose language depends on the scope (config.md §6.2, plan 9D decision 3). */
export function isCHeader(repoPath: string): boolean {
  return repoPath.toLowerCase().endsWith('.h') && !repoPath.endsWith('/.h') && repoPath !== '.h';
}

export function detectLanguage(
  repoPath: string,
  languages: QualorConfig['languages'],
): LanguageInfo {
  const name = repoPath.slice(repoPath.lastIndexOf('/') + 1);
  const dot = name.lastIndexOf('.');
  if (dot <= 0) return OTHER;
  const ext = name.slice(dot).toLowerCase();
  if (ext === '.h') {
    // C by default, as cppcheck and clang read a lone .h; resolveCHeaders may make it C++.
    if (languages === 'auto' || (languages as readonly string[]).includes('c')) return C;
    return (languages as readonly string[]).includes('cpp') ? CPP : OTHER;
  }
  const info = BY_EXTENSION.get(ext);
  if (info === undefined) return OTHER;
  if (languages !== 'auto' && !(languages as readonly string[]).includes(info.language)) {
    return OTHER;
  }
  return info;
}

/**
 * Plan 9D decision 3: the `.h` files detected as C become C++ when the scope holds a C++ file and
 * C++ is allowed (`languages: auto`, or a list with both `c` and `cpp`).
 */
export function resolveCHeaders<
  T extends { path: string; language: Language; grammar: GrammarId | null },
>(files: T[], languages: QualorConfig['languages']): T[] {
  const both =
    languages === 'auto' ||
    ((languages as readonly string[]).includes('c') &&
      (languages as readonly string[]).includes('cpp'));
  if (!both || !files.some((f) => f.language === 'cpp')) return files;
  return files.map((f) =>
    f.language === 'c' && isCHeader(f.path) ? { ...f, language: 'cpp', grammar: 'cpp' } : f,
  );
}
