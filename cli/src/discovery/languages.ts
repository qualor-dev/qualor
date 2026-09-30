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
]);

export function detectLanguage(
  repoPath: string,
  languages: QualorConfig['languages'],
): LanguageInfo {
  const name = repoPath.slice(repoPath.lastIndexOf('/') + 1);
  const dot = name.lastIndexOf('.');
  if (dot <= 0) return OTHER;
  const info = BY_EXTENSION.get(name.slice(dot).toLowerCase());
  if (info === undefined) return OTHER;
  if (languages !== 'auto' && !(languages as readonly string[]).includes(info.language)) {
    return OTHER;
  }
  return info;
}
