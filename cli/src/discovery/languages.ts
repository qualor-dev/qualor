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
const RUBY: LanguageInfo = { language: 'ruby', grammar: 'ruby' };
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
  ['.rb', RUBY],
  ['.rake', RUBY],
  ['.gemspec', RUBY],
  ['.ru', RUBY],
]);

/** Ruby files known by their whole name (plan 9B); case-sensitive, as Bundler and Rake are. */
const BY_NAME = new Map<string, LanguageInfo>([
  ['Gemfile', RUBY],
  ['Rakefile', RUBY],
]);

export function detectLanguage(
  repoPath: string,
  languages: QualorConfig['languages'],
): LanguageInfo {
  const name = repoPath.slice(repoPath.lastIndexOf('/') + 1);
  const dot = name.lastIndexOf('.');
  const info =
    BY_NAME.get(name) ?? (dot <= 0 ? undefined : BY_EXTENSION.get(name.slice(dot).toLowerCase()));
  if (info === undefined) return OTHER;
  if (languages !== 'auto' && !(languages as readonly string[]).includes(info.language)) {
    return OTHER;
  }
  return info;
}
