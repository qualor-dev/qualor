/**
 * Rule documentation links that still work. rules.sonarsource.com no longer resolves and the
 * RSPEC site needs a GitHub sign-in, so SonarSource's rules link to SonarCloud's public rule
 * browser (the `sonarsource` organisation, readable without an account); Qualor's own rules link to
 * their pages in the qualor-rules repository. The CLI writes these links into reports (and
 * tools/analyzers/sonarjs/run.mjs, which cannot import this package, builds the same ones); the
 * server applies {@link ruleHelpUri} to what it stored before, so old rows link correctly at once.
 */
import { QUALOR_RULE_ID } from './qualor';

/** SonarCloud's public organisation whose rule browser shows every SonarSource rule. */
const SONARCLOUD_RULES = 'https://sonarcloud.io/organizations/sonarsource/rules';

/**
 * The SonarJS rules (RSPEC keys of eslint-plugin-sonarjs 2.0.4) that SonarCloud has under
 * `typescript:` only: a `javascript:` key of these is not found. Checked against SonarCloud's
 * rules API on 2026-10-06; every other bundled key exists under `javascript:`.
 */
export const SONARJS_TYPESCRIPT_ONLY_KEYS: ReadonlySet<string> = new Set([
  'S1444',
  'S4023',
  'S4156',
  'S4322',
  'S4323',
  'S4324',
  'S4327',
  'S4328',
  'S4335',
  'S4621',
  'S4622',
  'S4623',
  'S4782',
  'S4798',
  'S6564',
  'S6571',
  'S6572',
  'S6598',
  'S6606',
  'S6759',
]);

const RSPEC_KEY = /^S[1-9]\d{0,5}$/;

/** A rule's page in SonarCloud's public rule browser: `repository` is SonarCloud's (`csharpsquid`). */
export function sonarCloudRuleUri(repository: string, rspecKey: string): string {
  const key = encodeURIComponent(`${repository}:${rspecKey}`);
  return `${SONARCLOUD_RULES}?open=${key}&rule_key=${key}`;
}

/** A SonarJS rule's page (`S3776`): under `typescript:` for the TypeScript-only rules. */
export function sonarjsHelpUri(rspecKey: string): string | null {
  if (!RSPEC_KEY.test(rspecKey)) return null;
  return sonarCloudRuleUri(
    SONARJS_TYPESCRIPT_ONLY_KEYS.has(rspecKey) ? 'typescript' : 'javascript',
    rspecKey,
  );
}

/** Where the qualor-rules repository keeps one page per rule, `<lang>/<name>.md`. */
const QUALOR_RULE_DOCS = 'https://github.com/qualor-dev/qualor-rules/blob/main/docs/rules';

/** A Qualor rule's page (`go/sql-injection`), or null for anything that is not a Qualor rule id. */
export function qualorRuleHelpUri(ruleId: string): string | null {
  return QUALOR_RULE_ID.test(ruleId) ? `${QUALOR_RULE_DOCS}/${ruleId}.md` : null;
}

/** rules.sonarsource.com's languages and SonarCloud's repository for each. */
const SONAR_REPOSITORY: Readonly<Record<string, string>> = {
  csharp: 'csharpsquid',
  vbnet: 'vbnet',
};
const DEAD_SONAR = /^https?:\/\/rules\.sonarsource\.com\/([a-z]+)\/RSPEC-([1-9]\d{0,5})\/?$/;
/** go vet analyzers whose package is named differently (pkg.go.dev answers 404 for the name). */
const GOVET_PACKAGE: Readonly<Record<string, string>> = {
  composites: 'composite',
  copylocks: 'copylock',
};
const GOVET_PASS =
  /^https:\/\/pkg\.go\.dev\/golang\.org\/x\/tools\/go\/analysis\/passes\/([a-z]+)$/;

/**
 * `uri` with a link Qualor knows is dead replaced by the live page of the same rule:
 * rules.sonarsource.com (JavaScript, TypeScript, C#, VB.NET) and the two go vet analyzers whose
 * pkg.go.dev path is not their name. Any other link is returned as it is.
 */
export function currentHelpUri(uri: string): string {
  const sonar = DEAD_SONAR.exec(uri);
  const language = sonar?.[1];
  const n = sonar?.[2];
  if (language !== undefined && n !== undefined) {
    if (language === 'javascript' || language === 'typescript') {
      return sonarjsHelpUri(`S${n}`) ?? uri;
    }
    const repository = Object.hasOwn(SONAR_REPOSITORY, language)
      ? SONAR_REPOSITORY[language]
      : undefined;
    return repository === undefined ? uri : sonarCloudRuleUri(repository, `S${n}`);
  }
  const pass = GOVET_PASS.exec(uri)?.[1];
  if (pass !== undefined && Object.hasOwn(GOVET_PACKAGE, pass)) {
    return uri.slice(0, -pass.length) + GOVET_PACKAGE[pass];
  }
  return uri;
}

/**
 * The documentation link to show for a rule: its stored link through {@link currentHelpUri}, or,
 * for a Qualor rule (`qualor:<lang>/<name>`) stored without one, its page in qualor-rules.
 */
export function ruleHelpUri(ruleKey: string, stored: string | null | undefined): string | null {
  if (stored !== null && stored !== undefined && stored !== '') return currentHelpUri(stored);
  return ruleKey.startsWith('qualor:') ? qualorRuleHelpUri(ruleKey.slice('qualor:'.length)) : null;
}
