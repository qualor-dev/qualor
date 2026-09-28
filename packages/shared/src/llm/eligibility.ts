import type { LlmFeature } from './features';

/** llm.md §5.2: credentials in code (hard-coded credentials, password in code, hard-coded key, …). */
export const SECRET_CWES = [798, 259, 321, 522, 312] as const;

export function isSecretRule(rule: {
  engineId: string;
  cwe: readonly number[];
  tags: readonly string[];
}): boolean {
  if (rule.engineId.toLowerCase() === 'gitleaks') return true;
  if (rule.cwe.some((c) => (SECRET_CWES as readonly number[]).includes(c))) return true;
  return rule.tags.some((t) => ['secret', 'secrets'].includes(t.toLowerCase()));
}

/**
 * llm.md §5.2's list, by the file name in lower case. Fail closed: `.env*`, `id_rsa*`,
 * `id_ed25519*`, `id_ecdsa*` and `credentials*` take any suffix, a source extension included
 * (`.env.ts`, `credentials.js`), and a key or state file keeps counting with a backup suffix
 * (`server.key.bak`, `prod.tfvars.json`, `terraform.tfstate.backup`).
 */
const CREDENTIAL_FILES: readonly RegExp[] = [
  /^\.env/,
  /\.env$/,
  /\.(pem|key|p12|pfx|jks|keystore|ppk|tfvars|tfstate)(\..*)?$/,
  /^id_(rsa|ed25519|ecdsa|dsa)/,
  /^\.(npmrc|pypirc|netrc|git-credentials|pgpass|htpasswd|dockercfg)$/,
  /^credentials/,
  /kubeconfig/,
  /^secrets\.ya?ml$/,
];

/** Credential files known by their directory as well as their name. */
const CREDENTIAL_PATHS: readonly RegExp[] = [
  /(^|\/)\.kube\/config$/,
  /(^|\/)\.docker\/config\.json$/,
];

/**
 * Whitespace and invisible characters, which do not hide a file name: every format character
 * (Unicode category Cf: the soft hyphen, zero-width and bidirectional controls, word joiners, the
 * BOM, tag characters and the rest), the Mongolian vowel separator and the variation selectors.
 */
const INVISIBLE = /[\s\p{Cf}\u180b-\u180f\ufe00-\ufe0f\u{e0100}-\u{e01ef}]/gu;

/** llm.md §5.2: a file that looks like it holds credentials, judged by its name in any case. */
export function isCredentialsFile(path: string): boolean {
  const normal = path.replace(INVISIBLE, '').replace(/\\/g, '/').toLowerCase();
  const name = normal.split('/').pop() ?? '';
  return CREDENTIAL_FILES.some((p) => p.test(name)) || CREDENTIAL_PATHS.some((p) => p.test(normal));
}

export const INELIGIBLE_REASONS = [
  'secret_rule',
  'credentials_file',
  'excluded_path',
  'excluded_project',
  'not_open',
  'no_location',
  'no_snippet',
] as const;
export type IneligibleReason = (typeof INELIGIBLE_REASONS)[number];

/** llm.md §5.2, §16: why an issue may not be sent for this feature, or null. Paths and projects the admin excluded are the server's check. */
export function llmIneligibility(
  feature: LlmFeature,
  issue: { status: string; path: string | null; startLine: number | null; hasSnippet: boolean },
  rule: { engineId: string; cwe: readonly number[]; tags: readonly string[] },
): IneligibleReason | null {
  if (isSecretRule(rule)) return 'secret_rule';
  if (issue.path !== null && isCredentialsFile(issue.path)) return 'credentials_file';
  if (feature !== 'explain' && issue.status !== 'open') return 'not_open';
  if (feature === 'fix') {
    if (issue.path === null || issue.startLine === null) return 'no_location';
    if (!issue.hasSnippet) return 'no_snippet';
  }
  return null;
}
