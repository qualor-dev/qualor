import { FIX_SECRET_NAME, secretEnvValues } from '@qualor/shared/fix';

/**
 * B9 (spec §12, §6.9), ruling T12b: the package managers of `qualor fix` run without Qualor's own
 * settings and the CI job's credentials, which a repository's `.npmrc` could otherwise send to a
 * registry of its choosing. Registry settings and credentials (`NPM_TOKEN`, `npm_config_*`,
 * `GOPROXY`, …), `PATH`, `HOME` and the other CI variables (`CI`, `CI_PROJECT_DIR`, `CI_COMMIT_SHA`)
 * pass: the managers use the job's own configuration, as the customer's build does (§6.5).
 */
export const FIX_DROPPED_ENV =
  /^(QUALOR_.*|ACTIONS_.*|CI_JOB_TOKEN|GITHUB_TOKEN|CI_JOB_JWT.*|CI_REGISTRY_PASSWORD|CI_DEPENDENCY_PROXY_PASSWORD|CI_DEPLOY_PASSWORD|SYSTEM_ACCESSTOKEN|AZURE_DEVOPS_EXT_PAT|SECRET_.*)$/;

/** Ruling T12b: a CI variable that holds a credential, whatever its exact name. */
const CI_PREFIX = /^(CI|GITHUB|RUNNER|SYSTEM|AGENT|BUILD|VSTS|ENDPOINT|AZURE_DEVOPS)_/;
const CREDENTIAL_WORD = /TOKEN|PASSWORD|SECRET|JWT|KEY/;

/**
 * Whether the tool environment drops the variable: {@link FIX_DROPPED_ENV}, or a `CI_`, `GITHUB_`,
 * `RUNNER_`, `SYSTEM_`, `AGENT_`, `BUILD_`, `VSTS_`, `ENDPOINT_` or `AZURE_DEVOPS_` name with `TOKEN`,
 * `PASSWORD`, `SECRET`, `JWT` or `KEY` in it. Names are compared in
 * upper case, since Windows reads `Qualor_Token` as `QUALOR_TOKEN`.
 */
export function isFixDroppedEnv(name: string): boolean {
  const upper = name.toUpperCase();
  return FIX_DROPPED_ENV.test(upper) || (CI_PREFIX.test(upper) && CREDENTIAL_WORD.test(upper));
}

/** The environment of a package manager: `env` without the dropped names and unset values. */
export function fixToolEnv(
  env: Readonly<Record<string, string | undefined>>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(env)) {
    if (value === undefined || isFixDroppedEnv(name)) continue;
    out[name] = value;
  }
  return out;
}

/** A value that is a word or a number of everyday text, never a credential (I1). */
const ORDINARY_VALUE = /^(true|false|[+-]?\d+(\.\d+)?)$/i;
/** I1: a credential has at least this many characters. */
const MIN_CREDENTIAL_CHARS = 8;

/**
 * A variable that holds a credential: secret-named (B9; `PWD` and `OLDPWD` hold directories,
 * R21), or a CI credential (ruling T12b: `CI_JOB_JWT` has none of B9's words).
 */
function isCredentialName(name: string): boolean {
  const upper = name.toUpperCase();
  if (CI_PREFIX.test(upper) && CREDENTIAL_WORD.test(upper)) return true;
  return FIX_SECRET_NAME.test(name) && upper !== 'PWD' && upper !== 'OLDPWD';
}

/**
 * The job's secrets (B9, I1, ruling T12b), beside the project token, from the variables that are
 * not Qualor's own settings (`QUALOR_PROJECT_KEY`, `QUALOR_URL`, … hold no secret; the token is
 * given apart):
 * - `scrub`, what messages and log lines are scrubbed of: the token, the values of secret-named
 *   variables (`secretEnvValues`, 4 characters or more, R21) and of every variable the tool
 *   environment drops;
 * - `credentials`, what no uploaded file may gain: the token, and the values of credential
 *   variables of 8 characters or more that are no `true`, `false` or number.
 */
export function fixJobSecrets(
  env: Readonly<Record<string, string | undefined>>,
  token: string,
): { scrub: string[]; credentials: string[] } {
  const others = Object.entries(env).filter(
    (entry): entry is [string, string] =>
      entry[1] !== undefined && !entry[0].toUpperCase().startsWith('QUALOR_'),
  );
  const named = secretEnvValues(Object.fromEntries(others));
  const dropped = others.filter(([name]) => isFixDroppedEnv(name)).map(([, value]) => value);
  const credentialNamed = others
    .filter(([name]) => isCredentialName(name))
    .map(([, value]) => value);
  const credentials = credentialNamed.filter(
    (v) => v.length >= MIN_CREDENTIAL_CHARS && !ORDINARY_VALUE.test(v),
  );
  return {
    scrub: [...new Set([token, ...named, ...dropped.filter((v) => v.length >= 4)])],
    credentials: [...new Set([token, ...credentials])],
  };
}
