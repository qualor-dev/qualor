/**
 * B9 (spec §12, §6.9): the package managers of `qualor fix` run without Qualor's own settings and
 * the CI job's credentials. Registry settings and credentials (`NPM_TOKEN`, `npm_config_*`,
 * `GOPROXY`, …), `PATH` and `HOME` pass: the managers use the job's own configuration, as the
 * customer's build does (§6.5).
 */
export const FIX_DROPPED_ENV = /^(QUALOR_.*|CI_JOB_TOKEN|GITHUB_TOKEN|ACTIONS_.*)$/;

/**
 * The environment of a package manager: `env` without the {@link FIX_DROPPED_ENV} names and unset
 * values. Names are compared in upper case, since Windows reads `Qualor_Token` as `QUALOR_TOKEN`.
 */
export function fixToolEnv(
  env: Readonly<Record<string, string | undefined>>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(env)) {
    if (value === undefined || FIX_DROPPED_ENV.test(name.toUpperCase())) continue;
    out[name] = value;
  }
  return out;
}
