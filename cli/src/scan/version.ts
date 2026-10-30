import { refNameProblem } from '../args';
import { CliError, EXIT, type ExitCode } from '../errors';
import { clean } from '../server/http';
import type { AnalysisStatus } from '../server/gate';

/** The label a version is recorded under: `project.version` when non-empty, else the tag. */
export function versionLabel(projectVersion: string | undefined, tag: string): string {
  const version = projectVersion?.trim();
  return version === undefined || version === '' ? tag : version;
}

/** The longest version label the server records (`project_versions_label_check`). */
export const MAX_VERSION_LABEL_CHARS = 100;

/** A label the server would refuse (VERSION_LABEL_INVALID) is a usage error before any request. */
export function checkVersionLabel(label: string): void {
  if (label.length > MAX_VERSION_LABEL_CHARS) {
    throw new CliError(
      EXIT.USAGE,
      `A version label is at most ${MAX_VERSION_LABEL_CHARS} characters; set project.version`,
    );
  }
}

/** The first release line whose server records tag scans as versions. */
const VERSIONS_SINCE = { major: 0, minor: 15 };

/**
 * False when the server's version (`GET /api/v0/system/version`) is a release before 0.15, which
 * cannot record a version. True otherwise, also when the version is unknown: the upload then
 * decides, as for any scan.
 */
export function serverRecordsVersions(serverVersion: string | null): boolean {
  const match =
    serverVersion === null ? null : /^(\d+)\.(\d+)\.\d+(?:[-+].*)?$/.exec(serverVersion);
  if (match === null) return true;
  const major = Number(match[1]);
  const minor = Number(match[2]);
  if (major !== VERSIONS_SINCE.major) return major > VERSIONS_SINCE.major;
  return minor >= VERSIONS_SINCE.minor;
}

/**
 * A tag that CI named (not `--tag`, which the argument parser checked) must be a usable ref name
 * too: the report's `scm.tag` is bounded the same way.
 */
export function checkCiTag(tag: string): void {
  const problem = refNameProblem(tag);
  if (problem !== null) {
    throw new CliError(
      EXIT.USAGE,
      `the tag CI reports (CI_COMMIT_TAG or GITHUB_REF_NAME) ${problem}; pass --tag NAME or --branch NAME`,
    );
  }
}

/**
 * The exit code of a tag scan, from the analysis the server finished (never the quality gate: a
 * version has no issues and no gate). A failed analysis is a server error, whatever `gate.failOnError`
 * says.
 */
export function versionExitCode(
  analysis: AnalysisStatus,
  label: string,
): { code: ExitCode; message: string } {
  if (analysis.status === 'failed') {
    const error = analysis.error;
    return {
      code: EXIT.SERVER,
      message: clean(
        error === null
          ? `analysis ${analysis.id} failed on the server`
          : `analysis ${analysis.id} failed on the server: ${error.code} ${error.message}`,
      ),
    };
  }
  return { code: EXIT.OK, message: `Recorded version ${clean(label)}` };
}
