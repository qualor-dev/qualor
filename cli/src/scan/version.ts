import { refNameProblem } from '../args';
import { CliError, EXIT, type ExitCode } from '../errors';
import { clean } from '../server/http';
import type { AnalysisStatus } from '../server/gate';

/** The label a version is recorded under: `project.version` when non-empty, else the tag. */
export function versionLabel(projectVersion: string | undefined, tag: string): string {
  const version = projectVersion?.trim();
  return version === undefined || version === '' ? tag : version;
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
