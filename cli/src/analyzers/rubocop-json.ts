import { departmentOf, RUBOCOP_COPS, RUBOCOP_SYNTAX_COP, rubocopHelpUri } from '@qualor/shared';
import { z } from 'zod';
import type { Logger } from '../log';
import { detailLine, shown, stderrLines } from './reason';

const offenseSchema = z.object({
  severity: z.string(),
  message: z.string(),
  cop_name: z.string(),
  location: z.object({
    start_line: z.number().int().positive(),
    start_column: z.number().int().positive(),
    last_line: z.number().int().positive(),
    last_column: z.number().int().nonnegative(),
  }),
});
const outputSchema = z.object({
  metadata: z.object({ rubocop_version: z.string() }),
  files: z.array(z.object({ path: z.string(), offenses: z.array(offenseSchema) })),
});

/** RuboCop's offense severities as SARIF levels (the mapping ignores them, report-format.md §7.1). */
const LEVEL: Readonly<Record<string, string>> = {
  info: 'note',
  refactor: 'note',
  convention: 'note',
  warning: 'warning',
  error: 'error',
  fatal: 'error',
};

/**
 * RuboCop's `--format json` report → SARIF 2.1.0 (config.md §6). Paths are relative to the
 * checked copy, i.e. the repository's own, and percent-encoded by segment so the normaliser
 * decodes the same name. `Lint/Syntax` (a file RuboCop cannot parse) and the offenses of cops
 * outside `cops` (an inline `rubocop:enable` can turn one on) are dropped and counted. A file
 * outside `files` (the list the CLI gave RuboCop) is dropped with a warning: run.rb escapes glob
 * characters, and this keeps anything RuboCop reached past them out of the report (B9-14). A report
 * of another RuboCop version throws: the install changed under the scan.
 */
export function rubocopJsonToSarif(
  output: unknown,
  o: { version: string; cops: ReadonlySet<string>; files?: ReadonlySet<string>; log?: Logger },
): unknown {
  const parsed = outputSchema.parse(output);
  if (parsed.metadata.rubocop_version !== o.version) {
    throw new Error(
      `RuboCop ${parsed.metadata.rubocop_version} wrote the report, not ${o.version}`,
    );
  }
  const used = new Set<string>();
  const results: unknown[] = [];
  let unparsable = 0;
  let outside = 0;
  let unlisted = 0;
  for (const file of parsed.files) {
    if (o.files !== undefined && !o.files.has(file.path)) {
      unlisted++;
      continue;
    }
    const uri = file.path.split('/').map(encodeURIComponent).join('/');
    for (const offense of file.offenses) {
      if (offense.cop_name === RUBOCOP_SYNTAX_COP) {
        unparsable++;
        continue;
      }
      if (!o.cops.has(offense.cop_name)) {
        outside++;
        continue;
      }
      used.add(offense.cop_name);
      const l = offense.location;
      const region: Record<string, number> = {
        startLine: l.start_line,
        startColumn: l.start_column,
        endLine: l.last_line,
      };
      // RuboCop's last column is inclusive; SARIF's end column is the one after.
      if (l.last_line > l.start_line || l.last_column + 1 > l.start_column)
        region['endColumn'] = l.last_column + 1;
      results.push({
        ruleId: offense.cop_name,
        level: LEVEL[offense.severity] ?? 'warning',
        message: { text: offense.message },
        locations: [{ physicalLocation: { artifactLocation: { uri }, region } }],
      });
    }
  }
  if (unlisted > 0) {
    o.log?.warn(
      `rubocop: RuboCop reported ${unlisted} file(s) Qualor did not give it; their findings were dropped`,
    );
  }
  if (unparsable > 0)
    o.log?.debug(`rubocop: ${unparsable} file(s) RuboCop could not parse (Lint/Syntax dropped)`);
  if (outside > 0)
    o.log?.debug(`rubocop: ${outside} offense(s) of cops outside the selection dropped`);
  const rules = [...used].sort().map((id) => {
    const helpUri = rubocopHelpUri(id);
    return {
      id,
      ...(helpUri !== null && { helpUri }),
      properties: { department: departmentOf(id) },
    };
  });
  return {
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'RuboCop',
            informationUri: 'https://rubocop.org',
            version: o.version,
            rules,
          },
        },
        results,
      },
    ],
  };
}

/**
 * Why RuboCop (or the runner) stopped, for the warn log only (8D minor 6 class): its `Error:`
 * line, else the runner's `rubocop: fatal:` line, else the first line that is no backtrace frame,
 * with the work directory shown as `<work>`. The environment is an allowlist, so no secret.
 */
export function rubocopFailureDetail(stderr: string, workDir: string): string | null {
  const lines = stderrLines(stderr);
  const line =
    lines.find((l) => l.startsWith('Error: ')) ??
    lines.find((l) => l.startsWith('rubocop: fatal: ')) ??
    lines.find((l) => !l.startsWith('/') && !/^\s/.test(l));
  return line === undefined ? null : detailLine(line.split(workDir).join('<work>'));
}

const CRASH = /^An error occurred while (\S+) cop was inspecting (.+):\d+:\d+\.$/;

/**
 * RuboCop isolates a cop that raises on a file and goes on (fact F6): one warning per cop and file
 * (the runner prefixes `rubocop: `), with the repository path (`input` is the checked copy), for
 * cops of RuboCop's table only.
 */
export function rubocopCrashWarnings(stderr: string, input: string): string[] {
  const seen = new Set<string>();
  for (const line of stderrLines(stderr)) {
    const [, cop, where] = CRASH.exec(line.trim()) ?? [];
    if (cop === undefined || where === undefined || !RUBOCOP_COPS.has(cop)) continue;
    const file = where.startsWith(`${input}/`) ? where.slice(input.length + 1) : where;
    seen.add(
      detailLine(
        `${cop} failed on ${shown(file)} (a RuboCop error); that file has no ${cop} findings`,
      ),
    );
  }
  return [...seen];
}
