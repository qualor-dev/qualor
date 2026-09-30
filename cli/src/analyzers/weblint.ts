import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  statSync,
} from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import type { Logger } from '../log';
import { isInside, staysInside } from './binary';
import { detailLine, stderrLines } from './reason';
import type { AnalyzerContext } from './types';

/** A repository configuration Qualor's HTML and CSS passes cannot use (config.md §6): a skip reason. */
export class WeblintConfigError extends Error {}

/** True when `file` exists as any kind of entry (a dangling link included). */
export function repoEntryExists(file: string): boolean {
  try {
    lstatSync(file);
    return true;
  } catch {
    return false;
  }
}

/**
 * A repository configuration file's text: a regular file (never a FIFO or a directory) that stays
 * inside the repository as written and after symlinks, of at most `maxBytes`. `rel` is the path as
 * the user wrote it or as Qualor looked it up, for the message.
 *
 * The file is opened once (non-blocking, so a FIFO swapped in cannot hang the scan) and its type and
 * size are taken from that descriptor; at most `maxBytes + 1` bytes are ever read.
 */
export function readRepoConfig(root: string, rel: string, maxBytes: number): string {
  return readRepoConfigBytes(root, rel, maxBytes).toString('utf8');
}

/**
 * `readRepoConfig`'s raw bytes, for a caller that checks the encoding itself (detekt). `name` is
 * what the messages call the file (default `rel`).
 */
export function readRepoConfigBytes(
  root: string,
  rel: string,
  maxBytes: number,
  name: string = rel,
): Buffer {
  const file = path.resolve(root, rel);
  if (!repoEntryExists(file)) throw new WeblintConfigError(`${name} cannot be read`);
  if (!staysInside(root, file)) throw new WeblintConfigError(`${name} is outside the repository`);
  const notRegular = () => new WeblintConfigError(`${name} is not a regular file`);
  try {
    if (!statSync(file).isFile()) throw notRegular();
  } catch (err) {
    if (err instanceof WeblintConfigError) throw err;
    throw new WeblintConfigError(`${name} cannot be read`);
  }
  let fd: number;
  try {
    fd = openSync(file, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  } catch {
    throw new WeblintConfigError(`${name} cannot be read`);
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) throw notRegular();
    const tooLarge = () =>
      new WeblintConfigError(`${name} is larger than ${maxBytes / 1024 / 1024} MiB`);
    if (stat.size > maxBytes) throw tooLarge();
    const buf = Buffer.alloc(maxBytes + 1);
    let length = 0;
    for (;;) {
      const n = readSync(fd, buf, length, buf.length - length, null);
      if (n === 0) break;
      length += n;
      if (length > maxBytes) throw tooLarge();
    }
    return buf.subarray(0, length);
  } catch (err) {
    if (err instanceof WeblintConfigError) throw err;
    throw new WeblintConfigError(`${name} cannot be read`);
  } finally {
    closeSync(fd);
  }
}

/** Where the `qualor/scanner` image installs the HTML and CSS passes (config.md §4). */
export const DEFAULT_WEBLINT_DIR = '/opt/qualor/weblint';

/**
 * The runner script of one pass, or why it cannot run. A missing install is a skip (an
 * image-bundled resource absent on a plain host, ruling G6, like sonarjs); a relative or
 * in-repository QUALOR_WEBLINT_DIR is unavailable (a merge request must never point it at its own
 * code).
 */
export function weblintScript(
  ctx: AnalyzerContext,
  script: 'stylelint.mjs' | 'htmlhint.mjs',
): { script: string } | { skip: string } | { unavailable: string } {
  const dir = ctx.env['QUALOR_WEBLINT_DIR'] || DEFAULT_WEBLINT_DIR;
  if (!path.isAbsolute(dir) || isInside(ctx.root, dir)) {
    return { unavailable: 'QUALOR_WEBLINT_DIR must be an absolute path outside the repository' };
  }
  const file = path.join(dir, script);
  if (!existsSync(file)) {
    return { skip: 'the HTML and CSS linters are not installed (qualor/scanner image)' };
  }
  return { script: file };
}

/**
 * Why a pass exited 2, from its stderr (final review, 8D minor 6): the `<engine>: fatal: …` line
 * files.mjs's `run()` writes, else the first non-empty line; control characters become spaces and
 * the line is cut at 300 characters. Null for any other exit code or an empty stderr. For the log
 * only, never a report `reason`.
 */
export function weblintFailureDetail(
  engine: 'stylelint' | 'htmlhint',
  exitCode: number | null,
  stderr: string,
): string | null {
  if (exitCode !== 2) return null;
  const lines = stderrLines(stderr);
  const prefix = `${engine}: fatal: `;
  const fatal = lines.findLast((l) => l.startsWith(prefix));
  const line = fatal === undefined ? lines[0] : fatal.slice(prefix.length);
  return line === undefined ? null : detailLine(line);
}

/**
 * tools/analyzers/weblint/{stylelint,htmlhint}.mjs's one stdout JSON line. Unknown keys are
 * accepted (and dropped), so a runner may add fields without breaking an older CLI.
 */
const summarySchema = z.object({
  files: z.number(),
  listed: z.number().optional(),
  parseErrors: z.number().optional(),
  unknownRules: z.array(z.string()).optional(),
  invalidOptions: z.number().optional(),
});

/**
 * The pass's summary line, for the log only (a report `reason` stays fixed, config.md §6). A
 * missing or malformed line is ignored: the run's exit code and SARIF already decide its status.
 */
export function logWeblintSummary(
  log: Logger,
  engine: 'stylelint' | 'htmlhint',
  stdout: string,
): void {
  const last = stdout
    .split('\n')
    .filter((l) => l.trim() !== '')
    .at(-1);
  if (last === undefined) return;
  let s: z.infer<typeof summarySchema>;
  try {
    s = summarySchema.parse(JSON.parse(last));
  } catch {
    return;
  }
  log.debug(
    s.listed !== undefined && s.listed !== s.files
      ? `${engine}: linted ${s.files} of ${s.listed} listed file(s)`
      : `${engine}: linted ${s.files} file(s)`,
  );
  // Debug, like sonarjs and ESLint: a file that does not parse is not a finding.
  if ((s.parseErrors ?? 0) > 0) log.debug(`${engine}: ${s.parseErrors} file(s) did not parse`);
  const unknown = s.unknownRules ?? [];
  if (unknown.length > 0) {
    log.warn(
      `${engine}: the configuration names rule(s) this ${engine} does not have: ${unknown.join(', ')}`,
    );
  }
  if ((s.invalidOptions ?? 0) > 0) {
    log.warn(`${engine}: ${s.invalidOptions} invalid rule option(s) in the configuration`);
  }
}
