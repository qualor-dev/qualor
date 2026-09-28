import {
  closeSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import { CliError, EXIT } from '../errors';
import type { Logger } from '../log';
import { msbuildEscape } from './hook';

export const SESSION_DIR = '.qualor/dotnet';
/** config.md §6.1: at most this many logs are read. */
export const MAX_LOGS = 10_000;
/** A project record is three short lines; anything larger is not one. */
const MAX_RECORD_BYTES = 64 * 1024;
/** Final review R10: what `begin` leaves under `auto` when it could not set the session up. */
export const HOOK_FAILED = 'hook-failed';
const MAX_HOOK_FAILED_BYTES = 1024;
/** Ruling D3: file-system timestamps are coarse. */
const FRESHNESS_SLACK_MS = 2_000;

const sessionSchema = z.strictObject({
  version: z.literal(1),
  id: z.string().regex(/^[0-9a-f]{32}$/),
  root: z.string().min(1),
  startedAt: z.iso.datetime(),
  cli: z.string().max(128),
  analyzers: z.array(z.string().min(1)).max(1_000),
});
export type SessionInfo = z.infer<typeof sessionSchema>;

export interface ProjectRecord {
  project: string;
  targetFramework: string;
  log: string;
}

const sessionDir = (root: string) => path.join(root, ...SESSION_DIR.split('/'));

/** A real directory, not a link or junction (config.md §6.1), or absent. */
function checkNoLink(p: string, label: string): void {
  let stat;
  try {
    stat = lstatSync(p);
  } catch {
    return;
  }
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new CliError(EXIT.USAGE, `${label} must be a directory, not a link or a file`);
  }
}

export function createSession(root: string, info: SessionInfo): void {
  checkNoLink(path.join(root, '.qualor'), '.qualor');
  checkNoLink(sessionDir(root), SESSION_DIR);
  rmSync(sessionDir(root), { recursive: true, force: true });
  const dir = sessionDir(root);
  mkdirSync(path.join(dir, 'sarif'), { recursive: true });
  mkdirSync(path.join(dir, 'projects'), { recursive: true });
  const items = info.analyzers
    .map((a) => `    <QualorBundledAnalyzer Include="${msbuildEscape(a)}" />`)
    .join('\n');
  writeFileSync(
    path.join(dir, 'session.props'),
    `<Project>\n  <ItemGroup>\n${items}\n  </ItemGroup>\n</Project>\n`,
  );
  // Written last: the hook activates on session.json, whose mtime is the session's start (D3).
  writeFileSync(path.join(dir, 'session.json'), `${JSON.stringify(info, null, 2)}\n`);
}

export function readSession(root: string): SessionInfo | null {
  try {
    const file = path.join(sessionDir(root), 'session.json');
    if (!lstatSync(file).isFile()) return null;
    const parsed = sessionSchema.safeParse(JSON.parse(readFileSync(file, 'utf8')));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

function regularFiles(dir: string, suffix: string): string[] {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return [];
  }
  return names
    .filter((n) => n.endsWith(suffix))
    .sort()
    .map((n) => path.join(dir, n))
    .filter((p) => {
      try {
        return lstatSync(p).isFile();
      } catch {
        return false;
      }
    });
}

/**
 * Ruling D2: three lines per record; a malformed record is ignored, and one that cannot be read
 * (final review R12, M3) is skipped with a debug line rather than aborting `end`.
 */
export function readProjectRecords(root: string, logger: Logger): ProjectRecord[] {
  checkNoLink(path.join(root, '.qualor'), '.qualor');
  checkNoLink(sessionDir(root), SESSION_DIR);
  const records: ProjectRecord[] = [];
  for (const file of regularFiles(path.join(sessionDir(root), 'projects'), '.txt').slice(
    0,
    MAX_LOGS,
  )) {
    let text: string;
    try {
      if (lstatSync(file).size > MAX_RECORD_BYTES) throw new Error('larger than a project record');
      text = readFileSync(file, 'utf8');
    } catch (err) {
      logger.debug(
        `roslyn: ${file} was not read: ${err instanceof Error ? err.message : String(err)}`,
      );
      continue;
    }
    const lines = text
      .replace(/^\uFEFF/, '')
      .split(/\r?\n/)
      .filter((l) => l !== '');
    const [project, targetFramework, log] = lines;
    if (
      lines.length !== 3 ||
      project === undefined ||
      targetFramework === undefined ||
      log === undefined
    )
      continue;
    records.push({ project, targetFramework, log });
  }
  return records;
}

/** Regular `*.sarif` files directly in `sarif/`, sorted, at most MAX_LOGS. */
export function listLogs(root: string): string[] {
  checkNoLink(path.join(root, '.qualor'), '.qualor');
  checkNoLink(sessionDir(root), SESSION_DIR);
  return regularFiles(path.join(sessionDir(root), 'sarif'), '.sarif').slice(0, MAX_LOGS);
}

/** Ruling D3: written during this session, not left by an earlier one. */
export function isFresh(log: string, root: string): boolean {
  try {
    const started = statSync(path.join(sessionDir(root), 'session.json')).mtimeMs;
    const stat = lstatSync(log);
    return stat.isFile() && stat.mtimeMs >= started - FRESHNESS_SLACK_MS;
  } catch {
    return false;
  }
}

export function removeSession(root: string): void {
  checkNoLink(path.join(root, '.qualor'), '.qualor');
  checkNoLink(sessionDir(root), SESSION_DIR);
  rmSync(sessionDir(root), { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
}

/**
 * Final review R10: under `enabled: auto`, a `begin` that could not write the session, the lease
 * or the hook leaves `.qualor/dotnet/hook-failed` with the reason, so `end` reports the engine
 * unavailable (incomplete for scm.md §9's ruling G6) instead of "begin was not run".
 */
export function writeHookFailed(root: string, reason: string): void {
  checkNoLink(path.join(root, '.qualor'), '.qualor');
  checkNoLink(sessionDir(root), SESSION_DIR);
  mkdirSync(sessionDir(root), { recursive: true });
  writeFileSync(path.join(sessionDir(root), HOOK_FAILED), `${reason}\n`);
}

/** The reason in `.qualor/dotnet/hook-failed` (a regular file, its first 1 KiB), else null. */
export function readHookFailed(root: string): string | null {
  try {
    checkNoLink(path.join(root, '.qualor'), '.qualor');
    checkNoLink(sessionDir(root), SESSION_DIR);
    const file = path.join(sessionDir(root), HOOK_FAILED);
    if (!lstatSync(file).isFile()) return null;
    const fd = openSync(file, 'r');
    try {
      const buffer = Buffer.alloc(MAX_HOOK_FAILED_BYTES);
      const read = readSync(fd, buffer, 0, buffer.length, 0);
      return buffer.subarray(0, read).toString('utf8').trim();
    } finally {
      closeSync(fd);
    }
  } catch {
    return null;
  }
}
