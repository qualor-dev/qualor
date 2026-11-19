import { lstatSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import type { FixStop, FixWorkspace } from './adapter';

/**
 * What every adapter (Tasks 13–16, ruling T14b) does with the scratch copy: repository paths
 * (`/`-separated, as `FixWorkspace.files` names them) and their files, the stops all of them give,
 * and the time a tool call may take.
 */

/** Whether a step's result is a stop (`FixStop`) rather than its value. */
export const isStop = (v: unknown): v is FixStop =>
  typeof v === 'object' && v !== null && !Array.isArray(v) && 'kind' in v;

/** A manifest, lockfile or layout Qualor does not change: `failure manifest_unsupported`. */
export const unsupported = (message: string): FixStop => ({
  kind: 'failure',
  code: 'manifest_unsupported',
  message,
});

/** A repository path's last segment. */
export const basename = (p: string): string => p.slice(p.lastIndexOf('/') + 1);
/** A repository path's folder with its slash ('' at the root). */
export const dirOf = (p: string): string => p.slice(0, p.lastIndexOf('/') + 1);

/** A repository path in the scratch copy. */
export const absolute = (ws: FixWorkspace, rel: string): string =>
  path.join(ws.root, ...rel.split('/'));
export const readText = (ws: FixWorkspace, rel: string): string =>
  readFileSync(absolute(ws, rel), 'utf8');
export const writeText = (ws: FixWorkspace, rel: string, text: string): void =>
  writeFileSync(absolute(ws, rel), text, 'utf8');

/** Whether a repository path is a regular file of the scratch copy: not a link, not missing. */
export function isRegularFile(ws: FixWorkspace, rel: string): boolean {
  try {
    return lstatSync(absolute(ws, rel)).isFile();
  } catch {
    return false;
  }
}

/** A link is followed by every read and write: the edit could land outside the scratch copy. */
export const notRegular = (file: string): FixStop =>
  unsupported(`${file} is not a regular file (a link?); Qualor edits only regular files.`);

/** What is left of the fix's time, for a tool call's `timeoutMs` (0 when it is up). */
export const timeLeft = (ws: FixWorkspace): number => Math.max(0, ws.deadline - Date.now());

/** Ruling T14c: one order for paths, by UTF-16 code units (never the locale's). */
export function byCodeUnit(a: string, b: string): number {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}

/** At most this many versions, modules or paths are named in a message. */
export const SHOWN = 5;

/** The first {@link SHOWN} items, comma-separated, with the count when there are more. */
export function listed(items: readonly string[]): string {
  const shown = items.slice(0, SHOWN).join(', ');
  return items.length > SHOWN ? `${shown}, … (${items.length} in all)` : shown;
}
