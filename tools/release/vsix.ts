import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { inflateRawSync } from 'node:zlib';
import { REPO_ROOT } from '../deploy/stack';
import type { Version } from './version';

/**
 * The Azure DevOps extension as a release asset (Azure sub-plan 3 ruling 14, sub-plan 9).
 * release.yml builds it with `pnpm extension:package` before the dry run; the dry run checks that
 * the VSIX is the extension of this version and writes it into the release directory, so it is
 * listed in the manifest and in SHA256SUMS (signed) and uploaded with the other assets.
 */

/** Where `pnpm extension:package` writes the VSIX (integrations/azure-devops/extension/scripts/package.ts). */
export const EXTENSION_OUT = path.join(REPO_ROOT, '.tmp', 'azure');
/** Its folder in the release directory; the asset keeps the file name (assets.ts). */
export const EXTENSION_DIR = 'azure-devops';
/** The Marketplace identity in vss-extension.json (not the dev variant of dev-overrides.json). */
const PUBLISHER = 'qualor';
const EXTENSION_ID = 'qualor';
const MANIFEST = 'extension.vsixmanifest';
const TASK = 'tasks/qualor/task.json';

/** A Marketplace version and a task version hold numbers only: a pre-release packs as x.y.z. */
const packed = (v: Version): string => `${v.major}.${v.minor}.${v.patch}`;
/** The file name tfx gives the VSIX: the extension's identity and its manifest version. */
export const vsixName = (v: Version): string => `${PUBLISHER}.${EXTENSION_ID}-${packed(v)}.vsix`;

const END_OF_DIRECTORY = Buffer.from([0x50, 0x4b, 0x05, 0x06]);
const DIRECTORY_ENTRY = 0x02014b50;

/**
 * The entries of a zip by name, read through its central directory: stored or deflated, no ZIP64
 * (a VSIX of a few hundred kilobytes). Anything else throws.
 */
export function zipEntries(zip: Buffer): Map<string, Buffer> {
  const end = zip.lastIndexOf(END_OF_DIRECTORY);
  if (end < 0 || end + 22 > zip.length) throw new Error('not a zip file');
  const count = zip.readUInt16LE(end + 10);
  let at = zip.readUInt32LE(end + 16);
  const out = new Map<string, Buffer>();
  for (let i = 0; i < count; i += 1) {
    if (zip.readUInt32LE(at) !== DIRECTORY_ENTRY) throw new Error('not a zip file');
    const method = zip.readUInt16LE(at + 10);
    const size = zip.readUInt32LE(at + 20);
    const nameLength = zip.readUInt16LE(at + 28);
    const extra = zip.readUInt16LE(at + 30);
    const comment = zip.readUInt16LE(at + 32);
    const local = zip.readUInt32LE(at + 42);
    const name = zip.toString('utf8', at + 46, at + 46 + nameLength);
    const start = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28);
    const data = zip.subarray(start, start + size);
    if (method === 8) out.set(name, inflateRawSync(data));
    else if (method === 0) out.set(name, Buffer.from(data));
    else throw new Error(`${name}: compression method ${method}, not stored or deflated`);
    at += 46 + nameLength + extra + comment;
  }
  return out;
}

/** The attributes of the manifest's `<Identity …/>`: Id, Publisher, Version (vss-extension.json). */
function identity(manifest: string): Record<string, string> {
  const element = /<Identity\b([^>]*)>/.exec(manifest)?.[1] ?? '';
  return Object.fromEntries(
    [...element.matchAll(/\s([\w:]+)="([^"]*)"/g)].map((m) => [m[1] ?? '', m[2] ?? '']),
  );
}

/** The task's version triple as x.y.z; `(none)` when task.json holds none. */
function taskVersion(text: string): string {
  const { Major, Minor, Patch } =
    (JSON.parse(text) as { version?: Record<string, unknown> }).version ?? {};
  return [Major, Minor, Patch].every((n) => typeof n === 'number')
    ? `${String(Major)}.${String(Minor)}.${String(Patch)}`
    : '(none)';
}

/**
 * What keeps `zip` from being this release's extension: not a zip, another extension (the dev
 * variant), another version in its manifest or in its task. Empty when it is.
 */
export function vsixProblems(zip: Buffer, v: Version): string[] {
  let entries: Map<string, Buffer>;
  try {
    entries = zipEntries(zip);
  } catch {
    return ['not a zip file'];
  }
  const want = packed(v);
  const problems: string[] = [];
  const manifest = entries.get(MANIFEST);
  if (manifest === undefined) problems.push(`no ${MANIFEST} in it`);
  else {
    const { Id, Publisher, Version } = identity(manifest.toString('utf8'));
    const id = `${Publisher ?? '(none)'}.${Id ?? '(none)'}`;
    if (id !== `${PUBLISHER}.${EXTENSION_ID}`) {
      problems.push(
        `it is the extension ${id}, not ${PUBLISHER}.${EXTENSION_ID}: build it without --overrides-file`,
      );
    } else if (Version !== want) {
      problems.push(`its version (vss-extension.json) is ${Version ?? '(none)'}, not ${want}`);
    }
  }
  const task = entries.get(TASK);
  if (task === undefined) problems.push(`no ${TASK} in it`);
  else {
    let found: string;
    try {
      found = taskVersion(task.toString('utf8'));
    } catch {
      found = '(not JSON)';
    }
    if (found !== want) problems.push(`its task (task.json) is ${found}, not ${want}`);
  }
  return problems;
}

/**
 * The VSIX of `v` that `pnpm extension:package` wrote into `from`, checked; the bytes are what the
 * dry run writes, so what was checked is what is released. Throws naming every problem.
 */
export function readVsix(
  v: Version,
  from = EXTENSION_OUT,
): { name: string; version: string; data: Buffer } {
  const name = vsixName(v);
  const file = path.join(from, name);
  if (!existsSync(file)) {
    throw new Error(`${file} is missing: run pnpm extension:package (after pnpm release:version)`);
  }
  const data = readFileSync(file);
  const problems = vsixProblems(data, v);
  if (problems.length > 0) {
    throw new Error(
      `${name}: ${problems.join('; ')}\nrun pnpm extension:package (after pnpm release:version)`,
    );
  }
  return { name, version: packed(v), data };
}
