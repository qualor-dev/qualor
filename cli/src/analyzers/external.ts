import { lstatSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { BUILTIN_ENGINES, engineMapping, sarifLogSchema, type EngineMapping } from '@qualor/shared';
import { CliError, EXIT } from '../errors';
import type { Warnings } from '../warnings';
import type { SarifCapture } from './types';

const MAX_EXTERNAL_SARIF_BYTES = 256 * 1024 * 1024;

/** report-format §7.2: `^[a-z0-9][a-z0-9-]{0,39}$`. */
export function slugifyEngineId(name: string): string {
  const slug = name
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40)
    .replace(/-+$/, '');
  return slug === '' ? 'external' : slug;
}

/** Ruling C10: the override wins; a slug equal to a built-in id becomes `ext-<slug>`. */
export function externalEngineId(
  toolName: string | undefined,
  override: string | undefined,
): { id: string; renamed: boolean } {
  if (override !== undefined) return { id: override, renamed: false };
  const slug = slugifyEngineId(toolName ?? '');
  if ((BUILTIN_ENGINES as readonly string[]).includes(slug)) {
    return { id: `ext-${slug}`.slice(0, 40), renamed: true };
  }
  return { id: slug, renamed: false };
}

/**
 * An externally run built-in tool keeps that tool's mapping (so external Gitleaks output is still
 * redacted); any other tool redacts results of rules tagged CWE-798 or "secret".
 */
function externalMapping(id: string): EngineMapping {
  const builtin = id.startsWith('ext-') ? engineMapping(id.slice(4)) : undefined;
  if (builtin !== undefined) return builtin;
  const secretRule = engineMapping('semgrep')?.redactRegion;
  return secretRule === undefined ? {} : { redactRegion: secretRule };
}

function readLog(root: string, p: string): { runs: unknown[]; toolName: string | undefined } {
  const abs = path.resolve(root, p);
  let text: string;
  try {
    // Fix-round finding 7: `lstat` (not `stat`) so a symlink is seen as itself, not followed to
    // whatever it points at; `isFile()` then rejects it (and FIFOs, devices, directories) outright,
    // reusing the same stat call for the size bound instead of a separate, followed `statSync`.
    const stat = lstatSync(abs);
    if (!stat.isFile()) throw new Error('not a regular file (symlinks are not followed)');
    if (stat.size > MAX_EXTERNAL_SARIF_BYTES) throw new Error('larger than 256 MiB');
    text = readFileSync(abs, 'utf8');
  } catch (err) {
    throw new CliError(
      EXIT.USAGE,
      `cannot read SARIF file ${p}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new CliError(EXIT.USAGE, `SARIF file ${p} is not valid JSON`);
  }
  const parsed = sarifLogSchema.safeParse(json);
  if (!parsed.success) throw new CliError(EXIT.USAGE, `${p} is not a SARIF 2.1.0 log`);
  return {
    runs: (json as { runs: unknown[] }).runs,
    toolName: parsed.data.runs[0]?.tool.driver.name,
  };
}

/** `--sarif` and `sarif[]` (config.md §3): one capture per engine id, files of one id merged. */
export function loadExternalSarif(
  inputs: readonly { path: string; engine?: string }[],
  o: { root: string; warnings: Warnings },
): SarifCapture[] {
  const byId = new Map<string, unknown[]>();
  for (const input of inputs) {
    const { runs, toolName } = readLog(o.root, input.path);
    const { id, renamed } = externalEngineId(toolName, input.engine);
    if (renamed) {
      o.warnings.add(
        'EXTERNAL_ENGINE_RENAMED',
        `external SARIF from a built-in tool is reported under an ext- engine id (${id})`,
      );
    }
    byId.set(id, [...(byId.get(id) ?? []), ...runs]);
  }
  return [...byId].map(([id, runs]): SarifCapture => ({
    engineId: id,
    kind: 'external',
    status: 'ok',
    reason: null,
    durationMs: 0,
    version: null,
    required: false,
    sarif: { version: '2.1.0', runs },
    mapping: externalMapping(id),
  }));
}
