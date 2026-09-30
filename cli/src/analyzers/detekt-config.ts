import { lstatSync } from 'node:fs';
import path from 'node:path';
import type { QualorConfig } from '@qualor/shared';
import { isMap, parseDocument, visit } from 'yaml';
import { within } from './binary';
import { shown } from './reason';
import { readRepoConfigBytes, WeblintConfigError } from './weblint';

/** Where a project keeps its detekt config, in lookup order (config.md §6). */
export const DETEKT_CONFIG_CANDIDATES: readonly string[] = [
  'config/detekt/detekt.yml', // the detekt Gradle plugin's default
  'config/detekt.yml',
  'detekt.yml',
  '.detekt.yml',
];

/** detekt's own default config is about 30 KiB. */
export const MAX_DETEKT_CONFIG_BYTES = 1024 * 1024;

/** snakeyaml's `maxAliasesForCollections` default, which detekt keeps (ruling E14). */
export const MAX_DETEKT_CONFIG_ALIASES = 50;

/**
 * Passed after the project's config, so it wins (detekt merges `--config` files, the later one
 * first). A config for another detekt version (unknown keys) never fails the run; the SARIF report
 * is always written; `AbsentOrWrongFileLicense` never runs, because it reads the file its
 * `licenseTemplateFile` names, resolved from the last config's directory, which could be any file
 * the job can read.
 */
export const QUALOR_DETEKT_OVERLAY = `# Qualor's settings over detekt's defaults and the project's config (config.md §6).
config:
  validation: false
  warningsAsErrors: false
output-reports:
  active: true
  exclude: []
comments:
  AbsentOrWrongFileLicense:
    active: false
`;

/**
 * `none`: detekt's defaults. `project`: the checked text of the project's config, which is what
 * detekt reads (a copy, never the checkout's file). `skip`: a problem of the checkout's config,
 * a skip reason under `auto` and a failed engine under `enabled: true` (ruling E7). `error`: an
 * invalid `qualor.yml` setting, exit 2 through `checkDetektConfig`.
 */
export type DetektConfig =
  | { kind: 'none' }
  | { kind: 'project'; rel: string; text: string }
  | { kind: 'skip'; reason: string }
  | { kind: 'error'; reason: string };

function exists(abs: string): boolean {
  try {
    lstatSync(abs);
    return true;
  } catch {
    return false;
  }
}

/** The YAML problem that makes detekt skip, or null for a config it may read. */
function yamlProblem(text: string): string | null {
  // Any exception of the parser or the walk (a RangeError on a deeply nested document) is a
  // refusal, never a CLI crash (ruling E14).
  try {
    const doc = parseDocument(text, { uniqueKeys: true });
    if (doc.errors.length > 0) return 'is not valid YAML';
    let tagged = doc.warnings.length > 0;
    let aliases = 0;
    visit(doc, {
      Alias() {
        aliases += 1;
      },
      Node(_key, node) {
        if ((node as { tag?: string }).tag !== undefined) tagged = true;
      },
    });
    if (tagged) return 'has an explicit YAML tag';
    // Counted here, because the yaml package's own limit only applies when it builds values.
    if (aliases > MAX_DETEKT_CONFIG_ALIASES) {
      return `has more than ${MAX_DETEKT_CONFIG_ALIASES} YAML aliases`;
    }
    if (!isMap(doc.contents)) return 'is not a YAML mapping';
    return null;
  } catch {
    return 'is not valid YAML';
  }
}

/**
 * Reads the config once and checks it (config.md §6): a regular file that stays inside the
 * repository after symlinks (a link to a file inside it is fine, ruling E6), at most 1 MiB, UTF-8,
 * a YAML mapping without a parse error, a duplicate key, an explicit tag or more than 50 aliases.
 */
function read(root: string, rel: string): DetektConfig {
  const name = shown(rel.split(path.sep).join('/'));
  let bytes: Buffer;
  try {
    bytes = readRepoConfigBytes(root, rel, MAX_DETEKT_CONFIG_BYTES, name);
  } catch (err) {
    if (err instanceof WeblintConfigError) return { kind: 'skip', reason: err.message };
    return { kind: 'skip', reason: `${name} cannot be read` };
  }
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return { kind: 'skip', reason: `${name} is not UTF-8` };
  }
  const problem = yamlProblem(text);
  if (problem !== null) return { kind: 'skip', reason: `${name} ${problem}` };
  return { kind: 'project', rel: rel.split(path.sep).join('/'), text };
}

/** A `configFile` outside the repository as written: an invalid qualor.yml setting, or null. */
function configFileError(root: string, named: string): string | null {
  // A link out of the repository on the way is the checkout's problem, which `read` reports as a
  // skip (ruling E7).
  return within(path.resolve(root), path.resolve(root, named))
    ? null
    : `configFile ${shown(named)} is outside the repository`;
}

export function detektConfig(root: string, config: QualorConfig): DetektConfig {
  const named = config.analyzers.detekt.configFile;
  if (named !== null) {
    const error = configFileError(root, named);
    if (error !== null) return { kind: 'error', reason: error };
    const abs = path.resolve(root, named);
    if (!exists(abs)) return { kind: 'skip', reason: `configFile ${shown(named)} does not exist` };
    return read(root, path.relative(root, abs));
  }
  for (const rel of DETEKT_CONFIG_CANDIDATES) {
    if (exists(path.join(root, rel))) return read(root, rel);
  }
  return { kind: 'none' };
}

/**
 * `qualor scan` stops with exit 2 on this before any analyzer runs (config.md §6, ruling E7): only
 * a `configFile` outside the repository. Every problem of the config file itself is a skip.
 */
export function checkDetektConfig(root: string, config: QualorConfig): string | null {
  const named = config.analyzers.detekt.configFile;
  return named === null ? null : configFileError(root, named);
}
