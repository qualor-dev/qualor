import { existsSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { ConfigError, interpolateEnv, parseConfig, type QualorConfig } from '@qualor/shared';
import { parse as parseYaml } from 'yaml';
import { CliError, EXIT } from '../errors';
import type { Logger } from '../log';
import { detectCi, type CiInfo } from './ci';

type Env = Readonly<Record<string, string | undefined>>;

export interface ConfigFlags {
  config?: string;
  projectKey?: string;
  sarif?: readonly string[];
  coverage?: readonly string[];
  wait?: boolean;
  tokenFile?: string;
  serverUrl?: string;
  caFile?: string;
}

export interface Settings {
  /** Absolute repo root: the directory the CLI runs in. */
  root: string;
  /** Absolute path of the qualor.yml that was read, or null when there is none. */
  configPath: string | null;
  /** Fully resolved: flags > env > file > CI > defaults (config.md §2). */
  config: QualorConfig;
  token: string | null;
  ci: CiInfo;
  /** Where `server.url` came from (config.md §2) never sends the token to a `'file'` URL. */
  serverUrlSource: 'flag' | 'env' | 'file' | null;
  /** Where `server.caFile` came from; ruling V8 never trusts a `'file'` CA when a token is sent. */
  caFileSource: 'flag' | 'env' | 'file' | null;
}

export interface LoadSettingsInput {
  cwd: string;
  env: Env;
  flags: ConfigFlags;
  log: Logger;
}

const MAX_CONFIG_BYTES = 1024 * 1024;
const MAX_TOKEN_FILE_BYTES = 64 * 1024;

function nonEmpty(v: string | undefined): string | undefined {
  return v === undefined || v.trim() === '' ? undefined : v;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function readYamlConfig(file: string): Record<string, unknown> {
  let doc: unknown;
  try {
    if (statSync(file).size > MAX_CONFIG_BYTES) throw new Error('larger than 1 MiB');
    doc = parseYaml(readFileSync(file, 'utf8'), { uniqueKeys: true, maxAliasCount: 100 });
  } catch (err) {
    throw new CliError(EXIT.USAGE, `${file}: ${message(err)}`);
  }
  if (doc === null || doc === undefined) return {};
  if (!isRecord(doc)) throw new CliError(EXIT.USAGE, `${file}: the top level must be a mapping`);
  return doc;
}

/**
 * Variable names that must never be interpolated into `qualor.yml`, because their value is a
 * secret: `${QUALOR_TOKEN}` in an arbitrary string field, e.g. `project.version`, would otherwise
 * put the token into the resolved config, and hence into `qualor validate`'s output and the
 * report. Matched case-insensitively by suffix, plus a handful of well-known CI secret variables
 * that do not end in one of those suffixes. `*_ACCESS_KEY`, `*_PASS` and `*_PASSPHRASE` need an
 * underscore (or the whole name) before them, so `BYPASS` or `AWS_ACCESS_KEY_ID` stay usable;
 * a bare `*_KEY` is deliberately not a secret (`PROJECT_KEY`, `CACHE_KEY`).
 */
const SECRET_VAR_SUFFIX = /(?:TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|CREDENTIALS?)$/i;
const SECRET_VAR_WORD_SUFFIX = /(?:^|_)(?:ACCESS_KEY|PASS|PASSPHRASE)$/i;
const SECRET_VAR_NAMES = new Set([
  'QUALOR_TOKEN',
  'CI_JOB_TOKEN',
  'GITHUB_TOKEN',
  'CI_REGISTRY_PASSWORD',
]);

/** Also used by the analyzer runner: stripped from the child process environment of every
 * analyzer, since analyzers run repo-controlled code. */
export function isSecretVarName(name: string): boolean {
  return (
    SECRET_VAR_NAMES.has(name) || SECRET_VAR_SUFFIX.test(name) || SECRET_VAR_WORD_SUFFIX.test(name)
  );
}

function rejectToken(raw: Record<string, unknown>, file: string): void {
  const server = raw['server'];
  if ('token' in raw || (isRecord(server) && 'token' in server)) {
    throw new CliError(
      EXIT.USAGE,
      `${file}: qualor.yml must not contain a token; set QUALOR_TOKEN or pass --token-file`,
    );
  }
}

function readToken(flags: ConfigFlags, env: Env, cwd: string): string | null {
  if (flags.tokenFile === undefined) return nonEmpty(env['QUALOR_TOKEN'])?.trim() ?? null;
  const file = path.resolve(cwd, flags.tokenFile);
  let text: string;
  try {
    if (statSync(file).size > MAX_TOKEN_FILE_BYTES) throw new Error('larger than 64 KiB');
    text = readFileSync(file, 'utf8');
  } catch (err) {
    throw new CliError(EXIT.USAGE, `cannot read --token-file ${flags.tokenFile}: ${message(err)}`);
  }
  const token = text.trim();
  if (token === '') throw new CliError(EXIT.USAGE, `--token-file ${flags.tokenFile} is empty`);
  return token;
}

/**
 * Applies flags, env and CI values to the raw file content before validation, so every source
 * goes through the same zod schema. A value of the wrong shape is left alone for the schema to
 * reject with its path.
 */
function applyOverrides(
  raw: Record<string, unknown>,
  flags: ConfigFlags,
  env: Env,
  ci: CiInfo,
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...raw };
  const project = raw['project'] ?? {};
  if (isRecord(project)) {
    const fileKey = project['key'];
    const key =
      flags.projectKey ??
      nonEmpty(env['QUALOR_PROJECT_KEY']) ??
      (fileKey === undefined || fileKey === '' ? (ci.projectPath ?? undefined) : fileKey);
    out['project'] = key === undefined ? project : { ...project, key };
  }
  const url = flags.serverUrl ?? nonEmpty(env['QUALOR_URL']);
  const caFile = flags.caFile ?? nonEmpty(env['QUALOR_CA_FILE']);
  const server = raw['server'] ?? {};
  if ((url !== undefined || caFile !== undefined) && isRecord(server)) {
    out['server'] = {
      ...server,
      ...(url !== undefined && { url }),
      ...(caFile !== undefined && { caFile }),
    };
  }
  if (flags.sarif !== undefined && flags.sarif.length > 0) {
    const list = raw['sarif'] ?? [];
    if (Array.isArray(list)) out['sarif'] = [...list, ...flags.sarif.map((p) => ({ path: p }))];
  }
  if (flags.coverage !== undefined && flags.coverage.length > 0) {
    const coverage = raw['coverage'] ?? {};
    if (isRecord(coverage)) {
      const reports = coverage['reports'] ?? [];
      if (Array.isArray(reports)) {
        out['coverage'] = {
          ...coverage,
          reports: [...reports, ...flags.coverage.map((p) => ({ path: p }))],
        };
      }
    }
  }
  if (flags.wait === false) {
    const gate = raw['gate'] ?? {};
    if (isRecord(gate)) out['gate'] = { ...gate, wait: false };
  }
  return out;
}

export function loadSettings(input: LoadSettingsInput): Settings {
  const { cwd, env, flags, log } = input;
  const explicit = flags.config ?? nonEmpty(env['QUALOR_CONFIG']);
  const file = path.resolve(cwd, explicit ?? 'qualor.yml');
  let raw: Record<string, unknown> = { version: 1 };
  let configPath: string | null = null;
  if (existsSync(file)) {
    raw = readYamlConfig(file);
    configPath = file;
  } else if (explicit !== undefined) {
    throw new CliError(EXIT.USAGE, `config file not found: ${file}`);
  }
  rejectToken(raw, file);
  // One pass: a secret-named reference resolves to '' inside the same replacement, so no text
  // produced by it (`$${QUALOR_TOKEN}{QUALOR_TOKEN}` -> `${QUALOR_TOKEN}`) is ever interpolated.
  const interpolated = interpolateEnv(
    raw,
    env,
    (name) => log.warn(`${file}: \${${name}} is not set; using an empty string`),
    {
      deny: isSecretVarName,
      onDenied: (name) =>
        log.warn(`${file}: \${${name}} refers to a secret variable and is not interpolated`),
    },
  );
  const ci = detectCi(env);
  const merged = applyOverrides(isRecord(interpolated) ? interpolated : {}, flags, env, ci);
  let config: QualorConfig;
  try {
    config = parseConfig(merged);
  } catch (err) {
    if (err instanceof ConfigError) {
      throw new CliError(
        EXIT.USAGE,
        configPath === null ? err.message : `${configPath}: ${err.message}`,
      );
    }
    throw err;
  }
  const serverUrlSource =
    flags.serverUrl !== undefined
      ? 'flag'
      : nonEmpty(env['QUALOR_URL']) !== undefined
        ? 'env'
        : config.server.url !== undefined
          ? 'file'
          : null;
  const fileCaFile = config.server.caFile;
  const caFileSource =
    flags.caFile !== undefined
      ? 'flag'
      : nonEmpty(env['QUALOR_CA_FILE']) !== undefined
        ? 'env'
        : fileCaFile !== null && fileCaFile !== ''
          ? 'file'
          : null;
  return {
    root: cwd,
    configPath,
    config,
    token: readToken(flags, env, cwd),
    ci,
    serverUrlSource,
    caFileSource,
  };
}

/** Upload needs both; `--dry-run` needs neither (config.md §7, exit code 2). */
export function requireServer(settings: Settings): { url: string; token: string } {
  const url = settings.config.server.url;
  if (url === undefined || settings.token === null) {
    throw new CliError(
      EXIT.USAGE,
      'a server URL (--server-url, QUALOR_URL or server.url) and a token (QUALOR_TOKEN or --token-file) are required unless --dry-run is used',
    );
  }
  return { url, token: settings.token };
}
