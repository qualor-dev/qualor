import { parseArgs } from 'node:util';
import { CliError, EXIT } from './errors';

export interface ScanFlags {
  config?: string;
  projectKey?: string;
  sarif: string[];
  coverage: string[];
  branch?: string;
  mr?: string;
  mrTarget?: string;
  wait: boolean;
  dryRun: boolean;
  output?: string;
  tokenFile?: string;
  serverUrl?: string;
  caFile?: string;
  /** scm.md §9: where to write GitLab's Code Quality report (in the working directory). */
  gitlabCodeQuality?: string;
  /** scm.md §9: where to write GitLab's SAST report (in the working directory). */
  gitlabSast?: string;
  /** scm.md §9 (plan 2B): where to write GitLab's Dependency Scanning report. */
  gitlabDependencyScanning?: string;
}

/** import-sonarqube.md §3: the steps of `--only`, in the order they run. */
export const IMPORT_STEPS = ['profiles', 'gates', 'projects', 'issues'] as const;
export type ImportStep = (typeof IMPORT_STEPS)[number];

/** import-sonarqube.md §3. */
export interface ImportFlags {
  url: string;
  token?: string;
  tokenFile?: string;
  organization?: string;
  sonarKind: 'auto' | 'server' | 'cloud';
  qualorOrganization?: string;
  projects: string[];
  only: ImportStep[];
  pathPrefix?: string;
  createProjects: boolean;
  setDefaults: boolean;
  overwrite: boolean;
  dryRun: boolean;
  output?: string;
  serverUrl?: string;
  qualorTokenFile?: string;
  caFile?: string;
  sonarCaFile?: string;
  sonarAuth: 'auto' | 'bearer' | 'basic';
  timeoutSeconds: number;
  maxIssues: number;
  /** Ruling S9: allow plain http to a host other than loopback (a token then goes in cleartext). */
  allowInsecureHttp: boolean;
}

export type Command =
  | { name: 'help' }
  | { name: 'version' }
  | { name: 'validate'; config?: string }
  | { name: 'scan'; flags: ScanFlags }
  | { name: 'import-sonarqube'; flags: ImportFlags }
  | { name: 'dotnet-begin'; config?: string }
  | { name: 'dotnet-end'; flags: ScanFlags }
  | { name: 'dotnet-abort' };

export const USAGE = `Usage:
  qualor scan [--config PATH] [--project-key KEY] [--sarif PATH]... [--coverage PATH]...
              [--branch NAME] [--mr ID --mr-target BRANCH] [--no-wait] [--token-file PATH]
              [--server-url URL] [--ca-file PATH] [--dry-run --output report.json.gz]
              [--gitlab-code-quality FILE] [--gitlab-sast FILE]
              [--gitlab-dependency-scanning FILE]
  qualor import sonarqube --url URL [--token TOKEN | --token-file PATH]
              [--organization SONAR_ORG] [--sonar-kind auto|server|cloud]
              [--qualor-organization KEY] [--project KEY]... [--only STEPS]
              [--path-prefix DIR] [--create-projects] [--set-defaults] [--overwrite]
              [--dry-run] [--output FILE] [--server-url URL] [--qualor-token-file PATH]
              [--ca-file PATH] [--sonar-ca-file PATH] [--sonar-auth auto|bearer|basic]
              [--timeout SECONDS] [--max-issues N] [--allow-insecure-http]
  qualor dotnet begin [--config PATH]
  qualor dotnet end [qualor scan options]
  qualor dotnet abort [--config PATH]
  qualor validate [--config PATH]
  qualor version
`;

function usageError(message: string): CliError {
  return new CliError(EXIT.USAGE, `${message}\n\n${USAGE}`);
}

function strict<T>(parse: () => T): T {
  try {
    return parse();
  } catch (err) {
    throw usageError(err instanceof Error ? err.message : String(err));
  }
}

function value(name: string, v: string | undefined): string | undefined {
  if (v !== undefined && v.trim() === '') throw usageError(`--${name} needs a non-empty value`);
  return v;
}

function values(name: string, list: string[] | undefined): string[] {
  return (list ?? []).map((v) => value(name, v) ?? v);
}

/** report-format §4 bounds for branch names and merge request ids. */
const MAX_BRANCH_CHARS = 255;
const MR_ID = /^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$/;
// eslint-disable-next-line no-control-regex -- control characters are exactly what is rejected
const REF_FORBIDDEN = /[\u0000- \u007f~^:?*[\\]|\.\.|@\{|\/\/|^[-/.]|[/.]$|\.lock$|\/\./;

/**
 * A light version of `git check-ref-format` (the SCM step still asks git itself): rejects names
 * git would refuse and, above all, names that could be read as a git option.
 */
function branchName(name: string, v: string | undefined): string | undefined {
  if (v === undefined) return v;
  if (v.length > MAX_BRANCH_CHARS) {
    throw usageError(`--${name} is longer than ${MAX_BRANCH_CHARS} characters`);
  }
  if (REF_FORBIDDEN.test(v)) throw usageError(`--${name} is not a valid git branch name`);
  return v;
}

function mrId(v: string | undefined): string | undefined {
  if (v !== undefined && !MR_ID.test(v)) {
    throw usageError('--mr must be 1-64 letters, digits, ".", "_" or "-"');
  }
  return v;
}

function parseScan(args: string[]): Command {
  const { values: v } = strict(() =>
    parseArgs({
      args,
      strict: true,
      allowPositionals: false,
      options: {
        config: { type: 'string' },
        'project-key': { type: 'string' },
        sarif: { type: 'string', multiple: true },
        coverage: { type: 'string', multiple: true },
        branch: { type: 'string' },
        mr: { type: 'string' },
        'mr-target': { type: 'string' },
        'no-wait': { type: 'boolean' },
        'dry-run': { type: 'boolean' },
        output: { type: 'string' },
        'token-file': { type: 'string' },
        'server-url': { type: 'string' },
        'ca-file': { type: 'string' },
        'gitlab-code-quality': { type: 'string' },
        'gitlab-sast': { type: 'string' },
        'gitlab-dependency-scanning': { type: 'string' },
      },
    }),
  );
  const flags: ScanFlags = {
    sarif: values('sarif', v.sarif),
    coverage: values('coverage', v.coverage),
    wait: v['no-wait'] !== true,
    dryRun: v['dry-run'] === true,
  };
  const optional = {
    config: value('config', v.config),
    projectKey: value('project-key', v['project-key']),
    branch: branchName('branch', value('branch', v.branch)),
    mr: mrId(value('mr', v.mr)),
    mrTarget: branchName('mr-target', value('mr-target', v['mr-target'])),
    output: value('output', v.output),
    tokenFile: value('token-file', v['token-file']),
    serverUrl: value('server-url', v['server-url']),
    caFile: value('ca-file', v['ca-file']),
    gitlabCodeQuality: value('gitlab-code-quality', v['gitlab-code-quality']),
    gitlabSast: value('gitlab-sast', v['gitlab-sast']),
    gitlabDependencyScanning: value('gitlab-dependency-scanning', v['gitlab-dependency-scanning']),
  };
  for (const [key, val] of Object.entries(optional)) {
    if (val !== undefined) Object.assign(flags, { [key]: val });
  }
  if ((flags.mr === undefined) !== (flags.mrTarget === undefined)) {
    throw usageError('--mr and --mr-target must be given together');
  }
  if (flags.dryRun && flags.output === undefined) throw usageError('--dry-run needs --output FILE');
  if (!flags.dryRun && flags.output !== undefined) {
    throw usageError('--output is only valid with --dry-run');
  }
  return { name: 'scan', flags };
}

/** import-sonarqube.md §3: a SonarQube Cloud organisation key. */
const SONAR_ORG = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$/;
// eslint-disable-next-line no-control-regex -- control characters are what is refused
const PROJECT_KEY = /^[^\u0000-\u001f\u007f]{1,400}$/;
const MAX_PROJECTS = 1000;
/** data-model.md `organizations.key`: a slug (no control character, safe anywhere in a URL). */
const QUALOR_ORG = /^[a-z0-9][a-z0-9-]{1,63}$/;
// eslint-disable-next-line no-control-regex -- control characters are what is refused
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

function oneOf<T extends string>(
  name: string,
  v: string | undefined,
  allowed: readonly T[],
  fallback: T,
): T {
  if (v === undefined) return fallback;
  if (!(allowed as readonly string[]).includes(v)) {
    throw usageError(`--${name} must be one of ${allowed.join(', ')}`);
  }
  return v as T;
}

function integer(
  name: string,
  v: string | undefined,
  min: number,
  max: number,
  fallback: number,
): number {
  if (v === undefined) return fallback;
  if (!/^\d{1,9}$/.test(v) || Number(v) < min || Number(v) > max) {
    throw usageError(`--${name} must be a whole number from ${min} to ${max}`);
  }
  return Number(v);
}

/** A relative directory with `/` separators and no empty, `.` or `..` part; a trailing `/` dropped. */
function relativeDir(name: string, v: string | undefined): string | undefined {
  if (v === undefined) return v;
  if (CONTROL.test(v)) throw usageError(`--${name} must not contain control characters`);
  const parts = v.replace(/\/+$/, '').split('/');
  if (
    v.startsWith('/') ||
    v.includes('\\') ||
    /^[A-Za-z]:/.test(v) ||
    parts.some((p) => p === '' || p === '.' || p === '..')
  ) {
    throw usageError(`--${name} must be a relative directory without . or .. segments`);
  }
  return parts.join('/');
}

function parseImport(args: string[]): Command {
  const [source, ...rest] = args;
  if (source !== 'sonarqube') throw usageError('qualor import supports one source: sonarqube');
  const { values: v } = strict(() => {
    try {
      return parseArgs({
        args: rest,
        strict: true,
        allowPositionals: false,
        options: {
          url: { type: 'string' },
          token: { type: 'string' },
          'token-file': { type: 'string' },
          organization: { type: 'string' },
          'sonar-kind': { type: 'string' },
          'qualor-organization': { type: 'string' },
          project: { type: 'string', multiple: true },
          only: { type: 'string' },
          'path-prefix': { type: 'string' },
          'create-projects': { type: 'boolean' },
          'set-defaults': { type: 'boolean' },
          overwrite: { type: 'boolean' },
          'dry-run': { type: 'boolean' },
          output: { type: 'string' },
          'server-url': { type: 'string' },
          'qualor-token-file': { type: 'string' },
          'ca-file': { type: 'string' },
          'sonar-ca-file': { type: 'string' },
          'sonar-auth': { type: 'string' },
          timeout: { type: 'string' },
          'max-issues': { type: 'string' },
          'allow-insecure-http': { type: 'boolean' },
        },
      });
    } catch (err) {
      // parseArgs quotes a stray argument, which may be a token pasted in the wrong place (§14),
      // so the original error is dropped rather than kept as a cause.
      if (
        err instanceof Error &&
        'code' in err &&
        err.code === 'ERR_PARSE_ARGS_UNEXPECTED_POSITIONAL'
      ) {
        // eslint-disable-next-line preserve-caught-error -- its message would carry the token
        throw new Error('qualor import sonarqube takes no positional arguments (not shown here)');
      }
      throw err;
    }
  });
  const url = value('url', v.url);
  if (url === undefined) throw usageError('qualor import sonarqube needs --url');
  if (v.token !== undefined && v['token-file'] !== undefined) {
    throw usageError('give the SonarQube token once: --token or --token-file, not both');
  }
  const only = v.only === undefined ? [...IMPORT_STEPS] : v.only.split(',').map((s) => s.trim());
  if (only.length === 0 || only.some((s) => !(IMPORT_STEPS as readonly string[]).includes(s))) {
    throw usageError(`--only takes a comma-separated subset of ${IMPORT_STEPS.join(',')}`);
  }
  const projects = values('project', v.project);
  if (projects.length > MAX_PROJECTS || projects.some((p) => !PROJECT_KEY.test(p))) {
    throw usageError('--project takes at most 1 000 project keys of 1-400 printable characters');
  }
  const organization = value('organization', v.organization);
  if (organization !== undefined && !SONAR_ORG.test(organization)) {
    throw usageError('--organization must be a SonarQube Cloud organisation key');
  }
  const qualorOrganization = value('qualor-organization', v['qualor-organization']);
  if (qualorOrganization !== undefined && !QUALOR_ORG.test(qualorOrganization)) {
    throw usageError(
      '--qualor-organization must be a Qualor organisation key (2-64 lower-case letters, digits or "-")',
    );
  }
  const flags: ImportFlags = {
    url,
    sonarKind: oneOf('sonar-kind', v['sonar-kind'], ['auto', 'server', 'cloud'] as const, 'auto'),
    projects: [...new Set(projects)],
    only: IMPORT_STEPS.filter((s) => only.includes(s)),
    createProjects: v['create-projects'] === true,
    setDefaults: v['set-defaults'] === true,
    overwrite: v.overwrite === true,
    dryRun: v['dry-run'] === true,
    sonarAuth: oneOf('sonar-auth', v['sonar-auth'], ['auto', 'bearer', 'basic'] as const, 'auto'),
    timeoutSeconds: integer('timeout', v.timeout, 1, 600, 30),
    maxIssues: integer('max-issues', v['max-issues'], 1, 1_000_000, 100_000),
    allowInsecureHttp: v['allow-insecure-http'] === true,
  };
  // The token's value is never part of a message (import-sonarqube.md §14).
  const optional = {
    token: value('token', v.token),
    tokenFile: value('token-file', v['token-file']),
    organization,
    qualorOrganization,
    pathPrefix: relativeDir('path-prefix', value('path-prefix', v['path-prefix'])),
    output: value('output', v.output),
    serverUrl: value('server-url', v['server-url']),
    qualorTokenFile: value('qualor-token-file', v['qualor-token-file']),
    caFile: value('ca-file', v['ca-file']),
    sonarCaFile: value('sonar-ca-file', v['sonar-ca-file']),
  };
  for (const [key, val] of Object.entries(optional)) {
    if (val !== undefined) Object.assign(flags, { [key]: val });
  }
  return { name: 'import-sonarqube', flags };
}

export function parseCommandLine(argv: readonly string[]): Command {
  const [name, ...rest] = argv;
  if (name === undefined || name === 'help' || name === '--help' || name === '-h') {
    return { name: 'help' };
  }
  if (name === 'version' || name === '--version') {
    strict(() => parseArgs({ args: rest, strict: true, allowPositionals: false, options: {} }));
    return { name: 'version' };
  }
  if (name === 'validate') {
    const { values: v } = strict(() =>
      parseArgs({
        args: rest,
        strict: true,
        allowPositionals: false,
        options: { config: { type: 'string' } },
      }),
    );
    const config = value('config', v.config);
    return config === undefined ? { name: 'validate' } : { name: 'validate', config };
  }
  if (name === 'scan') return parseScan(rest);
  if (name === 'import') return parseImport(rest);
  if (name === 'dotnet') {
    const [sub, ...args] = rest;
    if (sub === 'begin') {
      const { values: v } = strict(() =>
        parseArgs({
          args,
          strict: true,
          allowPositionals: false,
          options: { config: { type: 'string' } },
        }),
      );
      const config = value('config', v.config);
      return config === undefined ? { name: 'dotnet-begin' } : { name: 'dotnet-begin', config };
    }
    if (sub === 'end') {
      const scan = parseScan(args);
      if (scan.name !== 'scan')
        throw new Error('internal error: parseScan returned another command');
      return { name: 'dotnet-end', flags: scan.flags };
    }
    if (sub === 'abort') {
      // config.md §6.1: abort reads no configuration; --config is accepted so a job can pass
      // begin's arguments unchanged, and is ignored.
      const { values: v } = strict(() =>
        parseArgs({
          args,
          strict: true,
          allowPositionals: false,
          options: { config: { type: 'string' } },
        }),
      );
      value('config', v.config);
      return { name: 'dotnet-abort' };
    }
    throw usageError('qualor dotnet needs begin, end or abort (see https://qualor.dev/docs/cli)');
  }
  throw usageError(`unknown command ${JSON.stringify(name)}`);
}
