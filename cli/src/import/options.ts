import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import path from 'node:path';
import type { ImportFlags } from '../args';
import { CliError, EXIT } from '../errors';
import type { Logger } from '../log';
import { readCaFile, type ServerEndpoint } from '../server/http';
import { detectSonarKind } from './sonarqube/client';

/** import-sonarqube.md §4.2: 1–512 characters of %x21-7E, so the token fits a header. */
const TOKEN_CHARS = /^[\x21-\x7e]{1,512}$/;
const MAX_TOKEN_FILE = 4096;
/** U+FEFF, which Windows editors write at the start of a UTF-8 file. */
const LEADING_BOM = new RegExp(`^${String.fromCharCode(0xfeff)}`);
/** §3: `localhost`, `127.0.0.0/8` and `[::1]` may use http (ruling S9). */
const LOOPBACK = /^(?:localhost|\[::1\]|127(?:\.\d{1,3}){3})$/;

type Warning = { code: 'TOKEN_ON_COMMAND_LINE' | 'INSECURE_URL'; message: string };

export interface ImportSetup {
  sonar: {
    url: string;
    token: string;
    /** Resolved from `auto` by the `--url` host; never `auto` once resolved here. */
    kind: 'auto' | 'server' | 'cloud';
    organization: string | null;
    auth: 'auto' | 'bearer' | 'basic';
    timeoutMs: number;
    ca?: string;
  };
  qualor: ServerEndpoint;
  warnings: Warning[];
}

/**
 * A regular file of at most 4 KiB, a leading BOM and surrounding white space removed (ruling
 * SQ15). Neither the content nor the path is part of an error message.
 */
export function readTokenFile(file: string, flag: string): string {
  let fd: number | undefined;
  try {
    // O_NONBLOCK: opening a FIFO for reading must not wait for a writer (not defined on Windows).
    fd = openSync(file, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
    const stat = fstatSync(fd);
    if (!stat.isFile()) throw new CliError(EXIT.USAGE, `${flag} must name a regular file`);
    if (stat.size > MAX_TOKEN_FILE) throw new CliError(EXIT.USAGE, `${flag} is larger than 4 KiB`);
    const buf = Buffer.alloc(stat.size);
    let read = 0;
    while (read < buf.length) {
      const n = readSync(fd, buf, read, buf.length - read, null);
      if (n === 0) break;
      read += n;
    }
    return buf.subarray(0, read).toString('utf8').replace(LEADING_BOM, '').trim();
  } catch (err) {
    if (err instanceof CliError) throw err;
    const code =
      err instanceof Error && 'code' in err && typeof err.code === 'string'
        ? err.code
        : 'unreadable';
    throw new CliError(EXIT.USAGE, `cannot read ${flag}: ${code}`);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/** A variable that is unset, empty or only white space counts as unset (as for `qualor scan`). */
function nonEmpty(v: string | undefined): string | undefined {
  return v === undefined || v.trim() === '' ? undefined : v;
}

/** A token from the environment, surrounding white space removed (as `qualor scan` does). */
function envToken(v: string | undefined): string | undefined {
  return nonEmpty(v)?.trim();
}

/**
 * A token file's content; an empty one names the flag, not the path, which may itself be a
 * token pasted in the wrong place.
 */
function fileToken(file: string, flag: string, cwd: string): string {
  const token = readTokenFile(path.resolve(cwd, file), flag);
  if (token === '') throw new CliError(EXIT.USAGE, `the file given as ${flag} is empty`);
  return token;
}

/** The token is never part of the message (§14). */
function checkToken(token: string | undefined, what: string, hint: string): string {
  if (token === undefined || token === '') throw new CliError(EXIT.USAGE, `no ${what}: ${hint}`);
  if (!TOKEN_CHARS.test(token)) {
    throw new CliError(
      EXIT.USAGE,
      `the ${what} contains spaces or characters that cannot be sent in an HTTP header, or is over 512 characters`,
    );
  }
  return token;
}

/**
 * §3: http or https, no user name, password, query or fragment; the URL is never echoed. Plain
 * http to a host other than loopback would carry a token in cleartext: refused unless
 * `--allow-insecure-http`, which turns it into a warning (ruling S9).
 */
function checkUrl(flag: string, raw: string, allowHttp: boolean, warnings: Warning[]): string {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new CliError(EXIT.USAGE, `${flag} is not a valid URL`);
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') {
    throw new CliError(EXIT.USAGE, `${flag} must be an http or https URL`);
  }
  if (u.username !== '' || u.password !== '') {
    throw new CliError(EXIT.USAGE, `${flag} must not contain a user name or password`);
  }
  if (u.search !== '' || u.hash !== '' || raw.includes('?') || raw.includes('#')) {
    throw new CliError(EXIT.USAGE, `${flag} must not contain a query or a fragment`);
  }
  if (u.protocol === 'http:' && !LOOPBACK.test(u.hostname)) {
    if (!allowHttp) {
      throw new CliError(
        EXIT.USAGE,
        `${flag} uses http, so the token would travel unencrypted to ${u.host}; use https, or pass --allow-insecure-http to accept that`,
      );
    }
    warnings.push({
      code: 'INSECURE_URL',
      message: `${flag} uses http, so the token travels unencrypted to ${u.host}; use https`,
    });
  }
  return raw;
}

/** `readCaFile` names `server.caFile`; here the message names the flag given. */
function caFile(file: string, flag: string, cwd: string): string {
  try {
    return readCaFile(path.resolve(cwd, file), file);
  } catch (err) {
    if (err instanceof CliError) {
      throw new CliError(err.exitCode, err.message.replace('server.caFile', flag));
    }
    throw err;
  }
}

/**
 * import-sonarqube.md §3, §4.1, §14: both servers' addresses and tokens, checked before any
 * request. Warnings are logged once here and returned for the report; none carries a token.
 */
export function resolveImportSetup(
  flags: ImportFlags,
  env: Readonly<Record<string, string | undefined>>,
  cwd: string,
  log: Logger,
): ImportSetup {
  const warnings: Warning[] = [];
  const url = checkUrl('--url', flags.url, flags.allowInsecureHttp, warnings);
  const kind = flags.sonarKind === 'auto' ? detectSonarKind(url) : flags.sonarKind;
  const organization = flags.organization ?? null;
  if (kind === 'cloud' && organization === null) {
    throw new CliError(
      EXIT.USAGE,
      'SonarQube Cloud needs --organization (the organisation key); a SonarQube Server behind this address needs --sonar-kind server',
    );
  }
  if (kind === 'server' && organization !== null) {
    throw new CliError(
      EXIT.USAGE,
      '--organization is only for SonarQube Cloud; SonarQube Server has no organisations (a proxy in front of Cloud needs --sonar-kind cloud)',
    );
  }
  if (flags.token !== undefined) {
    warnings.push({
      code: 'TOKEN_ON_COMMAND_LINE',
      message:
        'a token on the command line is visible in the process list and shell history; prefer SONAR_TOKEN or --token-file',
    });
  }
  const sonarToken = checkToken(
    flags.token ??
      (flags.tokenFile !== undefined
        ? fileToken(flags.tokenFile, '--token-file', cwd)
        : envToken(env['SONAR_TOKEN'])),
    'SonarQube token',
    'set SONAR_TOKEN, or pass --token-file',
  );
  const serverUrl = flags.serverUrl ?? nonEmpty(env['QUALOR_URL'])?.trim();
  if (serverUrl === undefined) {
    throw new CliError(EXIT.USAGE, 'no Qualor server: set QUALOR_URL or pass --server-url');
  }
  const qualorUrl = checkUrl('--server-url', serverUrl, flags.allowInsecureHttp, warnings);
  const qualorToken = checkToken(
    flags.qualorTokenFile !== undefined
      ? fileToken(flags.qualorTokenFile, '--qualor-token-file', cwd)
      : envToken(env['QUALOR_TOKEN']),
    'Qualor token',
    'set QUALOR_TOKEN (a personal token with the admin scope), or pass --qualor-token-file',
  );
  if (sonarToken === qualorToken) {
    throw new CliError(
      EXIT.USAGE,
      'the SonarQube token and the Qualor token are the same token; each server needs its own',
    );
  }
  const qualorCaFile = flags.caFile ?? nonEmpty(env['QUALOR_CA_FILE']);
  const qualorCa = qualorCaFile === undefined ? undefined : caFile(qualorCaFile, '--ca-file', cwd);
  const sonarCa =
    flags.sonarCaFile === undefined ? undefined : caFile(flags.sonarCaFile, '--sonar-ca-file', cwd);
  for (const w of warnings) log.warn(w.message);
  return {
    sonar: {
      url,
      token: sonarToken,
      kind,
      organization,
      auth: flags.sonarAuth,
      timeoutMs: flags.timeoutSeconds * 1000,
      ...(sonarCa !== undefined && { ca: sonarCa }),
    },
    qualor: {
      url: qualorUrl,
      token: qualorToken,
      timeoutMs: flags.timeoutSeconds * 1000,
      ...(qualorCa !== undefined && { ca: qualorCa }),
    },
    warnings,
  };
}
