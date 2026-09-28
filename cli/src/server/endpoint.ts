import path from 'node:path';
import { isInside } from '../analyzers/binary';
import { shown } from '../analyzers/reason';
import type { Settings } from '../config/settings';
import { CliError, EXIT } from '../errors';
import type { Logger } from '../log';
import { readCaFile, type ServerEndpoint } from './http';

const Q_B9_MESSAGE =
  'server.url comes only from qualor.yml, which the repository controls, so the token is not sent there; ' +
  'set QUALOR_URL in the CI configuration or pass --server-url';

const V8_MESSAGE =
  'server.caFile comes only from qualor.yml, which the repository controls, so it is not trusted for a request that carries the token; ' +
  'set QUALOR_CA_FILE in the CI configuration or pass --ca-file';

/** What an HTTP header value may hold (RFC 9110 field-vchar, no spaces in a bearer token). */
const TOKEN_CHARS = /^[\x21-\x7e]+$/;
const LOOPBACK_HOSTS = new Set(['localhost', '[::1]']);

function isLoopback(hostname: string): boolean {
  return LOOPBACK_HOSTS.has(hostname) || /^127(?:\.\d{1,3}){3}$/.test(hostname);
}

/**
 * The server URL as the token may be sent to it: `http:` or `https:` (the config schema already
 * checks that), no user name or password (the token is the credential; a URL with one would
 * also carry it into messages), no query and no fragment (they would be dropped silently).
 * The URL itself is never repeated in the message, since it may hold a secret.
 */
function checkedUrl(url: string, log: Logger): URL {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new CliError(EXIT.USAGE, 'server.url is not a valid URL');
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new CliError(EXIT.USAGE, 'server.url must be an http or https URL');
  }
  if (parsed.username !== '' || parsed.password !== '') {
    throw new CliError(
      EXIT.USAGE,
      'server.url must not contain a user name or password; the token (QUALOR_TOKEN or --token-file) authenticates the CLI',
    );
  }
  if (parsed.search !== '' || parsed.hash !== '' || url.includes('?') || url.includes('#')) {
    throw new CliError(EXIT.USAGE, 'server.url must not contain a query or a fragment');
  }
  if (parsed.protocol === 'http:' && !isLoopback(parsed.hostname)) {
    log.warn(`server.url uses http, so the token is sent unencrypted to ${parsed.host}; use https`);
  }
  return parsed;
}

/**
 * The CA file a request that carries the token may trust (ruling V8, the CA side of the token rule): only
 * one from `--ca-file` or `QUALOR_CA_FILE`, i.e. from the CI configuration, read relative to
 * the directory the CLI runs in. One that only `qualor.yml` names is repository-controlled: an
 * upload refuses it (exit 2, before any request, without reading it); `--dry-run` warns and
 * uses the default store.
 */
function trustedCaFile(settings: Settings, o: { upload: boolean; log: Logger }): string | null {
  const { caFile } = settings.config.server;
  if (caFile === null || caFile === '' || settings.caFileSource === null) return null;
  if (settings.caFileSource === 'file') {
    if (o.upload) throw new CliError(EXIT.USAGE, V8_MESSAGE);
    o.log.warn(`${V8_MESSAGE}; the default CA store is used`);
    return null;
  }
  const file = path.resolve(settings.root, caFile);
  // The path comes from the CI, but a file inside the checkout has content the merge request
  // controls (a CI job that points at a committed CA trusts whatever the branch commits).
  if (isInside(settings.root, file)) {
    o.log.warn(
      `the CA file ${shown(caFile)} is inside the repository, so the checkout decides its content; ` +
        'keep a CI-supplied CA file (QUALOR_CA_FILE or --ca-file) outside the checkout',
    );
  }
  return readCaFile(file, caFile);
}

/**
 * The server the token may be sent to, or null when there is none (no URL or no token). The token rule:
 * a URL that only `qualor.yml` names (repo-controlled: a merge request could point it at its own
 * host) never receives the token. An upload refuses with exit 2; `--dry-run` warns and makes no
 * request, so the main-branch baseline is then unknown (`BASELINE_SERVER_NOT_CONFIGURED`).
 * The CA file (ruling V8) is read here, once, for every request (baseline, upload, gate polling).
 */
export function serverEndpoint(
  settings: Settings,
  o: { upload: boolean; log: Logger; env?: Readonly<Record<string, string | undefined>> },
): ServerEndpoint | null {
  const { url, timeoutSeconds } = settings.config.server;
  if (url === undefined || settings.token === null) return null;
  if (settings.serverUrlSource === 'file') {
    if (o.upload) throw new CliError(EXIT.USAGE, Q_B9_MESSAGE);
    o.log.warn(Q_B9_MESSAGE);
    return null;
  }
  const parsed = checkedUrl(url, o.log);
  if (!TOKEN_CHARS.test(settings.token)) {
    throw new CliError(
      EXIT.USAGE,
      'the token contains spaces or characters that cannot be sent in an HTTP header',
    );
  }
  if (parsed.protocol === 'https:' && o.env?.['NODE_TLS_REJECT_UNAUTHORIZED'] === '0') {
    o.log.warn(
      'NODE_TLS_REJECT_UNAUTHORIZED=0 is ignored: the CLI always verifies the server certificate; ' +
        'use QUALOR_CA_FILE or --ca-file for a private CA',
    );
  }
  const ca = trustedCaFile(settings, o);
  return {
    url,
    token: settings.token,
    timeoutMs: timeoutSeconds * 1000,
    ...(ca !== null && { ca }),
  };
}
