import { z } from 'zod';
import { VERSION } from '../index';
import type { Logger } from '../log';
import { clean, describeFailure, request, type ServerEndpoint } from './http';

const response = z.object({ version: z.string().min(1).max(64) });

/** A tiny JSON object; anything larger is not a Qualor server's answer. */
const MAX_VERSION_RESPONSE_BYTES = 4 * 1024;

/** `0.3` of `0.3.0`, `1.2` of `1.2.0-rc.1`; null for anything that is not a version. */
export function releaseLine(version: string): string | null {
  return /^(\d+\.\d+)\.\d+(?:[-+].*)?$/.exec(version)?.[1] ?? null;
}

/**
 * `GET /api/v0/system/version` when a scan starts: logs the server's version, and warns when it is
 * another release line than this scanner's (the scanner and the server are released together).
 * Informational only: a failure here never fails the scan. An older server without the route, a
 * rejected token or an unreachable server is logged at debug level; the requests that matter
 * (baseline, upload) report those problems themselves.
 */
export async function checkServerVersion(ep: ServerEndpoint, log: Logger): Promise<string | null> {
  let version: string;
  try {
    const res = await request(ep, {
      method: 'GET',
      path: 'api/v0/system/version',
      maxResponseBytes: MAX_VERSION_RESPONSE_BYTES,
    });
    if (res.status !== 200) {
      log.debug(`the server did not report its version (${describeFailure(res)})`);
      return null;
    }
    const parsed = response.safeParse(JSON.parse(res.body));
    if (!parsed.success) {
      log.debug('the server sent an invalid version response');
      return null;
    }
    version = clean(parsed.data.version);
  } catch (err) {
    log.debug(
      `the server did not report its version (${err instanceof Error ? err.message : String(err)})`,
    );
    return null;
  }
  log.info(`server ${new URL(ep.url).origin} runs Qualor ${version}`);
  const ours = releaseLine(VERSION);
  const theirs = releaseLine(version);
  if (ours !== null && theirs !== null && ours !== theirs) {
    log.warn(
      `this scanner is ${VERSION} and the server is ${version}: use the scanner of the server's release (qualor/scanner:${theirs})`,
    );
  }
  return version;
}
