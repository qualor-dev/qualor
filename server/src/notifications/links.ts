import type { Config } from '../config';
import type { RenderedMail } from '../mail/payload';
import type { NotifyLinks } from '../mail/templates/notify-common';
import { instanceHost, publicLink } from '../mail/templates/text';
import type { VulnerabilityMailLinks } from '../mail/templates/notify-vulnerability-common';
import { unsubscribeHeaders, unsubscribeToken, vulnerabilityUnsubscribeToken } from './unsubscribe';

export type WatchLinks = NotifyLinks & { token: string };

/** The links of one watcher's message about one project, and the token behind its stop link. */
export function watchLinks(
  config: Pick<Config, 'publicUrl' | 'secretKey'>,
  userId: string,
  projectId: string,
): WatchLinks {
  const token = unsubscribeToken(config.secretKey, userId, projectId);
  return {
    publicUrl: config.publicUrl,
    instanceHost: instanceHost(config.publicUrl),
    token,
    unsubscribeUrl: publicLink(config.publicUrl, `/unsubscribe#t=${token}`),
    settingsUrl: publicLink(config.publicUrl, '/settings/notifications'),
  };
}

/** The path of the one-click stop of the vulnerability emails (its own, not the project one). */
export const VULNERABILITY_UNSUBSCRIBE_API = '/api/v0/notifications/unsubscribe/vulnerabilities';

/**
 * The links of one watcher's vulnerability email: it is about several projects, so the stop link
 * stops the vulnerability emails of all of them (4b), on its own UI page.
 */
export function vulnerabilityMailLinks(
  config: Pick<Config, 'publicUrl' | 'secretKey'>,
  userId: string,
): VulnerabilityMailLinks & { token: string } {
  const token = vulnerabilityUnsubscribeToken(config.secretKey, userId);
  return {
    publicUrl: config.publicUrl,
    instanceHost: instanceHost(config.publicUrl),
    token,
    unsubscribeUrl: publicLink(config.publicUrl, `/unsubscribe/vulnerabilities#t=${token}`),
    settingsUrl: publicLink(config.publicUrl, '/settings/notifications'),
  };
}

/**
 * The message with RFC 8058 headers, when there is a public URL for them to point at. `path` is
 * the one-click endpoint (the project one unless given).
 */
export function withUnsubscribe(
  mail: RenderedMail,
  publicUrl: string | null,
  token: string,
  path?: string,
): RenderedMail {
  const headers = unsubscribeHeaders(publicUrl, token, path);
  return headers ? { ...mail, headers } : mail;
}
