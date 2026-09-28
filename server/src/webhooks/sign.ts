import { createHmac } from 'node:crypto';

/**
 * api.md §3 (ruling W2): `X-Qualor-Timestamp` is the Unix time of this attempt in seconds, and
 * `X-Qualor-Signature` is `sha256=` + the hex HMAC-SHA256, keyed with the webhook secret, of
 * `<timestamp>.<raw body>`. Signing the timestamp lets a receiver reject a replayed request by
 * its age without trusting an unsigned header.
 */
export function signatureHeaders(
  secret: string,
  body: string,
  timestampSeconds: number,
): { 'x-qualor-timestamp': string; 'x-qualor-signature': string } {
  const timestamp = String(timestampSeconds);
  const digest = createHmac('sha256', secret).update(`${timestamp}.${body}`, 'utf8').digest('hex');
  return { 'x-qualor-timestamp': timestamp, 'x-qualor-signature': `sha256=${digest}` };
}
