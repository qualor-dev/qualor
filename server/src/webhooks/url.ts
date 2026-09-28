import { BlockList, isIP } from 'node:net';
import { z } from 'zod';
import type { Executor } from '../db/client';
import { instanceSetting } from '../settings';

/**
 * The `instance_settings` row `webhooks` (ruling W3): `allowHttp` lets webhook URLs use plain
 * `http` (api.md §3), `allowInternalHosts` lets them reach loopback, private, link-local and other
 * non-public addresses. Both default to false; an invalid row is ignored.
 */
export const WEBHOOK_SETTINGS_KEY = 'webhooks';
export interface WebhookSettings {
  allowHttp: boolean;
  allowInternalHosts: boolean;
}
const settingsSchema = z
  .object({ allowHttp: z.boolean(), allowInternalHosts: z.boolean() })
  .partial();

export async function webhookSettings(db: Executor): Promise<WebhookSettings> {
  const value = await instanceSetting(db, WEBHOOK_SETTINGS_KEY, settingsSchema, {});
  return {
    allowHttp: value.allowHttp ?? false,
    allowInternalHosts: value.allowInternalHosts ?? false,
  };
}

/** The IANA IPv4 special-purpose ranges that are not globally reachable, plus multicast. */
const NON_PUBLIC_V4 = new BlockList();
for (const [network, prefix] of [
  ['0.0.0.0', 8], // "this network"
  ['10.0.0.0', 8], // private
  ['100.64.0.0', 10], // shared address space (carrier-grade NAT)
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local, cloud metadata services
  ['172.16.0.0', 12], // private
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.0.2.0', 24], // documentation (TEST-NET-1)
  ['192.88.99.0', 24], // 6to4 relay anycast (deprecated)
  ['192.168.0.0', 16], // private
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // documentation (TEST-NET-2)
  ['203.0.113.0', 24], // documentation (TEST-NET-3)
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved, and the limited broadcast 255.255.255.255
] as const) {
  NON_PUBLIC_V4.addSubnet(network, prefix, 'ipv4');
}

/**
 * Inside 2000::/3 (global unicast), the IANA IPv6 special-purpose ranges that are not globally
 * reachable or that tunnel to an IPv4 address the check could be bypassed through. Everything
 * outside 2000::/3 (loopback, unspecified, IPv4-compatible, discard-only, NAT64 local-use,
 * unique-local fc00::/7, link-local, site-local, multicast, SRv6, unallocated space) is refused
 * by {@link isNonPublicAddress} before this list is consulted.
 */
const NON_PUBLIC_V6_GLOBAL = new BlockList();
for (const [network, prefix] of [
  ['2001::', 23], // IETF protocol assignments, including Teredo 2001::/32 and ORCHID
  ['2001:db8::', 32], // documentation
  ['2002::', 16], // 6to4
  ['3fff::', 20], // documentation (RFC 9637)
] as const) {
  NON_PUBLIC_V6_GLOBAL.addSubnet(network, prefix, 'ipv6');
}

/** The eight 16-bit words of an address `isIP` accepted as IPv6 (no zone id). */
function ipv6Words(address: string): number[] | null {
  let text = address.toLowerCase();
  const lastColon = text.lastIndexOf(':');
  const tail = text.slice(lastColon + 1);
  if (tail.includes('.')) {
    // A trailing dotted IPv4 part (`::ffff:1.2.3.4`) is two words.
    const octets = tail.split('.').map((p) => Number(p));
    if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) {
      return null;
    }
    const [a = 0, b = 0, c = 0, d = 0] = octets;
    text = `${text.slice(0, lastColon + 1)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const words = (part: string | undefined): number[] =>
    part === undefined || part === '' ? [] : part.split(':').map((w) => Number.parseInt(w, 16));
  const head = words(halves[0]);
  const rest = halves.length === 2 ? words(halves[1]) : [];
  const gap = 8 - head.length - rest.length;
  if (gap < 0 || (halves.length === 1 && gap !== 0)) return null;
  const all = [...head, ...Array<number>(gap).fill(0), ...rest];
  return all.every((w) => Number.isInteger(w) && w >= 0 && w <= 0xffff) ? all : null;
}

/**
 * The IPv4 address an IPv6 address stands for, when it is IPv4-mapped (`::ffff:0:0/96`, the
 * socket connects to that IPv4 address) or NAT64 with the well-known prefix (`64:ff9b::/96`, a
 * NAT64 gateway forwards to it); null otherwise.
 */
function embeddedIpv4(words: readonly number[]): string | null {
  const [w0, w1, w2, w3, w4, w5, w6 = 0, w7 = 0] = words;
  const mapped = w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 && w4 === 0 && w5 === 0xffff;
  const nat64 = w0 === 0x64 && w1 === 0xff9b && w2 === 0 && w3 === 0 && w4 === 0 && w5 === 0;
  if (!mapped && !nat64) return null;
  return [w6 >> 8, w6 & 0xff, w7 >> 8, w7 & 0xff].join('.');
}

/**
 * True for an address that is not public unicast, or not an IP address at all (ruling W3). IPv4:
 * the IANA special-purpose ranges. IPv6: only global unicast (2000::/3) outside its special
 * ranges is public; an IPv4-mapped or NAT64 address is judged by the IPv4 address it embeds; an
 * address with a zone id (`fe80::1%eth0`) is never public (zone ids only scope local addresses).
 */
export function isNonPublicAddress(address: string): boolean {
  if (address.includes('%')) return true;
  const family = isIP(address);
  if (family === 4) return NON_PUBLIC_V4.check(address, 'ipv4');
  if (family !== 6) return true;
  const words = ipv6Words(address);
  if (!words) return true;
  const ipv4 = embeddedIpv4(words);
  if (ipv4 !== null) return isNonPublicAddress(ipv4);
  const [first = 0] = words;
  if ((first & 0xe000) !== 0x2000) return true;
  return NON_PUBLIC_V6_GLOBAL.check(address, 'ipv6');
}

/** The URL's host as `net` expects it: IPv6 literals lose their brackets. */
export function hostOf(url: URL): string {
  return url.hostname.startsWith('[') ? url.hostname.slice(1, -1) : url.hostname;
}

export const MAX_WEBHOOK_URL_LENGTH = 2_048;

/**
 * Checks a webhook URL when it is saved and again before every delivery attempt (api.md §3,
 * ruling W3): `https` (or `http` when allowed), no credentials or fragment, and — unless internal
 * hosts are allowed — no literal non-public address and no `localhost`. The WHATWG parser
 * normalises every IPv4 spelling (`2130706433`, `0x7f.1`, `0177.0.0.1`, `127.1`) to dotted
 * decimal and IPv6 to its canonical form, and rejects zone ids, so the literal check sees the
 * address the request would use. Host names are resolved only at delivery time, where every
 * resolved address is checked and the connection pinned to it (webhooks/send.ts), so a DNS change
 * after saving cannot redirect a delivery inside the network.
 */
export function webhookUrlProblem(raw: string, settings: WebhookSettings): string | null {
  if (raw.length > MAX_WEBHOOK_URL_LENGTH) return 'The URL is too long';
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return 'Not a valid URL';
  }
  // The normalised form is what is stored and sent; percent-encoding can make it longer.
  if (url.href.length > MAX_WEBHOOK_URL_LENGTH) return 'The URL is too long';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && settings.allowHttp)) {
    return settings.allowHttp ? 'Use an http or https URL' : 'Use an https URL';
  }
  if (url.username !== '' || url.password !== '') {
    return 'The URL must not contain credentials; use the webhook secret';
  }
  if (url.hash !== '' || raw.includes('#')) return 'The URL must not contain a fragment';
  if (settings.allowInternalHosts) return null;
  const host = hostOf(url).toLowerCase().replace(/\.$/, '');
  if (host === 'localhost' || host.endsWith('.localhost')) {
    return 'The URL points at this machine';
  }
  if (isIP(host) !== 0 && isNonPublicAddress(host)) {
    return 'The URL points at a private, loopback or otherwise non-public address';
  }
  return null;
}
