import { BlockList, isIP } from 'node:net';
import { hostOf, isNonPublicAddress, MAX_WEBHOOK_URL_LENGTH } from '../webhooks/url';

/** scm.md §2.1: at most this many entries in `QUALOR_SCM_INTERNAL_HOSTS`. */
export const MAX_INTERNAL_HOSTS = 50;

/**
 * A host as `QUALOR_SCM_INTERNAL_HOSTS` lists it and as it is compared: lower case, no dot at the
 * end.
 */
export function normalHost(host: string): string {
  return host
    .trim()
    .toLowerCase()
    .replace(/\.$/, '')
    .replace(/^\[(.*)\]$/, '$1');
}

/**
 * An entry's host as a URL's host would read it (WHATWG): IPv4 in dotted decimal whatever its
 * spelling (`127.1`, `0x7f.0.0.1`), IPv6 in its canonical form. Null when it is not a bare host.
 */
function canonicalHost(host: string): string | null {
  if (!/^[a-z0-9.:_-]{1,253}$/.test(host) || host.includes('..') || host.startsWith('.')) {
    return null;
  }
  let url: URL;
  try {
    url = new URL(`http://${host.includes(':') ? `[${host}]` : host}/`);
  } catch {
    return null;
  }
  if (url.port !== '' || url.pathname !== '/' || url.username !== '' || url.password !== '') {
    return null;
  }
  const canonical = normalHost(hostOf(url));
  return canonical === '' ? null : canonical;
}

/**
 * The key a host and port are listed and compared under: the host alone for the scheme's default
 * port, else `host:port` (`[v6]:port` for IPv6).
 */
function hostKey(host: string, port: string | null): string {
  if (port === null) return host;
  return host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`;
}

/** One entry: `host`, `host:port`, an IPv6 literal (`::1`) or `[v6]:port`. Null when invalid. */
function parseEntry(entry: string): string | null {
  const text = entry.trim().toLowerCase();
  let host: string;
  let port: string | null = null;
  const bracketed = /^\[([^\]]*)\](?::([0-9]{1,5}))?$/.exec(text);
  if (bracketed) {
    host = bracketed[1] ?? '';
    if (isIP(host) !== 6) return null;
    port = bracketed[2] ?? null;
  } else if ((text.match(/:/g) ?? []).length >= 2) {
    host = text;
    if (isIP(host) !== 6) return null;
  } else {
    const withPort = /^([^:]*):([0-9]{1,5})$/.exec(text);
    if (text.includes(':') && !withPort) return null;
    host = withPort ? (withPort[1] ?? '') : text;
    port = withPort ? (withPort[2] ?? null) : null;
  }
  const canonical = canonicalHost(host.replace(/\.$/, ''));
  if (canonical === null) return null;
  if (port !== null) {
    const n = Number(port);
    if (!Number.isInteger(n) || n < 1 || n > 65_535) return null;
    port = String(n);
  }
  return hostKey(canonical, port);
}

/**
 * `QUALOR_SCM_INTERNAL_HOSTS` (scm.md §2.1): comma-separated host names or IP literals, each
 * optionally with a port (`gitlab.corp:8443`, `[fd00::5]:8443`); exact and case-insensitive (no
 * wildcard, no CIDR). An entry without a port allows only the scheme's default port (443 for https,
 * 80 for http); an entry with a port allows only that port. Hosts are normalised as a URL's host
 * is, so a listed address matches every spelling of that address and nothing else. Throws a
 * message naming the bad entry.
 */
export function parseInternalHosts(raw: string | undefined): ReadonlySet<string> {
  const hosts = new Set<string>();
  for (const entry of (raw ?? '').split(',')) {
    if (entry.trim() === '') continue;
    const key = parseEntry(entry);
    if (key === null) {
      throw new Error(`"${entry.trim().slice(0, 60)}" is not a host name or IP address`);
    }
    hosts.add(key);
  }
  if (hosts.size > MAX_INTERNAL_HOSTS) {
    throw new Error(`at most ${MAX_INTERNAL_HOSTS} hosts`);
  }
  return hosts;
}

/**
 * True when the URL's host and port are listed in `QUALOR_SCM_INTERNAL_HOSTS`: the host with the
 * URL's port, or, for the scheme's default port, the host alone.
 */
export function isInternalHostAllowed(url: URL, internalHosts: ReadonlySet<string>): boolean {
  const host = normalHost(hostOf(url));
  if (url.port !== '') return internalHosts.has(hostKey(host, url.port));
  const defaultPort = url.protocol === 'http:' ? '80' : '443';
  return internalHosts.has(host) || internalHosts.has(hostKey(host, defaultPort));
}

/**
 * IPv4 networks that are never a GitLab: link-local (AWS/GCP/Azure metadata 169.254.169.254 is in
 * it) and the other clouds' metadata addresses.
 */
const NEVER_SCM_V4: readonly (readonly [string, number])[] = [
  ['169.254.0.0', 16],
  ['100.100.100.200', 32], // Alibaba Cloud metadata
  ['192.0.0.192', 32], // Oracle Cloud metadata
];

/**
 * The IPv6 networks that carry an IPv4 network, in every layout a resolver may answer with:
 * IPv4-compatible (`::a.b.c.d`), IPv4-translated (`::ffff:0:a.b.c.d`), well-known and local-use
 * NAT64 (RFC 6052, RFC 8215: `64:ff9b::/96`, `64:ff9b:1::/96`, and the local-use `/48` layout
 * with its reserved octet), and 6to4 (`2002:a.b.c.d::/48`). IPv4-mapped (`::ffff:a.b.c.d`) needs
 * none: BlockList matches it with the IPv4 rule.
 */
function embedded(v4: string, prefix: number): (readonly [string, number])[] {
  const [a = 0, b = 0, c = 0, d = 0] = v4.split('.').map(Number);
  const high = ((a << 8) | b).toString(16);
  const low = ((c << 8) | d).toString(16);
  const tail = `${high}:${low}`;
  return [
    [`::${tail}`, 96 + prefix],
    [`::ffff:0:${tail}`, 96 + prefix],
    [`64:ff9b::${tail}`, 96 + prefix],
    [`64:ff9b:1::${tail}`, 96 + prefix],
    // /48 layout: bits 48-63 the first half, 64-71 the reserved octet, 72-87 the second half.
    [
      `64:ff9b:1:${high}:${c.toString(16)}:${(d << 8).toString(16)}::`,
      prefix <= 16 ? 48 + prefix : 64 + 8 + (prefix - 16),
    ],
    [`2002:${tail}::`, 16 + prefix],
  ];
}

/** Link-local and cloud metadata addresses: never a GitLab, even for a listed host. */
const NEVER_SCM = new BlockList();
for (const [network, prefix] of NEVER_SCM_V4) {
  NEVER_SCM.addSubnet(network, prefix, 'ipv4');
  for (const [v6, v6Prefix] of embedded(network, prefix)) NEVER_SCM.addSubnet(v6, v6Prefix, 'ipv6');
}
for (const [network, prefix] of [
  ['fe80::', 10], // link-local
  ['fd00:ec2::254', 128], // AWS metadata (IPv6)
  ['fd20:ce::254', 128], // GCP metadata (IPv6)
] as const) {
  NEVER_SCM.addSubnet(network, prefix, 'ipv6');
}

/** Loopback (and "this host", which connects locally): only for a listed loopback host. */
const LOOPBACK = new BlockList();
for (const [network, prefix, family] of [
  ['127.0.0.0', 8, 'ipv4'],
  ['0.0.0.0', 8, 'ipv4'],
  ['::1', 128, 'ipv6'],
  ['::', 128, 'ipv6'],
  ['64:ff9b::7f00:0', 104, 'ipv6'], // NAT64 of 127.0.0.0/8
] as const) {
  LOOPBACK.addSubnet(network, prefix, family);
}

function inList(list: BlockList, address: string): boolean {
  const family = isIP(address);
  if (family === 0) return true;
  // An IPv4 rule also matches the IPv4-mapped IPv6 form (`::ffff:169.254.169.254`).
  return list.check(address, family === 4 ? 'ipv4' : 'ipv6');
}

/** The URL's host is `localhost` (or `*.localhost`) or a loopback IP literal. */
export function isLoopbackHost(url: URL): boolean {
  const host = normalHost(hostOf(url));
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  return isIP(host) !== 0 && inList(LOOPBACK, host);
}

/**
 * scm.md §2.1, defence in depth for listed hosts: the addresses a request to this base URL may
 * never use, whatever `QUALOR_SCM_INTERNAL_HOSTS` says. Link-local and cloud metadata addresses
 * always; loopback unless the listed host is itself loopback (`localhost`, `127.0.0.1`, `::1`), so
 * a listed name that resolves to 127.0.0.1 cannot reach the server's own ports.
 */
export function scmRefusedAddress(baseUrl: URL): (address: string) => boolean {
  const loopbackAllowed = isLoopbackHost(baseUrl);
  return (address) => inList(NEVER_SCM, address) || (!loopbackAllowed && inList(LOOPBACK, address));
}

export interface BaseUrlNames {
  /** The environment variable that lists internal hosts. */
  variable: string;
  /** What the credential is called, as in "use the token". */
  credential: string;
}

/**
 * scm.md §2.1 (and llm.md §4, with its own list and names): the problem with a base URL, or null.
 * `https`, or `http` only for a listed internal host; no credentials, query or fragment; at most 2 048 characters normalised;
 * `localhost` and literal non-public addresses only when listed (with the URL's port); link-local
 * and metadata literals never. Host names are resolved only at request time, where every address
 * is checked (http/outbound.ts).
 */
export function baseUrlProblem(
  raw: string,
  internalHosts: ReadonlySet<string>,
  names: BaseUrlNames,
): string | null {
  if (raw.length > MAX_WEBHOOK_URL_LENGTH) return 'The URL is too long';
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return 'Not a valid URL';
  }
  if (url.href.length > MAX_WEBHOOK_URL_LENGTH) return 'The URL is too long';
  const internal = isInternalHostAllowed(url, internalHosts);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && internal)) {
    return `Use an https URL (http only for a host in ${names.variable})`;
  }
  if (url.username !== '' || url.password !== '') {
    return `The URL must not contain credentials; use ${names.credential}`;
  }
  if (url.search !== '' || raw.includes('?')) return 'The URL must not contain a query';
  if (url.hash !== '' || raw.includes('#')) return 'The URL must not contain a fragment';
  const host = normalHost(hostOf(url));
  if (isIP(host) !== 0 && inList(NEVER_SCM, host)) {
    return 'The URL points at a link-local or cloud metadata address';
  }
  if (internal) return null;
  if (host === 'localhost' || host.endsWith('.localhost')) {
    return `The URL points at this machine; list the host in ${names.variable}`;
  }
  if (isIP(host) !== 0 && isNonPublicAddress(host)) {
    return `The URL points at a non-public address; list the host in ${names.variable}`;
  }
  return null;
}

/** scm.md §2.1: the problem with an SCM connection's base URL, or null. */
export function scmBaseUrlProblem(raw: string, internalHosts: ReadonlySet<string>): string | null {
  return baseUrlProblem(raw, internalHosts, {
    variable: 'QUALOR_SCM_INTERNAL_HOSTS',
    credential: 'the token',
  });
}

/** The stored form of a base URL: normalised, without a trailing slash. */
export function normalBaseUrl(raw: string): string {
  return new URL(raw).href.replace(/\/+$/, '');
}
