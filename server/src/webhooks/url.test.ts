import { describe, expect, it } from 'vitest';
import { isNonPublicAddress, webhookUrlProblem } from './url';

const strict = { allowHttp: false, allowInternalHosts: false };

describe('webhook URL checks (ruling W3)', () => {
  it('classifies addresses: public unicast only', () => {
    for (const address of [
      '127.0.0.1',
      '10.1.2.3',
      '172.16.0.1',
      '192.168.1.1',
      '169.254.169.254',
      '100.64.0.1',
      '0.0.0.0',
      '224.0.0.1',
      '255.255.255.255',
      '::1',
      '::',
      'fe80::1',
      'fd00::1',
      '::ffff:127.0.0.1',
      '::ffff:a9fe:a9fe',
      '64:ff9b::a9fe:a9fe',
      '2002:7f00:1::',
      'not-an-ip',
    ]) {
      expect(isNonPublicAddress(address), address).toBe(true);
    }
    for (const address of ['93.184.215.14', '1.1.1.1', '2606:4700:4700::1111']) {
      expect(isNonPublicAddress(address), address).toBe(false);
    }
  });

  it('refuses every IANA special-purpose IPv4 range, at both ends', () => {
    for (const [first, last] of [
      ['0.0.0.0', '0.255.255.255'], // "this network"
      ['10.0.0.0', '10.255.255.255'], // private
      ['100.64.0.0', '100.127.255.255'], // shared address space (CGN)
      ['127.0.0.0', '127.255.255.255'], // loopback
      ['169.254.0.0', '169.254.255.255'], // link-local (cloud metadata)
      ['172.16.0.0', '172.31.255.255'], // private
      ['192.0.0.0', '192.0.0.255'], // IETF protocol assignments
      ['192.0.2.0', '192.0.2.255'], // TEST-NET-1
      ['192.88.99.0', '192.88.99.255'], // 6to4 relay anycast (deprecated)
      ['192.168.0.0', '192.168.255.255'], // private
      ['198.18.0.0', '198.19.255.255'], // benchmarking
      ['198.51.100.0', '198.51.100.255'], // TEST-NET-2
      ['203.0.113.0', '203.0.113.255'], // TEST-NET-3
      ['224.0.0.0', '239.255.255.255'], // multicast
      ['240.0.0.0', '255.255.255.255'], // reserved and limited broadcast
    ]) {
      expect(isNonPublicAddress(first!), first).toBe(true);
      expect(isNonPublicAddress(last!), last).toBe(true);
    }
    // Just outside the ranges.
    for (const address of [
      '1.0.0.0',
      '9.255.255.255',
      '11.0.0.0',
      '100.63.255.255',
      '100.128.0.0',
      '126.255.255.255',
      '128.0.0.0',
      '169.253.255.255',
      '169.255.0.0',
      '172.15.255.255',
      '172.32.0.0',
      '192.167.255.255',
      '192.169.0.0',
      '198.17.255.255',
      '198.20.0.0',
      '223.255.255.255',
    ]) {
      expect(isNonPublicAddress(address), address).toBe(false);
    }
  });

  it('refuses every non-global IPv6 range, and IPv6 that embeds a non-public IPv4 address', () => {
    for (const address of [
      '::', // unspecified
      '::1', // loopback
      '::7f00:1', // IPv4-compatible (deprecated), ::/96
      '::ffff:0:7f00:1', // IPv4-translated (RFC 2765)
      '::ffff:10.0.0.1', // IPv4-mapped, dotted
      '::ffff:a00:1', // IPv4-mapped, hex
      '0:0:0:0:0:ffff:a9fe:a9fe', // IPv4-mapped, uncompressed
      '::ffff:0.0.0.0',
      '64:ff9b::7f00:1', // NAT64 well-known prefix → 127.0.0.1
      '64:ff9b::a00:1', // NAT64 → 10.0.0.1
      '64:ff9b:1::1', // NAT64 local-use
      '100::1', // discard-only
      '2001::1', // Teredo
      '2001:0:4136:e378:8000:63bf:3fff:fdd2', // Teredo
      '2001:2::1', // benchmarking (in 2001::/23)
      '2001:10::1', // ORCHID (in 2001::/23)
      '2001:db8::1', // documentation
      '2002::1', // 6to4
      '2002:c0a8:101::1', // 6to4 of 192.168.1.1
      '3fff::1', // documentation (RFC 9637)
      '5f00::1', // SRv6 SIDs
      'fc00::1', // unique local
      'fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', // unique local
      'fe80::1', // link-local
      'febf:ffff::1', // link-local
      'fec0::1', // site-local (deprecated)
      'ff02::1', // multicast
      '4000::1', // unallocated (outside 2000::/3)
      '1::1', // reserved
      'fe80::1%eth0', // a zone id is only meaningful for a non-global address
      'fe80::1%1',
      '2606:4700:4700::1111%eth0',
      '1.1.1.1%eth0',
    ]) {
      expect(isNonPublicAddress(address), address).toBe(true);
    }
    for (const address of [
      '2001:4860:4860::8888',
      '2a00:1450:4001:80b::200e',
      '2600::',
      '::ffff:1.1.1.1', // IPv4-mapped public address
      '::ffff:5db8:d70e',
      '64:ff9b::101:101', // NAT64 (DNS64) of 1.1.1.1
      '64:ff9b::1.1.1.1',
    ]) {
      expect(isNonPublicAddress(address), address).toBe(false);
    }
  });

  it('accepts a public https URL and refuses http, credentials and fragments', () => {
    expect(webhookUrlProblem('https://hooks.example.com/qualor?x=1', strict)).toBeNull();
    expect(webhookUrlProblem('http://hooks.example.com/', strict)).toBe('Use an https URL');
    expect(webhookUrlProblem('ftp://hooks.example.com/', strict)).toBe('Use an https URL');
    expect(webhookUrlProblem('https://user:pw@hooks.example.com/', strict)).toMatch(/credentials/);
    expect(webhookUrlProblem('https://user@hooks.example.com/', strict)).toMatch(/credentials/);
    expect(webhookUrlProblem('https://hooks.example.com/#x', strict)).toMatch(/fragment/);
    expect(webhookUrlProblem('https://hooks.example.com/#', strict)).toMatch(/fragment/);
    expect(webhookUrlProblem('not a url', strict)).toBe('Not a valid URL');
    expect(webhookUrlProblem(`https://example.com/${'a'.repeat(2_048)}`, strict)).toMatch(/long/);
    // The stored, normalised form is what is bounded: 700 characters that percent-encode to
    // 4 200 are too long, though the raw text is short.
    const encoded = `https://example.com/${'\u00e9'.repeat(700)}`;
    expect(encoded.length).toBeLessThan(2_048);
    expect(webhookUrlProblem(encoded, strict)).toMatch(/long/);
  });

  it('refuses loopback, private and metadata addresses in any spelling', () => {
    for (const url of [
      'https://localhost/',
      'https://LOCALHOST/',
      'https://localhost./',
      'https://api.localhost/',
      'https://api.localhost./',
      'https://127.0.0.1/',
      'https://127.0.0.1./',
      'https://127.1/', // shortened
      'https://2130706433/', // decimal
      'https://0x7f.1/', // hex
      'https://0x7f000001/', // hex, one part
      'https://0177.0.0.1/', // octal
      'https://017700000001/', // octal, one part
      'https://0x7f.0.0.01/', // mixed
      'https://0/', // 0.0.0.0
      'https://[::1]/',
      'https://[0:0:0:0:0:0:0:1]/',
      'https://[::]/',
      'https://[::ffff:169.254.169.254]/',
      'https://[::ffff:a9fe:a9fe]/',
      'https://[::ffff:0:a9fe:a9fe]/',
      'https://[64:ff9b::169.254.169.254]/',
      'https://[fd00:ec2::254]/', // AWS IPv6 metadata
      'https://[fe80::1]/',
      'https://169.254.169.254/latest/meta-data/',
      'https://2852039166/', // 169.254.169.254 in decimal
      'https://10.0.0.5:8443/hook',
    ]) {
      expect(webhookUrlProblem(url, strict), url).not.toBeNull();
    }
    // A zone id is not valid in a URL host at all.
    expect(webhookUrlProblem('https://[fe80::1%25eth0]/', strict)).toBe('Not a valid URL');
  });

  it('accepts public IP literals, whatever their spelling', () => {
    for (const url of [
      'https://1.1.1.1/',
      'https://16843009/', // 1.1.1.1 in decimal
      'https://0x01010101/',
      'https://[2606:4700:4700::1111]/',
      'https://[::ffff:1.1.1.1]/',
    ]) {
      expect(webhookUrlProblem(url, strict), url).toBeNull();
    }
  });

  it('allows http and internal hosts only when the instance settings say so', () => {
    const open = { allowHttp: true, allowInternalHosts: true };
    expect(webhookUrlProblem('http://127.0.0.1:9000/hook', open)).toBeNull();
    expect(webhookUrlProblem('https://localhost/', { ...open, allowHttp: false })).toBeNull();
    expect(
      webhookUrlProblem('http://127.0.0.1:9000/hook', { ...open, allowInternalHosts: false }),
    ).not.toBeNull();
    expect(
      webhookUrlProblem('http://hooks.example.com/', { ...open, allowInternalHosts: false }),
    ).toBeNull();
    // allowHttp never opens other schemes, and allowInternalHosts never allows credentials.
    expect(webhookUrlProblem('ftp://hooks.example.com/', open)).toBe('Use an http or https URL');
    expect(webhookUrlProblem('file:///etc/passwd', open)).toBe('Use an http or https URL');
    expect(webhookUrlProblem('http://u:p@127.0.0.1/', open)).toMatch(/credentials/);
  });
});
