import { describe, expect, it } from 'vitest';
import {
  isInternalHostAllowed,
  normalBaseUrl,
  parseInternalHosts,
  scmBaseUrlProblem,
  scmRefusedAddress,
} from './url';

describe('SCM base URLs (scm.md §2.1)', () => {
  const none = new Set<string>();
  const internal = parseInternalHosts('gitlab.corp.internal, 10.1.2.3,[::1],LOCALHOST.,[::1]:8443');

  it('parses QUALOR_SCM_INTERNAL_HOSTS: exact hosts, lower case, brackets and final dot removed', () => {
    expect([...internal]).toEqual([
      'gitlab.corp.internal',
      '10.1.2.3',
      '::1',
      'localhost',
      '[::1]:8443',
    ]);
    expect(parseInternalHosts(undefined).size).toBe(0);
    expect(parseInternalHosts(' , ').size).toBe(0);
    expect(() => parseInternalHosts('*.corp')).toThrow(/is not a host name/);
    expect(() => parseInternalHosts('host:8080/x')).toThrow(/is not a host name/);
    expect(() =>
      parseInternalHosts(Array.from({ length: 51 }, (_, i) => `h${i}.corp`).join(',')),
    ).toThrow(/at most 50/);
  });

  it('accepts a public https URL, with a path, and stores it without a trailing slash', () => {
    expect(scmBaseUrlProblem('https://gitlab.example.com', none)).toBeNull();
    expect(scmBaseUrlProblem('https://example.com/gitlab/', none)).toBeNull();
    expect(normalBaseUrl('https://GitLab.Example.com/gitlab/')).toBe(
      'https://gitlab.example.com/gitlab',
    );
    expect(normalBaseUrl('https://gitlab.example.com')).toBe('https://gitlab.example.com');
  });

  it('refuses http, credentials, queries, fragments and garbage', () => {
    expect(scmBaseUrlProblem('http://gitlab.example.com', none)).toMatch(/https/);
    expect(scmBaseUrlProblem('https://u:p@gitlab.example.com', none)).toMatch(/credentials/);
    expect(scmBaseUrlProblem('https://gitlab.example.com/?x=1', none)).toMatch(/query/);
    expect(scmBaseUrlProblem('https://gitlab.example.com/?', none)).toMatch(/query/);
    expect(scmBaseUrlProblem('https://gitlab.example.com/#x', none)).toMatch(/fragment/);
    expect(scmBaseUrlProblem('gitlab', none)).toBe('Not a valid URL');
    expect(scmBaseUrlProblem(`https://example.com/${'a'.repeat(2_048)}`, none)).toMatch(/long/);
  });

  it('refuses localhost and non-public literals unless the operator listed the host', () => {
    expect(scmBaseUrlProblem('https://localhost', none)).toMatch(/QUALOR_SCM_INTERNAL_HOSTS/);
    expect(scmBaseUrlProblem('https://127.0.0.1', none)).toMatch(/non-public/);
    expect(scmBaseUrlProblem('https://2130706433', none)).toMatch(/non-public/);
    expect(scmBaseUrlProblem('https://[::1]', none)).toMatch(/non-public/);
    expect(scmBaseUrlProblem('https://10.1.2.3', none)).toMatch(/non-public/);
    expect(scmBaseUrlProblem('https://10.1.2.3', internal)).toBeNull();
    expect(scmBaseUrlProblem('https://[::1]:8443', internal)).toBeNull();
    expect(scmBaseUrlProblem('http://gitlab.corp.internal', internal)).toBeNull();
    expect(scmBaseUrlProblem('http://GITLAB.corp.internal.', internal)).toBeNull();
    // Listing a host does not allow credentials or queries.
    expect(scmBaseUrlProblem('http://u@gitlab.corp.internal', internal)).toMatch(/credentials/);
  });
});

describe('QUALOR_SCM_INTERNAL_HOSTS allows exactly the listed hosts (scm.md §2.1)', () => {
  const internal = parseInternalHosts('gitlab.corp.internal,10.1.2.3,::1');
  const allowed = (raw: string) => isInternalHostAllowed(new URL(raw), internal);

  it('matches a listed name exactly, in any case and with a final dot, and nothing around it', () => {
    expect(allowed('https://gitlab.corp.internal/x')).toBe(true);
    expect(allowed('https://GitLab.CORP.internal.')).toBe(true);
    expect(allowed('https://GitLab.CORP.internal.:8443')).toBe(false);
    expect(allowed('https://evil.gitlab.corp.internal')).toBe(false);
    expect(allowed('https://gitlab.corp.internal.evil.example')).toBe(false);
    expect(allowed('https://corp.internal')).toBe(false);
    expect(allowed('https://gitlab-corp.internal')).toBe(false);
    expect(allowed('https://gitlab.corp.internal@evil.example')).toBe(false);
    // An unlisted name may still resolve to an internal address: it is saved (only literals can be
    // judged here) and refused at request time by the resolved-address check (gitlab/client.test.ts).
    expect(scmBaseUrlProblem('https://other.corp.internal', internal)).toBeNull();
    expect(scmBaseUrlProblem('http://other.corp.internal', internal)).toMatch(/https/);
  });

  it('matches IP literals by address, whatever their spelling, and no other address', () => {
    expect(allowed('https://10.1.2.3')).toBe(true);
    expect(allowed('https://0x0a.1.2.3')).toBe(true);
    expect(allowed('https://167838211')).toBe(true);
    expect(allowed('https://10.1.2.4')).toBe(false);
    expect(allowed('https://[0:0:0:0:0:0:0:1]')).toBe(true);
    expect(allowed('https://[::ffff:10.1.2.3]')).toBe(false);
    expect(allowed('https://127.0.0.1')).toBe(false);
    // An entry is normalised like a URL's host, so another spelling of a listed address matches.
    expect([...parseInternalHosts('127.1,[0:0::1],::FFFF:7F00:1')]).toEqual([
      '127.0.0.1',
      '::1',
      '::ffff:7f00:1',
    ]);
  });

  it('refuses wildcards, ports, CIDR ranges, paths, URLs and empty labels as entries', () => {
    for (const bad of [
      '*',
      '*.corp',
      '.corp',
      'a..corp',
      'host:0',
      'host:65536',
      'host:',
      'host:80:80',
      '[gitlab.corp]:8443',
      '[::1]8443',
      '10.0.0.0/8',
      'https://gitlab.corp',
      'a b',
      'user@host',
    ]) {
      expect(() => parseInternalHosts(bad), bad).toThrow(/is not a host name/);
    }
  });
});

describe('QUALOR_SCM_INTERNAL_HOSTS and ports (scm.md §2.1)', () => {
  it("allows only the scheme's default port for an entry without one", () => {
    const hosts = parseInternalHosts('gitlab.corp,10.0.0.5');
    const allowed = (raw: string) => isInternalHostAllowed(new URL(raw), hosts);
    expect(allowed('https://gitlab.corp')).toBe(true);
    expect(allowed('https://gitlab.corp:443/x')).toBe(true);
    expect(allowed('http://gitlab.corp')).toBe(true);
    expect(allowed('http://gitlab.corp:80')).toBe(true);
    for (const raw of [
      'https://gitlab.corp:8443',
      'https://gitlab.corp:22',
      'http://gitlab.corp:443',
      'https://gitlab.corp:80',
      'http://10.0.0.5:5432',
      'https://10.0.0.5:6379',
    ]) {
      expect(allowed(raw), raw).toBe(false);
    }
    // So the save refuses them like any unlisted internal address, and the test endpoint cannot
    // be used to probe other ports of a listed host.
    expect(scmBaseUrlProblem('https://10.0.0.5:22', hosts)).toMatch(/non-public/);
    expect(scmBaseUrlProblem('http://gitlab.corp:8080', hosts)).toMatch(/https/);
  });

  it('allows only the named port for an entry with one', () => {
    const hosts = parseInternalHosts('GitLab.Corp.:8443,[FD00::5]:08443,127.0.0.1:3000');
    expect([...hosts]).toEqual(['gitlab.corp:8443', '[fd00::5]:8443', '127.0.0.1:3000']);
    const allowed = (raw: string) => isInternalHostAllowed(new URL(raw), hosts);
    expect(allowed('https://gitlab.corp:8443')).toBe(true);
    expect(allowed('http://gitlab.corp.:8443')).toBe(true);
    expect(allowed('https://[fd00::5]:8443')).toBe(true);
    expect(allowed('http://127.0.0.1:3000')).toBe(true);
    expect(allowed('https://gitlab.corp')).toBe(false);
    expect(allowed('https://gitlab.corp:8444')).toBe(false);
    expect(allowed('https://[fd00::5]')).toBe(false);
    expect(allowed('http://127.0.0.1:3001')).toBe(false);
    expect(allowed('http://127.0.0.1')).toBe(false);
    // An IPv6 literal with a port must be bracketed: unbracketed, the "port" is part of the address.
    const unbracketed = parseInternalHosts('fd00::5:8443');
    expect([...unbracketed]).toEqual(['fd00::5:8443']);
    expect(isInternalHostAllowed(new URL('https://[fd00::5]:8443'), unbracketed)).toBe(false);
    // A default port named explicitly allows that port, which is the default one.
    const https = parseInternalHosts('gitlab.corp:443');
    expect(isInternalHostAllowed(new URL('https://gitlab.corp'), https)).toBe(true);
    expect(isInternalHostAllowed(new URL('http://gitlab.corp'), https)).toBe(false);
  });
});

describe('addresses refused even for a listed host (scm.md §2.1)', () => {
  it('never allows link-local or cloud metadata addresses, as a literal or once resolved', () => {
    const hosts = parseInternalHosts('169.254.169.254,[fd00:ec2::254],gitlab.corp');
    expect(scmBaseUrlProblem('http://169.254.169.254', hosts)).toMatch(/metadata/);
    expect(scmBaseUrlProblem('http://[fd00:ec2::254]', hosts)).toMatch(/metadata/);
    const refused = scmRefusedAddress(new URL('https://gitlab.corp'));
    for (const address of [
      '169.254.169.254',
      '169.254.0.1',
      '::ffff:169.254.169.254',
      '::ffff:a9fe:a9fe',
      '64:ff9b::a9fe:a9fe',
      'fe80::1',
      'fd00:ec2::254',
      'fd20:ce::254',
      '100.100.100.200',
      '192.0.0.192',
      // IPv4 embedded in IPv6 in every other way a resolver may answer: IPv4-compatible,
      // IPv4-translated (SIIT), local-use NAT64 (RFC 8215, /96 and /48 layouts) and 6to4.
      '::a9fe:a9fe',
      '::ffff:0:a9fe:a9fe',
      '64:ff9b:1::a9fe:a9fe',
      '64:ff9b:1:a9fe:a9:fe00::',
      '2002:a9fe:a9fe::1',
      '::6464:64c8',
      '64:ff9b::6464:64c8',
      '2002:6464:64c8::',
      '64:ff9b:1:c000:0:c000::',
      '::ffff:0:c000:c0',
    ]) {
      expect(refused(address), address).toBe(true);
    }
    expect(scmBaseUrlProblem('https://[2002:a9fe:a9fe::1]', hosts)).toMatch(/metadata/);
    // Only the embedded metadata and link-local networks, not their neighbours.
    for (const address of [
      '2002:a9ff::1',
      '64:ff9b:1::a9ff:1',
      '::ffff:0:a9ff:1',
      '2002:c0a8:1::',
    ]) {
      expect(refused(address), address).toBe(false);
    }
    expect(refused('10.0.0.5')).toBe(false);
    expect(refused('192.168.1.2')).toBe(false);
    expect(refused('fd00::5')).toBe(false);
  });

  it('allows loopback only when the listed host is itself loopback', () => {
    const byName = scmRefusedAddress(new URL('https://gitlab.corp'));
    for (const address of ['127.0.0.1', '127.8.9.1', '::1', '::ffff:127.0.0.1', '0.0.0.0', '::']) {
      expect(byName(address), address).toBe(true);
    }
    for (const base of ['http://localhost:8080', 'http://127.0.0.1:3000', 'http://[::1]:8443']) {
      const loopback = scmRefusedAddress(new URL(base));
      expect(loopback('127.0.0.1'), base).toBe(false);
      expect(loopback('::1'), base).toBe(false);
      expect(loopback('169.254.169.254'), base).toBe(true);
    }
  });
});
