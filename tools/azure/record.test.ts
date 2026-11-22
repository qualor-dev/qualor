import { describe, expect, it } from 'vitest';
import {
  isPublicGuid,
  isSyntheticGuid,
  LISTED_KINDS,
  redact,
  syntheticGuid,
  syntheticIds,
  withSyntheticIds,
  type RedactionTable,
} from './record.js';

/** The tests' own salt; the probe takes the operator's from AZURE_PROBE_ID_SALT. */
const SALT = 'test-salt';

const table: RedactionTable = {
  idSalt: SALT,
  secrets: ['s3cr3t-value'],
  emails: ['jane@corp.example'],
  names: ['Jane Doe'],
  tenantIds: ['11111111-2222-3333-4444-555555555555'],
  hosts: ['ado.corp.example'],
  orgs: ['acme-secret-org'],
};

describe('redact', () => {
  it('removes listed secrets, e-mails, names, tenant ids, hosts and organisation names everywhere, including inside URLs', () => {
    const input = {
      url: 'https://ado.corp.example/acme-secret-org/_apis/x?token=s3cr3t-value',
      who: { mail: 'jane@corp.example', displayName: 'Jane Doe' },
      list: ['tenant 11111111-2222-3333-4444-555555555555 done'],
    };
    const out = JSON.stringify(redact(input, table));
    for (const v of LISTED_KINDS.flatMap((k) => table[k])) expect(out).not.toContain(v);
    expect(out).toContain('https://ado.example.invalid/probe-org/_apis/x?token=<secret>');
    expect(out).toContain('user@example.invalid');
    expect(out).toContain('Probe User');
    expect(out).toContain('00000000-0000-0000-0000-00000000000t');
  });

  it('removes unlisted JWTs and PATs', () => {
    const jwt = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl';
    const pat = `${'a'.repeat(76)}AZDO${'b'.repeat(4)}`;
    expect(pat).toHaveLength(84);
    const out = JSON.stringify(redact({ h: `Bearer ${jwt}`, p: pat }, table));
    expect(out).not.toContain('eyJ');
    expect(out).not.toContain('AZDO');
    expect(out).toContain('<secret>');
  });

  it('removes long session-token PATs but keeps git SHAs', () => {
    const long = 'Ab1'.repeat(286) + 'Zz';
    const sha = 'a3f5c9d1e2b4a6c8d0e1f2a3b4c5d6e7f8091a2b';
    const out = JSON.stringify(redact({ t: long, sha }, table));
    expect(out).not.toContain('Ab1Ab1Ab1');
    expect(out).toContain(sha);
  });

  it('removes a 64-hex run, keeps a 40-hex SHA, and makes a GUID synthetic', () => {
    const hex64 = '0123456789abcdef'.repeat(4);
    const sha = 'a3f5c9d1e2b4a6c8d0e1f2a3b4c5d6e7f8091a2b';
    const guid = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
    const out = JSON.stringify(redact({ hex64, sha, guid }, table));
    expect(out).not.toContain(hex64);
    expect(out).toContain(sha);
    expect(out).not.toContain(guid);
    expect(out).toContain(syntheticGuid(guid, SALT));
  });

  it('maps GUIDs and keeps numbers and booleans', () => {
    const guid = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
    expect(redact({ id: guid, n: 42, ok: true, z: null }, table)).toEqual({
      id: syntheticGuid(guid, SALT),
      n: 42,
      ok: true,
      z: null,
    });
  });
});

describe('synthetic ids', () => {
  const real = '3a7c19e2-5b4d-4f60-9e81-2c6d0b7a4f15'; // invented
  const other = 'b81f04c6-d2e9-4a37-8c5b-7e90f1a3d264'; // invented
  const GUID = /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g;

  it('gives the same synthetic GUID for the same real one, a different one for another', () => {
    expect(syntheticGuid(real, SALT)).toBe(syntheticGuid(real, SALT));
    expect(syntheticGuid(real.toUpperCase(), SALT)).toBe(syntheticGuid(real, SALT).toUpperCase());
    expect(syntheticGuid(real, SALT)).not.toBe(syntheticGuid(other, SALT));
    expect(syntheticGuid(real, SALT)).not.toBe(real);
    expect(isSyntheticGuid(syntheticGuid(real, SALT))).toBe(true);
    expect(syntheticGuid(real, SALT)).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-8[0-9a-f]{3}-fa6e0000[0-9a-f]{4}$/,
    );
  });

  it('depends on the salt, and refuses an empty one', () => {
    expect(syntheticGuid(real, 'another-salt')).not.toBe(syntheticGuid(real, SALT));
    expect(isSyntheticGuid(syntheticGuid(real, 'another-salt'))).toBe(true);
    expect(() => syntheticGuid(real, '')).toThrow(/salt/);
  });

  it('leaves GUIDs as they are when the table has no salt', () => {
    const unsalted: RedactionTable = { ...table };
    delete unsalted.idSalt;
    expect(redact({ id: real }, unsalted)).toEqual({ id: real });
  });

  it('keeps Microsoft constants', () => {
    for (const c of [
      '00000000-0000-0000-0000-000000000000',
      '499b84ac-1321-427f-aa17-267ca6975798',
      '2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87',
      'cbdc66da-9728-4af8-aada-9a5a32e4a226',
      '0609b952-1397-4640-95ec-e00a01b2c241',
      'fa4e907d-c16b-4a4c-9dfa-4906e5d171dd',
      '00000002-0000-8888-8000-000000000000',
      '000007f5-0000-8888-8000-000000000000',
    ]) {
      expect(syntheticIds(`id ${c}.`, SALT), c).toBe(`id ${c}.`);
      expect(isPublicGuid(c.toUpperCase())).toBe(true);
    }
  });

  it('re-encodes a descriptor with the mapped GUID', () => {
    const descriptor = `aadsp.${Buffer.from(real).toString('base64url')}`;
    const out = syntheticIds(`MemberAvatars/${descriptor}?x=1`, SALT);
    const m = /aadsp\.([A-Za-z0-9_-]+)\?x=1$/.exec(out);
    expect(m).not.toBeNull();
    expect(Buffer.from(m?.[1] ?? '', 'base64url').toString('utf8')).toBe(syntheticGuid(real, SALT));
    expect(syntheticIds(out, SALT)).toBe(out);
  });

  it('leaves descriptors without a GUID, and ordinary words, alone', () => {
    const text = 'win.<sid> aad.bm90IGEgZ3VpZA ad.example.invalid load.ts';
    expect(syntheticIds(text, SALT)).toBe(text);
  });

  it('leaves no real GUID of a sample, in any form, and is idempotent', () => {
    const sample = {
      url: `https://spsprodneu1.vssps.visualstudio.com/A${real}/_apis/Identities/${other}`,
      lower: `a${real}`,
      artifact: `vstfs:///Git/PullRequestId/${other}%2f${real}%2f13`,
      upper: `repository ${real.toUpperCase()} does not exist`,
      n: real.replace(/-/g, ''),
      uniqueName: `00000002-0000-8888-8000-000000000000@${other}`,
      descriptor: `aad.${Buffer.from(other).toString('base64url')}`,
      [`key ${other}`]: 1,
      sha: 'a3f5c9d1e2b4a6c8d0e1f2a3b4c5d6e7f8091a2b',
    };
    const out = withSyntheticIds(sample, SALT);
    const text = JSON.stringify(out);
    for (const g of [real, other]) {
      expect(text.toLowerCase()).not.toContain(g);
      expect(text.toLowerCase()).not.toContain(g.replace(/-/g, ''));
      expect(text).not.toContain(Buffer.from(g).toString('base64url'));
    }
    for (const m of text.matchAll(GUID)) {
      const g = m[0];
      expect(isPublicGuid(g) || isSyntheticGuid(g), g).toBe(true);
    }
    expect(text).toContain(`/A${syntheticGuid(real, SALT)}/`);
    expect(text).toContain(`%2f${syntheticGuid(real, SALT)}%2f13`);
    expect(text).toContain(syntheticGuid(real, SALT).toUpperCase());
    expect(text).toContain(syntheticGuid(real, SALT).replace(/-/g, ''));
    expect(text).toContain(`00000002-0000-8888-8000-000000000000@${syntheticGuid(other, SALT)}`);
    expect(text).toContain('a3f5c9d1e2b4a6c8d0e1f2a3b4c5d6e7f8091a2b');
    expect(withSyntheticIds(out, SALT)).toEqual(out);
  });

  it('keeps the tenant placeholder, which is not a GUID', () => {
    const out = JSON.stringify(
      redact({ t: 'tenant 11111111-2222-3333-4444-555555555555\\x' }, table),
    );
    expect(out).toContain('00000000-0000-0000-0000-00000000000t');
  });
});

describe('redact: machine values no table lists', () => {
  it('replaces private IPv4 addresses, AWS and Windows host names, and Windows SIDs', () => {
    const input = {
      a: 'from 10.1.2.3 and 172.31.9.9 and 192.168.0.9',
      b: 'Agent machine name: ip-172-31-5-6.eu-north-1.compute.internal',
      c: 'EC2AMAZ-TEST123\\probe-user and ec2amaz-abc123',
      d: 'System.Security.Principal.WindowsIdentity;S-1-5-21-1111111111-222222222-3333333333-1003',
      e: 'win.Uy0xLTUtMjEtMTExMTExMTExMS0x',
    };
    const out = JSON.stringify(redact(input, table));
    for (const v of [
      '10.1.2.3',
      '172.31.9.9',
      '192.168.0.9',
      'ip-172-31-5-6',
      'TEST123',
      'abc123',
    ]) {
      expect(out, v).not.toContain(v);
    }
    expect(out).not.toContain('1111111111');
    expect(out).toContain('S-1-5-21-0-0-0-1003');
    expect(out).not.toContain('Uy0xLTUtMjEt');
    expect(out).toContain('192.0.2.1');
    expect(out).toContain('agent.example.invalid');
  });

  it('keeps versions, public addresses and plain words', () => {
    const input = { v: 'Server 20.0.37104.1 agent 4.264.2', ip: '8.8.8.8', w: 'ship-it 10.5' };
    expect(redact(input, table)).toEqual(input);
  });
});
