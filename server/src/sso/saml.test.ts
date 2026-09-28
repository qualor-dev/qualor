import { describe, expect, it } from 'vitest';
import { SAML_CONFIG } from './connection-config';
import { jsonbTextBytes, parseSamlForm, samlClaims } from './saml';

const NUL = String.fromCharCode(0);
const LONE = String.fromCharCode(0xd800);
const cfg = (over: Record<string, unknown> = {}) =>
  SAML_CONFIG.parse({
    idpEntityId: 'https://idp.test/saml',
    idpSsoUrl: 'https://idp.test/sso',
    idpCertificates: ['x'],
    claims: { groups: 'groups' },
    emailVerified: true,
    ...over,
  });

describe('samlClaims (sso-scim.md §6.3, §8.3)', () => {
  it('reads the NameID as subject and username, the attributes, and the email as verified only when the connection says so', () => {
    expect(
      samlClaims(
        { email: 'a@acme.example', displayName: ['Alice'], groups: ['g1', 'g2'] },
        'alice-id',
        cfg(),
      ),
    ).toEqual({
      subject: 'alice-id',
      username: 'alice-id',
      email: 'a@acme.example',
      emailVerified: true,
      displayName: 'Alice',
      groups: ['g1', 'g2'],
      nameId: 'alice-id',
    });
    expect(
      samlClaims({ email: 'a@acme.example' }, 'n', cfg({ emailVerified: false })),
    ).toMatchObject({
      emailVerified: false,
    });
    // No email: never verified.
    expect(samlClaims({}, 'n', cfg())).toMatchObject({ email: null, emailVerified: false });
  });

  it('uses the configured username attribute, and treats multi-valued or blank values as absent', () => {
    const c = cfg({ claims: { username: 'uid', groups: 'groups' } });
    expect(samlClaims({ uid: 'alice' }, 'n', c)).toMatchObject({ username: 'alice', nameId: 'n' });
    expect(samlClaims({}, 'n', c)).toMatchObject({ username: null });
    expect(samlClaims({ uid: ['a', 'b'], email: '   ' }, 'n', c)).toMatchObject({
      username: null,
      email: null,
    });
    expect(samlClaims({ groups: 'one' }, 'n', c)).toMatchObject({ groups: ['one'] });
    expect(samlClaims({}, 'n', c)).toMatchObject({ groups: [] });
  });

  it('refuses groups holding anything but strings (saml.claims), never dropping them quietly', () => {
    const c = cfg({ claims: { groups: 'groups' } });
    for (const groups of [['a', { x: 1 }], { _: 'a', $: {} }, [null], 7]) {
      expect(() => samlClaims({ groups }, 'n', c)).toThrow(
        expect.objectContaining({ code: 'invalid_response', detail: 'saml.claims' }),
      );
    }
  });

  it('reads own attributes only', () => {
    const attrs = Object.create({ email: 'proto@acme.example' }) as Record<string, unknown>;
    expect(samlClaims(attrs, 'n', cfg())).toMatchObject({ email: null });
    expect(
      samlClaims({ constructor: 'x' }, 'n', cfg({ claims: { displayName: 'constructor' } })),
    ).toMatchObject({ displayName: 'x' });
  });

  it('refuses a NameID with NUL, or empty, or over 255 characters (saml.name_id)', () => {
    for (const nameId of [`a${NUL}b`, `a${LONE}`, '', 'n'.repeat(256)]) {
      expect(() => samlClaims({}, nameId, cfg())).toThrow(
        expect.objectContaining({ code: 'invalid_response', detail: 'saml.name_id' }),
      );
    }
  });

  it('refuses an email, username, display name or group PostgreSQL cannot store (saml.claims)', () => {
    const c = cfg({ claims: { username: 'uid', groups: 'groups' } });
    for (const attrs of [
      { email: `a${LONE}@acme.example` },
      { email: [`a${NUL}@acme.example`] },
      { uid: `x${NUL}` },
      { displayName: `D${LONE}` },
      { groups: ['ok', `g${NUL}`] },
    ]) {
      expect(() => samlClaims(attrs, 'n', c)).toThrow(
        expect.objectContaining({ code: 'invalid_response', detail: 'saml.claims' }),
      );
    }
  });

  it('refuses more than 1 000 groups (groups.too_many)', () => {
    const groups = Array.from({ length: 1_001 }, (_, i) => `g${String(i)}`);
    expect(() => samlClaims({ groups }, 'n', cfg())).toThrow(
      expect.objectContaining({ detail: 'groups.too_many' }),
    );
  });
});

describe('jsonbTextBytes', () => {
  it('measures JSON as jsonb prints it: a space after every colon and comma', () => {
    expect(jsonbTextBytes({ a: 'x', b: [true, null, 'y'] })).toBe(
      '{"a": "x", "b": [true, null, "y"]}'.length,
    );
    expect(jsonbTextBytes({})).toBe(2);
    expect(jsonbTextBytes([])).toBe(2);
    expect(jsonbTextBytes({ a: undefined, b: 'x' })).toBe('{"b": "x"}'.length);
    // Escapes and UTF-8 as jsonb writes them.
    expect(jsonbTextBytes('a"b\\c\n' + String.fromCharCode(1) + 'é')).toBe(
      Buffer.byteLength('"a\\"b\\\\c\\n\\u0001é"', 'utf8'),
    );
  });
});

describe('parseSamlForm', () => {
  it('keeps SAMLResponse and RelayState when each appears once', () => {
    expect(parseSamlForm('SAMLResponse=PHg%2B&RelayState=abc&other=1')).toEqual({
      SAMLResponse: 'PHg+',
      RelayState: 'abc',
    });
    expect(parseSamlForm('SAMLResponse=a&SAMLResponse=b&RelayState=r')).toEqual({
      RelayState: 'r',
    });
    expect(parseSamlForm('')).toEqual({});
  });
});
