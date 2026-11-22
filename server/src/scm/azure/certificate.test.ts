import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  X509Certificate,
} from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { TEST_IDP, TEST_SP } from '../../../test/saml';
import { TEST_SERVER_CERT_PEM, TEST_SERVER_KEY_PEM } from '../../../test/tls';
import { selfSignedRsaCertificate } from '../../../test/x509';
import {
  AZURE_CERTIFICATE_PROBLEM_TEXT,
  MAX_AZURE_CERTIFICATE_BYTES,
  parseAzureCertificate,
  type AzureCertificateProblem,
} from './certificate';

// The SAML tests' committed RSA 2048 pair (openssl, valid until 2126), allowlisted in .gitleaks.toml.
const CERT = TEST_IDP.certPem;
const KEY = createPrivateKey(TEST_IDP.keyPem);
const PKCS8 = KEY.export({ type: 'pkcs8', format: 'pem' }).toString();
const PKCS1 = KEY.export({ type: 'pkcs1', format: 'pem' }).toString();
const IDP = new X509Certificate(CERT);
/** How Entra and the Azure portal show a certificate's thumbprint: SHA-1, upper-case hex. */
const THUMBPRINT = IDP.fingerprint.replaceAll(':', '');

const problemOf = (pem: string, now?: () => number): AzureCertificateProblem | null => {
  const parsed = now === undefined ? parseAzureCertificate(pem) : parseAzureCertificate(pem, now);
  return 'problem' in parsed ? parsed.problem : null;
};

const parsed = (pem: string) => {
  const result = parseAzureCertificate(pem);
  if ('problem' in result) throw new Error(`refused: ${result.problem}`);
  return result;
};

describe('parseAzureCertificate (Azure DevOps design §7.1)', () => {
  it('accepts a certificate and its PKCS#8 key, with the thumbprint and expiry Entra shows', () => {
    const result = parsed(`${CERT}${PKCS8}`);
    expect(result.thumbprintSha1).toBe(THUMBPRINT);
    expect(result.thumbprintSha1).toMatch(/^[0-9A-F]{40}$/);
    expect(result.notAfter).toEqual(IDP.validToDate);
    expect(new X509Certificate(result.certificatePem).raw.equals(IDP.raw)).toBe(true);
    expect(result.certificatePem).toMatch(
      /^-----BEGIN CERTIFICATE-----\n[\s\S]+\n-----END CERTIFICATE-----\n$/,
    );
    expect(result.key.type).toBe('private');
    expect(createPublicKey(result.key).export({ type: 'spki', format: 'der' })).toEqual(
      IDP.publicKey.export({ type: 'spki', format: 'der' }),
    );
  });

  it('accepts a PKCS#1 key (RSA PRIVATE KEY), the key first, CRLF line ends and white space', () => {
    expect(parsed(`${PKCS1}${CERT}`).thumbprintSha1).toBe(THUMBPRINT);
    const windows = `\r\n  ${CERT}${PKCS8}  \r\n`.replaceAll('\n', '\r\n');
    expect(parsed(windows).thumbprintSha1).toBe(THUMBPRINT);
  });

  it('accepts what openssl pkcs12 -nodes writes: attribute lines around the blocks', () => {
    const exported = [
      'Bag Attributes',
      '    localKeyID: 01 00 00 00',
      'subject=CN = qualor-test-idp',
      'issuer=CN = qualor-test-idp',
      CERT.trim(),
      'Bag Attributes',
      '    localKeyID: 01 00 00 00',
      'Key Attributes: <No Attributes>',
      PKCS8.trim(),
      '',
    ].join('\n');
    expect(parsed(exported).thumbprintSha1).toBe(THUMBPRINT);
  });

  it('picks the certificate of the key when the text also holds another one (a chain)', () => {
    const result = parsed(`${TEST_SP.certPem}${CERT}${PKCS8}`);
    expect(result.thumbprintSha1).toBe(THUMBPRINT);
    expect(new X509Certificate(result.certificatePem).raw.equals(IDP.raw)).toBe(true);
  });

  it('refuses a text over 16 KiB before reading it, and accepts one of exactly 16 KiB', () => {
    expect(MAX_AZURE_CERTIFICATE_BYTES).toBe(16 * 1024);
    const pair = `${CERT}${PKCS8}`;
    const filler = (bytes: number) => '#'.repeat(bytes - Buffer.byteLength(pair));
    expect(problemOf(`${pair}${filler(MAX_AZURE_CERTIFICATE_BYTES)}`)).toBeNull();
    expect(problemOf(`${pair}${filler(MAX_AZURE_CERTIFICATE_BYTES + 1)}`)).toBe('too_large');
    // Bytes, not characters: '€' is three bytes in UTF-8.
    const euros = Math.floor((MAX_AZURE_CERTIFICATE_BYTES - Buffer.byteLength(pair)) / 3) + 1;
    const wide = `${pair}${'€'.repeat(euros)}`;
    expect(wide.length).toBeLessThan(MAX_AZURE_CERTIFICATE_BYTES);
    expect(problemOf(wide)).toBe('too_large');
    expect(problemOf('x'.repeat(MAX_AZURE_CERTIFICATE_BYTES + 1))).toBe('too_large');
  });

  it('refuses a text without a certificate, or whose certificate block is not one', () => {
    expect(problemOf(PKCS8)).toBe('no_certificate');
    expect(problemOf('')).toBe('no_certificate');
    const broken = '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n';
    expect(problemOf(`${broken}${PKCS8}`)).toBe('no_certificate');
  });

  it('refuses a text without a key, with a key that is not one, or with two keys', () => {
    expect(problemOf(CERT)).toBe('no_key');
    const broken = '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n';
    expect(problemOf(`${CERT}${broken}`)).toBe('no_key');
    expect(problemOf(`${CERT}${PKCS8}${PKCS1}`)).toBe('no_key');
    // A public key is no private key.
    const spki = IDP.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    expect(problemOf(`${CERT}${spki}`)).toBe('no_key');
  });

  it('refuses an encrypted key, PKCS#8 or PKCS#1 with a Proc-Type header', () => {
    const options = { cipher: 'aes-256-cbc', passphrase: 'not-a-secret' } as const;
    const pkcs8 = KEY.export({ type: 'pkcs8', format: 'pem', ...options }).toString();
    const pkcs1 = KEY.export({ type: 'pkcs1', format: 'pem', ...options }).toString();
    expect(pkcs8).toContain('ENCRYPTED PRIVATE KEY');
    expect(pkcs1).toContain('Proc-Type: 4,ENCRYPTED');
    expect(problemOf(`${CERT}${pkcs8}`)).toBe('encrypted');
    expect(problemOf(`${CERT}${pkcs1}`)).toBe('encrypted');
  });

  it('refuses a certificate whose key is not RSA (the EC P-256 pair of the test server)', () => {
    expect(problemOf(`${TEST_SERVER_CERT_PEM}${TEST_SERVER_KEY_PEM}`)).toBe('not_rsa');
  });

  it('refuses an RSA key under 2048 bits (a 1024-bit certificate and its key)', () => {
    const short = generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey;
    const certificate = selfSignedRsaCertificate(short);
    expect(new X509Certificate(certificate).checkPrivateKey(short)).toBe(true);
    const pem = `${certificate}${short.export({ type: 'pkcs8', format: 'pem' }).toString()}`;
    expect(problemOf(pem)).toBe('too_short');
  });

  it('accepts a 2048-bit certificate made the same way (the size alone decides)', () => {
    const key = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
    const pem = `${selfSignedRsaCertificate(key)}${key.export({ type: 'pkcs8', format: 'pem' }).toString()}`;
    expect(problemOf(pem)).toBeNull();
  });

  it('refuses a key that does not belong to the certificate', () => {
    const other = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
    expect(problemOf(`${CERT}${other.export({ type: 'pkcs8', format: 'pem' }).toString()}`)).toBe(
      'mismatch',
    );
  });

  it('refuses a certificate whose notAfter has passed; valid up to that instant', () => {
    const notAfter = IDP.validToDate.getTime();
    expect(problemOf(`${CERT}${PKCS8}`, () => notAfter)).toBeNull();
    expect(problemOf(`${CERT}${PKCS8}`, () => notAfter + 1)).toBe('expired');
  });

  it('never puts the key text into its answer', () => {
    const answer = parseAzureCertificate(`${CERT}${PKCS8}`);
    const body = PKCS8.split('\n')[1]!;
    expect(JSON.stringify(answer)).not.toContain(body);
    expect(JSON.stringify(parseAzureCertificate(`${CERT}${PKCS8}`, () => Infinity))).toBe(
      '{"problem":"expired"}',
    );
  });

  it('has a text for every problem', () => {
    const problems: AzureCertificateProblem[] = [
      'too_large',
      'no_certificate',
      'no_key',
      'encrypted',
      'not_rsa',
      'too_short',
      'mismatch',
      'expired',
    ];
    expect(Object.keys(AZURE_CERTIFICATE_PROBLEM_TEXT).sort()).toEqual([...problems].sort());
    for (const problem of problems) {
      expect(AZURE_CERTIFICATE_PROBLEM_TEXT[problem]).toMatch(/^[A-Z][^\n]{10,120}[^.]$/);
    }
  });
});
