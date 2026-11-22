import { createHash, createPrivateKey, X509Certificate, type KeyObject } from 'node:crypto';
import { MIN_RSA_BITS } from '../github/app-auth';

/** Azure DevOps design §7.1: the certificate and its key, in one PEM text of at most 16 KiB. */
export const MAX_AZURE_CERTIFICATE_BYTES = 16 * 1024;

export type AzureCertificateProblem =
  | 'too_large'
  | 'no_certificate'
  | 'no_key'
  | 'encrypted'
  | 'not_rsa'
  | 'too_short'
  | 'mismatch'
  | 'expired';

/** The 422 texts of `body.certificate`. */
export const AZURE_CERTIFICATE_PROBLEM_TEXT: Record<AzureCertificateProblem, string> = {
  too_large: 'The certificate and key are larger than 16 KiB',
  no_certificate: 'Add the certificate as a PEM block (BEGIN CERTIFICATE)',
  no_key: 'Add the private key as one unencrypted PEM block (BEGIN PRIVATE KEY)',
  encrypted: 'Use the private key without a password',
  not_rsa: 'The certificate must have an RSA key',
  too_short: 'The key must be an RSA key of at least 2048 bits',
  mismatch: 'The private key does not belong to the certificate',
  expired: 'The certificate has expired',
};

const CERTIFICATE_BLOCK =
  /^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----$/gm;
const KEY_BLOCK =
  /^-----BEGIN (RSA )?PRIVATE KEY-----\n[A-Za-z0-9+/=\n]+\n-----END \1PRIVATE KEY-----$/gm;
/** Only the header lines say so; the base64 key material may spell anything. */
const ENCRYPTED = /^(?:-----BEGIN ENCRYPTED PRIVATE KEY-----|Proc-Type: 4,ENCRYPTED)$/m;

function certificates(text: string): X509Certificate[] {
  const found: X509Certificate[] = [];
  for (const [block] of text.matchAll(CERTIFICATE_BLOCK)) {
    try {
      found.push(new X509Certificate(block));
    } catch {
      // Not a certificate: the others may still be.
    }
  }
  return found;
}

function privateKey(text: string): KeyObject | null {
  const blocks = [...text.matchAll(KEY_BLOCK)].map(([block]) => block);
  const [block] = blocks;
  if (blocks.length !== 1 || block === undefined) return null;
  try {
    return createPrivateKey({ key: block, format: 'pem' });
  } catch {
    return null;
  }
}

/**
 * Azure DevOps design §7.1: the certificate a service principal signs its client assertions
 * with, and the private key, from one PEM text (as `openssl pkcs12 -nodes` writes it: other lines
 * around the blocks are ignored; line ends and the white space around lines do not matter). The
 * key is one unencrypted `PRIVATE KEY` (PKCS#8) or `RSA PRIVATE KEY` (PKCS#1) block, RSA of at
 * least 2048 bits; of the certificates (a chain may come along) the one of that key is taken, and
 * it must not have expired at `now`. The thumbprint is the certificate's SHA-1 in upper-case hex
 * without separators, as Entra and the Azure portal show it. Never returns or logs the input.
 */
export function parseAzureCertificate(
  pem: string,
  now: () => number = Date.now,
):
  | { certificatePem: string; key: KeyObject; thumbprintSha1: string; notAfter: Date }
  | { problem: AzureCertificateProblem } {
  if (Buffer.byteLength(pem, 'utf8') > MAX_AZURE_CERTIFICATE_BYTES) return { problem: 'too_large' };
  const text = pem
    .split(/\r\n?|\n/)
    .map((line) => line.trim())
    .join('\n');
  if (ENCRYPTED.test(text)) return { problem: 'encrypted' };
  const found = certificates(text);
  if (found.length === 0) return { problem: 'no_certificate' };
  const key = privateKey(text);
  if (key === null) return { problem: 'no_key' };
  if (key.asymmetricKeyType !== 'rsa') return { problem: 'not_rsa' };
  if ((key.asymmetricKeyDetails?.modulusLength ?? 0) < MIN_RSA_BITS) {
    return { problem: 'too_short' };
  }
  const certificate = found.find((candidate) => candidate.checkPrivateKey(key));
  if (certificate === undefined) return { problem: 'mismatch' };
  const notAfter = certificate.validToDate;
  if (notAfter.getTime() < now()) return { problem: 'expired' };
  return {
    certificatePem: certificate.toString(),
    key,
    thumbprintSha1: createHash('sha1').update(certificate.raw).digest('hex').toUpperCase(),
    notAfter,
  };
}

/** A certificate {@link parseAzureCertificate} accepted. */
export type ParsedCertificate = Exclude<
  ReturnType<typeof parseAzureCertificate>,
  { problem: unknown }
>;
