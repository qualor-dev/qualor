import { execFileSync } from 'node:child_process';
import { createPrivateKey, generateKeyPairSync } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { REPO_ROOT } from '../deploy/stack';
import {
  ALLOWED_TEST_KEYS,
  findPrivateKeys,
  LARGE_FILES_NOT_SCANNED,
  privateKeyFileNames,
  SCAN_SIZE_LIMIT,
  trackedPrivateKeys,
} from './license-tool';

/** Built at run time, so this file itself holds no key-shaped text. */
const dash = '-'.repeat(5);
const begin = (label: string): string => `${dash}BEGIN ${label}${dash}`;
const end = (label: string): string => `${dash}END ${label}${dash}`;
const ED_PREFIX = ['MC4CAQAw', 'BQYDK2Vw', 'BCIEI'].join('');
const BACKSLASH_N = String.fromCharCode(92) + 'n';

function trackedPaths(): string[] {
  return execFileSync('git', ['ls-files', '-z'], { cwd: REPO_ROOT, encoding: 'utf8' })
    .split('\0')
    .filter((f) => f !== '');
}

/** The tracked files the scan reads, and those above its size limit (never skipped silently). */
function trackedFiles(): { files: { path: string; text: string }[]; tooLarge: string[] } {
  const files: { path: string; text: string }[] = [];
  const tooLarge: string[] = [];
  for (const f of trackedPaths()) {
    let size: number;
    try {
      size = statSync(path.join(REPO_ROOT, f)).size;
    } catch {
      continue; // deleted in the working tree
    }
    if (size > SCAN_SIZE_LIMIT) tooLarge.push(f);
    else files.push({ path: f, text: readFileSync(path.join(REPO_ROOT, f), 'latin1') });
  }
  return { files, tooLarge };
}

describe('no private key is tracked (enterprise.md §15, Global Constraints)', () => {
  it('finds a key in a JSON or JavaScript string, a comment or a concatenation (Task 10 I-1)', () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey;
    const pkcs8 = String(rsa.export({ type: 'pkcs8', format: 'pem' }));
    const encrypted = String(
      rsa.export({
        type: 'pkcs8',
        format: 'pem',
        cipher: 'aes-256-cbc',
        passphrase: 'a throwaway passphrase for tests',
      }),
    );
    const lines = pkcs8.trimEnd().split('\n');
    const forms: [string, string][] = [
      [
        'an escaped encrypted PEM',
        `const PEM = '${encrypted.trimEnd().split('\n').join(BACKSLASH_N)}';`,
      ],
      [
        'a cloud service account file',
        JSON.stringify({ type: 'service_account', private_key: pkcs8 }, null, 2),
      ],
      ['a commented block', lines.map((l) => `// ${l}`).join('\n')],
      ['a shell comment', lines.map((l) => `#   ${l}`).join('\r\n')],
      ['a Markdown quote', lines.map((l) => `> ${l}`).join('\n')],
      ['a concatenation', lines.map((l) => `  '${l}${BACKSLASH_N}' +`).join('\n')],
      ['carriage returns only', lines.join('\r')],
    ];
    for (const [name, text] of forms) {
      expect(trackedPrivateKeys([{ path: name, text }]), name).toEqual([name]);
    }
  });

  it('finds a JWK private member in YAML or a JavaScript object (Task 10 M-2)', () => {
    const { d } = generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' });
    const forms: [string, string][] = [
      ['YAML', `signing:\n  kty: OKP\n  crv: Ed25519\n  d: ${String(d)}\n`],
      ['YAML, quoted', `kty: "OKP"\nd: '${String(d)}'\n`],
      ['JavaScript', `const jwk = { kty: 'OKP', crv: 'Ed25519', d: '${String(d)}' };`],
      ['JavaScript, quoted names', `const jwk = { 'kty': 'OKP', 'd': "${String(d)}" };`],
    ];
    for (const [name, text] of forms) {
      expect(trackedPrivateKeys([{ path: name, text }]), name).toEqual([name]);
    }
  });

  it('finds an SSH2 key and a lower-case PEM line, and CRLF RSA and encrypted keys (Task 10 M-3, M-4)', () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey;
    const body = rsa
      .export({ type: 'pkcs1', format: 'der' })
      .toString('base64')
      .match(/.{1,64}/g)!;
    const four = '-'.repeat(4);
    const crlf = (pem: string) => pem.replace(/\n/g, '\r\n');
    const forms: [string, string][] = [
      [
        'SSH2',
        [
          `${four} BEGIN SSH2 ENCRYPTED PRIVATE KEY ${four}`,
          'Comment: "rsa-key-20260926"',
          ...body,
          `${four} END SSH2 ENCRYPTED PRIVATE KEY ${four}`,
        ].join('\n'),
      ],
      [
        'lower case',
        `${begin('RSA PRIVATE KEY').toLowerCase()}\n${body.join('\n')}\n${end('RSA PRIVATE KEY').toLowerCase()}\n`,
      ],
      ['RSA, CRLF', crlf(String(rsa.export({ type: 'pkcs1', format: 'pem' })))],
      [
        'encrypted, CRLF',
        crlf(
          String(
            rsa.export({
              type: 'pkcs8',
              format: 'pem',
              cipher: 'aes-256-cbc',
              passphrase: 'a throwaway passphrase for tests',
            }),
          ),
        ),
      ],
    ];
    for (const [name, text] of forms) {
      expect(trackedPrivateKeys([{ path: name, text }]), name).toEqual([name]);
    }
  });

  it('finds a base64url Ed25519 key whose text holds - and _ (Task 10 M-4)', () => {
    // A fixed seed whose base64url spelling has both characters that base64 spells + and /.
    const der = Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      Buffer.alloc(32, 0xfb),
    ]);
    expect(createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }).asymmetricKeyType).toBe(
      'ed25519',
    );
    const text = `LICENSE_SIGNING_KEY=${der.toString('base64url')}\n`;
    expect(text).toMatch(/-/);
    expect(text).toMatch(/_/);
    expect(trackedPrivateKeys([{ path: '.env', text }])).toEqual(['.env']);
  });

  it('flags files named as private keys, whatever they hold (Task 10 M-3)', () => {
    expect(
      privateKeyFileNames([
        'a/key.p8',
        'b/server.key',
        'c/cert.p12',
        'd/cert.pfx',
        'e/key.der',
        'f/putty.ppk',
        'g/.ssh/id_ed25519',
        'h/prod-2026.private.pem',
        'i/public.pem',
        'j/keyboard.ts',
        'k/id_ed25519.pub',
      ]),
    ).toEqual([
      'a/key.p8',
      'b/server.key',
      'c/cert.p12',
      'd/cert.pfx',
      'e/key.der',
      'f/putty.ppk',
      'g/.ssh/id_ed25519',
      'h/prod-2026.private.pem',
    ]);
    expect(privateKeyFileNames(trackedPaths())).toEqual([]);
  });

  it('reads every tracked file, or names why one is too large to (Task 10 M-1)', () => {
    const pinned = new Set(LARGE_FILES_NOT_SCANNED.map((f) => f.path));
    expect(trackedFiles().tooLarge.filter((f) => !pinned.has(f))).toEqual([]);
  });

  it('detects an Ed25519 PKCS#8 key and an encrypted key block', () => {
    expect(
      trackedPrivateKeys([
        { path: 'a.pem', text: `${begin('PRIVATE KEY')}\n${ED_PREFIX}A...\n` },
        { path: 'b.pem', text: `${begin('ENCRYPTED PRIVATE KEY')}\nMIGbMFcGCSqGSIb3DQEFDTBK\n` },
        {
          path: 'c.ts',
          text: `const k = '${begin('ENCRYPTED PRIVATE KEY')}' // a string in a test`,
        },
        { path: 'd.md', text: 'nothing here' },
      ]),
    ).toEqual(['a.pem', 'b.pem']);
  });

  it('detects every form node:crypto writes an Ed25519 private key in', () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const pkcs8 = privateKey.export({ type: 'pkcs8', format: 'der' });
    const jwk = privateKey.export({ format: 'jwk' });
    const encrypted = privateKey.export({
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase: 'a throwaway passphrase for tests',
    });
    const forms: [string, string][] = [
      ['pem', String(privateKey.export({ type: 'pkcs8', format: 'pem' }))],
      [
        'pem, CRLF',
        String(privateKey.export({ type: 'pkcs8', format: 'pem' })).replace(/\n/g, '\r\n'),
      ],
      ['encrypted pem', String(encrypted)],
      ['base64 in JSON', JSON.stringify({ signingKey: pkcs8.toString('base64') })],
      ['base64url in .env', `LICENSE_SIGNING_KEY=${pkcs8.toString('base64url')}\n`],
      ['hex', `key = "${pkcs8.toString('hex')}"`],
      ['HEX', pkcs8.toString('hex').toUpperCase()],
      ['DER bytes', `\x00\x01${pkcs8.toString('latin1')}\x00`],
      ['JWK', JSON.stringify(jwk, null, 2)],
    ];
    for (const [name, text] of forms) {
      expect(trackedPrivateKeys([{ path: name, text }]), name).toEqual([name]);
    }
  });

  it('detects other PEM private keys (RSA, EC, OpenSSH, traditional encrypted) and PuTTY keys', () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey;
    const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
    const forms: [string, string][] = [
      ['rsa pkcs1', String(rsa.export({ type: 'pkcs1', format: 'pem' }))],
      ['ec sec1', String(ec.export({ type: 'sec1', format: 'pem' }))],
      [
        'traditional encrypted',
        String(
          rsa.export({
            type: 'pkcs1',
            format: 'pem',
            cipher: 'aes-256-cbc',
            passphrase: 'a throwaway passphrase for tests',
          }),
        ),
      ],
      [
        'openssh',
        `${begin('OPENSSH PRIVATE KEY')}\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n${end('OPENSSH PRIVATE KEY')}\n`,
      ],
      ['putty', `${['PuTTY', 'User', 'Key', 'File'].join('-')}-3: ssh-ed25519\nEncryption: none\n`],
      ['ec jwk', JSON.stringify(ec.export({ format: 'jwk' }))],
    ];
    for (const [name, text] of forms) {
      expect(trackedPrivateKeys([{ path: name, text }]), name).toEqual([name]);
    }
  });

  it('does not flag public keys, the bare prefix, escaped strings or a header alone', () => {
    const { publicKey } = generateKeyPairSync('ed25519');
    const texts = [
      String(publicKey.export({ type: 'spki', format: 'pem' })),
      JSON.stringify(publicKey.export({ format: 'jwk' })),
      `the prefix \`${ED_PREFIX}\` marks an Ed25519 PKCS#8 key`,
      `const PEM = '${begin('RSA PRIVATE KEY')}\\nMIIEow==\\n${end('RSA PRIVATE KEY')}\\n';`,
      `${begin('PRIVATE KEY')}\n${end('PRIVATE KEY')}\n`,
      'const x = { "d": "short" };',
    ];
    for (const text of texts) expect(trackedPrivateKeys([{ path: 'f', text }]), text).toEqual([]);
  });

  it('allows a listed test key only in its own file, and only that exact key', () => {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const pem = String(privateKey.export({ type: 'pkcs8', format: 'pem' }));
    const [found] = findPrivateKeys(pem);
    expect(found).toBeDefined();
    const allowed = [{ path: 'test/tls.ts', fingerprint: found!.fingerprint, reason: 'test' }];
    expect(trackedPrivateKeys([{ path: 'test/tls.ts', text: pem }], allowed)).toEqual([]);
    expect(trackedPrivateKeys([{ path: 'elsewhere.ts', text: pem }], allowed)).toEqual([
      'elsewhere.ts',
    ]);
    const second = String(
      generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({
        type: 'pkcs8',
        format: 'pem',
      }),
    );
    expect(
      trackedPrivateKeys([{ path: 'test/tls.ts', text: `${pem}\n${second}` }], allowed),
    ).toEqual(['test/tls.ts']);
  });

  it('every allowed test key is in the tree, is not Ed25519, and protects nothing', () => {
    const files = new Map(trackedFiles().files.map((f) => [f.path, f.text]));
    for (const entry of ALLOWED_TEST_KEYS) {
      const text = files.get(entry.path);
      expect(text, entry.path).toBeDefined();
      const found = findPrivateKeys(text ?? '').filter((k) => k.fingerprint === entry.fingerprint);
      expect(found, entry.path).toHaveLength(1);
      const pem = found[0]!.text;
      // A licence signing key is Ed25519; an allowed test key never is.
      expect(createPrivateKey(pem).asymmetricKeyType).not.toBe('ed25519');
    }
  });

  it('finds none among the tracked files', () => {
    expect(trackedPrivateKeys(trackedFiles().files)).toEqual([]);
  });

  it('ignores private key files by name', () => {
    expect(readFileSync(path.join(REPO_ROOT, '.gitignore'), 'utf8')).toMatch(/^\*\.private\.pem$/m);
    const ignored = execFileSync(
      'git',
      ['check-ignore', '--no-index', 'somewhere/prod-2026.private.pem'],
      {
        cwd: REPO_ROOT,
        encoding: 'utf8',
      },
    );
    expect(ignored.trim()).toBe('somewhere/prod-2026.private.pem');
  });
});
