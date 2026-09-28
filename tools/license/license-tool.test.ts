import { spawnSync } from 'node:child_process';
import {
  createPrivateKey,
  generateKeyPairSync,
  sign as signWithKey,
  type KeyObject,
} from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir, userInfo } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { Config } from '../../server/src/config';
import type { Executor } from '../../server/src/db/client';
import { createEdition } from '../../server/src/license/edition';
import { readBootLicense } from '../../server/src/license/source';
import { normaliseKey } from '../../server/src/license/token';
import { verifyLicenseKey } from '../../server/src/license/verify';
import {
  BUSINESS_FEATURES,
  ENTERPRISE_FEATURES,
  testPayload,
  testSigner,
  T0,
} from '../../server/test/license';
import { REPO_ROOT } from '../deploy/stack';
import {
  gitEnvironment,
  inspectKey,
  inspectLicense,
  inspectVerifyOptions,
  insideGitWorkTree,
  keygen,
  PASSPHRASE_VARIABLE,
  refuseMissingPrerequisites,
  refuseRetiredFeatures,
  signKey,
} from './license-tool';

const PASS = 'a throwaway passphrase for tests';
const TSX = path.join(REPO_ROOT, 'node_modules', 'tsx', 'dist', 'cli.mjs');
const CLI = path.join(REPO_ROOT, 'tools', 'license', 'cli.ts');
const dirs: string[] = [];
function scratch(): string {
  const dir = mkdtempSync(path.join(tmpdir(), 'qualor-license-tool-'));
  dirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

/**
 * Signs arbitrary payload bytes by hand, bypassing `signLicenseKey`'s own schema check: how a
 * pre-5A key (with an `organizations` member) was made, and the only way to make one now
 * (enterprise.md §3.1). Mirrors `signBytes` in `server/src/license/verify.test.ts`.
 */
function signBytes(kid: string, privateKey: KeyObject, body: Buffer): string {
  const input = `QLK1.${kid}.${body.toString('base64url')}`;
  return `${input}.${signWithKey(null, Buffer.from(input), privateKey).toString('base64url')}`;
}

describe('refuseRetiredFeatures (enterprise.md §1.4, §3.1, §15)', () => {
  it('throws on a retired feature and leaves the rest alone', () => {
    expect(() => refuseRetiredFeatures(['llm.fix-quota', 'rbac'])).toThrow(
      'rbac is retired: roles and project access are in the community edition since Qualor 5B; leave it out',
    );
    expect(() =>
      refuseRetiredFeatures(['llm.fix-quota', 'audit-log', 'sso', 'scim']),
    ).not.toThrow();
    expect(() => refuseRetiredFeatures([])).not.toThrow();
  });
});

describe('refuseMissingPrerequisites (enterprise.md §7.1, §15, §17 item 11)', () => {
  it('throws when a feature is listed without its prerequisite', () => {
    expect(() => refuseMissingPrerequisites(['audit-log.stream'])).toThrow(
      'audit-log.stream needs audit-log in --features (enterprise.md §7.1)',
    );
    expect(() => refuseMissingPrerequisites(['llm.fix-quota', 'sso.multi'])).toThrow(
      'sso.multi needs sso in --features (enterprise.md §7.1)',
    );
  });

  it('does not throw once the prerequisite is listed too, or for a feature with none', () => {
    expect(() =>
      refuseMissingPrerequisites([
        'audit-log',
        'audit-log.stream',
        'sso',
        'sso.multi',
        'scim',
        'llm.fix-quota',
      ]),
    ).not.toThrow();
    expect(() => refuseMissingPrerequisites([])).not.toThrow();
  });

  it('reads only its own prerequisites, never an inherited object key', () => {
    // `constructor` matches the feature pattern; Object.prototype must not make it need anything.
    expect(() => refuseMissingPrerequisites(['constructor'])).not.toThrow();
  });
});

describe('pnpm license:keygen (enterprise.md §15)', () => {
  it('writes an encrypted private key outside the repository and prints the public line', () => {
    const dir = scratch();
    const { privateKeyPath, x, line } = keygen({ kid: 'test-tool', outDir: dir, passphrase: PASS });
    expect(privateKeyPath).toBe(path.join(dir, 'test-tool.private.pem'));
    expect(existsSync(privateKeyPath)).toBe(true);
    expect(Buffer.from(x, 'base64url')).toHaveLength(32);
    expect(line).toBe(`  'test-tool': '${x}',`);
    const pem = readFileSync(privateKeyPath, 'utf8');
    expect(pem).toContain('-----BEGIN ENCRYPTED PRIVATE KEY-----');
    if (process.platform !== 'win32') expect(statSync(privateKeyPath).mode & 0o777).toBe(0o600);
  });

  it('refuses a directory inside the repository, even .tmp/ or one that does not exist yet', () => {
    expect(insideGitWorkTree(REPO_ROOT)).toBe(true);
    expect(insideGitWorkTree(path.join(REPO_ROOT, '.git'))).toBe(true);
    expect(insideGitWorkTree(tmpdir())).toBe(false);
    for (const outDir of [
      path.join(REPO_ROOT, '.tmp'),
      path.join(REPO_ROOT, '.tmp', 'license-keys-that-do-not-exist', 'deeper'),
      path.join(REPO_ROOT, '.git'),
    ]) {
      expect(() => keygen({ kid: 'test-x', outDir, passphrase: PASS }), outDir).toThrow(
        /repository/,
      );
    }
    expect(existsSync(path.join(REPO_ROOT, '.tmp', 'license-keys-that-do-not-exist'))).toBe(false);
  });

  it('refuses a short or missing passphrase, a bad kid and an existing file', () => {
    const dir = scratch();
    expect(() => keygen({ kid: 'test-x', outDir: dir, passphrase: 'short' })).toThrow(/16/);
    expect(() => keygen({ kid: 'test-x', outDir: dir, passphrase: undefined })).toThrow(
      /QUALOR_LICENSE_SIGNING_PASSPHRASE/,
    );
    expect(() => keygen({ kid: 'Bad Kid', outDir: dir, passphrase: PASS })).toThrow(/kid/);
    keygen({ kid: 'test-x', outDir: dir, passphrase: PASS });
    expect(() => keygen({ kid: 'test-x', outDir: dir, passphrase: PASS })).toThrow(/exists/);
  });
});

describe('pnpm license:sign and license:inspect', () => {
  it('signs a key the server verifies with the printed public key', () => {
    const dir = scratch();
    const { privateKeyPath, x } = keygen({ kid: 'test-tool', outDir: dir, passphrase: PASS });
    const key = signKey({
      keyFile: privateKeyPath,
      passphrase: PASS,
      kid: 'test-tool',
      customer: 'Acme Corporation',
      issued: '2026-10-01',
      expires: '2027-10-01',
      features: ['llm.fix-quota'],
    });
    const result = verifyLicenseKey(key, {
      publicKeys: { 'test-tool': x },
      revoked: [],
      now: new Date('2026-11-01T00:00:00Z'),
    });
    expect(result).toMatchObject({
      ok: true,
      license: {
        customer: 'Acme Corporation',
        issued: '2026-10-01T00:00:00Z',
        expires: '2027-10-01T00:00:00Z',
        features: ['llm.fix-quota'],
      },
    });
    const report = inspectKey(key, {
      extraKeys: { 'test-tool': x },
      now: new Date('2027-10-05T00:00:00Z'),
    });
    expect(report).toContain('state: grace');
    expect(report).toContain('Acme Corporation');
    expect(inspectKey(key)).toContain('unknown-key'); // the compiled keys do not know it
  });

  it('signs the Business and the Enterprise feature lists, and inspect shows them (enterprise.md §1.7, §17 item 12)', () => {
    const dir = scratch();
    const { privateKeyPath, x } = keygen({ kid: 'test-tool', outDir: dir, passphrase: PASS });
    for (const features of [BUSINESS_FEATURES, ENTERPRISE_FEATURES]) {
      const key = signKey({
        keyFile: privateKeyPath,
        passphrase: PASS,
        kid: 'test-tool',
        customer: 'Acme Corporation',
        expires: '2027-10-01',
        features: [...features],
      });
      const report = inspectKey(key, { extraKeys: { 'test-tool': x } });
      expect(report).toContain('state: active');
      for (const feature of features) expect(report).toContain(`"${feature}"`);
    }
  });

  it('signs a key whose payload has no organizations member (enterprise.md §3.1)', () => {
    const dir = scratch();
    const { privateKeyPath } = keygen({ kid: 'test-tool', outDir: dir, passphrase: PASS });
    const key = signKey({
      keyFile: privateKeyPath,
      passphrase: PASS,
      kid: 'test-tool',
      customer: 'Acme',
      expires: '2027-10-01',
      features: ['llm.fix-quota'],
    });
    const json = JSON.parse(
      Buffer.from(key.split('.')[2]!, 'base64url').toString('utf8'),
    ) as object;
    expect(Object.keys(json)).toEqual(['v', 'id', 'customer', 'issued', 'expires', 'features']);
  });

  it('inspect reads a pre-5A key as valid and prints no organizations (enterprise.md §3.1)', () => {
    const signer = testSigner('test-pre-5a');
    const payload = testPayload();
    const key = signBytes(
      signer.kid,
      signer.privateKey,
      Buffer.from(JSON.stringify({ ...payload, organizations: 10 })),
    );
    const out = inspectKey(key, { extraKeys: { [signer.kid]: signer.x }, now: T0 });
    expect(out).toContain('state: active');
    expect(out).not.toMatch(/organi[sz]ations/);
  });

  it('inspect of a pre-5B key listing rbac prints it active, with the features as the key says (enterprise.md §1.4)', () => {
    // signKey itself never refuses a retired feature (only the CLI's --features parsing does),
    // so a key signed before rbac was retired still inspects exactly as the key says.
    const dir = scratch();
    const { privateKeyPath, x } = keygen({ kid: 'test-tool', outDir: dir, passphrase: PASS });
    const key = signKey({
      keyFile: privateKeyPath,
      passphrase: PASS,
      kid: 'test-tool',
      customer: 'Acme Corporation',
      issued: '2026-10-01',
      expires: '2027-10-01',
      features: ['rbac', 'audit-log'],
    });
    const out = inspectKey(key, {
      extraKeys: { 'test-tool': x },
      now: new Date('2026-11-01T00:00:00Z'),
    });
    expect(out).toContain('state: active');
    expect(out).toContain('"rbac"');
    expect(out).toContain('"audit-log"');
  });

  it('fails with the wrong passphrase and on a payload the server would reject', () => {
    const dir = scratch();
    const { privateKeyPath } = keygen({ kid: 'test-tool', outDir: dir, passphrase: PASS });
    const base = {
      keyFile: privateKeyPath,
      kid: 'test-tool',
      customer: 'A',
      expires: '2027-10-01',
      features: [],
    };
    expect(() => signKey({ ...base, passphrase: 'the wrong passphrase!!' })).toThrow();
    expect(() =>
      signKey({ ...base, passphrase: PASS, expires: '2020-01-01', issued: '2026-01-01' }),
    ).toThrow(/before/);
  });

  it('accepts only YYYY-MM-DD or a full UTC timestamp, and no rolled-over date', () => {
    const dir = scratch();
    const { privateKeyPath, x } = keygen({ kid: 'test-tool', outDir: dir, passphrase: PASS });
    const base = {
      keyFile: privateKeyPath,
      passphrase: PASS,
      kid: 'test-tool',
      customer: 'A',
      issued: '2026-10-01',
      features: [],
    };
    for (const expires of [
      '2027',
      '2027-02-30',
      '2027-10-01 00:00',
      'tomorrow',
      '2027-10-01T25:00:00Z',
    ]) {
      expect(() => signKey({ ...base, expires }), expires).toThrow();
    }
    const key = signKey({ ...base, expires: '2027-10-01T12:30:00Z' });
    const verified = verifyLicenseKey(key, {
      publicKeys: { 'test-tool': x },
      revoked: [],
      now: new Date('2026-11-01T00:00:00Z'),
    });
    expect(verified.ok && verified.license.expires).toBe('2027-10-01T12:30:00Z');
  });

  it('signs only with a test- kid or a compiled production key (Task 10 I-2)', () => {
    const dir = scratch();
    // A production-style kid that is not compiled in (PRODUCTION_KEYS holds the released ones).
    const made = keygen({ kid: 'prod-unlisted', outDir: dir, passphrase: PASS });
    const base = {
      keyFile: made.privateKeyPath,
      passphrase: PASS,
      kid: 'prod-unlisted',
      customer: 'A',
      expires: '2099-10-01',
      features: [],
    };
    expect(() => signKey(base)).toThrow(/not in PRODUCTION_KEYS/);
    expect(() => signKey({ ...base, productionKeys: { 'prod-unlisted': made.x } })).not.toThrow();
    const other = String(generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }).x);
    expect(() => signKey({ ...base, productionKeys: { 'prod-unlisted': other } })).toThrow(
      /not the private key/,
    );
  });

  it('warns about a key that is already expired or not valid yet (Task 10 M-6)', () => {
    const dir = scratch();
    const { privateKeyPath } = keygen({ kid: 'test-tool', outDir: dir, passphrase: PASS });
    const base = {
      keyFile: privateKeyPath,
      passphrase: PASS,
      kid: 'test-tool',
      customer: 'A',
      features: [],
      now: new Date('2027-01-01T00:00:00Z'),
    };
    const warnings: string[] = [];
    const onWarning = (m: string) => void warnings.push(m);
    signKey({ ...base, issued: '2026-01-01', expires: '2026-06-01', onWarning });
    signKey({ ...base, issued: '2026-01-01', expires: '2026-12-25', onWarning });
    signKey({ ...base, issued: '2027-03-01', expires: '2028-03-01', onWarning });
    signKey({ ...base, issued: '2026-12-01', expires: '2028-03-01', onWarning });
    expect(warnings).toEqual([
      expect.stringMatching(/expired on 2026-06-01.*past its grace period/),
      expect.stringMatching(/expired on 2026-12-25.*grace period until 2027-01-08/),
      expect.stringMatching(/not valid before 2027-03-01.*restarted/),
    ]);
  });

  it('refuses a timestamp with milliseconds, as the usage text says (Task 10 M-8)', () => {
    const dir = scratch();
    const { privateKeyPath } = keygen({ kid: 'test-tool', outDir: dir, passphrase: PASS });
    expect(() =>
      signKey({
        keyFile: privateKeyPath,
        passphrase: PASS,
        kid: 'test-tool',
        customer: 'A',
        expires: '2027-10-01T12:30:00.000Z',
        features: [],
      }),
    ).toThrow(/YYYY-MM-DDTHH:MM:SSZ/);
  });

  it('never hands the signing passphrase or GIT_DIR to git (Task 10 M-7)', () => {
    const env = gitEnvironment({
      PATH: '/bin',
      GIT_DIR: '/x/.git',
      GIT_WORK_TREE: '/x',
      [PASSPHRASE_VARIABLE]: PASS,
    });
    expect(env).toEqual({ PATH: '/bin' });
  });

  it.runIf(process.platform === 'win32')(
    'restricts the private key file to the current user on Windows (Task 10 M-5)',
    () => {
      const dir = scratch();
      const { privateKeyPath, warnings } = keygen({
        kid: 'test-acl',
        outDir: dir,
        passphrase: PASS,
      });
      expect(warnings).toEqual([]);
      const acl = spawnSync('icacls', [privateKeyPath], { encoding: 'utf8' }).stdout;
      const entries = acl
        .replace(privateKeyPath, '')
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => l.includes(':('));
      expect(entries).toHaveLength(1);
      expect(entries[0]).toContain(`${userInfo().username}:(F)`);
    },
  );

  it('refuses a private key that is not the one the compiled keys hold for the kid', () => {
    const dir = scratch();
    const { privateKeyPath } = keygen({ kid: 'test-tool', outDir: dir, passphrase: PASS });
    const other = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }).x;
    expect(() =>
      signKey({
        keyFile: privateKeyPath,
        passphrase: PASS,
        kid: 'test-tool',
        customer: 'A',
        expires: '2027-10-01',
        features: [],
        knownKeys: { 'test-tool': String(other) },
      }),
    ).toThrow(/not the private key/);
  });

  /**
   * Node reads the first valid PEM block and ignores the rest, so an unencrypted key with a stray
   * encrypted header appended would be signed with any passphrase. The file must hold exactly one
   * PEM block, the encrypted one.
   */
  it('refuses a disguised unencrypted key, trailing junk after the block, and a second block', () => {
    const dir = scratch();
    const { privateKeyPath: encryptedPath } = keygen({
      kid: 'test-tool',
      outDir: dir,
      passphrase: PASS,
    });
    const encryptedPem = readFileSync(encryptedPath, 'utf8');
    const { privateKey: unencryptedPem } = generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    expect(unencryptedPem).toContain('-----BEGIN PRIVATE KEY-----');
    const base = {
      passphrase: PASS,
      kid: 'test-tool',
      customer: 'A',
      expires: '2027-10-01',
      features: [],
    };
    const sameError = /is not an encrypted private key \(pnpm license:keygen\)/;

    // A plain unencrypted key gets refused (the baseline this bug let slip past).
    const plain = path.join(dir, 'plain.private.pem');
    writeFileSync(plain, unencryptedPem);
    expect(() => signKey({ ...base, keyFile: plain })).toThrow(sameError);

    // The bug: the same unencrypted key, disguised with a stray encrypted-header line, must be
    // refused with the very same error -- not silently signed with any passphrase.
    const disguised = path.join(dir, 'disguised.private.pem');
    writeFileSync(disguised, `${unencryptedPem}-----BEGIN ENCRYPTED PRIVATE KEY-----\n`);
    expect(() => signKey({ ...base, keyFile: disguised })).toThrow(sameError);
    expect(() =>
      signKey({ ...base, keyFile: disguised, passphrase: 'any passphrase at all, right or wrong' }),
    ).toThrow(sameError);

    // A genuine encrypted block with trailing junk after its END line.
    const trailingJunk = path.join(dir, 'trailing-junk.private.pem');
    writeFileSync(trailingJunk, `${encryptedPem}\nnot part of the key\n`);
    expect(() => signKey({ ...base, keyFile: trailingJunk })).toThrow(sameError);

    // Two genuine encrypted blocks concatenated: still exactly one BEGIN line is required.
    const secondBlock = path.join(dir, 'second-block.private.pem');
    writeFileSync(secondBlock, `${encryptedPem}${encryptedPem}`);
    expect(() => signKey({ ...base, keyFile: secondBlock })).toThrow(sameError);
  });
});

/**
 * The binding carry of the Task 1-3 review: `license:inspect` parses and judges a key exactly as
 * the server does. The same inputs go through the server's own boot path (readBootLicense from
 * QUALOR_LICENSE and from QUALOR_LICENSE_FILE, then the edition's state) and through inspect.
 */
describe('license:inspect agrees with the server on every input', () => {
  const { x, good, future, preFiveA } = ((): {
    x: string;
    good: string;
    future: string;
    preFiveA: string;
  } => {
    const dir = mkdtempSync(path.join(tmpdir(), 'qualor-license-parity-'));
    try {
      const made = keygen({ kid: 'test-parity', outDir: dir, passphrase: PASS });
      const sign = (over: Partial<Parameters<typeof signKey>[0]> = {}): string =>
        signKey({
          keyFile: made.privateKeyPath,
          passphrase: PASS,
          kid: 'test-parity',
          customer: 'Parity Ltd',
          issued: '2026-10-01',
          expires: '2027-10-01',
          features: ['llm.fix-quota'],
          ...over,
        });
      const privateKey = createPrivateKey({
        key: readFileSync(made.privateKeyPath, 'utf8'),
        passphrase: PASS,
      });
      return {
        x: made.x,
        good: sign(),
        future: sign({ issued: '2030-01-01', expires: '2031-01-01' }),
        // A pre-5A key (enterprise.md §3.1): the schema drops organizations, but the signature
        // still covers the payload text exactly as signed, so it verifies like any other key.
        preFiveA: signBytes(
          'test-parity',
          privateKey,
          Buffer.from(
            JSON.stringify({
              ...testPayload({
                customer: 'Parity Ltd',
                issued: '2026-10-01T00:00:00Z',
                expires: '2027-10-01T00:00:00Z',
                features: ['llm.fix-quota'],
              }),
              organizations: 10,
            }),
          ),
        ),
      };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  })();
  const [prefix, kid, payload, signature] = good.split('.') as [string, string, string, string];
  const flip = (s: string): string =>
    (s[5] === 'A' ? `${s.slice(0, 5)}B` : `${s.slice(0, 5)}A`) + s.slice(6);

  const inputs: [string, string][] = [
    ['a good key', good],
    [
      'a key wrapped by an e-mail client',
      `${good.slice(0, 60)}\r\n  ${good.slice(60, 130)}\n\t${good.slice(130)}\n`,
    ],
    ['a key with a trailing newline', `${good}\n`],
    ['a changed payload', [prefix, kid, flip(payload), signature].join('.')],
    ['a changed signature', [prefix, kid, payload, flip(signature)].join('.')],
    ['another kid', [prefix, 'test-other', payload, signature].join('.')],
    ['a kid that names Object.prototype', [prefix, 'constructor', payload, signature].join('.')],
    ['padding', `${good}=`],
    ['a byte-order mark', `${String.fromCharCode(0xfeff)}${good}`],
    ['three parts', [prefix, kid, payload].join('.')],
    ['too long', `${good}${' '.repeat(10)}${'A'.repeat(9000)}`],
    ['a far-future issue date', future],
    ['a pre-5A key with a retired organisation limit', preFiveA],
    ['text', 'not a licence key'],
  ];
  const at = [
    new Date('2026-11-01T00:00:00Z'),
    new Date('2027-10-01T00:00:00Z'),
    new Date('2027-10-20T00:00:00Z'),
  ];

  for (const [name, text] of inputs) {
    it(name, async () => {
      for (const now of at) {
        const verifyOptions = inspectVerifyOptions(now, { 'test-parity': x });
        const fileDir = scratch();
        const file = path.join(fileDir, 'license.txt');
        writeFileSync(file, text, 'utf8');
        const db = {} as Executor; // neither source reads the database
        for (const license of [
          { text, file: null },
          { text: null, file },
        ]) {
          const boot = await readBootLicense({ license } as Config, db, verifyOptions);
          const server = createEdition({ boot, now: () => now }).state();
          expect(inspectLicense(text, { extraKeys: { 'test-parity': x }, now }), name).toEqual(
            server,
          );
        }
        // The upload route verifies the whitespace-free text.
        expect(
          inspectLicense(normaliseKey(text), { extraKeys: { 'test-parity': x }, now }),
        ).toEqual(inspectLicense(text, { extraKeys: { 'test-parity': x }, now }));
      }
    });
  }

  it('inspect adds keys only for itself: the compiled map is the server map', () => {
    const now = new Date('2026-11-01T00:00:00Z');
    expect(inspectLicense(good, { now }).reason).toBe('unknown-key');
    expect(inspectVerifyOptions(now, {}).publicKeys).toEqual(
      inspectVerifyOptions(now, undefined).publicKeys,
    );
  });
});

describe('the command line never prints or leaks a private key', () => {
  function run(args: string[], env: Record<string, string>, input?: string | Buffer) {
    const r = spawnSync(process.execPath, [TSX, CLI, ...args], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      input,
      env: { ...process.env, QUALOR_LICENSE_SIGNING_PASSPHRASE: '', ...env },
    });
    return { status: r.status, out: r.stdout, err: r.stderr };
  }

  it('keygen, sign and inspect print only public material', () => {
    const dir = scratch();
    const keygenRun = run(['keygen', '--kid', 'test-cli', '--out', dir], {
      QUALOR_LICENSE_SIGNING_PASSPHRASE: PASS,
    });
    expect(keygenRun.err).toBe('');
    expect(keygenRun.status).toBe(0);
    const pemPath = path.join(dir, 'test-cli.private.pem');
    const pem = readFileSync(pemPath, 'utf8');
    const body = pem.split('\n').filter((l) => l !== '' && !l.startsWith('-----'));
    expect(keygenRun.out).toMatch(/^ {2}'test-cli': '[A-Za-z0-9_-]{43}',$/m);
    expect(keygenRun.out).not.toMatch(/PRIVATE KEY-----/);
    for (const line of body) expect(keygenRun.out).not.toContain(line);

    const signRun = run(
      [
        'sign',
        '--key',
        pemPath,
        '--kid',
        'test-cli',
        '--customer',
        'Acme',
        '--expires',
        '2099-01-01',
        '--features',
        'llm.fix-quota',
      ],
      { QUALOR_LICENSE_SIGNING_PASSPHRASE: PASS },
    );
    expect(signRun.err).toBe('');
    expect(signRun.status).toBe(0);
    expect(signRun.out).toMatch(/^QLK1\.test-cli\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\n$/);
    for (const line of body) expect(signRun.out).not.toContain(line);

    const inspectRun = run(['inspect', '-'], {}, `${signRun.out}`);
    expect(inspectRun.status).toBe(0);
    expect(inspectRun.out).toContain('state: invalid');
    expect(inspectRun.out).toContain('reason: unknown-key');
  });

  it('a wrong passphrase fails without echoing it or the key file', () => {
    const dir = scratch();
    keygen({ kid: 'test-cli', outDir: dir, passphrase: PASS });
    const pemPath = path.join(dir, 'test-cli.private.pem');
    const wrong = 'the wrong passphrase, but long';
    const r = run(
      ['sign', '--key', pemPath, '--kid', 'test-cli', '--customer', 'A', '--expires', '2099-01-01'],
      { QUALOR_LICENSE_SIGNING_PASSPHRASE: wrong },
    );
    expect(r.status).toBe(1);
    expect(r.out).toBe('');
    expect(r.err).not.toContain(wrong);
    expect(r.err).not.toContain('PRIVATE KEY');
  });

  it('refuses a passphrase on the command line and an unknown option', () => {
    expect(
      run(['keygen', '--kid', 'test-cli', '--passphrase', PASS, '--out', scratch()], {}).status,
    ).toBe(1);
    expect(run(['frobnicate'], {}).status).toBe(1);
  });

  it('refuses --organizations with a message that keys no longer carry an organisation limit', () => {
    // The refusal happens before any key file is read: the path below does not exist.
    const r = run(
      [
        'sign',
        '--key',
        path.join(scratch(), 'does-not-exist.private.pem'),
        '--kid',
        'test-cli',
        '--customer',
        'Acme',
        '--expires',
        '2027-10-01',
        '--organizations',
        '25',
      ],
      {},
    );
    expect(r.status).toBe(1);
    expect(r.err).toContain(
      '--organizations is no longer used: licence keys carry no organisation limit',
    );
    expect(r.out).toBe('');
    expect(r.out).not.toMatch(/QLK1\./);
  });

  it('refuses a retired feature with a message that roles are in the community edition, before any key file is read (enterprise.md §1.4)', () => {
    // The refusal happens before any key file is read: the path below does not exist.
    const r = run(
      [
        'sign',
        '--key',
        path.join(scratch(), 'does-not-exist.private.pem'),
        '--kid',
        'test-cli',
        '--customer',
        'Acme',
        '--expires',
        '2027-10-01',
        '--features',
        'llm.fix-quota,rbac',
      ],
      {},
    );
    expect(r.status).toBe(1);
    expect(r.err).toContain(
      'rbac is retired: roles and project access are in the community edition since Qualor 5B; leave it out',
    );
    expect(r.out).toBe('');
    expect(r.out).not.toMatch(/QLK1\./);
  });

  it('refuses a feature without its prerequisite, before any key file is read (enterprise.md §7.1, §17 item 11)', () => {
    for (const [features, message] of [
      ['llm.fix-quota,audit-log.stream', 'audit-log.stream needs audit-log in --features'],
      ['sso.multi', 'sso.multi needs sso in --features'],
    ] as const) {
      // The refusal happens before the key file is read: the path below does not exist.
      const r = run(
        [
          'sign',
          '--key',
          path.join(scratch(), 'does-not-exist.private.pem'),
          '--kid',
          'test-cli',
          '--customer',
          'Acme',
          '--expires',
          '2027-10-01',
          '--features',
          features,
        ],
        {},
      );
      expect(r.status, features).toBe(1);
      expect(r.err, features).toContain(message);
      expect(r.out, features).toBe('');
      expect(r.out, features).not.toMatch(/QLK1\./);
    }
  });

  it('the usage text names the Business and the Enterprise feature lists (enterprise.md §1.7, §15)', () => {
    const r = run(['frobnicate'], {});
    expect(r.err).toContain('Business:   --features sso,audit-log,llm.fix-quota');
    expect(r.err).toContain(
      'Enterprise: --features sso,sso.multi,audit-log,audit-log.stream,llm.fix-quota,scim',
    );
  });

  it('inspect decodes standard input as the server decodes QUALOR_LICENSE_FILE', () => {
    const dir = scratch();
    keygen({ kid: 'test-cli', outDir: dir, passphrase: PASS });
    const key = signKey({
      keyFile: path.join(dir, 'test-cli.private.pem'),
      passphrase: PASS,
      kid: 'test-cli',
      customer: 'Acme',
      expires: '2099-01-01',
      features: [],
    });
    const bom = String.fromCharCode(0xfeff);
    const utf8 = run(
      ['inspect', '-'],
      {},
      `${key}
`,
    );
    expect(utf8.out).toContain('reason: unknown-key'); // decoded to a key, not "malformed"
    for (const input of [
      Buffer.from(
        `${bom}${key}
`,
        'utf8',
      ),
      Buffer.from(
        `${bom}${key}
`,
        'utf16le',
      ),
    ]) {
      const r = run(['inspect', '-'], {}, input);
      expect(r.status).toBe(0);
      expect(r.out).toBe(utf8.out);
    }
    const noMark = run(['inspect', '-'], {}, Buffer.from(key, 'utf16le'));
    expect(noMark.status).toBe(1);
    expect(noMark.err).toMatch(/UTF-8/);
  }, 60_000);

  it('inspect refuses input above the server limit of 16 KiB', () => {
    const r = run(['inspect', '-'], {}, 'A'.repeat(16 * 1024 + 1));
    expect(r.status).toBe(1);
    expect(r.err).toMatch(/16 KiB/);
  });
});
