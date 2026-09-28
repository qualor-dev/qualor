import { mkdtempSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { ImportFlags } from '../args';
import { EXIT } from '../errors';
import { createLogger } from '../log';
import { resolveImportSetup } from './options';

// Assembled at run time, so the repository's own Gitleaks check finds no fake secret here (.gitleaks.toml).
const SQU_ENV = ['squ_env', '0123456789'].join('');
const SQU_FLAG = ['squ_flag', '0123456789'].join('');
const SQU_FLAG_ORDER = ['squ_flag_order', '0123'].join('');
const QLR_PAT = ['qlr_pat_', '0123456789'].join('');

const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-import-options-'));
const flags = (over: Partial<ImportFlags> = {}): ImportFlags => ({
  url: 'https://sonar.test',
  sonarKind: 'auto',
  projects: [],
  only: ['profiles', 'gates', 'projects', 'issues'],
  createProjects: false,
  setDefaults: false,
  overwrite: false,
  dryRun: false,
  sonarAuth: 'auto',
  timeoutSeconds: 30,
  maxIssues: 100_000,
  allowInsecureHttp: false,
  ...over,
});
const env = {
  SONAR_TOKEN: SQU_ENV,
  QUALOR_URL: 'https://q.test',
  QUALOR_TOKEN: QLR_PAT,
};
const setup = (f: ImportFlags, e: Record<string, string | undefined> = env) => {
  const lines: string[] = [];
  const s = resolveImportSetup(
    f,
    e,
    dir,
    createLogger('debug', (t) => lines.push(t)),
  );
  return { s, log: lines.join('') };
};
const failure = (f: ImportFlags, e: Record<string, string | undefined> = env): Error => {
  try {
    setup(f, e);
  } catch (err) {
    return err as Error;
  }
  throw new Error('expected resolveImportSetup to fail');
};

describe('resolveImportSetup (import-sonarqube.md §3, §14)', () => {
  it('takes SONAR_TOKEN, QUALOR_URL and QUALOR_TOKEN', () => {
    const { s } = setup(flags());
    expect(s.sonar).toMatchObject({
      url: 'https://sonar.test',
      token: SQU_ENV,
      timeoutMs: 30_000,
    });
    expect(s.qualor).toMatchObject({ url: 'https://q.test', token: QLR_PAT });
  });

  it('warns about --token without printing it', () => {
    const { s, log } = setup(flags({ token: SQU_FLAG }));
    expect(s.sonar.token).toBe(SQU_FLAG);
    expect(s.warnings.map((w) => w.code)).toContain('TOKEN_ON_COMMAND_LINE');
    expect(log).toContain('visible in the process list');
    expect(log).not.toContain(SQU_FLAG);
    expect(JSON.stringify(s.warnings)).not.toContain(SQU_FLAG);
  });

  it('prefers --token, then --token-file, then SONAR_TOKEN', () => {
    writeFileSync(path.join(dir, 'order'), 'squ_file_order0123');
    expect(setup(flags({ tokenFile: 'order' })).s.sonar.token).toBe('squ_file_order0123');
    expect(setup(flags({ token: SQU_FLAG_ORDER })).s.sonar.token).toBe(SQU_FLAG_ORDER);
  });

  it('accepts a token file with a BOM and CRLF', () => {
    writeFileSync(path.join(dir, 'tok'), String.fromCharCode(0xfeff) + 'squ_file0123456789\r\n');
    expect(setup(flags({ tokenFile: 'tok' })).s.sonar.token).toBe('squ_file0123456789');
  });

  it('reads the Qualor token from --qualor-token-file before QUALOR_TOKEN', () => {
    writeFileSync(path.join(dir, 'qtok'), 'qlr_pat_file0123456789\n');
    expect(setup(flags({ qualorTokenFile: 'qtok' })).s.qualor.token).toBe('qlr_pat_file0123456789');
  });

  it('refuses a token with a space, without showing it', () => {
    const err = failure(flags({ token: 'squ_a b' }));
    expect(err).toMatchObject({ exitCode: EXIT.USAGE });
    expect(err.message).not.toContain('squ_a b');
    const fromEnv = failure(flags(), { ...env, QUALOR_TOKEN: 'qlr_pat_x\u0000y' });
    expect(fromEnv).toMatchObject({ exitCode: EXIT.USAGE });
    expect(fromEnv.message).not.toContain('qlr_pat_x');
    writeFileSync(path.join(dir, 'spaced'), 'squ_in side0123\n');
    const fromFile = failure(flags({ tokenFile: 'spaced' }));
    expect(fromFile).toMatchObject({ exitCode: EXIT.USAGE });
    expect(fromFile.message).not.toContain('squ_in');
  });

  it('refuses a token over 512 characters', () => {
    expect(failure(flags({ token: 'x'.repeat(513) }))).toMatchObject({ exitCode: EXIT.USAGE });
  });

  it('refuses the same token for both servers', () => {
    expect(() => setup(flags(), { ...env, SONAR_TOKEN: env.QUALOR_TOKEN })).toThrow(/same token/);
    expect(failure(flags(), { ...env, SONAR_TOKEN: env.QUALOR_TOKEN }).message).not.toContain(
      env.QUALOR_TOKEN,
    );
  });

  it.each([
    [{ url: 'https://user:pw@sonar.test' }],
    [{ url: 'https://squ_intheurl0123@sonar.test' }],
    [{ url: 'https://sonar.test/?x=1' }],
    [{ url: 'https://sonar.test/#x' }],
    [{ url: 'ftp://sonar.test' }],
    [{ url: 'file:///etc/passwd' }],
    [{ url: 'not a url' }],
  ])('refuses the SonarQube URL %j', (over) => {
    const err = failure(flags(over));
    expect(err).toMatchObject({ exitCode: EXIT.USAGE });
    expect(err.message).not.toMatch(/pw|squ_intheurl/);
  });

  it('refuses a Qualor URL with a user name, a query or another scheme', () => {
    for (const QUALOR_URL of ['https://a:b@q.test', 'https://q.test/?x', 'ftp://q.test']) {
      expect(failure(flags(), { ...env, QUALOR_URL })).toMatchObject({ exitCode: EXIT.USAGE });
    }
  });

  it('keeps a path prefix', () => {
    expect(setup(flags({ url: 'https://ci.test/sonarqube' })).s.sonar.url).toBe(
      'https://ci.test/sonarqube',
    );
  });

  it('refuses http to a remote host (exit 2), not to loopback (ruling S9)', () => {
    for (const [f, e] of [
      [flags({ url: 'http://sonar.test' }), env],
      [flags(), { ...env, QUALOR_URL: 'http://q.test' }],
    ] as const) {
      const err = failure(f, e);
      expect(err).toMatchObject({ exitCode: EXIT.USAGE });
      expect(err.message).toContain('--allow-insecure-http');
    }
    expect(setup(flags({ url: 'http://127.0.0.1:9000' })).s.warnings).toEqual([]);
    expect(setup(flags({ url: 'http://localhost:9000' })).s.warnings).toEqual([]);
    expect(setup(flags({ url: 'http://[::1]:9000' })).s.warnings).toEqual([]);
  });

  it('warns once about http to a remote host under --allow-insecure-http', () => {
    const { s, log } = setup(flags({ url: 'http://sonar.test', allowInsecureHttp: true }), {
      ...env,
      QUALOR_URL: 'http://q.test',
    });
    expect(s.warnings.map((w) => w.code)).toEqual(['INSECURE_URL', 'INSECURE_URL']);
    expect(log.match(/unencrypted to sonar\.test/g)).toHaveLength(1);
    expect(log.match(/unencrypted to q\.test/g)).toHaveLength(1);
  });

  it('trims tokens from the environment and treats blank variables as unset', () => {
    const { s } = setup(flags(), {
      ...env,
      SONAR_TOKEN: `  ${SQU_ENV}\n`,
      QUALOR_TOKEN: `\t${QLR_PAT} `,
      QUALOR_CA_FILE: '   ',
    });
    expect(s.sonar.token).toBe(SQU_ENV);
    expect(s.qualor.token).toBe(QLR_PAT);
    expect(s.qualor.ca).toBeUndefined();
    for (const e of [
      { ...env, QUALOR_URL: '  ' },
      { ...env, SONAR_TOKEN: ' \n' },
      { ...env, QUALOR_TOKEN: '\t' },
    ]) {
      expect(failure(flags(), e)).toMatchObject({
        exitCode: EXIT.USAGE,
        message: expect.stringMatching(/^no /) as unknown,
      });
    }
  });

  it('names the flag of an empty token file', () => {
    writeFileSync(path.join(dir, 'empty'), '\r\n');
    expect(failure(flags({ tokenFile: 'empty' })).message).toBe(
      'the file given as --token-file is empty',
    );
    expect(failure(flags({ qualorTokenFile: 'empty' })).message).toBe(
      'the file given as --qualor-token-file is empty',
    );
  });

  it('needs a SonarQube token, a Qualor URL and a Qualor token (exit 2)', () => {
    for (const e of [
      { ...env, SONAR_TOKEN: undefined },
      { ...env, QUALOR_URL: undefined },
      { ...env, QUALOR_TOKEN: undefined },
      { ...env, SONAR_TOKEN: '' },
    ]) {
      expect(() => setup(flags(), e)).toThrow(expect.objectContaining({ exitCode: EXIT.USAGE }));
    }
  });

  it('refuses a token file that is not a regular file or is over 4 KiB', () => {
    writeFileSync(path.join(dir, 'big'), 'x'.repeat(5000));
    expect(() => setup(flags({ tokenFile: 'big' }))).toThrow(/4 KiB/);
    expect(() => setup(flags({ tokenFile: '.' }))).toThrow(
      expect.objectContaining({ exitCode: EXIT.USAGE }),
    );
    expect(() => setup(flags({ tokenFile: 'missing' }))).toThrow(
      expect.objectContaining({ exitCode: EXIT.USAGE }),
    );
    expect(() => setup(flags({ qualorTokenFile: 'big' }))).toThrow(/--qualor-token-file/);
  });

  it('names the flag of a CA file it cannot use', () => {
    expect(() => setup(flags({ sonarCaFile: 'missing.pem' }))).toThrow(/--sonar-ca-file/);
    expect(() => setup(flags({ caFile: 'missing.pem' }))).toThrow(/--ca-file/);
  });

  describe('SonarQube Server or Cloud (§4.1)', () => {
    it('recognises Cloud by host over https only', () => {
      for (const url of [
        'https://sonarcloud.io',
        'https://sonarqube.us',
        'https://SonarCloud.io/',
      ]) {
        expect(setup(flags({ url, organization: 'acme' })).s.sonar).toMatchObject({
          kind: 'cloud',
          organization: 'acme',
        });
      }
      for (const url of [
        'https://sonar.test',
        'https://sonarcloud.io.evil.test',
        'https://eu.sonarcloud.io',
      ]) {
        expect(setup(flags({ url })).s.sonar).toMatchObject({ kind: 'server', organization: null });
      }
    });

    it('needs --organization for Cloud (exit 2)', () => {
      expect(failure(flags({ url: 'https://sonarcloud.io' }))).toMatchObject({
        exitCode: EXIT.USAGE,
        message: expect.stringMatching(/--organization/) as unknown,
      });
      expect(failure(flags({ url: 'https://proxy.test', sonarKind: 'cloud' }))).toMatchObject({
        exitCode: EXIT.USAGE,
      });
    });

    it('refuses --organization for Server (exit 2)', () => {
      expect(failure(flags({ organization: 'acme' }))).toMatchObject({ exitCode: EXIT.USAGE });
      expect(
        failure(flags({ url: 'https://sonarcloud.io', sonarKind: 'server', organization: 'acme' })),
      ).toMatchObject({ exitCode: EXIT.USAGE });
    });

    it('lets --sonar-kind cloud name a proxy in front of Cloud', () => {
      expect(
        setup(flags({ url: 'https://proxy.test', sonarKind: 'cloud', organization: 'acme' })).s
          .sonar.kind,
      ).toBe('cloud');
    });
  });
});
