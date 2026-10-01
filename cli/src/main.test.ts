import { describe, expect, it } from 'vitest';
import { captureIO } from '../test/io';
import { useTempDirs, writeTree } from '../test/tmp';
import { main } from './main';
import { GRAMMARS } from './parse/grammars';
import { VERSION } from './index';

const tmp = useTempDirs();
// Assembled at run time, so the repository's own Gitleaks check finds no fake secret here (.gitleaks.toml).
const SQU_MAIN = ['squ_main', '0123456789'].join('');
const QLR_PAT_MAIN = ['qlr_pat_main', '0123456789'].join('');

describe('main', () => {
  it('prints the version, the platform and the embedded grammar ABI versions', async () => {
    const c = captureIO();
    expect(await main(['version'], c.io)).toBe(0);
    const grammars = GRAMMARS.map((g) => `${g} \\(ABI 1[3-5]\\)`).join(', ');
    expect(c.stdout()).toMatch(
      new RegExp(
        `^qualor ${VERSION.replaceAll('.', '\\.')} \\(${process.platform}-${process.arch}\\)\\n` +
          `grammars: ${grammars}\\n$`,
      ),
    );
    expect(GRAMMARS).toContain('python');
    expect(c.stdout()).toContain(
      'html (ABI 14), css (ABI 15), kotlin (ABI 14), swift (ABI 15), php (ABI 15), ruby (ABI 14), go (ABI 15)',
    );
  });

  it('prints the usage for help', async () => {
    const c = captureIO();
    expect(await main([], c.io)).toBe(0);
    expect(c.stdout()).toContain('qualor scan');
  });

  it('prints the usage on stdout and exits 0 for a command with --help', async () => {
    const c = captureIO();
    expect(await main(['import', 'sonarqube', '--help'], c.io)).toBe(0);
    expect(c.stdout()).toContain('qualor import sonarqube --url URL');
    expect(c.stderr()).toBe('');
  });

  it('exits 2 on an unknown command and explains why on stderr', async () => {
    const c = captureIO();
    expect(await main(['scna'], c.io)).toBe(2);
    expect(c.stderr()).toContain('error: unknown command "scna"');
  });

  it('runs qualor import sonarqube, which refuses plain http to a remote host before any request', async () => {
    const c = captureIO({
      cwd: tmp(),
      env: {
        SONAR_TOKEN: SQU_MAIN,
        QUALOR_URL: 'https://q.test',
        QUALOR_TOKEN: QLR_PAT_MAIN,
      },
    });
    expect(await main(['import', 'sonarqube', '--url', 'http://sonar.example.test'], c.io)).toBe(2);
    expect(c.stderr()).toContain('--allow-insecure-http');
    expect(c.stderr()).not.toContain('not available in this build');
    expect(c.stderr()).not.toMatch(/squ_main|qlr_pat_main/);
  });

  it('exits 2 on an invalid QUALOR_LOG_LEVEL', async () => {
    const c = captureIO({ env: { QUALOR_LOG_LEVEL: 'loud' } });
    expect(await main(['version'], c.io)).toBe(2);
    expect(c.stderr()).toContain('QUALOR_LOG_LEVEL');
  });

  it('validate prints the resolved config and exits 0', async () => {
    const root = tmp();
    writeTree(root, { 'qualor.yml': 'version: 1\nproject:\n  key: acme/app\n' });
    const c = captureIO({ cwd: root, env: { QUALOR_TOKEN: 'qlr_pat_x' } });
    expect(await main(['validate'], c.io)).toBe(0);
    expect(c.stdout()).toContain('key: acme/app');
    expect(c.stdout()).toContain('token: «redacted»');
    expect(c.stdout()).not.toContain('qlr_pat_x');
  });

  it('validate exits 2 on an invalid qualor.yml', async () => {
    const root = tmp();
    writeTree(root, { 'qualor.yml': 'version: 2\n' });
    const c = captureIO({ cwd: root });
    expect(await main(['validate'], c.io)).toBe(2);
    expect(c.stderr()).toContain('version');
  });

  it('validate never leaks the token through a ${QUALOR_TOKEN} reference elsewhere in qualor.yml', async () => {
    const root = tmp();
    writeTree(root, { 'qualor.yml': 'version: 1\nproject:\n  version: ${QUALOR_TOKEN}\n' });
    const c = captureIO({ cwd: root, env: { QUALOR_TOKEN: 'qlr_pat_should_not_leak' } });
    expect(await main(['validate'], c.io)).toBe(0);
    expect(c.stdout()).not.toContain('qlr_pat_should_not_leak');
    expect(c.stderr()).toContain('refers to a secret variable and is not interpolated');
  });
});
