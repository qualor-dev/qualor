import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { useTempDirs, writeTree } from '../../test/tmp';
import { CliError } from '../errors';
import { createLogger, silentLogger } from '../log';
import { loadSettings, requireServer } from './settings';

const tmp = useTempDirs();
const GITLAB = { GITLAB_CI: 'true', CI_PROJECT_PATH: 'acme/from-ci' };

function failure(run: () => unknown): CliError {
  try {
    run();
  } catch (err) {
    if (err instanceof CliError) return err;
    throw err;
  }
  throw new Error('expected a CliError');
}

describe('loadSettings', () => {
  it('works without qualor.yml in GitLab CI and takes the key from CI_PROJECT_PATH', () => {
    const root = tmp();
    const s = loadSettings({
      cwd: root,
      env: { ...GITLAB, QUALOR_URL: 'https://qualor.acme.test', QUALOR_TOKEN: 'qlr_prj_x' },
      flags: {},
      log: silentLogger,
    });
    expect(s.configPath).toBeNull();
    expect(s.config.project.key).toBe('acme/from-ci');
    expect(s.config.server.url).toBe('https://qualor.acme.test');
    expect(s.token).toBe('qlr_prj_x');
    expect(s.config.analyzers.eslint.timeoutSeconds).toBe(900);
    expect(requireServer(s)).toEqual({ url: 'https://qualor.acme.test', token: 'qlr_prj_x' });
  });

  it('rejects an unknown key, a token key and version 2 with exit code 2', () => {
    const root = tmp();
    writeTree(root, { 'qualor.yml': 'version: 1\nanalyzers:\n  eslnt: {}\n' });
    const unknown = failure(() =>
      loadSettings({ cwd: root, env: {}, flags: {}, log: silentLogger }),
    );
    expect(unknown.exitCode).toBe(2);
    expect(unknown.message).toContain('eslnt');

    writeTree(root, { 'qualor.yml': 'version: 1\nserver:\n  token: abc\n' });
    const token = failure(() => loadSettings({ cwd: root, env: {}, flags: {}, log: silentLogger }));
    expect(token.exitCode).toBe(2);
    expect(token.message).toContain('QUALOR_TOKEN');
    expect(token.message).not.toContain('abc');

    writeTree(root, { 'qualor.yml': 'version: 2\n' });
    const version = failure(() =>
      loadSettings({ cwd: root, env: {}, flags: {}, log: silentLogger }),
    );
    expect(version.exitCode).toBe(2);
    expect(version.message).toContain('version');
  });

  it('rejects an unknown Ruff selector as a config error naming it, exit code 2', () => {
    const root = tmp();
    writeTree(root, { 'qualor.yml': 'version: 1\nanalyzers:\n  ruff:\n    select: [F, ZZZ9]\n' });
    const err = failure(() => loadSettings({ cwd: root, env: {}, flags: {}, log: silentLogger }));
    expect(err.exitCode).toBe(2);
    expect(err.message).toContain('analyzers.ruff.select.1');
    expect(err.message).toContain('unknown Ruff rule selector "ZZZ9"');
  });

  it('rejects Semgrep registry configs with a message about the network', () => {
    const root = tmp();
    writeTree(root, {
      'qualor.yml': 'version: 1\nanalyzers:\n  semgrep:\n    configs: [p/default]\n',
    });
    const err = failure(() => loadSettings({ cwd: root, env: {}, flags: {}, log: silentLogger }));
    expect(err.exitCode).toBe(2);
    expect(err.message).toContain('network');
  });

  it('resolves project.key by precedence: flag > env > file > CI', () => {
    const root = tmp();
    writeTree(root, { 'qualor.yml': 'version: 1\nproject:\n  key: from/file\n' });
    const key = (flags: { projectKey?: string }, env: Record<string, string>) =>
      loadSettings({ cwd: root, env: { ...GITLAB, ...env }, flags, log: silentLogger }).config
        .project.key;
    expect(key({ projectKey: 'from/flag' }, { QUALOR_PROJECT_KEY: 'from/env' })).toBe('from/flag');
    expect(key({}, { QUALOR_PROJECT_KEY: 'from/env' })).toBe('from/env');
    expect(key({}, {})).toBe('from/file');
    writeTree(root, { 'qualor.yml': 'version: 1\n' });
    expect(key({}, {})).toBe('acme/from-ci');
  });

  it('resolves server.url by precedence: env > file', () => {
    const root = tmp();
    writeTree(root, { 'qualor.yml': 'version: 1\nserver:\n  url: https://file.test\n' });
    const url = (env: Record<string, string>) =>
      loadSettings({ cwd: root, env, flags: {}, log: silentLogger }).config.server.url;
    expect(url({ QUALOR_URL: 'https://env.test' })).toBe('https://env.test');
    expect(url({})).toBe('https://file.test');
  });

  it('takes --server-url over QUALOR_URL over the file, and records where the URL came from', () => {
    const root = tmp();
    writeTree(root, { 'qualor.yml': 'version: 1\nserver:\n  url: https://file.test\n' });
    const load = (env: Record<string, string>, serverUrl?: string) =>
      loadSettings({
        cwd: root,
        env,
        flags: serverUrl === undefined ? {} : { serverUrl },
        log: silentLogger,
      });
    const flag = load({ QUALOR_URL: 'https://env.test' }, 'https://flag.test');
    expect([flag.config.server.url, flag.serverUrlSource]).toEqual(['https://flag.test', 'flag']);
    const env = load({ QUALOR_URL: 'https://env.test' });
    expect([env.config.server.url, env.serverUrlSource]).toEqual(['https://env.test', 'env']);
    const file = load({});
    expect([file.config.server.url, file.serverUrlSource]).toEqual(['https://file.test', 'file']);
    const none = loadSettings({ cwd: tmp(), env: {}, flags: {}, log: silentLogger });
    expect(none.serverUrlSource).toBeNull();
    expect(() => load({}, 'ftp://flag.test')).toThrow(expect.objectContaining({ exitCode: 2 }));
  });

  it('takes --ca-file over QUALOR_CA_FILE over the file, and records where it came from (V8)', () => {
    const root = tmp();
    writeTree(root, { 'qualor.yml': 'version: 1\nserver:\n  caFile: certs/file.pem\n' });
    const load = (env: Record<string, string>, caFile?: string) =>
      loadSettings({
        cwd: root,
        env,
        flags: caFile === undefined ? {} : { caFile },
        log: silentLogger,
      });
    const flag = load({ QUALOR_CA_FILE: '/env.pem' }, '/flag.pem');
    expect([flag.config.server.caFile, flag.caFileSource]).toEqual(['/flag.pem', 'flag']);
    const env = load({ QUALOR_CA_FILE: '/env.pem' });
    expect([env.config.server.caFile, env.caFileSource]).toEqual(['/env.pem', 'env']);
    const file = load({ QUALOR_CA_FILE: '  ' });
    expect([file.config.server.caFile, file.caFileSource]).toEqual(['certs/file.pem', 'file']);
    const none = loadSettings({ cwd: tmp(), env: {}, flags: {}, log: silentLogger });
    expect([none.config.server.caFile, none.caFileSource]).toEqual([null, null]);
    writeTree(root, { 'qualor.yml': 'version: 1\nserver:\n  caFile: ""\n' });
    expect(load({}).caFileSource).toBeNull();
  });

  it('interpolates ${VAR} and ${VAR:-default}, warning about unset variables', () => {
    const root = tmp();
    writeTree(root, {
      'qualor.yml':
        'version: 1\nproject:\n  key: ${KEY:-acme/default}\n  version: ${CI_COMMIT_TAG}\n',
    });
    const lines: string[] = [];
    const s = loadSettings({
      cwd: root,
      env: {},
      flags: {},
      log: createLogger('warn', (t) => lines.push(t)),
    });
    expect(s.config.project.key).toBe('acme/default');
    expect(s.config.project.version).toBe('');
    expect(lines.join('')).toContain(
      `${path.join(root, 'qualor.yml')}: \${CI_COMMIT_TAG} is not set`,
    );
  });

  it('never interpolates a secret-named variable, even with a fallback, and still interpolates a normal one', () => {
    const root = tmp();
    writeTree(root, {
      'qualor.yml':
        'version: 1\n' +
        'project:\n' +
        '  key: acme/app\n' +
        '  version: ${QUALOR_TOKEN}\n' +
        'server:\n' +
        '  caFile: ${MY_API_KEY:-fallback}\n' +
        'scm:\n' +
        '  mainBranch: ${CI_BUILD_LABEL:-stable}\n',
    });
    const lines: string[] = [];
    const s = loadSettings({
      cwd: root,
      env: { QUALOR_TOKEN: 'qlr_pat_should_not_leak', MY_API_KEY: 'also_should_not_leak' },
      flags: {},
      log: createLogger('warn', (t) => lines.push(t)),
    });
    expect(s.config.project.version).toBe('');
    expect(s.config.server.caFile).toBe('');
    expect(s.config.scm.mainBranch).toBe('stable');
    const warnings = lines.join('');
    expect(warnings).toContain(
      '${QUALOR_TOKEN} refers to a secret variable and is not interpolated',
    );
    expect(warnings).toContain('${MY_API_KEY} refers to a secret variable and is not interpolated');
    const serialized = JSON.stringify(s.config);
    expect(serialized).not.toContain('qlr_pat_should_not_leak');
    expect(serialized).not.toContain('also_should_not_leak');
  });

  it('cannot be tricked into interpolating a secret by a second pass (nested and adjacent references)', () => {
    const root = tmp();
    const TOKEN = 'qlr_pat_bypass_must_not_leak';
    writeTree(root, {
      'qualor.yml':
        'version: 1\n' +
        'project:\n' +
        '  key: acme/app\n' +
        '  version: "$${QUALOR_TOKEN}{QUALOR_TOKEN}"\n' +
        '  name: "${QUALOR_TOKEN}${QUALOR_TOKEN}$${QUALOR_TOKEN}{QUALOR_TOKEN}}"\n' +
        'server:\n' +
        '  caFile: "${UNSET_VAR:-${QUALOR_TOKEN}}"\n' +
        'scm:\n' +
        '  mainBranch: "${INDIRECT}"\n',
    });
    const lines: string[] = [];
    const s = loadSettings({
      cwd: root,
      env: { QUALOR_TOKEN: TOKEN, INDIRECT: '${QUALOR_TOKEN}' },
      flags: {},
      log: createLogger('warn', (t) => lines.push(t)),
    });
    expect(s.token).toBe(TOKEN);
    expect(JSON.stringify(s.config)).not.toContain(TOKEN);
    expect(s.config.project.version).toBe('${QUALOR_TOKEN}');
    expect(lines.join('')).toContain(
      '${QUALOR_TOKEN} refers to a secret variable and is not interpolated',
    );
  });

  it('treats *_SECRET_ACCESS_KEY, *_ACCESS_KEY, *_PASS and *_PASSPHRASE as secrets, but not every *_KEY', () => {
    const root = tmp();
    writeTree(root, {
      'qualor.yml':
        'version: 1\n' +
        'project:\n' +
        '  key: ${PROJECT_KEY}\n' +
        '  name: "${AWS_SECRET_ACCESS_KEY}|${MINIO_ACCESS_KEY}|${DB_PASS}|${GPG_PASSPHRASE}|${BYPASS}|${AWS_ACCESS_KEY_ID}"\n',
    });
    const s = loadSettings({
      cwd: root,
      env: {
        PROJECT_KEY: 'acme/app',
        AWS_SECRET_ACCESS_KEY: 'x1',
        MINIO_ACCESS_KEY: 'x2',
        DB_PASS: 'x3',
        GPG_PASSPHRASE: 'x4',
        BYPASS: 'plain',
        AWS_ACCESS_KEY_ID: 'AKIA',
      },
      flags: {},
      log: silentLogger,
    });
    expect(s.config.project.key).toBe('acme/app');
    expect(s.config.project.name).toBe('||||plain|AKIA');
  });

  it('uses --config and QUALOR_CONFIG, and fails when an explicit file is missing', () => {
    const root = tmp();
    writeTree(root, { 'ci/q.yml': 'version: 1\nproject:\n  key: from/explicit\n' });
    const s = loadSettings({
      cwd: root,
      env: {},
      flags: { config: 'ci/q.yml' },
      log: silentLogger,
    });
    expect(s.configPath).toBe(path.join(root, 'ci', 'q.yml'));
    expect(s.config.project.key).toBe('from/explicit');
    const viaEnv = loadSettings({
      cwd: root,
      env: { QUALOR_CONFIG: 'ci/q.yml' },
      flags: {},
      log: silentLogger,
    });
    expect(viaEnv.config.project.key).toBe('from/explicit');
    const missing = failure(() =>
      loadSettings({ cwd: root, env: {}, flags: { config: 'nope.yml' }, log: silentLogger }),
    );
    expect(missing.exitCode).toBe(2);
    expect(missing.message).toContain('config file not found');
  });

  it('--token-file wins over QUALOR_TOKEN (config.md §5), and QUALOR_TOKEN is used without it', () => {
    const root = tmp();
    writeTree(root, { 'token.txt': 'qlr_from_file\n' });
    const env = { QUALOR_TOKEN: 'qlr_from_env' };
    expect(
      loadSettings({ cwd: root, env, flags: { tokenFile: 'token.txt' }, log: silentLogger }).token,
    ).toBe('qlr_from_file');
    expect(loadSettings({ cwd: root, env, flags: {}, log: silentLogger }).token).toBe(
      'qlr_from_env',
    );
  });

  it('reads --token-file (trimmed) and rejects a missing or empty one', () => {
    const root = tmp();
    writeTree(root, { 'token.txt': '  qlr_pat_secret\n', 'empty.txt': '\n' });
    const s = loadSettings({
      cwd: root,
      env: { QUALOR_TOKEN: 'ignored' },
      flags: { tokenFile: 'token.txt' },
      log: silentLogger,
    });
    expect(s.token).toBe('qlr_pat_secret');
    for (const tokenFile of ['missing.txt', 'empty.txt']) {
      const err = failure(() =>
        loadSettings({ cwd: root, env: {}, flags: { tokenFile }, log: silentLogger }),
      );
      expect(err.exitCode).toBe(2);
    }
  });

  it('appends --sarif and --coverage to the file lists, and --no-wait turns off gate.wait', () => {
    const root = tmp();
    writeTree(root, {
      'qualor.yml':
        'version: 1\nsarif:\n  - path: a.sarif\ncoverage:\n  reports:\n    - path: lcov.info\n',
    });
    const s = loadSettings({
      cwd: root,
      env: {},
      flags: { sarif: ['b.sarif'], coverage: ['jacoco.xml'], wait: false },
      log: silentLogger,
    });
    expect(s.config.sarif.map((x) => x.path)).toEqual(['a.sarif', 'b.sarif']);
    expect(s.config.coverage.reports).toEqual([
      { path: 'lcov.info', format: 'auto' },
      { path: 'jacoco.xml', format: 'auto' },
    ]);
    expect(s.config.gate.wait).toBe(false);
  });

  it('reports invalid YAML and a non-mapping document with the file name', () => {
    const root = tmp();
    writeTree(root, { 'qualor.yml': 'version: 1\n  bad: [indent\n' });
    const yaml = failure(() => loadSettings({ cwd: root, env: {}, flags: {}, log: silentLogger }));
    expect(yaml.exitCode).toBe(2);
    expect(yaml.message).toContain('qualor.yml');
    writeTree(root, { 'qualor.yml': '- just\n- a list\n' });
    const list = failure(() => loadSettings({ cwd: root, env: {}, flags: {}, log: silentLogger }));
    expect(list.message).toContain('mapping');
  });

  it('requireServer names both missing settings without printing the token', () => {
    const root = tmp();
    const s = loadSettings({ cwd: root, env: {}, flags: {}, log: silentLogger });
    const err = failure(() => requireServer(s));
    expect(err.exitCode).toBe(2);
    expect(err.message).toContain('QUALOR_URL');
    expect(err.message).toContain('QUALOR_TOKEN');
  });
});
