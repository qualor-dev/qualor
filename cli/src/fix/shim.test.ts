import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { useTempDirs, writeTree } from '../../test/tmp';
import { resolveTool, shimScript } from './shim';

const tmp = useTempDirs();

/** The shim npm's installer writes for npm itself (C:/Program Files/nodejs/npm.cmd). */
const NPM_CMD = [
  ":: Created by npm, please don't edit manually.",
  '@ECHO OFF',
  '',
  'SETLOCAL',
  '',
  'SET "NODE_EXE=%~dp0\\node.exe"',
  'IF NOT EXIST "%NODE_EXE%" (',
  '  SET "NODE_EXE=node"',
  ')',
  '',
  'SET "NPM_PREFIX_JS=%~dp0\\node_modules\\npm\\bin\\npm-prefix.js"',
  'SET "NPM_CLI_JS=%~dp0\\node_modules\\npm\\bin\\npm-cli.js"',
  'FOR /F "delims=" %%F IN (\'CALL "%NODE_EXE%" "%NPM_PREFIX_JS%"\') DO (',
  '  SET "NPM_PREFIX_NPM_CLI_JS=%%F\\node_modules\\npm\\bin\\npm-cli.js"',
  ')',
  'IF EXIST "%NPM_PREFIX_NPM_CLI_JS%" (',
  '  SET "NPM_CLI_JS=%NPM_PREFIX_NPM_CLI_JS%"',
  ')',
  '',
  '"%NODE_EXE%" "%NPM_CLI_JS%" %*',
  '',
].join('\r\n');

/** A shim of npm's cmd-shim (`npm install -g pnpm`: %APPDATA%/npm/pnpm.cmd). */
const cmdShim = (script: string) =>
  [
    '@ECHO off',
    'GOTO start',
    ':find_dp0',
    'SET dp0=%~dp0',
    'EXIT /b',
    ':start',
    'SETLOCAL',
    'CALL :find_dp0',
    '',
    'IF EXIST "%dp0%\\node.exe" (',
    '  SET "_prog=%dp0%\\node.exe"',
    ') ELSE (',
    '  SET "_prog=node"',
    '  SET PATHEXT=%PATHEXT:;.JS;=;%',
    ')',
    '',
    `endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & "%_prog%"  "%dp0%\\${script}" %*`,
    '',
  ].join('\r\n');

const WIN = { platform: 'win32' as const };

describe('shimScript', () => {
  it('reads the script of npm’s own shim and of a cmd-shim', () => {
    expect(shimScript(NPM_CMD)).toBe('node_modules\\npm\\bin\\npm-cli.js');
    expect(shimScript(cmdShim('node_modules\\pnpm\\bin\\pnpm.cjs'))).toBe(
      'node_modules\\pnpm\\bin\\pnpm.cjs',
    );
  });

  it('reads nothing from a .cmd that is no node cmd-shim', () => {
    expect(shimScript('@echo off\r\n"%JAVA_HOME%\\bin\\java.exe" -classpath x %*\r\n')).toBeNull();
    // A cmd-shim of a native program (`bun.cmd`) runs no node.
    expect(shimScript('@ECHO off\r\n"%dp0%\\node_modules\\bun\\bin\\bun.exe"   %*\r\n')).toBeNull();
  });
});

describe('resolveTool on Windows (ruling T12a)', () => {
  it('runs npm’s shim as the node.exe beside it with the npm-cli.js beside it', () => {
    const dir = tmp('qualor-shim-');
    writeTree(dir, {
      'npm.cmd': NPM_CMD,
      'node.exe': '',
      'node_modules/npm/bin/npm-cli.js': '',
    });
    expect(resolveTool('npm', { root: tmp(), env: { PATH: dir }, ...WIN })).toEqual({
      command: path.join(dir, 'node.exe'),
      args: [path.join(dir, 'node_modules', 'npm', 'bin', 'npm-cli.js')],
    });
  });

  it('runs a cmd-shim without node.exe beside it with the node on PATH', () => {
    const shims = tmp('qualor-shim-');
    const nodeDir = tmp('qualor-node-');
    writeTree(shims, {
      'pnpm.cmd': cmdShim('node_modules\\pnpm\\bin\\pnpm.cjs'),
      'node_modules/pnpm/bin/pnpm.cjs': '',
    });
    writeTree(nodeDir, { 'node.exe': '' });
    const env = { PATH: `${shims};${nodeDir}` };
    expect(resolveTool('pnpm', { root: tmp(), env, ...WIN })).toEqual({
      command: path.join(nodeDir, 'node.exe'),
      args: [path.join(shims, 'node_modules', 'pnpm', 'bin', 'pnpm.cjs')],
    });
  });

  it('prefers a real executable to a shim', () => {
    const dir = tmp('qualor-shim-');
    writeTree(dir, { 'yarn.exe': '', 'yarn.cmd': cmdShim('node_modules\\yarn\\bin\\yarn.js') });
    expect(resolveTool('yarn', { root: tmp(), env: { PATH: dir }, ...WIN })).toEqual({
      command: path.join(dir, 'yarn.exe'),
      args: [],
    });
  });

  it('does not serve a shim whose script lies outside its directory, or is missing', () => {
    const base = tmp('qualor-shim-');
    writeTree(base, {
      'bin/yarn.cmd': cmdShim('..\\elsewhere\\yarn.js'),
      'bin/node.exe': '',
      'elsewhere/yarn.js': '',
      'bin2/pnpm.cmd': cmdShim('node_modules\\pnpm\\bin\\pnpm.cjs'),
      'bin2/node.exe': '',
    });
    const outside = resolveTool('yarn', {
      root: tmp(),
      env: { PATH: path.join(base, 'bin') },
      ...WIN,
    });
    expect(outside).toEqual({ problem: expect.stringContaining('yarn.cmd') });
    const missing = resolveTool('pnpm', {
      root: tmp(),
      env: { PATH: path.join(base, 'bin2') },
      ...WIN,
    });
    expect(missing).toEqual({ problem: expect.stringContaining('pnpm.cmd') });
  });

  it('does not serve a .cmd that is no node cmd-shim, and says why', () => {
    const dir = tmp('qualor-shim-');
    writeTree(dir, { 'mvn.cmd': '@echo off\r\n"%JAVA_HOME%\\bin\\java.exe" -classpath x %*\r\n' });
    expect(resolveTool('mvn', { root: tmp(), env: { PATH: dir }, ...WIN })).toEqual({
      problem: expect.stringMatching(/mvn\.cmd.*shell/),
    });
  });

  it('never takes a shim or its node from the repository', () => {
    const root = tmp('qualor-repo-');
    writeTree(root, {
      'bin/npm.cmd': NPM_CMD,
      'bin/node.exe': '',
      'bin/node_modules/npm/bin/npm-cli.js': '',
    });
    expect(resolveTool('npm', { root, env: { PATH: path.join(root, 'bin') }, ...WIN })).toBeNull();
  });

  it('is null for a tool that is not installed, and looks for no .cmd off Windows', () => {
    const dir = tmp('qualor-shim-');
    writeTree(dir, { 'npm.cmd': NPM_CMD, 'node.exe': '', 'node_modules/npm/bin/npm-cli.js': '' });
    expect(resolveTool('yarn', { root: tmp(), env: { PATH: dir }, ...WIN })).toBeNull();
    expect(resolveTool('npm', { root: tmp(), env: { PATH: dir }, platform: 'linux' })).toBeNull();
  });
});
