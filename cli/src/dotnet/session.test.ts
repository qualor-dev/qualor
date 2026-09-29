import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { createLogger, silentLogger } from '../log';
import { useTempDirs } from '../../test/tmp';
import {
  createSession,
  isFresh,
  listLogs,
  readProjectRecords,
  readSession,
  removeSession,
  SESSION_DIR,
  type SessionInfo,
} from './session';

const tmp = useTempDirs();
const info = (
  root: string,
  analyzers: SessionInfo['analyzers'] = { roslynator: [], sonar: [] },
): SessionInfo => ({
  version: 1,
  id: 'a'.repeat(32),
  root,
  startedAt: '2026-09-25T10:00:00.000Z',
  cli: '0.0.0-test',
  analyzers,
});

describe('session files (config.md §6.1, rulings D1–D3)', () => {
  it('creates session.json, session.props, sarif/ and projects/, emptying an old session', () => {
    const root = tmp();
    mkdirSync(path.join(root, SESSION_DIR, 'sarif'), { recursive: true });
    writeFileSync(path.join(root, SESSION_DIR, 'sarif', 'old.sarif'), '{}');
    const analyzers = { roslynator: ['/opt/a;b/R.dll'], sonar: ['/opt/S.dll'] };
    createSession(root, info(root, analyzers));
    expect(readSession(root)).toEqual(info(root, analyzers));
    expect(listLogs(root)).toEqual([]);
    expect(existsSync(path.join(root, SESSION_DIR, 'projects'))).toBe(true);
    const props = readFileSync(path.join(root, SESSION_DIR, 'session.props'), 'utf8');
    expect(props).toContain('<QualorBundledAnalyzer Include="/opt/a%3Bb/R.dll" />');
    expect(props).toContain('<QualorBundledSonarAnalyzer Include="/opt/S.dll" />');
  });

  it('refuses a session.json from an older CLI (a flat analyzers array) as though there were none (Task 4)', () => {
    const root = tmp();
    createSession(root, info(root));
    // Before Task 4, `analyzers` was a flat array of Roslynator paths; a CLI upgraded mid-build
    // must not read that shape as this session's own (config.md §6.1): `end` then reports no
    // session, rather than misreading the old array as today's `{ roslynator, sonar }` object.
    writeFileSync(
      path.join(root, SESSION_DIR, 'session.json'),
      `${JSON.stringify({ ...info(root), analyzers: ['/opt/a/Roslynator.dll'] }, null, 2)}\n`,
    );
    expect(readSession(root)).toBeNull();
  });

  it('refuses a .qualor that is a link or not a directory', () => {
    const root = tmp();
    writeFileSync(path.join(root, '.qualor'), 'x');
    expect(() => createSession(root, info(root))).toThrow(/\.qualor/);
    const other = tmp();
    const outside = tmp();
    symlinkSync(outside, path.join(other, '.qualor'), 'junction');
    expect(() => createSession(other, info(other))).toThrow(/\.qualor/);
  });

  it('reads project records written by the hook, ignoring anything else', () => {
    const root = tmp();
    createSession(root, info(root));
    const projects = path.join(root, SESSION_DIR, 'projects');
    writeFileSync(
      path.join(projects, '-15.txt'),
      '\uFEFF/r/src/A/A.csproj\r\nnet8.0\r\n/r/.qualor/dotnet/sarif/A--15-net8.0.sarif\r\n',
    );
    writeFileSync(path.join(projects, 'bad.txt'), 'only one line\n');
    writeFileSync(path.join(projects, 'x.json'), '{}');
    expect(readProjectRecords(root, silentLogger)).toEqual([
      {
        project: '/r/src/A/A.csproj',
        targetFramework: 'net8.0',
        log: '/r/.qualor/dotnet/sarif/A--15-net8.0.sarif',
      },
    ]);
  });

  it('skips a record it cannot read, with a debug line, instead of failing (final review R12, M3)', () => {
    const root = tmp();
    createSession(root, info(root));
    const projects = path.join(root, SESSION_DIR, 'projects');
    writeFileSync(path.join(projects, 'a.txt'), '/r/A.csproj\nnet8.0\n/r/A.sarif\n');
    writeFileSync(path.join(projects, 'huge.txt'), 'x'.repeat(100_000));
    const lines: string[] = [];
    expect(
      readProjectRecords(
        root,
        createLogger('debug', (t) => lines.push(t)),
      ),
    ).toEqual([{ project: '/r/A.csproj', targetFramework: 'net8.0', log: '/r/A.sarif' }]);
    expect(lines.join('')).toMatch(/huge\.txt was not read/);
  });

  it('lists regular .sarif files only and judges freshness against session.json', () => {
    const root = tmp();
    createSession(root, info(root));
    const sarif = path.join(root, SESSION_DIR, 'sarif');
    writeFileSync(path.join(sarif, 'A.sarif'), '{}');
    writeFileSync(path.join(sarif, 'note.txt'), '');
    mkdirSync(path.join(sarif, 'dir.sarif'));
    expect(listLogs(root)).toEqual([path.join(sarif, 'A.sarif')]);
    const old = path.join(sarif, 'Old.sarif');
    writeFileSync(old, '{}');
    const past = new Date(Date.now() - 60_000);
    utimesSync(old, past, past);
    expect(isFresh(path.join(sarif, 'A.sarif'), root)).toBe(true);
    expect(isFresh(old, root)).toBe(false);
    expect(isFresh(path.join(sarif, 'missing.sarif'), root)).toBe(false);
  });

  it('removes the session directory, and readSession then returns null', () => {
    const root = tmp();
    createSession(root, info(root));
    removeSession(root);
    expect(readSession(root)).toBeNull();
    expect(existsSync(path.join(root, '.qualor'))).toBe(true); // only .qualor/dotnet goes
  });

  it('refuses to read a session directory that became a link', () => {
    const root = tmp();
    createSession(root, info(root));
    const sessionPath = path.join(root, ...SESSION_DIR.split('/'));
    rmSync(sessionPath, { recursive: true, force: true });
    const outside = tmp();
    symlinkSync(outside, sessionPath, 'junction');
    expect(() => readProjectRecords(root, silentLogger)).toThrow(/\.qualor\/dotnet/);
    expect(() => listLogs(root)).toThrow(/\.qualor\/dotnet/);
  });

  it('refuses to remove or read when .qualor itself became a link (review round 1, finding 3)', () => {
    const root = tmp();
    createSession(root, info(root));
    const qualorPath = path.join(root, '.qualor');
    rmSync(qualorPath, { recursive: true, force: true });
    const outside = tmp();
    symlinkSync(outside, qualorPath, 'junction');
    expect(() => readProjectRecords(root, silentLogger)).toThrow(/\.qualor/);
    expect(() => listLogs(root)).toThrow(/\.qualor/);
    expect(() => removeSession(root)).toThrow(/\.qualor/);
  });
});
