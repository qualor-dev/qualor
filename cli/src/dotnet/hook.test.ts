import * as fs from 'node:fs';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { CliError } from '../errors';
import { useTempDirs } from '../../test/tmp';
import {
  HOOK_FILE,
  HOOK_MARKER,
  hookPath,
  hookText,
  installHook,
  msbuildEscape,
  msbuildUserDir,
  removeHook,
} from './hook';

// renameSync, readFileSync and lstatSync are replaced by pass-through spies, so individual tests
// can force a rename, a read or a stat to fail (review round 1, findings 1 and 2; Task 9's Linux
// run) without depending on OS-specific permission or error-code behaviour.
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof fs>();
  return {
    ...actual,
    renameSync: vi.fn(actual.renameSync),
    readFileSync: vi.fn(actual.readFileSync),
    lstatSync: vi.fn(actual.lstatSync),
  };
});

const tmp = useTempDirs();

describe('msbuildUserDir (config.md §4, §6.1)', () => {
  it('prefers QUALOR_MSBUILD_USER_DIR', () => {
    expect(msbuildUserDir({ QUALOR_MSBUILD_USER_DIR: '/x/MSBuild' }, 'linux', '/home/u')).toBe(
      '/x/MSBuild',
    );
  });
  it('uses LOCALAPPDATA on Windows', () => {
    expect(
      msbuildUserDir({ LOCALAPPDATA: 'C:\\Users\\u\\AppData\\Local' }, 'win32', 'C:\\Users\\u'),
    ).toBe(path.join('C:\\Users\\u\\AppData\\Local', 'Microsoft', 'MSBuild'));
  });
  it('uses an absolute XDG_DATA_HOME, else ~/.local/share, on Linux', () => {
    expect(msbuildUserDir({ XDG_DATA_HOME: '/data' }, 'linux', '/home/u')).toBe(
      path.join('/data', 'Microsoft', 'MSBuild'),
    );
    expect(msbuildUserDir({ XDG_DATA_HOME: 'rel' }, 'linux', '/home/u')).toBe(
      path.join('/home/u', '.local', 'share', 'Microsoft', 'MSBuild'),
    );
  });
  it('uses ~/Library/Application Support on macOS, ignoring XDG_DATA_HOME (ruling R6)', () => {
    expect(msbuildUserDir({}, 'darwin', '/Users/u')).toBe(
      path.join('/Users/u', 'Library', 'Application Support', 'Microsoft', 'MSBuild'),
    );
    // Since .NET 8, LocalApplicationData on macOS is ~/Library/Application Support, not
    // $XDG_DATA_HOME; a set XDG_DATA_HOME therefore has no effect there.
    expect(msbuildUserDir({ XDG_DATA_HOME: '/data' }, 'darwin', '/Users/u')).toBe(
      path.join('/Users/u', 'Library', 'Application Support', 'Microsoft', 'MSBuild'),
    );
  });
  it('refuses a relative QUALOR_MSBUILD_USER_DIR', () => {
    expect(() => msbuildUserDir({ QUALOR_MSBUILD_USER_DIR: 'rel' }, 'linux', '/h')).toThrow(
      CliError,
    );
  });
});

describe('the hook text', () => {
  const text = hookText();
  it('starts with the marker and is well-formed', () => {
    expect(text.startsWith(`${HOOK_MARKER}\n`)).toBe(true);
    expect(text).toContain('<Project>');
    expect(text.trimEnd().endsWith('</Project>')).toBe(true);
  });
  it('does nothing without a live session (Review Focus 2)', () => {
    expect(text).toContain(
      'GetDirectoryNameOfFileAbove($(MSBuildProjectDirectory), .qualor/dotnet/session.json)',
    );
    expect(text).toContain('GetLastWriteTime(');
    expect(text).not.toContain('GetLastWriteTimeUtc'); // refused by MSBuild (probe P3)
    expect(text).toMatch(/'\$\(Language\)' == 'C#'/);
    // Whole days, an integer: TotalHours is a double that MSBuild prints as 8.026275E-05 for a
    // session a fraction of a second old, which its numeric comparison refuses (MSB4086; found by
    // real.test.ts on Linux, plan 2D Task 8). Days < 1 holds exactly when TotalHours < 24.
    expect(text).toContain('.Days)</_QualorAgeDays>');
    expect(text).not.toContain('TotalHours');
    expect(text).toMatch(/\$\(_QualorAgeDays\) &lt; 1\b/);
    // Every top-level property group, target and import after the activation test is
    // conditioned on it (the groups nested inside a target inherit the target's condition).
    const afterActivation = text.slice(text.indexOf('  <Import'));
    const topLevel = afterActivation.match(/^ {2}<(PropertyGroup|Target|Import)\b[^>]*>/gm) ?? [];
    expect(topLevel).toHaveLength(4);
    for (const tag of topLevel) expect(tag).toMatch(/_QualorActive/);
  });
  it('turns warnings from errors off and points ErrorLog at the session before CoreCompile', () => {
    expect(text).toContain('<TreatWarningsAsErrors>false</TreatWarningsAsErrors>');
    expect(text).toContain(
      '<CodeAnalysisTreatWarningsAsErrors>false</CodeAnalysisTreatWarningsAsErrors>',
    );
    expect(text).toContain('BeforeTargets="CoreCompile"');
    expect(text).toContain('<ErrorLog>$(_QualorLog),version=2.1</ErrorLog>');
    expect(text).toContain('AfterTargets="CoreCompile"');
    expect(text).toContain('<AnalysisMode>All</AnalysisMode>');
  });
  it('also turns the MSBuild warnings-as-errors properties off, in both places (final review R12, M1)', () => {
    const count = (needle: string) => text.split(needle).length - 1;
    expect(count('<TreatWarningsAsErrors>false</TreatWarningsAsErrors>')).toBe(2);
    expect(count('<MSBuildTreatWarningsAsErrors>false</MSBuildTreatWarningsAsErrors>')).toBe(2);
    expect(count('<MSBuildWarningsAsErrors></MSBuildWarningsAsErrors>')).toBe(2);
  });
  it('does not enforce code style in the build: an IDE rule set to error could fail it (final review R11)', () => {
    expect(text).not.toContain('EnforceCodeStyleInBuild');
  });
  it('adds the bundled analyzers only when the project has no Roslynator of its own', () => {
    expect(text).toContain("StartsWith('Roslynator.')");
    expect(text).toContain('<Analyzer Include="@(QualorBundledAnalyzer)" />');
  });
});

describe('installHook / removeHook', () => {
  it('writes the hook and removes only its own file', () => {
    const userDir = tmp();
    installHook(userDir);
    const file = hookPath(userDir);
    expect(file).toBe(
      path.join(userDir, 'Current', 'Microsoft.Common.targets', 'ImportBefore', HOOK_FILE),
    );
    expect(readFileSync(file, 'utf8')).toBe(hookText());
    expect(removeHook(userDir)).toBe(true);
    expect(existsSync(file)).toBe(false);
    expect(removeHook(userDir)).toBe(false);
  });
  it('never overwrites or removes a file of that name without the marker', () => {
    const userDir = tmp();
    const file = hookPath(userDir);
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, '<Project />');
    expect(() => installHook(userDir)).toThrow(/not Qualor's/);
    expect(removeHook(userDir)).toBe(false);
    expect(readFileSync(file, 'utf8')).toBe('<Project />');
  });
  it('cleans up its temp file and rethrows on a failed rename, leaving no partial hook (ruling R4)', () => {
    const userDir = tmp();
    vi.mocked(fs.renameSync).mockImplementationOnce(() => {
      throw new Error('EBUSY: resource busy or locked, rename');
    });
    expect(() => installHook(userDir)).toThrow('EBUSY');
    const importBefore = path.dirname(hookPath(userDir));
    const parent = path.dirname(importBefore);
    // ImportBefore/ is wildcard-imported by MSBuild: no partial or stray file was left in it.
    expect(readdirSync(importBefore)).toEqual([]);
    // The temp file lived beside ImportBefore/, on the same file system; it was removed too.
    expect(readdirSync(parent)).toEqual(['ImportBefore']);
    // A later install is unaffected by the failed one.
    installHook(userDir);
    expect(readFileSync(hookPath(userDir), 'utf8')).toBe(hookText());
  });
  it('treats ENOTDIR (a blocked parent, as Linux reports it) as absent, like ENOENT (Task 9 Linux run)', () => {
    // A file blocking Current/ or Microsoft.Common.targets/ makes the target path unreachable.
    // Windows reports that as ENOENT from lstat; Linux reports ENOTDIR (checked directly on both).
    // Either way installHook must fall through to its ordinary mkdir/write (which fails with the
    // same OS error, handled by `begin` as "the hook cannot be written"), never as a foreign file
    // at the hook's own path (config.md §6.1 step 2, exit 2).
    const userDir = tmp();
    vi.mocked(fs.lstatSync).mockImplementationOnce(() => {
      const err = new Error('ENOTDIR: not a directory, lstat') as NodeJS.ErrnoException;
      err.code = 'ENOTDIR';
      throw err;
    });
    installHook(userDir);
    expect(readFileSync(hookPath(userDir), 'utf8')).toBe(hookText());
  });
  it('treats a file it cannot read as foreign, not absent (ruling R4)', () => {
    const userDir = tmp();
    const file = hookPath(userDir);
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, '<Project />');
    vi.mocked(fs.readFileSync).mockImplementationOnce(() => {
      const err = new Error('EACCES: permission denied, open') as NodeJS.ErrnoException;
      err.code = 'EACCES';
      throw err;
    });
    expect(() => installHook(userDir)).toThrow(/not Qualor's/);
    expect(readFileSync(file, 'utf8')).toBe('<Project />');
  });
});

describe('msbuildEscape', () => {
  it('escapes MSBuild specials and XML', () => {
    expect(msbuildEscape('a;b%c$d@e\'f?g*h&i<j>k"l')).toBe(
      'a%3Bb%25c%24d%40e%27f%3Fg%2Ah&amp;i&lt;j&gt;k&quot;l',
    );
  });
});
