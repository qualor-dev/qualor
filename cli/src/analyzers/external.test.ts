import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { useTempDirs, writeTree } from '../../test/tmp';
import { CliError } from '../errors';
import { Warnings } from '../warnings';
import { externalEngineId, loadExternalSarif, slugifyEngineId } from './external';

const tmp = useTempDirs();
const log = (name: string, results: unknown[] = []) =>
  JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name } }, results }] });

/**
 * A *file* symlink (unlike a directory junction) needs Developer Mode or elevation on Windows.
 * Probing once lets the test below run wherever the platform actually allows it and skip only
 * where it does not, instead of assuming based on `process.platform` alone.
 */
function canCreateFileSymlinks(): boolean {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-symlink-check-'));
  try {
    const target = path.join(dir, 'target.txt');
    writeFileSync(target, 'x');
    symlinkSync(target, path.join(dir, 'link.txt'), 'file');
    return true;
  } catch {
    return false;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const CAN_SYMLINK_FILES = canCreateFileSymlinks();

describe('engine ids of external SARIF', () => {
  it('slugifies tool names within the engine id pattern', () => {
    expect(slugifyEngineId('OSV-Scanner')).toBe('osv-scanner');
    expect(slugifyEngineId('Trivy Vulnerability Scanner')).toBe('trivy-vulnerability-scanner');
    expect(slugifyEngineId('Détecteur  ÉLITE!')).toBe('detecteur-elite');
    expect(slugifyEngineId('')).toBe('external');
    expect(slugifyEngineId('中文')).toBe('external');
    expect(slugifyEngineId('x'.repeat(60))).toHaveLength(40);
  });

  it('keeps built-in ids for Qualor and renames them for external tools (ruling C10)', () => {
    expect(externalEngineId('ESLint', undefined)).toEqual({ id: 'ext-eslint', renamed: true });
    expect(externalEngineId('gitleaks', undefined)).toEqual({ id: 'ext-gitleaks', renamed: true });
    expect(externalEngineId('ESLint', 'my-lint')).toEqual({ id: 'my-lint', renamed: false });
    expect(externalEngineId('osv-scanner', undefined)).toEqual({
      id: 'osv-scanner',
      renamed: false,
    });
  });
});

describe('loadExternalSarif', () => {
  it('loads files, merges files of the same engine and warns about renamed built-in ids', () => {
    const root = tmp();
    writeTree(root, {
      'a.sarif': log('OSV-Scanner'),
      'reports/b.sarif': log('osv-scanner'),
      'c.sarif': log('ESLint'),
    });
    const warnings = new Warnings();
    const captures = loadExternalSarif(
      [
        { path: 'a.sarif' },
        { path: path.join(root, 'reports', 'b.sarif') },
        { path: 'c.sarif' },
        { path: 'c.sarif', engine: 'team-lint' },
      ],
      { root, warnings },
    );
    expect(captures.map((c) => [c.engineId, c.kind, c.status, c.required])).toEqual([
      ['osv-scanner', 'external', 'ok', false],
      ['ext-eslint', 'external', 'ok', false],
      ['team-lint', 'external', 'ok', false],
    ]);
    expect((captures[0]?.sarif as { runs: unknown[] }).runs).toHaveLength(2);
    expect(captures[1]?.mapping).toBeDefined();
    expect(warnings.list()).toEqual([
      expect.objectContaining({ code: 'EXTERNAL_ENGINE_RENAMED', count: 1 }),
    ]);
  });

  it('exits 2 for a missing, non-JSON or non-SARIF file, naming it', () => {
    const root = tmp();
    writeTree(root, { 'bad.json': '{', 'other.json': '{"hello":1}' });
    for (const p of ['missing.sarif', 'bad.json', 'other.json']) {
      let err: unknown;
      try {
        loadExternalSarif([{ path: p }], { root, warnings: new Warnings() });
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(CliError);
      expect((err as CliError).exitCode).toBe(2);
      expect((err as CliError).message).toContain(p);
    }
  });

  it.skipIf(!CAN_SYMLINK_FILES)(
    'exits 2 for a --sarif path that is a symlink, without following it (fix-round finding 7)',
    () => {
      const root = tmp();
      const outside = tmp();
      writeTree(outside, { 'real.sarif': log('OSV-Scanner') });
      symlinkSync(path.join(outside, 'real.sarif'), path.join(root, 'linked.sarif'), 'file');
      let err: unknown;
      try {
        loadExternalSarif([{ path: 'linked.sarif' }], { root, warnings: new Warnings() });
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(CliError);
      expect((err as CliError).exitCode).toBe(2);
      expect((err as CliError).message).toContain('linked.sarif');
    },
  );
});
