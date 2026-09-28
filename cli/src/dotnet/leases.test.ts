import { mkdirSync, readdirSync, utimesSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { useTempDirs } from '../../test/tmp';
import { hookPath } from './hook';
import { addLease, leaseDir, releaseLeases } from './leases';

const tmp = useTempDirs();
const now = new Date('2026-09-25T12:00:00Z');

describe('leases (ruling D10, final review R9)', () => {
  it('live beside the hook, in the parent of ImportBefore/ (MSBuild imports every file inside it)', () => {
    const userDir = path.join('/u', 'Microsoft', 'MSBuild');
    const dir = leaseDir(userDir);
    expect(dir).toBe(path.join(userDir, 'Current', 'Microsoft.Common.targets', '.qualor-leases'));
    expect(path.dirname(dir)).toBe(path.dirname(path.dirname(hookPath(userDir))));
  });

  it('counts the other live sessions when one is released', () => {
    const dir = tmp();
    addLease(dir, 'a'.repeat(32), '/r1', now);
    addLease(dir, 'b'.repeat(32), '/r2', now);
    expect(releaseLeases(dir, 'a'.repeat(32), now)).toBe(1);
    expect(releaseLeases(dir, 'b'.repeat(32), now)).toBe(0);
    expect(readdirSync(dir)).toEqual([]);
  });

  it('drops leases older than 24 hours and ignores names that are not session ids', () => {
    const dir = tmp();
    mkdirSync(dir, { recursive: true });
    const stale = path.join(dir, 'c'.repeat(32));
    writeFileSync(stale, '{}');
    const old = new Date(now.getTime() - 25 * 3600_000);
    utimesSync(stale, old, old);
    writeFileSync(path.join(dir, 'README'), '');
    expect(releaseLeases(dir, 'd'.repeat(32), now)).toBe(0);
    expect(readdirSync(dir)).toEqual(['README']);
  });
});
