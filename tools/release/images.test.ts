import { describe, expect, it } from 'vitest';
import { RELEASE_ORDER, releaseRefs } from './images';
import { parseVersion } from './version';

describe('image release names (release.md §5)', () => {
  it('orders each sources image before its image, and scanner before scanner-dotnet', () => {
    expect(RELEASE_ORDER).toEqual([
      'scanner-sources',
      'scanner',
      'scanner-dotnet',
      'server-sources',
      'server',
    ]);
    expect(releaseRefs('qualor', parseVersion('1.2.3'), [])[2]).toEqual({
      image: 'scanner-dotnet',
      refs: ['qualor/scanner-dotnet:1.2.3', 'qualor/scanner-dotnet:1.2', 'qualor/scanner-dotnet:1'],
    });
    expect(releaseRefs('qualor', parseVersion('2.0.0-rc.1'), [])[4]?.refs).toEqual([
      'qualor/server:2.0.0-rc.1',
    ]);
  });

  it('releases 0.1.0 as 0.1.0 and 0.1 only, never :0 or :latest', () => {
    const all = releaseRefs('qualor', parseVersion('0.1.0'), []);
    expect(all[4]?.refs).toEqual(['qualor/server:0.1.0', 'qualor/server:0.1']);
    for (const ref of all.flatMap((r) => r.refs)) expect(ref).not.toMatch(/:(0|latest)$/);
  });

  it('never moves a tag backwards: a backport keeps its minor tag, not the major (release.md §2)', () => {
    const released = ['1.2.3', '1.3.0'].map(parseVersion);
    for (const { image, refs } of releaseRefs('qualor', parseVersion('1.2.4'), released)) {
      expect(refs, image).toEqual([`qualor/${image}:1.2.4`, `qualor/${image}:1.2`]);
    }
    const older = releaseRefs('qualor', parseVersion('0.1.3'), ['0.1.4'].map(parseVersion));
    expect(older.flatMap((r) => r.refs)).toEqual(RELEASE_ORDER.map((i) => `qualor/${i}:0.1.3`));
  });
});
