import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { openApiDocument, serializeOpenApi } from '../../server/src/http/openapi-doc';
import { VERSION } from '../../server/src/index';
import {
  CHART_FILE,
  compareVersions,
  CONSTANT_FILES,
  currentVersion,
  gitTag,
  imageTags,
  OPENAPI_FILE,
  PACKAGE_FILES,
  parseVersion,
  readVersions,
  releasedVersions,
  setVersion,
  versionArgument,
  versionProblems,
} from './version';

const ALL_FILES = [...PACKAGE_FILES, ...CONSTANT_FILES, OPENAPI_FILE, CHART_FILE];

describe('versions (release.md §2)', () => {
  it('parses SemVer with an optional pre-release, and nothing else', () => {
    expect(parseVersion('1.2.3')).toEqual({
      text: '1.2.3',
      major: 1,
      minor: 2,
      patch: 3,
      prerelease: null,
    });
    expect(parseVersion('1.0.0-rc.1').prerelease).toBe('rc.1');
    for (const bad of [
      '1.2',
      'v1.2.3',
      '01.2.3',
      '1.2.3+build.5',
      '1.2.3-',
      '1.2.3-01',
      ' 1.2.3',
      'latest',
    ]) {
      expect(() => parseVersion(bad), bad).toThrow(/not a SemVer version/);
    }
  });

  it('tags 0.y.z and 0.y in 0.x, x.y.z, x.y and x from 1.0, and a pre-release only with its full version', () => {
    expect(imageTags(parseVersion('0.1.0'), [])).toEqual(['0.1.0', '0.1']);
    expect(imageTags(parseVersion('0.4.2'), [])).toEqual(['0.4.2', '0.4']);
    expect(imageTags(parseVersion('1.2.3'), [])).toEqual(['1.2.3', '1.2', '1']);
    expect(imageTags(parseVersion('2.0.0-rc.2'), [])).toEqual(['2.0.0-rc.2']);
    expect(imageTags(parseVersion('0.2.0-rc.1'), [])).toEqual(['0.2.0-rc.1']);
    expect(gitTag(parseVersion('0.1.0'))).toBe('v0.1.0');
  });

  it('never publishes a floating 0 tag or latest', () => {
    for (const text of ['0.1.0', '0.9.12', '0.0.1', '1.0.0', '3.4.5', '0.3.0-rc.1']) {
      const tags = imageTags(parseVersion(text), []);
      expect(tags, text).not.toContain('0');
      expect(tags, text).not.toContain('latest');
    }
  });

  it('finds one version everywhere in this repository', () => {
    const versions = readVersions();
    for (const f of ALL_FILES.filter((x) => x !== CHART_FILE)) {
      expect(versions, f).toHaveProperty(f);
    }
    expect(versionProblems(versions)).toEqual([]);
    expect(currentVersion().text).toBe(Object.values(versions)[0]);
  });

  it('counts the chart version and appVersion as version locations', () => {
    const versions = readVersions();
    expect(versions).toHaveProperty('deploy/helm/qualor/Chart.yaml version');
    expect(versions).toHaveProperty('deploy/helm/qualor/Chart.yaml appVersion');
  });

  it('lists every location that differs', () => {
    expect(versionProblems({ a: '1.0.0', b: '1.0.0', c: '0.9.0' })).toEqual([
      'the versions differ: a 1.0.0, b 1.0.0, c 0.9.0',
    ]);
  });
});

describe('setVersion', () => {
  let dir = '';
  afterEach(() => rmSync(dir, { recursive: true, force: true }));
  const copy = (): void => {
    dir = mkdtempSync(path.join(tmpdir(), 'qualor-version-'));
    for (const f of ALL_FILES) {
      mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
      cpSync(f, path.join(dir, f));
    }
  };

  it('sets every location, keeping the rest of each file', () => {
    copy();
    const changed = setVersion(dir, parseVersion('1.4.0'));
    expect(changed.sort()).toEqual([...ALL_FILES].sort());
    expect(new Set(Object.values(readVersions(dir)))).toEqual(new Set(['1.4.0']));
    expect(versionProblems(readVersions(dir))).toEqual([]);
  });

  it('leaves the committed OpenAPI document equal to the one the bumped server generates', async () => {
    copy();
    setVersion(dir, parseVersion('0.1.0'));
    // The generator takes info.version from VERSION, and nothing else in it depends on the version.
    const generated = (await openApiDocument()) as { info: { version: string } };
    expect(generated.info.version).toBe(VERSION);
    const bumped = { ...generated, info: { ...generated.info, version: '0.1.0' } };
    expect(readFileSync(path.join(dir, OPENAPI_FILE), 'utf8')).toBe(serializeOpenApi(bumped));
    expect(readVersions(dir)['server/src/index.ts']).toBe('0.1.0');
  });

  it('changes nothing when one file has no version', () => {
    copy();
    const broken = path.join(dir, 'server/src/index.ts');
    writeFileSync(broken, readFileSync(broken, 'utf8').replace(/^export const VERSION.*$/m, ''));
    const before = ALL_FILES.map((f) => readFileSync(path.join(dir, f), 'utf8'));
    expect(() => setVersion(dir, parseVersion('0.1.0'))).toThrow(
      /server\/src\/index\.ts: no version found/,
    );
    expect(ALL_FILES.map((f) => readFileSync(path.join(dir, f), 'utf8'))).toEqual(before);
  });
});

describe('the chart is a required version location (release.md §2, ruling RE6)', () => {
  let dir = '';
  afterEach(() => rmSync(dir, { recursive: true, force: true }));
  const copy = (skip?: string): void => {
    dir = mkdtempSync(path.join(tmpdir(), 'qualor-version-'));
    for (const f of ALL_FILES) {
      if (f === skip) continue;
      mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
      cpSync(f, path.join(dir, f));
    }
  };

  it('sets the chart version and appVersion with everything else', () => {
    copy();
    expect(setVersion(dir, parseVersion('0.1.0'))).toContain(CHART_FILE);
    const chart = readFileSync(path.join(dir, CHART_FILE), 'utf8');
    expect(chart).toMatch(/^version: 0\.1\.0$/m);
    // The quote Prettier gave it is kept.
    expect(chart).toMatch(/^appVersion: '0\.1\.0'$/m);
    expect(parse(chart)).toMatchObject({ version: '0.1.0', appVersion: '0.1.0' });
  });

  it('refuses a checkout without the chart, in readVersions and in setVersion', () => {
    copy(CHART_FILE);
    expect(() => readVersions(dir)).toThrow(/Chart\.yaml/);
    const before = ALL_FILES.filter((f) => f !== CHART_FILE).map((f) =>
      readFileSync(path.join(dir, f), 'utf8'),
    );
    expect(() => setVersion(dir, parseVersion('0.1.0'))).toThrow(/Chart\.yaml/);
    expect(
      ALL_FILES.filter((f) => f !== CHART_FILE).map((f) => readFileSync(path.join(dir, f), 'utf8')),
    ).toEqual(before);
  });

  it('reports a chart without its version or appVersion, and changes nothing', () => {
    copy();
    const chart = path.join(dir, CHART_FILE);
    writeFileSync(chart, readFileSync(chart, 'utf8').replace(/^appVersion:.*$/m, ''));
    expect(readVersions(dir)[`${CHART_FILE} appVersion`]).toBe('(none)');
    expect(versionProblems(readVersions(dir))).not.toEqual([]);
    const before = ALL_FILES.map((f) => readFileSync(path.join(dir, f), 'utf8'));
    expect(() => setVersion(dir, parseVersion('0.1.0'))).toThrow(
      /deploy\/helm\/qualor\/Chart\.yaml: no version found/,
    );
    expect(ALL_FILES.map((f) => readFileSync(path.join(dir, f), 'utf8'))).toEqual(before);
  });

  it('reads an appVersion in either quote, and none whose quotes do not match', () => {
    copy();
    const chart = path.join(dir, CHART_FILE);
    const text = readFileSync(chart, 'utf8');
    const withAppVersion = (line: string) =>
      writeFileSync(chart, text.replace(/^appVersion:.*$/m, line));
    const read = () => readVersions(dir)[`${CHART_FILE} appVersion`];
    withAppVersion(`appVersion: "0.0.0"`);
    expect(read()).toBe('0.0.0');
    withAppVersion(`appVersion: '0.0.0'`);
    expect(read()).toBe('0.0.0');
    withAppVersion(`appVersion: '0.0.0"`);
    expect(read()).toBe('(none)');
    withAppVersion(`appVersion: "0.0.0'`);
    expect(read()).toBe('(none)');
  });
});

describe('pnpm release:version arguments', () => {
  it('takes exactly one version, after an optional --', () => {
    expect(versionArgument(['0.1.0']).text).toBe('0.1.0');
    expect(versionArgument(['--', '0.1.0']).text).toBe('0.1.0');
    for (const args of [[], ['0.1.0', '0.2.0'], ['0.1.0', '--force'], ['--']]) {
      expect(() => versionArgument(args), args.join(' ')).toThrow(/usage/);
    }
    expect(() => versionArgument(['latest'])).toThrow(/not a SemVer version/);
  });
});

describe('moving tags never go backwards (release.md §2)', () => {
  const vs = (...texts: string[]) => texts.map(parseVersion);

  it('drops x.y and x when a newer release of that line already holds them', () => {
    // A backport 1.2.4 after 1.3.0 keeps 1.2 but must not move 1.
    expect(imageTags(parseVersion('1.2.4'), vs('1.2.3', '1.3.0'))).toEqual(['1.2.4', '1.2']);
    // A fix of an old line after a newer patch of the same line moves nothing.
    expect(imageTags(parseVersion('1.2.4'), vs('1.2.5', '1.3.0'))).toEqual(['1.2.4']);
    // The newest release of its line moves both.
    expect(imageTags(parseVersion('1.3.1'), vs('1.2.4', '1.3.0'))).toEqual(['1.3.1', '1.3', '1']);
    // Another major does not count; 0.x has no floating 0 either way.
    expect(imageTags(parseVersion('1.4.0'), vs('2.0.0'))).toEqual(['1.4.0', '1.4', '1']);
    expect(imageTags(parseVersion('0.1.3'), vs('0.1.4', '0.2.0'))).toEqual(['0.1.3']);
    expect(imageTags(parseVersion('0.1.5'), vs('0.1.4', '0.2.0'))).toEqual(['0.1.5', '0.1']);
  });

  it('ignores pre-releases and a re-release of the same version', () => {
    expect(imageTags(parseVersion('1.2.4'), vs('1.3.0-rc.1', '1.2.4'))).toEqual([
      '1.2.4',
      '1.2',
      '1',
    ]);
  });

  it('orders versions, a pre-release before its release', () => {
    const sorted = vs('1.10.0', '1.2.0', '1.2.0-rc.1', '0.9.9', '1.2.1').sort(compareVersions);
    expect(sorted.map((v) => v.text)).toEqual(['0.9.9', '1.2.0-rc.1', '1.2.0', '1.2.1', '1.10.0']);
  });

  it('reads the released versions from the v* git tags, skipping any other tag', () => {
    const calls: string[][] = [];
    const released = releasedVersions('/repo', (args) => {
      calls.push(args);
      return 'v0.1.0\nv0.2.0-rc.1\nvnext\nv1.2\n';
    });
    expect(calls).toEqual([['tag', '--list', 'v*']]);
    expect(released.map((v) => v.text)).toEqual(['0.1.0', '0.2.0-rc.1']);
  });
});
