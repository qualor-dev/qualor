import { spawnSync } from 'node:child_process';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { openApiDocument, serializeOpenApi } from '../../server/src/http/openapi-doc';
import { VERSION } from '../../server/src/index';
import {
  AZURE_EXAMPLES,
  CHART_FILE,
  compareVersions,
  CONSTANT_FILES,
  currentVersion,
  ENTERPRISE_OPENAPI_FILE,
  EXTENSION_FILE,
  gitTag,
  imageTags,
  OPENAPI_FILE,
  PACKAGE_FILES,
  parseVersion,
  readVersions,
  releasedVersions,
  setVersion,
  TASK_FILE,
  versionArgument,
  versionProblems,
  type Version,
} from './version';

const ALL_FILES = [
  ...PACKAGE_FILES,
  ...CONSTANT_FILES,
  OPENAPI_FILE,
  ENTERPRISE_OPENAPI_FILE,
  CHART_FILE,
  EXTENSION_FILE,
  TASK_FILE,
  ...AZURE_EXAMPLES.map((e) => e.file),
];

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
    for (const f of ALL_FILES.filter((x) => x !== CHART_FILE && x !== TASK_FILE)) {
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

describe('the Azure Pipelines extension follows VERSION', () => {
  let dir = '';
  afterEach(() => rmSync(dir, { recursive: true, force: true }));
  const copy = (): void => {
    dir = mkdtempSync(path.join(tmpdir(), 'qualor-version-'));
    for (const f of ALL_FILES) {
      mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
      cpSync(f, path.join(dir, f));
    }
  };
  const edit = (file: string, from: RegExp, to: string): void => {
    const p = path.join(dir, file);
    writeFileSync(p, readFileSync(p, 'utf8').replace(from, to));
  };

  it('rewrites the manifest version, the task version and the imageTag default', () => {
    copy();
    setVersion(dir, parseVersion('1.4.2'));
    const manifest = JSON.parse(readFileSync(path.join(dir, EXTENSION_FILE), 'utf8')) as {
      version: string;
    };
    const task = JSON.parse(readFileSync(path.join(dir, TASK_FILE), 'utf8')) as {
      version: unknown;
      inputs: { name: string; defaultValue: string }[];
    };
    expect(manifest.version).toBe('1.4.2');
    expect(task.version).toEqual({ Major: 1, Minor: 4, Patch: 2 });
    expect(task.inputs.find((i) => i.name === 'imageTag')?.defaultValue).toBe('1.4.2');
    expect(versionProblems(readVersions(dir))).toEqual([]);
  });

  it('reports a manifest version, a task version or an imageTag that differs', () => {
    copy();
    edit(EXTENSION_FILE, /"version": "[^"]*"/, '"version": "9.9.9"');
    expect(versionProblems(readVersions(dir))[0]).toContain(`${EXTENSION_FILE} 9.9.9`);
    copy();
    edit(TASK_FILE, /"Patch": \d+/, '"Patch": 99');
    expect(versionProblems(readVersions(dir))[0]).toMatch(/task\.json version \d+\.\d+\.99/);
    copy();
    edit(TASK_FILE, /("name": "imageTag"[^}]*?"defaultValue": ")[^"]*/, '$19.9.9');
    expect(versionProblems(readVersions(dir))[0]).toContain('task.json imageTag 9.9.9');
  });

  it('keeps a pre-release in step: numbers in the files, the full version in the image tag', () => {
    copy();
    setVersion(dir, parseVersion('1.5.0-rc.1'));
    expect(versionProblems(readVersions(dir))).toEqual([]);
    const manifest = JSON.parse(readFileSync(path.join(dir, EXTENSION_FILE), 'utf8')) as {
      version: string;
    };
    expect(manifest.version).toBe('1.5.0');
  });

  it('changes nothing when task.json has no imageTag default', () => {
    copy();
    edit(TASK_FILE, /"imageTag"/, '"imageTagX"');
    const before = ALL_FILES.map((f) => readFileSync(path.join(dir, f), 'utf8'));
    expect(() => setVersion(dir, parseVersion('0.1.0'))).toThrow(/task\.json: no version found/);
    expect(ALL_FILES.map((f) => readFileSync(path.join(dir, f), 'utf8'))).toEqual(before);
  });
});

describe('the Azure Pipelines examples pin the minor tag of VERSION', () => {
  let dir = '';
  afterEach(() => rmSync(dir, { recursive: true, force: true }));
  const copy = (): void => {
    dir = mkdtempSync(path.join(tmpdir(), 'qualor-version-'));
    for (const f of ALL_FILES) {
      mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
      cpSync(f, path.join(dir, f));
    }
  };
  const text = (file: string): string => readFileSync(path.join(dir, file), 'utf8');

  it('rewrites the image variable and the imageTag input to major.minor', () => {
    copy();
    setVersion(dir, parseVersion('1.4.2'));
    expect(text('integrations/azure-devops/qualor-docker.yml')).toContain(
      'QUALOR_SCANNER_IMAGE: qualor/scanner:1.4',
    );
    expect(text('integrations/azure-devops/qualor-dotnet-docker.yml')).toContain(
      'QUALOR_SCANNER_IMAGE: qualor/scanner-dotnet:1.4',
    );
    expect(text('integrations/azure-devops/qualor.yml')).toContain("imageTag: '1.4'");
    expect(text('integrations/azure-devops/qualor-dotnet.yml')).toContain("imageTag: '1.4'");
    expect(versionProblems(readVersions(dir))).toEqual([]);
  });

  it('reports a pin that is not the minor line of VERSION', () => {
    for (const { file } of AZURE_EXAMPLES) {
      copy();
      const p = path.join(dir, file);
      writeFileSync(
        p,
        text(file).replace(/(scanner(?:-dotnet)?:|imageTag: ')[0-9]+[.][0-9]+/, '$19.9'),
      );
      expect(versionProblems(readVersions(dir))[0]).toContain(`${file} 9.9`);
    }
  });

  it('changes nothing when an example has no pin', () => {
    copy();
    const file = 'integrations/azure-devops/qualor.yml';
    writeFileSync(path.join(dir, file), text(file).replace("imageTag: '", "imageTagX: '"));
    const before = ALL_FILES.map((f) => text(f));
    expect(() => setVersion(dir, parseVersion('0.1.0'))).toThrow(
      /azure-devops[/]qualor[.]yml: no version found/,
    );
    expect(ALL_FILES.map((f) => text(f))).toEqual(before);
  });

  it('rewrites the fix pipelines too: the imageTag input and the image variable', () => {
    const fix = 'integrations/azure-devops/qualor-fix.yml';
    const fixDocker = 'integrations/azure-devops/qualor-fix-docker.yml';
    expect(AZURE_EXAMPLES.map((e) => e.file)).toEqual(expect.arrayContaining([fix, fixDocker]));
    copy();
    // The next minor of the checkout, never a literal: this file must not name the version it is
    // run at, nor the next one (the scan of every tracked file below).
    const v = parseVersion(VERSION);
    const next = parseVersion(`${v.major}.${v.minor + 1}.0`);
    const changed = setVersion(dir, next);
    expect(changed).toEqual(expect.arrayContaining([fix, fixDocker]));
    const line = `${next.major}.${next.minor}`;
    expect(text(fix)).toContain(`      imageTag: '${line}'\n`);
    expect(text(fixDocker)).toContain(`  QUALOR_SCANNER_IMAGE: qualor/scanner:${line}\n`);
    expect(versionProblems(readVersions(dir))).toEqual([]);
  });

  it('pins major.minor for a pre-release as well, every example alike (sub-plan 3 ruling 19)', () => {
    copy();
    setVersion(dir, parseVersion('1.5.0-rc.1'));
    for (const { file } of AZURE_EXAMPLES) {
      expect(text(file), file).toMatch(/(?:scanner(?:-dotnet)?:|imageTag: ')1[.]5(?:'|\n)/);
      expect(text(file), file).not.toContain('rc.1');
    }
    expect(versionProblems(readVersions(dir))).toEqual([]);
  });
});

describe('enterprise/openapi.json carries VERSION like server/openapi.json', () => {
  let dir = '';
  afterEach(() => rmSync(dir, { recursive: true, force: true }));
  const copy = (): void => {
    dir = mkdtempSync(path.join(tmpdir(), 'qualor-version-'));
    for (const f of ALL_FILES) {
      mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
      cpSync(f, path.join(dir, f));
    }
  };
  const doc = (root: string): { info: { version: string } } =>
    JSON.parse(readFileSync(path.join(root, ENTERPRISE_OPENAPI_FILE), 'utf8')) as {
      info: { version: string };
    };

  it('sets info.version and leaves the rest as the generator writes it', () => {
    expect(ENTERPRISE_OPENAPI_FILE).toBe('enterprise/openapi.json');
    copy();
    expect(setVersion(dir, parseVersion('1.4.0'))).toContain(ENTERPRISE_OPENAPI_FILE);
    // The enterprise generator takes info.version from the server's document (VERSION) and
    // nothing else in it from the version: the committed document with the new info.version.
    const committed = doc('.');
    expect(committed.info.version).toBe(VERSION);
    const bumped = { ...committed, info: { ...committed.info, version: '1.4.0' } };
    expect(readFileSync(path.join(dir, ENTERPRISE_OPENAPI_FILE), 'utf8')).toBe(
      serializeOpenApi(bumped),
    );
    setVersion(dir, parseVersion('1.5.0-rc.1'));
    expect(doc(dir).info.version).toBe('1.5.0-rc.1');
  });

  it('reports an info.version that differs', () => {
    copy();
    const p = path.join(dir, ENTERPRISE_OPENAPI_FILE);
    writeFileSync(p, readFileSync(p, 'utf8').replace(/"version": "[^"]*"/, '"version": "9.9.9"'));
    expect(versionProblems(readVersions(dir))[0]).toContain(`${ENTERPRISE_OPENAPI_FILE} 9.9.9`);
  });
});

/**
 * Tracked files that hold Qualor's version but are not release:version's to write. The scan
 * below fails on any other file that names the checkout's version, or the next patch or minor
 * one (so the test still passes once release:version has raised the files). Lockfiles and
 * licence lists are not scanned: their versions are other software's.
 */
const NOT_WRITTEN = [
  // Docs: raised by hand from the release checklist.
  'README.md',
  'SECURITY.md',
  'deploy/dockerhub/qualor.md',
  'deploy/dockerhub/scanner-dotnet.md',
  'deploy/dockerhub/scanner.md',
  'deploy/dockerhub/server.md',
  'docs/guide/ai-prompts.md',
  'docs/guide/cli.md',
  'docs/guide/fix-merge-requests.md',
  'docs/guide/github.md',
  'docs/guide/gitlab.md',
  'docs/guide/install-server.md',
  'docs/guide/languages-and-analyzers.md',
  'docs/guide/migrate-from-dependency-track.md',
  'docs/guide/other-ci.md',
  'docs/guide/quick-start.md',
  'docs/guide/releases.md',
  'docs/guide/sbom-upload.md',
  // The review job runs the released scanner: raised in a commit of its own once it is published.
  '.github/workflows/ci.yml',
  // Quotes: release history, test fixtures, a comment.
  'CHANGELOG.md',
  'cli/test/gitlab-component.test.ts',
  'integrations/azure-devops/extension/tasks/qualor/src/plan.test.ts',
  'packages/shared/test/sbom-samples/README.md',
  'server/src/onboarding/azure-pipeline.test.ts',
  'server/src/onboarding/ci-setup.test.ts',
  'server/src/vulnerabilities/export/round-trip.db.test.ts',
  'tools/azure/items/27-onboarding.ts',
  'tools/azure/items/onboarding.test.ts',
  'tools/deploy/sources.test.ts',
  'tools/release/publish.ts',
  'ui/src/app/project/dependencies/dependencies.page.spec.ts',
];
// Recorded Azure DevOps answers quote the version a bench run had: data, not version files.
const NOT_SCANNED =
  /(?:^|\/)(?:pnpm-lock\.yaml|package-lock\.json|yarn\.lock|gradle\.lockfile|go\.sum)$|^deploy\/scanner\/licenses\/|^server\/test\/azure-shapes\//;

const escape = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
/** The version itself, or its minor line as an image tag, a task's imageTag or a component ref. */
function holdsVersion(text: string, v: Version): boolean {
  const line = escape(`${v.major}.${v.minor}`);
  return (
    new RegExp(`(?<![\\d.])${escape(v.text)}(?!\\d)`).test(text) ||
    new RegExp(`(?:qualor/[\\w-]+:|imageTag: '|@v?)${line}(?![\\d.])`).test(text)
  );
}

describe('every tracked file that holds the version (Azure sub-plan 9)', () => {
  it('finds the version and the minor-line pins, and no other number', () => {
    const v = parseVersion('3.4.5');
    for (const yes of [
      'image: qualor/scanner:3.4.5',
      'QUALOR_SCANNER_IMAGE: qualor/scanner-dotnet:3.4',
      "      imageTag: '3.4'",
      'uses: qualor-dev/scan-action@v3.4',
      'component: gitlab.com/qualor/qualor/qualor@3.4',
      '"version": "3.4.5",',
    ]) {
      expect(holdsVersion(yes, v), yes).toBe(true);
    }
    for (const no of ['Ruff 3.4.9', '13.4.5', '3.4.50', '3.4em', '(3.4 fix MRs)', 'v3.4.51']) {
      expect(holdsVersion(no, v), no).toBe(false);
    }
  });

  it('is one release:version writes, or one listed as not written', () => {
    const tracked = spawnSync('git', ['ls-files', '-z'], { encoding: 'utf8' })
      .stdout.split('\0')
      .filter((f) => f !== '' && existsSync(f));
    expect(tracked).toContain('tools/release/version.ts');
    const v = parseVersion(VERSION);
    const versions = [
      v,
      parseVersion(`${v.major}.${v.minor}.${v.patch + 1}`),
      parseVersion(`${v.major}.${v.minor + 1}.0`),
    ];
    const known = new Set([...ALL_FILES, ...NOT_WRITTEN]);
    const unknown: string[] = [];
    for (const f of tracked.filter((t) => !NOT_SCANNED.test(t))) {
      const data = readFileSync(f);
      if (data.includes(0)) continue; // binary
      const text = data.toString('utf8');
      const held = versions.filter((x) => holdsVersion(text, x)).map((x) => x.text);
      if (held.length > 0 && !known.has(f)) unknown.push(`${f} (${held.join(', ')})`);
    }
    expect(unknown).toEqual([]);
    for (const f of NOT_WRITTEN) expect(tracked, f).toContain(f);
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
