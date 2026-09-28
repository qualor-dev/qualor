import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { REPO_ROOT, type RunResult } from '../deploy/stack';
import { parseSums, releaseFiles, sha256sums, SUMS, SUMS_BUNDLE } from './checksums';
import { PLAIN_HTTP, SIGN_OFFLINE, VERIFY_OFFLINE } from './cosign';
import { RELEASE_ORDER } from './images';
import {
  CHART_REPOSITORY,
  publish,
  publishGateProblems,
  REKOR_FOR_REAL_RELEASES,
  REQUIRED_SECRETS,
  SECRET_NAMES,
  takeSecrets,
  type Exec,
  type RepoFacts,
} from './publish';
import { toWork } from './toolbox';
import { imageTags, parseVersion, type Version } from './version';

const v = parseVersion('0.1.0');
const TOKEN = 'dckr_pat_not-a-real-token';
const PASSWORD = 'not-a-real-cosign-password';
const KEY = 'not a real key';
const GH = 'ghs_not-a-real-token';
const GATED = {
  CI: 'true',
  GITHUB_ACTIONS: 'true',
  GITHUB_EVENT_NAME: 'workflow_dispatch',
  GITHUB_REF_TYPE: 'tag',
  GITHUB_REF_NAME: 'v0.1.0',
  QUALOR_RELEASE_CONFIRM: 'publish v0.1.0',
  DOCKERHUB_USERNAME: 'qualor',
  DOCKERHUB_TOKEN: TOKEN,
  COSIGN_PRIVATE_KEY: KEY,
  COSIGN_PASSWORD: PASSWORD,
  GH_TOKEN: GH,
};
const SECRETS = [TOKEN, PASSWORD, KEY, GH];
/** The digest the dry run recorded for every image (and that Docker Hub reports back, R-DIGEST). */
const DIGEST = `sha256:${'0'.repeat(64)}`;
const CHART_DIGEST = `sha256:${'c'.repeat(64)}`;
const PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nnot a real public key\n-----END PUBLIC KEY-----\n';
const HEAD = 'a'.repeat(40);

let root = '';
let dir = '';
/** The git facts of the checkout: a tracked cosign.pub, HEAD on origin/main. */
let repo: RepoFacts;

/** A complete dry-run directory for `version`, with the refs of `imageTags(version, released)`. */
async function writeRelease(
  version: Version,
  released: readonly Version[],
  change: (m: Record<string, unknown>) => void = () => undefined,
): Promise<void> {
  dir = path.join(root, 'release', version.text);
  rmSync(dir, { recursive: true, force: true });
  const t = version.text;
  const files: Record<string, string> = {
    [`cli/qualor-${t}-linux-x64`]: 'bin',
    'cli-sources/SHA256SUMS': 'x',
    [`helm/qualor-${t}.tgz`]: 'chart',
    'sbom/cli.spdx.json': '{}',
    'sbom/server.spdx.json': '{}',
    'sbom/scanner.spdx.json': '{}',
    'sbom/scanner-dotnet.spdx.json': '{}',
    'images.json': '[]',
    'release-notes.md': 'notes',
    'cosign.pub': 'the throwaway key of the dry run',
  };
  for (const [f, text] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
    writeFileSync(path.join(dir, f), text);
  }
  const images = RELEASE_ORDER.map((image) => ({
    image,
    refs: imageTags(version, released).map((tag) => `qualor/${image}:${tag}`),
    digest: DIGEST,
    sbom: image.endsWith('sources') ? null : `sbom/${image}.spdx.json`,
  }));
  const m: Record<string, unknown> = {
    version: t,
    gitCommit: HEAD,
    createdAt: 'now',
    dryRun: true,
    targets: ['linux-x64'],
    cliSources: true,
    images,
    chart: { file: `helm/qualor-${t}.tgz`, digest: `sha256:${'1'.repeat(64)}` },
    files: releaseFiles(dir),
  };
  change(m);
  writeManifest(m);
  writeFileSync(path.join(dir, SUMS), await sha256sums(dir));
  writeFileSync(path.join(dir, SUMS_BUNDLE), '{}');
}
function writeManifest(m: unknown): void {
  writeFileSync(path.join(dir, 'release-manifest.json'), JSON.stringify(m));
}
function readManifestJson(): Record<string, unknown> & { images: { refs: string[] }[] } {
  return JSON.parse(readFileSync(path.join(dir, 'release-manifest.json'), 'utf8')) as Record<
    string,
    unknown
  > & { images: { refs: string[] }[] };
}

beforeEach(async () => {
  mkdirSync(path.join(REPO_ROOT, '.tmp'), { recursive: true });
  root = mkdtempSync(path.join(REPO_ROOT, '.tmp', 'publish-root-'));
  writeFileSync(path.join(root, 'cosign.pub'), PUBLIC_KEY);
  for (const image of ['scanner', 'server']) {
    mkdirSync(path.join(root, '.tmp', `${image}-sources`), { recursive: true });
  }
  repo = { head: () => HEAD, tracks: () => true, contains: (ref) => ref === 'origin/main' };
  await writeRelease(v, []);
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

interface Call {
  command: string;
  args: string[];
  input?: string;
  env?: Record<string, string>;
}

interface Fake {
  /** Docker Hub's digest for a pushed ref. */
  pushDigest?: (ref: string) => string;
  publicKey?: string;
  /** Changes the downloaded draft (a tampered upload). */
  tamper?: (downloadDir: string) => void;
  onCall?: (c: Call) => void;
}

/** A fake executor: Docker Hub, Helm, cosign and gh as the release sees them. */
function recorder(fake: Fake = {}): { exec: Exec; calls: Call[] } {
  const calls: Call[] = [];
  let uploaded: string[] = [];
  const exec: Exec = (command, args, o = {}): RunResult => {
    const call = { command, args, input: o.input, env: o.env };
    calls.push(call);
    fake.onCall?.(call);
    const ok = (stdout = '', stderr = ''): RunResult => ({ code: 0, stdout, stderr });
    if (command === 'docker' && args[0] === 'push') {
      const ref = args[1] ?? '';
      return ok(`x: digest: ${fake.pushDigest?.(ref) ?? DIGEST} size: 1\n`);
    }
    if (command === 'cosign' && args[0] === 'public-key') return ok(fake.publicKey ?? PUBLIC_KEY);
    if (command === 'helm') return ok('', `Pushed: x\nDigest: ${CHART_DIGEST}\n`);
    if (command === 'cosign' && args[0] === 'sign-blob') {
      // cosign writes the bundle (a /work path) next to SHA256SUMS.
      const bundle = args[args.indexOf('--bundle') + 1] ?? '';
      writeFileSync(path.join(REPO_ROOT, bundle.replace(/^\/work\//, '')), '{}');
      return ok();
    }
    if (command === 'tar') {
      writeFileSync(args[1] ?? '', `tar of ${args[4] ?? ''}`);
      return ok();
    }
    if (command === 'gh' && args[1] === 'create') {
      uploaded = args.slice(args.indexOf('--notes-file') + 2);
      return ok();
    }
    if (command === 'gh' && args[1] === 'download') {
      const to = args[args.indexOf('--dir') + 1] ?? '';
      for (const f of uploaded) copyFileSync(f, path.join(to, path.basename(f)));
      fake.tamper?.(to);
      return ok();
    }
    return ok();
  };
  return { exec, calls };
}

const run = (
  exec: Exec,
  env: Record<string, string | undefined> = GATED,
  released: readonly Version[] = [],
  version: Version = v,
): Promise<void> => publish(env, version, dir, exec, root, released, repo);

const isPush = (c: Call): boolean => c.command === 'docker' && c.args[0] === 'push';
const isStaging = (c: Call): boolean => isPush(c) && /:staging-/.test(c.args[1] ?? '');
const isSign = (c: Call): boolean =>
  c.command === 'cosign' && ['sign', 'attest'].includes(c.args[0] ?? '');
const isVerify = (c: Call): boolean =>
  c.command === 'cosign' && ['verify', 'verify-attestation'].includes(c.args[0] ?? '');

describe('release:publish (release.md §11)', () => {
  it('refuses outside the gated release job and runs no command', async () => {
    for (const env of [{}, { CI: 'true', GITHUB_ACTIONS: 'true', GITHUB_EVENT_NAME: 'push' }]) {
      const { exec, calls } = recorder();
      await expect(run(exec, env)).rejects.toThrow(/release:publish refused; nothing was run/);
      expect(calls).toEqual([]);
    }
  });

  it('lists every missing condition, one at a time', () => {
    expect(publishGateProblems(GATED, '0.1.0', root)).toEqual([]);
    for (const name of Object.keys(GATED)) {
      const env: Record<string, string | undefined> = { ...GATED, [name]: undefined };
      expect(publishGateProblems(env, '0.1.0', root).join('\n'), name).toContain(name);
    }
    expect(
      publishGateProblems({ ...GATED, QUALOR_RELEASE_CONFIRM: 'publish' }, '0.1.0', root),
    ).toEqual(['QUALOR_RELEASE_CONFIRM must be "publish v0.1.0"']);
    expect(publishGateProblems({ ...GATED, GITHUB_REF_NAME: 'v0.1.1' }, '0.1.0', root)).toEqual([
      'GITHUB_REF_NAME must be "v0.1.0"',
    ]);
    rmSync(path.join(root, 'cosign.pub'));
    expect(publishGateProblems(GATED, '0.1.0', root)).toEqual([
      'cosign.pub is not committed at the repository root',
    ]);
    expect(REQUIRED_SECRETS).toEqual([
      'DOCKERHUB_USERNAME',
      'DOCKERHUB_TOKEN',
      'COSIGN_PRIVATE_KEY',
      'COSIGN_PASSWORD',
    ]);
  });

  it('runs no command when any one condition is missing, empty or wrong', async () => {
    const variants: [string, Record<string, string | undefined>][] = [];
    for (const name of Object.keys(GATED)) {
      variants.push([`${name} unset`, { ...GATED, [name]: undefined }]);
      variants.push([`${name} empty`, { ...GATED, [name]: '' }]);
    }
    variants.push(['a push event', { ...GATED, GITHUB_EVENT_NAME: 'push' }]);
    variants.push(['a branch', { ...GATED, GITHUB_REF_TYPE: 'branch', GITHUB_REF_NAME: 'main' }]);
    variants.push(['another tag', { ...GATED, GITHUB_REF_NAME: 'v0.1.1' }]);
    variants.push(['no version', { ...GATED, QUALOR_RELEASE_CONFIRM: 'publish' }]);
    variants.push(['GitLab', { ...GATED, GITHUB_ACTIONS: undefined, GITLAB_CI: 'true' }]);
    for (const [what, env] of variants) {
      const { exec, calls } = recorder();
      await expect(run(exec, env), what).rejects.toThrow(
        /release:publish refused; nothing was run/,
      );
      expect(calls, what).toEqual([]);
    }
    rmSync(path.join(root, 'cosign.pub'));
    const { exec, calls } = recorder();
    await expect(run(exec)).rejects.toThrow(/cosign\.pub/);
    expect(calls).toEqual([]);
  });

  it('refuses a dry run without images or CLI sources', async () => {
    writeManifest({ version: '0.1.0', cliSources: false, images: [], chart: { digest: null } });
    const { exec, calls } = recorder();
    await expect(run(exec)).rejects.toThrow(/not complete for publishing/);
    expect(calls).toEqual([]);
  });

  it('refuses a dry run whose tags are not releaseRefs(v, releasedVersions()), before any command', async () => {
    // A 0.x release never gets a floating "0".
    await writeRelease(v, [], (m) => {
      for (const img of m['images'] as { refs: string[] }[]) {
        img.refs.push(img.refs[0]?.replace(/:[^:]+$/, ':0') ?? '');
      }
    });
    const { exec, calls } = recorder();
    await expect(run(exec)).rejects.toThrow(/tags/);
    expect(calls).toEqual([]);
    // A tag a newer release holds: 0.1 after 0.1.1 was released.
    await writeRelease(v, []);
    const { exec: exec2, calls: calls2 } = recorder();
    await expect(run(exec2, GATED, [parseVersion('0.1.1')])).rejects.toThrow(/tags/);
    expect(calls2).toEqual([]);
  });

  it('refuses a manifest that is not the dry run’s own at HEAD, or that leaves the directory', async () => {
    const cases: [string, (m: Record<string, unknown>) => void, RegExp][] = [
      ['not a dry run', (m) => (m['dryRun'] = false), /dryRun: true/],
      ['another commit', (m) => (m['gitCommit'] = 'b'.repeat(40)), /not at HEAD/],
      ['a dirty tree', (m) => (m['gitCommit'] = `${HEAD}-dirty`), /not at HEAD/],
      ['files: ..', (m) => (m['files'] = ['../outside']), /leaves the release directory/],
      ['files: absolute', (m) => (m['files'] = [path.join(root, 'x')]), /leaves/],
      ['files: backslash', (m) => (m['files'] = ['cli\\x']), /leaves/],
      ['files: missing', (m) => (m['files'] = ['cli/nothing']), /not a regular file/],
      ['files: a directory', (m) => (m['files'] = ['cli']), /not a regular file/],
      [
        'chart outside',
        (m) => (m['chart'] = { file: '../x.tgz', digest: `sha256:${'1'.repeat(64)}` }),
        /chart\.file/,
      ],
      [
        'an SBOM outside',
        (m) => {
          const images = m['images'] as { sbom: string | null }[];
          const img = images.find((i) => i.sbom !== null);
          if (img) img.sbom = '../../sbom.json';
        },
        /sbom/,
      ],
    ];
    for (const [what, change, message] of cases) {
      await writeRelease(v, [], change);
      const { exec, calls } = recorder();
      await expect(run(exec), what).rejects.toThrow(message);
      expect(calls, what).toEqual([]);
    }
  });

  it('refuses a release directory changed since its SHA256SUMS, before any command', async () => {
    writeFileSync(path.join(dir, 'release-notes.md'), 'changed after the dry run');
    const { exec, calls } = recorder();
    await expect(run(exec)).rejects.toThrow(/release-notes\.md: the SHA-256 does not match/);
    expect(calls).toEqual([]);
  });

  it('refuses an untracked cosign.pub and a HEAD on no release branch; accepts release/<M>.<m>', async () => {
    repo = { ...repo, tracks: () => false };
    const a = recorder();
    await expect(run(a.exec)).rejects.toThrow(/not tracked by git/);
    expect(a.calls).toEqual([]);
    repo = { head: () => HEAD, tracks: () => true, contains: () => false };
    const b = recorder();
    await expect(run(b.exec)).rejects.toThrow(/on neither origin\/main nor origin\/release\/0\.1/);
    expect(b.calls).toEqual([]);
    repo = { ...repo, contains: (ref) => ref === 'origin/release/0.1' };
    const c = recorder();
    await run(c.exec);
    expect(c.calls.some((x) => x.command === 'gh')).toBe(true);
  });

  it('checks the key against the tracked cosign.pub before it logs in', async () => {
    const { exec, calls } = recorder({ publicKey: 'another public key' });
    await expect(run(exec)).rejects.toThrow(/does not belong to the tracked cosign\.pub/);
    expect(calls.map((c) => `${c.command} ${c.args[0] ?? ''}`)).toEqual(['cosign public-key']);
    expect(existsSync(path.join(root, '.tmp', 'release-work', '0.1.0', 'publish'))).toBe(false);
  });

  it('removes a stale key directory first and writes the key 0600', async () => {
    const secrets = path.join(root, '.tmp', 'release-work', '0.1.0', 'publish');
    mkdirSync(secrets, { recursive: true });
    writeFileSync(path.join(secrets, 'cosign.key'), 'stale', { mode: 0o644 });
    writeFileSync(path.join(secrets, 'left-over'), 'x');
    let checked = false;
    const { exec } = recorder({
      onCall: (c) => {
        if (c.args[0] !== 'public-key') return;
        checked = true;
        expect(existsSync(path.join(secrets, 'left-over'))).toBe(false);
        expect(readFileSync(path.join(secrets, 'cosign.key'), 'utf8')).toBe(KEY);
        if (process.platform !== 'win32') {
          expect(statSync(path.join(secrets, 'cosign.key')).mode & 0o777).toBe(0o600);
        }
      },
    });
    await run(exec);
    expect(checked).toBe(true);
    expect(existsSync(secrets)).toBe(false);
  });

  it('publishes a backport without the moving tag a newer release holds', async () => {
    const backport = parseVersion('0.1.1');
    const released = [parseVersion('0.1.0'), parseVersion('0.2.0')];
    await writeRelease(backport, released);
    const env = { ...GATED, GITHUB_REF_NAME: 'v0.1.1', QUALOR_RELEASE_CONFIRM: 'publish v0.1.1' };
    const { exec, calls } = recorder();
    await run(exec, env, released, backport);
    const pushes = calls.filter((c) => isPush(c) && !isStaging(c));
    expect(pushes.map((c) => c.args[1])).toEqual(
      RELEASE_ORDER.flatMap((image) => [`qualor/${image}:0.1.1`, `qualor/${image}:0.1`]),
    );
    // 0.2.0 is newer but on another line: 0.1 still moves to 0.1.1.
  });
});

describe('the order of publishing (ruling R-ORDER)', () => {
  it('stages, signs and verifies every image before any version tag, then drafts, verifies and publishes', async () => {
    const { exec, calls } = recorder();
    await run(exec);
    const at = (p: (c: Call) => boolean): number => calls.findIndex(p);
    const last = (p: (c: Call) => boolean): number => calls.findLastIndex(p);
    // The key first, then the login.
    expect(calls[0]).toMatchObject({
      command: 'cosign',
      args: ['public-key', '--key', expect.any(String) as unknown],
    });
    expect(calls[1]).toMatchObject({
      command: 'docker',
      args: ['login', '--username', 'qualor', '--password-stdin', 'docker.io'],
      input: TOKEN,
    });
    // Staging: one push per image, in §5's order, of the one staging tag.
    expect(calls.filter(isStaging).map((c) => c.args[1])).toEqual(
      RELEASE_ORDER.map((image) => `qualor/${image}:staging-0.1.0`),
    );
    // Every signature and its verification before the first version or moving tag.
    const firstReleaseTag = at((c) => isPush(c) && !isStaging(c));
    expect(last(isStaging)).toBeLessThan(at(isSign));
    const imageSigns = calls.filter(
      (c) => isSign(c) && !c.args.at(-1)?.includes('/qualor/qualor@'),
    );
    expect(imageSigns).toHaveLength(5 + 3);
    expect(calls.findLastIndex((c) => imageSigns.includes(c))).toBeLessThan(firstReleaseTag);
    const imageVerifies = calls.filter(
      (c) => isVerify(c) && !c.args.at(-1)?.includes('/qualor/qualor@'),
    );
    expect(imageVerifies.map((c) => c.args[0]).sort()).toEqual([
      ...Array<string>(5).fill('verify'),
      ...Array<string>(3).fill('verify-attestation'),
    ]);
    expect(calls.findLastIndex((c) => imageVerifies.includes(c))).toBeLessThan(firstReleaseTag);
    // With the tracked cosign.pub, not the dry run's throwaway key.
    const trackedKey = toWork(path.join(root, 'cosign.pub'));
    for (const c of imageVerifies) expect(c.args).toContain(trackedKey);
    // Then the release tags, 0.Y.Z and 0.Y, never 0 or latest.
    const releasePushes = calls.filter((c) => isPush(c) && !isStaging(c)).map((c) => c.args[1]);
    expect(releasePushes).toEqual(
      RELEASE_ORDER.flatMap((image) => imageTags(v, []).map((t) => `qualor/${image}:${t}`)),
    );
    for (const p of releasePushes) expect(p).not.toMatch(/:(0|latest)$/);
    // The chart after the images: pushed, signed, verified.
    const helm = at((c) => c.command === 'helm');
    expect(calls[helm]?.args).toEqual(['push', expect.any(String) as unknown, CHART_REPOSITORY]);
    expect(helm).toBeGreaterThan(last((c) => isPush(c)));
    const chartRef = `registry-1.docker.io/qualor/qualor@${CHART_DIGEST}`;
    const chartSign = at((c) => isSign(c) && c.args.at(-1) === chartRef);
    const chartVerify = at((c) => isVerify(c) && c.args.at(-1) === chartRef);
    expect(helm).toBeLessThan(chartSign);
    expect(chartSign).toBeLessThan(chartVerify);
    // The assets signed, then a draft, its download verified, and only then published.
    const signBlob = at((c) => c.command === 'cosign' && c.args[0] === 'sign-blob');
    const create = at((c) => c.command === 'gh' && c.args[1] === 'create');
    const download = at((c) => c.command === 'gh' && c.args[1] === 'download');
    const verifyDownload = last((c) => c.command === 'cosign' && c.args[0] === 'verify-blob');
    const publishDraft = at((c) => c.command === 'gh' && c.args[1] === 'edit');
    expect(chartVerify).toBeLessThan(signBlob);
    expect(signBlob).toBeLessThan(create);
    expect(calls[create]?.args.slice(0, 5)).toEqual([
      'release',
      'create',
      'v0.1.0',
      '--draft',
      '--verify-tag',
    ]);
    expect(create).toBeLessThan(download);
    expect(download).toBeLessThan(verifyDownload);
    expect(verifyDownload).toBeLessThan(publishDraft);
    expect(calls[publishDraft]?.args).toEqual(['release', 'edit', 'v0.1.0', '--draft=false']);
    expect(publishDraft).toBe(calls.length - 1);
    // Everything by digest.
    for (const c of calls.filter((x) => isSign(x) || isVerify(x))) {
      expect(c.args.at(-1)).toMatch(/@sha256:[0-9a-f]{64}$/);
    }
  });

  it('tags nothing user-facing when a staged digest differs (R-DIGEST)', async () => {
    const { exec, calls } = recorder({
      pushDigest: (ref) => (ref.startsWith('qualor/server:') ? `sha256:${'d'.repeat(64)}` : DIGEST),
    });
    await expect(run(exec)).rejects.toThrow(/R-DIGEST/);
    expect(calls.filter((c) => isPush(c) && !isStaging(c))).toEqual([]);
    expect(calls.filter(isSign)).toEqual([]);
    expect(calls.filter((c) => c.command === 'gh' || c.command === 'helm')).toEqual([]);
  });

  it('keeps the release a draft when its download does not verify', async () => {
    const { exec, calls } = recorder({
      tamper: (to) => writeFileSync(path.join(to, 'qualor-0.1.0.tgz'), 'swapped'),
    });
    await expect(run(exec)).rejects.toThrow(
      /does not verify; it stays a draft[\s\S]*qualor-0\.1\.0\.tgz/,
    );
    expect(calls.filter((c) => c.command === 'gh' && c.args[1] === 'edit')).toEqual([]);
  });

  it('uploads exactly the flat assets, every one listed in the SHA256SUMS it signed (I-2)', async () => {
    const { exec, calls } = recorder();
    await run(exec);
    const create = calls.find((c) => c.command === 'gh' && c.args[1] === 'create');
    const files = create?.args.slice((create.args.indexOf('--notes-file') ?? 0) + 2) ?? [];
    const names = files.map((f) => path.basename(f));
    expect(names).toContain(SUMS);
    expect(names).toContain(SUMS_BUNDLE);
    for (const n of [
      'qualor-0.1.0-cli-sources.tar',
      'qualor-0.1.0-scanner-sources.tar',
      'qualor-0.1.0-server-sources.tar',
      'qualor-0.1.0-linux-x64',
      'qualor-0.1.0.tgz',
      'qualor-0.1.0-server.spdx.json',
    ]) {
      expect(names, n).toContain(n);
    }
    const sums = files.find((f) => path.basename(f) === SUMS) ?? '';
    const listed = parseSums(readFileSync(sums, 'utf8')).map((l) => l.file);
    expect(listed.sort()).toEqual(names.filter((n) => n !== SUMS && n !== SUMS_BUNDLE).sort());
    // The signed SHA256SUMS is that one.
    const signBlob = calls.find((c) => c.command === 'cosign' && c.args[0] === 'sign-blob');
    expect(signBlob?.args).toContain(
      `/work/${path.relative(REPO_ROOT, sums).split(path.sep).join('/')}`,
    );
    // The published manifest and key, not the dry run's.
    const manifest = JSON.parse(
      readFileSync(files.find((f) => path.basename(f) === 'release-manifest.json') ?? '', 'utf8'),
    ) as { dryRun: boolean; chart: { digest: string } };
    expect(manifest).toMatchObject({ dryRun: false, chart: { digest: CHART_DIGEST } });
    expect(readFileSync(files.find((f) => path.basename(f) === 'cosign.pub') ?? '', 'utf8')).toBe(
      PUBLIC_KEY,
    );
    // The dry run's directory is left as it was: it still verifies against its own sums.
    expect(readManifestJson()['dryRun']).toBe(true);
  });
});

describe('what each tool gets (release.md §11, per-tool environments)', () => {
  it('passes no secret as an argument and each tool only its own', async () => {
    const { exec, calls } = recorder();
    await run(exec);
    for (const c of calls) {
      for (const a of c.args) for (const s of SECRETS) expect(a).not.toContain(s);
      const values = Object.values(c.env ?? {});
      const allowed =
        c.command === 'gh'
          ? [GH]
          : c.command === 'cosign' && c.args[0] !== 'verify-blob'
            ? [PASSWORD]
            : [];
      for (const s of SECRETS.filter((x) => !allowed.includes(x))) {
        expect(values, `${c.command} ${c.args[0] ?? ''}`).not.toContain(s);
      }
    }
    for (const c of calls.filter((x) => x.command === 'docker')) {
      // The host's Docker CLI gets a host path, never the toolbox's /work path.
      expect(c.env?.['DOCKER_CONFIG'], c.args[0]).toMatch(/publish[\\/]docker$/);
      expect(c.env?.['DOCKER_CONFIG']).not.toMatch(/^\/work/);
    }
    for (const c of calls.filter((x) => x.command === 'tar')) expect(c.env).toEqual({});
    for (const c of calls.filter((x) => x.command === 'helm')) {
      expect(Object.keys(c.env ?? {}).sort()).toEqual(['DOCKER_CONFIG', 'HELM_REGISTRY_CONFIG']);
    }
    for (const c of calls.filter((x) => x.command === 'gh'))
      expect(c.env).toEqual({ GH_TOKEN: GH });
    expect(existsSync(path.join(root, '.tmp', 'release-work', '0.1.0', 'publish'))).toBe(false);
  });

  it('takes the secrets out of the process environment before anything runs', () => {
    const processEnv: Record<string, string | undefined> = { ...GATED, PATH: '/bin' };
    const env = takeSecrets(processEnv);
    expect(env).toMatchObject(GATED);
    for (const name of SECRET_NAMES) expect(processEnv, name).not.toHaveProperty(name);
    expect(processEnv['PATH']).toBe('/bin');
    const source = readFileSync('tools/release/publish.ts', 'utf8');
    const main = source.slice(source.indexOf("if (process.argv[1]?.endsWith('publish.ts'))"));
    expect(main.indexOf('takeSecrets(process.env)')).toBeGreaterThan(-1);
    expect(main.indexOf('takeSecrets(process.env)')).toBeLessThan(main.indexOf('publish('));
  });
});

describe('registry flags and Rekor (R-REGOPTS)', () => {
  it('never talks plain HTTP or to an insecure registry', async () => {
    const { exec, calls } = recorder();
    await run(exec);
    const insecure = [...PLAIN_HTTP, '--plain-http', '--insecure', '--insecure-skip-tls-verify'];
    for (const c of calls) {
      for (const flag of insecure)
        expect(c.args, `${c.command} ${c.args.join(' ')}`).not.toContain(flag);
    }
  });

  it('does not upload to Rekor, and verifies without it, unless the switch is turned on', async () => {
    expect(REKOR_FOR_REAL_RELEASES).toBe(false);
    const { exec, calls } = recorder();
    await run(exec);
    const cosign = calls.filter((c) => c.command === 'cosign');
    expect(cosign.map((c) => c.args[0])).toContain('sign-blob');
    for (const c of cosign.filter((x) =>
      ['sign', 'attest', 'sign-blob'].includes(x.args[0] ?? ''),
    )) {
      expect(c.args).toEqual(expect.arrayContaining([...SIGN_OFFLINE]));
      expect(c.env).toMatchObject({ COSIGN_PASSWORD: PASSWORD });
    }
    for (const c of cosign.filter((x) => x.args[0]?.startsWith('verify'))) {
      expect(c.args).toEqual(expect.arrayContaining([...VERIFY_OFFLINE]));
    }
  });
});
