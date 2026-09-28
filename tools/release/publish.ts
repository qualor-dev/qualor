import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { must, REPO_ROOT, run, type RunResult } from '../deploy/stack';
import { NEVER_PUBLISHED } from '../deploy/release';
import { IMAGE_SOURCES, writeAssets } from './assets';
import { SUMS, SUMS_BUNDLE, sumsProblems } from './checksums';
import {
  attestArgs,
  signBlobArgs,
  signImageArgs,
  verifyAttestationArgs,
  verifyBlobArgs,
  verifyImageArgs,
  type RegistryOptions,
} from './cosign';
import { releaseRefs } from './images';
import { readManifest, type ReleaseManifest } from './manifest';
import { parsePushDigest } from './registry';
import { runTool, toWork } from './toolbox';
import { gitTracks, verifyRelease } from './verify';
import { currentVersion, gitTag, releasedVersions, type Version } from './version';

/**
 * `pnpm release:publish` (release.md §11, ruling RE7). Runs only in the `publish` job of
 * .github/workflows/release.yml: started by a person, on the tag v<version>, with the protected
 * environment "release" and its secrets. Anywhere else it lists what is missing and runs nothing.
 * Never run in plan 4A.
 */
export const REQUIRED_SECRETS = [
  'DOCKERHUB_USERNAME',
  'DOCKERHUB_TOKEN',
  'COSIGN_PRIVATE_KEY',
  'COSIGN_PASSWORD',
] as const;
/** Everything taken out of the process environment before any command runs (per-tool env). */
export const SECRET_NAMES = [...REQUIRED_SECRETS, 'GH_TOKEN', 'GITHUB_TOKEN'] as const;
export const CHART_REPOSITORY = 'oci://registry-1.docker.io/qualor';
/**
 * Open, default off: whether real signatures are also recorded in the public Rekor
 * transparency log. This constant is the one switch, and it is off. With false, every cosign call
 * of the publish path (sign, attest, sign-blob) carries --tlog-upload=false and
 * --use-signing-config=false, so nothing goes to Rekor, and every verification skips the
 * transparency log (VERIFY_OFFLINE), as every documented verify command does (repo-docs.test.ts).
 * Turning it on is a reviewed commit that changes this line, publish.test.ts and release.md §11
 * together, once the maintainer decides; it is deliberately not an environment variable or
 * a workflow input.
 */
export const REKOR_FOR_REAL_RELEASES = false;
/** Ruling R-REGOPTS: Docker Hub over HTTPS; never the dry run's plain-HTTP flags. */
export const PUBLISH_OPTIONS: RegistryOptions = {
  offline: !REKOR_FOR_REAL_RELEASES,
  plainHttp: false,
};
/** The namespace of every published image. */
const NAMESPACE = 'qualor';
/** Ruling R-ORDER: the one non-moving tag an image has before it is signed. */
export const stagingTag = (v: Version): string => `staging-${v.text}`;

export function publishGateProblems(
  env: Record<string, string | undefined>,
  version: string,
  root = REPO_ROOT,
): string[] {
  const problems: string[] = [];
  const want = (name: string, value: string): void => {
    if (env[name] !== value) problems.push(`${name} must be "${value}"`);
  };
  want('CI', 'true');
  want('GITHUB_ACTIONS', 'true');
  want('GITHUB_EVENT_NAME', 'workflow_dispatch');
  want('GITHUB_REF_TYPE', 'tag');
  want('GITHUB_REF_NAME', `v${version}`);
  want('QUALOR_RELEASE_CONFIRM', `publish v${version}`);
  for (const s of REQUIRED_SECRETS) {
    if (!env[s]) problems.push(`${s} is not set (a secret of the environment "release")`);
  }
  if (!env['GH_TOKEN']) problems.push('GH_TOKEN is not set (the job token, for gh release)');
  if (!existsSync(path.join(root, 'cosign.pub'))) {
    problems.push('cosign.pub is not committed at the repository root');
  }
  return problems;
}

export type Command = 'docker' | 'cosign' | 'helm' | 'gh' | 'tar';
/** `env` is everything the command gets beyond the scrubbed process environment. */
export type Exec = (
  command: Command,
  args: string[],
  o?: { input?: string; env?: Record<string, string> },
) => RunResult;

/** What publishing reads from git; read-only, and injectable for the tests. */
export interface RepoFacts {
  head(): string;
  tracks(file: string): boolean;
  /** Whether HEAD is `ref` or an ancestor of it (false when the ref does not exist). */
  contains(ref: string): boolean;
}

export const gitFacts = (root = REPO_ROOT): RepoFacts => ({
  head: () => must(run('git', ['rev-parse', 'HEAD'], { cwd: root }), 'git rev-parse').stdout.trim(),
  tracks: (file) => gitTracks(file, root),
  contains: (ref) =>
    run('git', ['merge-base', '--is-ancestor', 'HEAD', ref], { cwd: root }).code === 0,
});

/** The branches a release may be cut from (release.md §11). */
export const releaseBranches = (v: Version): string[] => [
  'origin/main',
  `origin/release/${v.major}.${v.minor}`,
];

/** A manifest path must stay inside the release directory and name a regular file there. */
function insideProblems(dir: string, what: string, file: unknown): string[] {
  if (
    typeof file !== 'string' ||
    file === '' ||
    path.isAbsolute(file) ||
    file.includes('\\') ||
    file.split('/').some((p) => p === '..' || p === '.' || p === '')
  ) {
    return [`${what} ${JSON.stringify(file)} leaves the release directory`];
  }
  const full = path.join(dir, file);
  if (!existsSync(full) || !lstatSync(full).isFile()) {
    return [`${what} ${file} is not a regular file in the release directory`];
  }
  return [];
}

/**
 * What the dry run must hold before anything is pushed: images and CLI sources, a manifest that
 * is the dry run's own at this very commit, contained paths, an intact directory, and exactly the
 * tags of releaseRefs(v, releasedVersions()), so 0.x publishes only 0.Y.Z and 0.Y and a moving
 * tag never goes backwards (release.md §2). Also: a tracked cosign.pub, and a HEAD on a release
 * branch. Everything here only reads.
 */
async function publishableProblems(
  m: ReleaseManifest,
  v: Version,
  released: readonly Version[],
  root: string,
  dir: string,
  repo: RepoFacts,
): Promise<string[]> {
  if (
    m.version !== v.text ||
    !m.cliSources ||
    !Array.isArray(m.images) ||
    m.images.length === 0 ||
    m.chart.digest === null
  ) {
    return [
      'the dry run is not complete for publishing: run pnpm release:dry-run with images and CLI sources',
    ];
  }
  const problems: string[] = [];
  if (m.dryRun !== true) problems.push('release-manifest.json does not say dryRun: true');
  const head = repo.head();
  if (m.gitCommit !== head) {
    problems.push(
      `the dry run was made at ${m.gitCommit}, not at HEAD ${head} (a dirty tree never publishes)`,
    );
  }
  if (!Array.isArray(m.files)) problems.push('release-manifest.json has no files list');
  else for (const f of m.files) problems.push(...insideProblems(dir, 'files:', f));
  problems.push(...insideProblems(dir, 'chart.file:', m.chart.file));
  for (const img of m.images) {
    if (img.sbom !== null) problems.push(...insideProblems(dir, `${img.image} sbom:`, img.sbom));
  }
  const sums = path.join(dir, SUMS);
  if (!existsSync(sums)) problems.push(`${SUMS} is missing from the release directory`);
  else problems.push(...(await sumsProblems(dir, readFileSync(sums, 'utf8'))));
  const want = releaseRefs(NAMESPACE, v, released);
  const have = m.images.map((i) => ({ image: i.image, refs: i.refs }));
  if (JSON.stringify(have) !== JSON.stringify(want)) {
    problems.push(
      `the dry run's image tags are not the release's tags (releaseRefs with the released versions): ` +
        `expected ${JSON.stringify(want)}, found ${JSON.stringify(have)}`,
    );
  }
  for (const ref of m.images.flatMap((i) => i.refs)) {
    const tag = ref.slice(ref.lastIndexOf(':') + 1);
    if ((NEVER_PUBLISHED as readonly string[]).includes(tag)) {
      problems.push(`${ref}: the tag "${tag}" is never published`);
    }
  }
  for (const image of IMAGE_SOURCES) {
    if (!existsSync(path.join(root, '.tmp', `${image}-sources`))) {
      problems.push(`.tmp/${image}-sources is missing: run pnpm deploy:sources`);
    }
  }
  if (!repo.tracks('cosign.pub')) {
    problems.push('cosign.pub at the repository root is not tracked by git');
  }
  const branches = releaseBranches(v);
  if (!branches.some((b) => repo.contains(b))) {
    problems.push(
      `HEAD ${head} is on neither ${branches.join(' nor ')}: tag a merged commit (release.md §11)`,
    );
  }
  return problems;
}

const normalizeKey = (pem: string): string => pem.replace(/\r\n/g, '\n').trim();

export async function publish(
  env: Record<string, string | undefined>,
  v: Version,
  dir: string,
  exec: Exec,
  root = REPO_ROOT,
  released?: readonly Version[],
  repo: RepoFacts = gitFacts(root),
): Promise<void> {
  const problems = publishGateProblems(env, v.text, root);
  if (problems.length > 0) {
    throw new Error(`release:publish refused; nothing was run:\n  ${problems.join('\n  ')}`);
  }
  const m = readManifest(dir);
  // The `v*` tags of the checkout (release.yml fetches them all), read only after the gate.
  const notReady = await publishableProblems(
    m,
    v,
    released ?? releasedVersions(root),
    root,
    dir,
    repo,
  );
  if (notReady.length > 0) {
    throw new Error(`release:publish refused; nothing was run:\n  ${notReady.join('\n  ')}`);
  }
  const work = path.join(root, '.tmp', 'release-work', v.text);
  const secrets = path.join(work, 'publish');
  const download = path.join(work, 'download');
  const assets = path.join(root, '.tmp', 'release-assets', v.text);
  const dockerConfig = path.join(secrets, 'docker');
  const pub = path.join(root, 'cosign.pub');
  // Per-tool environments (release.md §11): docker gets its config path only, cosign its
  // password by name, Helm its config paths, gh its token, tar nothing.
  const dockerEnv = { DOCKER_CONFIG: dockerConfig };
  const cosignEnv = {
    COSIGN_PASSWORD: env['COSIGN_PASSWORD'] ?? '',
    DOCKER_CONFIG: toWork(dockerConfig),
  };
  const helmEnv = {
    DOCKER_CONFIG: toWork(dockerConfig),
    HELM_REGISTRY_CONFIG: `${toWork(dockerConfig)}/config.json`,
  };
  const ghEnv = { GH_TOKEN: env['GH_TOKEN'] ?? '' };
  const verifier = {
    verifyBlob: (p: string, f: string, b: string) =>
      exec('cosign', verifyBlobArgs(p, f, b), { env: {} }).code === 0,
  };
  const docker = (args: string[], what: string): RunResult =>
    must(exec('docker', args, { env: dockerEnv }), what);
  const cosign = (args: string[], what: string): RunResult =>
    must(exec('cosign', args, { env: cosignEnv }), what);

  // A directory left by a crashed run may hold an old key with other permissions: start clean.
  rmSync(secrets, { recursive: true, force: true });
  mkdirSync(dockerConfig, { recursive: true });
  try {
    const keyFile = path.join(secrets, 'cosign.key');
    writeFileSync(keyFile, env['COSIGN_PRIVATE_KEY'] ?? '', { mode: 0o600 });
    chmodSync(keyFile, 0o600);
    const key = toWork(keyFile);

    // 1. The key must be the one whose public half is tracked, before any login.
    const derived = cosign(['public-key', '--key', key], 'cosign public-key').stdout;
    if (normalizeKey(derived) !== normalizeKey(readFileSync(pub, 'utf8'))) {
      throw new Error(
        'COSIGN_PRIVATE_KEY does not belong to the tracked cosign.pub; nothing was pushed',
      );
    }

    // 2. Log in; the token goes through stdin only.
    must(
      exec(
        'docker',
        ['login', '--username', env['DOCKERHUB_USERNAME'] ?? '', '--password-stdin', 'docker.io'],
        { input: env['DOCKERHUB_TOKEN'], env: dockerEnv },
      ),
      'docker login',
    );

    // 3. Every image under the one staging tag (R-ORDER), in §5's order; digests compared.
    const pushAs = (source: string, target: string, want: string): void => {
      if (source !== target) docker(['tag', source, target], `docker tag ${target}`);
      const pushed = parsePushDigest(docker(['push', target], `docker push ${target}`).stdout);
      // Ruling R-DIGEST: the packaged chart pins the digest the dry run signed and recorded.
      if (pushed !== want) {
        throw new Error(
          `${target}: Docker Hub reports ${pushed}, but the dry run recorded ${want}, which the ` +
            'packaged chart pins (ruling R-DIGEST); stopping before any version tag is pushed',
        );
      }
    };
    for (const img of m.images) {
      const first = img.refs[0] ?? '';
      pushAs(first, `${NAMESPACE}/${img.image}:${stagingTag(v)}`, img.digest);
    }

    // 4. Sign and attest by digest, then verify each with the tracked cosign.pub.
    for (const img of m.images) {
      const signed = `docker.io/${NAMESPACE}/${img.image}@${img.digest}`;
      cosign(signImageArgs(key, signed, PUBLISH_OPTIONS), `cosign sign ${img.image}`);
      if (img.sbom) {
        const sbom = toWork(path.join(dir, img.sbom));
        cosign(attestArgs(key, signed, sbom, PUBLISH_OPTIONS), `cosign attest ${img.image}`);
      }
    }
    for (const img of m.images) {
      const signed = `docker.io/${NAMESPACE}/${img.image}@${img.digest}`;
      cosign(verifyImageArgs(toWork(pub), signed, PUBLISH_OPTIONS), `cosign verify ${img.image}`);
      if (img.sbom) {
        cosign(
          verifyAttestationArgs(toWork(pub), signed, PUBLISH_OPTIONS),
          `cosign verify-attestation ${img.image}`,
        );
      }
    }

    // 5. Only now the version and moving tags, each compared with the signed digest again.
    for (const img of m.images) {
      for (const ref of img.refs) pushAs(ref, ref, img.digest);
    }

    // 6. The chart: pushed, signed by digest, verified.
    const pushed = must(
      exec('helm', ['push', toWork(path.join(dir, m.chart.file)), CHART_REPOSITORY], {
        env: helmEnv,
      }),
      'helm push',
    );
    const chartDigest = /Digest: (sha256:[0-9a-f]{64})/.exec(pushed.stdout + pushed.stderr)?.[1];
    if (!chartDigest) throw new Error('helm push printed no digest');
    // docker.io, like the images: the name docker login stored the credentials under.
    const chartRef = `docker.io/${NAMESPACE}/qualor@${chartDigest}`;
    cosign(signImageArgs(key, chartRef, PUBLISH_OPTIONS), 'cosign sign chart');
    cosign(verifyImageArgs(toWork(pub), chartRef, PUBLISH_OPTIONS), 'cosign verify chart');

    // 7. The release assets (release.md §3, I-2): flat, their own SHA256SUMS, signed, verified.
    const published: ReleaseManifest = {
      ...m,
      dryRun: false,
      chart: { ...m.chart, digest: chartDigest },
    };
    const sums = await writeAssets({
      dir,
      version: v.text,
      out: assets,
      replace: {
        'cosign.pub': readFileSync(pub, 'utf8'),
        'release-manifest.json': `${JSON.stringify(published, null, 2)}\n`,
      },
      tar: (tarFile, cwd, entry) => {
        must(exec('tar', ['-cf', tarFile, '-C', cwd, entry], { env: {} }), `tar ${entry}`);
      },
      imageSourcesRoot: path.join(root, '.tmp'),
    });
    const bundle = path.join(assets, SUMS_BUNDLE);
    cosign(
      signBlobArgs(key, toWork(sums), toWork(bundle), { offline: PUBLISH_OPTIONS.offline }),
      'cosign sign-blob',
    );
    const own = await verifyRelease(assets, pub, verifier);
    if (own.length > 0) throw new Error(`the release assets do not verify:\n  ${own.join('\n  ')}`);

    // 8. A draft release with exactly those files; download it, verify it, then publish it.
    const files = readdirSync(assets)
      .sort()
      .map((f) => path.join(assets, f));
    const tag = gitTag(v);
    must(
      exec(
        'gh',
        [
          'release',
          'create',
          tag,
          '--draft',
          '--verify-tag',
          '--title',
          `Qualor ${v.text}`,
          '--notes-file',
          path.join(assets, 'release-notes.md'),
          ...files,
        ],
        { env: ghEnv },
      ),
      'gh release create --draft',
    );
    rmSync(download, { recursive: true, force: true });
    mkdirSync(download, { recursive: true });
    must(
      exec('gh', ['release', 'download', tag, '--dir', download], { env: ghEnv }),
      'gh release download',
    );
    const downloaded = await verifyRelease(download, pub, verifier);
    if (downloaded.length > 0) {
      throw new Error(
        `the draft release ${tag} does not verify; it stays a draft:\n  ${downloaded.join('\n  ')}`,
      );
    }
    must(
      exec('gh', ['release', 'edit', tag, '--draft=false'], { env: ghEnv }),
      'gh release edit --draft=false',
    );
  } finally {
    rmSync(secrets, { recursive: true, force: true });
    rmSync(download, { recursive: true, force: true });
  }
}

/**
 * Takes the secrets out of `processEnv` (so no command inherits them) and returns them with the
 * rest of it, for publish() to hand to each tool as it needs them.
 */
export function takeSecrets(
  processEnv: Record<string, string | undefined>,
): Record<string, string | undefined> {
  const env = { ...processEnv };
  for (const name of SECRET_NAMES) Reflect.deleteProperty(processEnv, name);
  return env;
}

/** cosign and Helm run in the toolbox; only the registry calls get the bridge network. */
const OFFLINE_COSIGN = new Set(['public-key', 'verify-blob']);
const realExec: Exec = (command, args, o = {}) => {
  if (command === 'cosign' || command === 'helm') {
    const byName: Record<string, string> = {};
    const plain: Record<string, string> = {};
    for (const [name, value] of Object.entries(o.env ?? {})) {
      if (name === 'COSIGN_PASSWORD') byName[name] = value;
      else plain[name] = value;
    }
    const offline = command === 'cosign' && OFFLINE_COSIGN.has(args[0] ?? '');
    return runTool(command, args, {
      ...(offline ? {} : { network: 'bridge', allowPublishNetwork: true }),
      env: byName,
      plainEnv: plain,
    });
  }
  return run(command, args, { input: o.input, env: o.env });
};

if (process.argv[1]?.endsWith('publish.ts')) {
  const env = takeSecrets(process.env);
  const v = currentVersion();
  publish(env, v, path.join(REPO_ROOT, '.tmp', 'release', v.text), realExec).catch(
    (error: unknown) => {
      process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 1;
    },
  );
}
