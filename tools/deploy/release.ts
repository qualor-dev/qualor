import type { ImageName } from './debian-sources';
import { IMAGES } from './debian-sources';
import { imageTags, parseVersion, type Version } from '../release/version';

/**
 * The image names of a release: Docker Hub's `qualor` namespace, one tag for an image and
 * its `-sources` companion. Kept apart from release-images.ts, which runs Docker, so the order of
 * the steps can be tested.
 */
export const NAMESPACE = 'qualor';
/**
 * Where the images wait while they are checked. It is not a Docker Hub namespace Qualor owns and
 * nothing documents pushing it, so a failed check leaves nothing a release push would pick up.
 */
export const STAGING = 'qualor-release-staging';
export const TAG = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;
/** A Docker Hub namespace: lower-case letters, digits and single separators. */
export const NAMESPACE_PATTERN =
  /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$/;

export interface ReleaseArgs {
  tag: string;
  /** The moving tags (release.md §2, `imageTags`), given as `--also <tag>`, each once. */
  also: string[];
  namespace: string;
}

/** Decided 2026-09-26: never `latest`, and no floating `0` in 0.x. */
export const NEVER_PUBLISHED = ['latest', '0'] as const;

function option(argv: readonly string[], name: string, fallback: string): string {
  const i = argv.indexOf(name);
  return i === -1 ? fallback : (argv[i + 1] ?? '');
}

/** Every value of a repeatable option; a missing value is ''. */
function options(argv: readonly string[], name: string): string[] {
  const out: string[] = [];
  argv.forEach((a, i) => {
    if (a === name) out.push(argv[i + 1] ?? '');
  });
  return out;
}

export function releaseArgs(argv: readonly string[]): ReleaseArgs {
  const tag = option(argv, '--tag', 'dev');
  const also = options(argv, '--also');
  for (const t of [tag, ...also]) {
    if (!TAG.test(t)) throw new Error(`not a valid image tag: "${t}"`);
    if ((NEVER_PUBLISHED as readonly string[]).includes(t)) {
      throw new Error(`the tag "${t}" is never published`);
    }
  }
  const seen = new Set<string>();
  for (const t of [tag, ...also]) {
    if (seen.has(t)) throw new Error(`the tag "${t}" is given twice`);
    seen.add(t);
  }
  const namespace = option(argv, '--namespace', NAMESPACE);
  if (!NAMESPACE_PATTERN.test(namespace) || namespace === STAGING) {
    throw new Error(`not a valid namespace: "${namespace}"`);
  }
  return { tag, also, namespace };
}

/**
 * release.md §2, §5: every `--also` tag must be a moving tag that `imageTags(tag, released)`
 * gives the SemVer `--tag`, so a moving tag never goes backwards and never names another line.
 * No `--also` at all is always allowed (a build under one tag).
 */
export function alsoProblems(
  { tag, also }: Pick<ReleaseArgs, 'tag' | 'also'>,
  released: readonly Version[],
): string[] {
  if (also.length === 0) return [];
  let v: Version;
  try {
    v = parseVersion(tag);
  } catch {
    return [`--also needs a SemVer --tag (release.md §2); ${JSON.stringify(tag)} is not one`];
  }
  const allowed = imageTags(v, released).slice(1);
  return also
    .filter((t) => !allowed.includes(t))
    .map(
      (t) =>
        `--also ${t}: ${tag} gets no moving tag ${t} (it would move backwards; allowed: ` +
        `${allowed.length > 0 ? allowed.join(', ') : 'none'})`,
    );
}

export type Flavour = ImageName | `${ImageName}-sources` | 'scanner-dotnet';

/** release.md §5: the push order; each sources image before its image, scanner before scanner-dotnet. */
export const RELEASE_ORDER: readonly Flavour[] = [
  'scanner-sources',
  'scanner',
  'scanner-dotnet',
  'server-sources',
  'server',
];

export const releaseRef = (namespace: string, image: Flavour, tag: string): string =>
  `${namespace}/${image}:${tag}`;
export const stagingRef = (image: Flavour, tag: string): string => `${STAGING}/${image}:${tag}`;

/** What the release needs from Docker; release-images.ts implements it with the CLI. */
export interface ReleaseDocker {
  /** Build `ref` from `args` (the `docker build` arguments after `-t ref`). */
  build(ref: string, args: string[]): void;
  /** Why the Debian packages of `ref` differ from deploy/<image>/debian-sources.json. */
  drift(ref: string, image: ImageName): string[];
  tag(source: string, target: string): void;
  /** Remove the name `ref` (the image stays while another name points at it). */
  untag(ref: string): void;
}

export interface ReleaseInputs {
  /** `docker build` arguments of each image, without `-t`. */
  imageArgs: Record<ImageName, string[]>;
  /** `docker build` arguments of each sources image, without `-t`. */
  sourcesArgs: Record<ImageName, string[]>;
  /** `docker build` arguments of qualor/scanner-dotnet, built FROM the staging scanner. */
  dotnetArgs: (scannerRef: string) => string[];
  /** The error message of a drift, from the staging ref and the problems. */
  driftMessage: (image: ImageName, ref: string, problems: string[]) => string;
}

/**
 * Builds the five images under staging names, checks the Debian packages of the server and the
 * scanner, and only then gives them their release names (every tag: `tag`, then `also`), each
 * sources image before its image and the scanner before scanner-dotnet (release.md §5).
 * scanner-dotnet is built FROM the staging scanner, and only after its Debian check passed; it
 * adds no copyleft component and carries the scanner's sources image. A failed build or check
 * throws before any release name is tagged, so no `qualor/<image>:<tag>` ever exists without
 * its `qualor/<image>-sources:<tag>` (the staging names stay for inspection). Returns the release
 * names in push order.
 */
export function release(
  { tag, also, namespace }: ReleaseArgs,
  inputs: ReleaseInputs,
  docker: ReleaseDocker,
): string[] {
  for (const image of IMAGES) {
    const ref = stagingRef(image, tag);
    docker.build(ref, inputs.imageArgs[image]);
    const problems = docker.drift(ref, image);
    if (problems.length > 0) throw new Error(inputs.driftMessage(image, ref, problems));
    docker.build(stagingRef(`${image}-sources`, tag), inputs.sourcesArgs[image]);
    if (image === 'scanner')
      docker.build(stagingRef('scanner-dotnet', tag), inputs.dotnetArgs(ref));
  }
  const released: string[] = [];
  for (const flavour of RELEASE_ORDER) {
    for (const t of [tag, ...also]) {
      const target = releaseRef(namespace, flavour, t);
      docker.tag(stagingRef(flavour, tag), target);
      released.push(target);
    }
  }
  for (const flavour of RELEASE_ORDER) docker.untag(stagingRef(flavour, tag));
  return released;
}
