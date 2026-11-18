/**
 * B8, R20: the `qualor` binary is linked against glibc. The CI scripts stop a musl image before
 * they start it (a glibc binary cannot start there at all); the binary itself also refuses when a
 * musl loader is present, which catches an image with a glibc compatibility layer (gcompat).
 */

/** musl's dynamic loader per architecture, as musl names them. */
const MUSL_LOADERS: readonly string[] = [
  'x86_64',
  'aarch64',
  'armhf',
  'arm',
  'i386',
  'powerpc64le',
  'powerpc64',
  'riscv64',
  's390x',
  'loongarch64',
  'mips64',
  'mips64el',
  'x32',
].map((arch) => `/lib/ld-musl-${arch}.so.1`);

/**
 * Why `qualor fix` cannot run here, or null: only the compiled binary (`process.versions.bun`) on
 * Linux with a musl loader in `/lib` refuses. The message names the loader found.
 */
export function muslProblem(o: {
  platform: NodeJS.Platform;
  compiled: boolean;
  exists: (p: string) => boolean;
}): string | null {
  if (o.platform !== 'linux' || !o.compiled) return null;
  const loader = MUSL_LOADERS.find((p) => o.exists(p));
  if (loader === undefined) return null;
  return (
    `qualor fix needs a glibc-based image (Debian, Ubuntu, the RHEL family); this system uses musl ` +
    `(${loader}), as Alpine does. Run the fix job in a glibc image ` +
    '(see https://qualor.dev/docs/fix-merge-requests)'
  );
}
