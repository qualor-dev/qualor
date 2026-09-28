import { existsSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { REPO_ROOT, run } from '../deploy/stack';
import { sumsProblems, SUMS, SUMS_BUNDLE } from './checksums';
import { verifyBlobArgs } from './cosign';
import { runTool, toWork } from './toolbox';

/** release.md §12: the signature of SHA256SUMS, every hash, no unlisted file. */
export interface BlobVerifier {
  verifyBlob(pub: string, file: string, bundle: string): boolean;
}

/** cosign verify-blob in the toolbox, with --network none (the toolbox's default). */
export const cosignVerifier: BlobVerifier = {
  verifyBlob: (pub, file, bundle) =>
    runTool('cosign', verifyBlobArgs(pub, file, bundle)).code === 0,
};

export async function verifyRelease(
  dir: string,
  pub: string,
  verifier: BlobVerifier,
): Promise<string[]> {
  const sums = path.join(dir, SUMS);
  const bundle = path.join(dir, SUMS_BUNDLE);
  const missing = [sums, bundle]
    .filter((f) => !existsSync(f))
    .map((f) => `${path.basename(f)} is missing`);
  if (missing.length > 0) return missing;
  const problems: string[] = [];
  if (!verifier.verifyBlob(toWork(pub), toWork(sums), toWork(bundle))) {
    problems.push(`${SUMS}: the signature does not verify with ${path.basename(pub)}`);
  }
  problems.push(...(await sumsProblems(dir, readFileSync(sums, 'utf8'))));
  return problems;
}

export const VERIFY_USAGE = 'usage: pnpm release:verify <dir> [--key <cosign.pub> | --self-check]';

export interface VerifyArgs {
  dir: string;
  key?: string;
  selfCheck: boolean;
}

/** Ruling R-VERIFYKEY: one directory, `--key <file>` or `--self-check`, and nothing else. */
export function parseVerifyArgs(argv: readonly string[]): VerifyArgs {
  const args = argv[0] === '--' ? argv.slice(1) : [...argv];
  let dir: string | undefined;
  let key: string | undefined;
  let selfCheck = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? '';
    if (a === '--key' && key === undefined) {
      key = args[++i];
      if (key === undefined || key === '' || key.startsWith('--')) throw new Error(VERIFY_USAGE);
    } else if (a === '--self-check' && !selfCheck) selfCheck = true;
    else if (!a.startsWith('-') && a !== '' && dir === undefined) dir = a;
    else throw new Error(`${VERIFY_USAGE}\n(refused: ${JSON.stringify(a)})`);
  }
  if (dir === undefined) throw new Error(VERIFY_USAGE);
  if (key !== undefined && selfCheck) {
    throw new Error(`${VERIFY_USAGE}\n(--key and --self-check exclude each other)`);
  }
  return { dir, key, selfCheck };
}

export interface VerifyKey {
  pub: string;
  /** Printed with the key, every time. */
  source: string;
  warning?: string;
}

/** Whether git tracks `file` (relative to the repository root). */
export function gitTracks(file: string, root = REPO_ROOT): boolean {
  return run('git', ['ls-files', '--error-unmatch', '--', file], { cwd: root }).code === 0;
}

/**
 * The key of release.md §12: `--key`, else the git-tracked repository-root cosign.pub; the
 * directory's own key only with --self-check, and then with a warning.
 */
export function resolveVerifyKey(
  a: VerifyArgs,
  root = REPO_ROOT,
  tracked: (file: string) => boolean = (f) => gitTracks(f, root),
): VerifyKey {
  if (a.key !== undefined) {
    const pub = path.resolve(a.key);
    if (!existsSync(pub)) throw new Error(`${pub}: no such key file`);
    if (!statSync(pub).isFile()) throw new Error(`${pub}: not a regular file (a public key)`);
    return { pub, source: '--key' };
  }
  if (a.selfCheck) {
    return {
      pub: path.join(path.resolve(a.dir), 'cosign.pub'),
      source: '--self-check: the cosign.pub inside the directory',
      warning:
        'WARNING: --self-check verifies the directory with the key it carries itself. That ' +
        'proves only that the directory is consistent, not who made it. Verify a real release ' +
        'with --key and the published https://qualor.dev/cosign.pub.',
    };
  }
  const committed = path.join(root, 'cosign.pub');
  if (existsSync(committed) && tracked('cosign.pub')) {
    return { pub: committed, source: 'the git-tracked cosign.pub at the repository root' };
  }
  throw new Error(
    'no key to verify with: git tracks no cosign.pub at the repository root yet. Pass ' +
      '--key <cosign.pub> (the published https://qualor.dev/cosign.pub), or --self-check for a ' +
      "dry run's own directory",
  );
}
