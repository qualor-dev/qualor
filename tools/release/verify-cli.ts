import { copyFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { REPO_ROOT } from '../deploy/stack';
import { buildToolbox, toWork } from './toolbox';
import { cosignVerifier, parseVerifyArgs, resolveVerifyKey, verifyRelease } from './verify';

function insideRepo(file: string): boolean {
  try {
    toWork(file);
    return true;
  } catch {
    return false;
  }
}

/**
 * `pnpm release:verify <dir> [--key <cosign.pub> | --self-check]` (release.md §12, ruling
 * R-VERIFYKEY). A key outside the repository is copied into .tmp/release-verify/ first, since
 * the toolbox sees only /work.
 */
async function main(): Promise<void> {
  const a = parseVerifyArgs(process.argv.slice(2));
  const dir = path.resolve(a.dir);
  if (!insideRepo(dir)) {
    throw new Error(`${dir} is outside the repository; the toolbox sees only the repository`);
  }
  const k = resolveVerifyKey(a);
  process.stdout.write(`key: ${k.pub} (${k.source})\n`);
  if (k.warning) process.stderr.write(`${k.warning}\n`);
  let pub = k.pub;
  if (!insideRepo(pub)) {
    const copy = path.join(REPO_ROOT, '.tmp', 'release-verify', 'cosign.pub');
    mkdirSync(path.dirname(copy), { recursive: true });
    copyFileSync(pub, copy);
    pub = copy;
  }
  buildToolbox();
  const problems = await verifyRelease(dir, pub, cosignVerifier);
  if (problems.length > 0) throw new Error(`release:verify failed:\n  ${problems.join('\n  ')}`);
  process.stdout.write(`verified: ${dir}\n`);
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
