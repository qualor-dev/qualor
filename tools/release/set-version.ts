import { REPO_ROOT } from '../deploy/stack';
import { setVersion, versionArgument } from './version';

/** `pnpm release:version <x.y.z>` (release.md §2): the only way a version changes. */
try {
  const v = versionArgument(process.argv.slice(2));
  const changed = setVersion(REPO_ROOT, v);
  process.stdout.write(
    `set ${v.text} in:\n  ${changed.join('\n  ')}\nadd its CHANGELOG.md section\n`,
  );
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
