import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { REPO_ROOT } from '../deploy/stack';
import { buildToolbox } from './toolbox';

/**
 * `pnpm helm:test` / `pnpm release:test` (ruling RE5): builds the toolbox image, then runs the
 * vitest project release-tools, filtered by the arguments (for example tools/helm).
 */
buildToolbox();
const vitest = path.join(REPO_ROOT, 'node_modules', 'vitest', 'vitest.mjs');
const r = spawnSync(
  process.execPath,
  [vitest, 'run', '--project', 'release-tools', ...process.argv.slice(2)],
  { cwd: REPO_ROOT, stdio: 'inherit', env: { ...process.env, QUALOR_RELEASE_TOOLS: '1' } },
);
process.exitCode = r.status ?? 1;
