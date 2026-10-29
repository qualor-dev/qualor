import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * `pnpm site:screens`: the qualor.dev site's four product screens (overview, issues, issue-ai,
 * gate), captured from the seeded e2e server (ui/e2e/site-screens.shot.ts). The issue-ai screen
 * asks the real model, so the key is required before anything starts: no build, no server, no
 * browser. The key is only passed on in the environment, never printed.
 */
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

/** The place the screens go: `SITE_SCREENS_OUT`, else the site's assets next to the repository. */
const DEFAULT_OUTS = ['../qualor.dev/src/assets/screens', '../../qualor.dev/src/assets/screens'];

export type SiteScreensPlan = { ok: true; out: string } | { ok: false; message: string };

/** Whether the capture may start, and where it writes. Pure: `exists` stands in for the disk. */
export function planSiteScreens(
  env: Record<string, string | undefined>,
  exists: (dir: string) => boolean,
  base = root,
): SiteScreensPlan {
  if ((env['LIVE_OPENAI_API_KEY'] ?? '') === '') {
    return {
      ok: false,
      message:
        'site:screens asks the real model for the issue-ai screen and needs LIVE_OPENAI_API_KEY in ' +
        'the environment. Nothing was started.',
    };
  }
  const given = env['SITE_SCREENS_OUT'];
  if (given !== undefined && given !== '') return { ok: true, out: path.resolve(base, given) };
  const found = DEFAULT_OUTS.map((dir) => path.resolve(base, dir)).find(exists);
  if (found === undefined) {
    return {
      ok: false,
      message:
        'site:screens found no ../qualor.dev/src/assets/screens: set SITE_SCREENS_OUT to the ' +
        'directory the PNGs go to. Nothing was started.',
    };
  }
  return { ok: true, out: found };
}

if (
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const plan = planSiteScreens(process.env, existsSync);
  if (!plan.ok) {
    process.stderr.write(`${plan.message}\n`);
    process.exit(1);
  }
  const run = spawnSync(
    'pnpm',
    ['--filter', '@qualor/ui', 'exec', 'playwright', 'test', '--project=site-screens'],
    {
      cwd: root,
      stdio: 'inherit',
      shell: process.platform === 'win32',
      env: { ...process.env, QUALOR_TELEMETRY: 'false', SITE_SCREENS_OUT: plan.out },
    },
  );
  process.exit(run.status ?? 1);
}
