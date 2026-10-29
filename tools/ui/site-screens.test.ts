import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { planSiteScreens } from './site-screens';

const base = '/repo/qualor-cc';
const key = { LIVE_OPENAI_API_KEY: 'sk-not-a-real-key' };

describe('planSiteScreens', () => {
  it('refuses without the key, before it looks at any directory', () => {
    const plan = planSiteScreens({ SITE_SCREENS_OUT: '/out' }, () => {
      throw new Error('looked at the disk');
    });
    expect(plan.ok).toBe(false);
    expect(plan).toMatchObject({ message: expect.stringContaining('LIVE_OPENAI_API_KEY') });
  });

  it('refuses an empty key', () => {
    expect(planSiteScreens({ LIVE_OPENAI_API_KEY: '' }, () => true).ok).toBe(false);
  });

  it('writes to SITE_SCREENS_OUT when it is set', () => {
    const plan = planSiteScreens({ ...key, SITE_SCREENS_OUT: 'shots' }, () => false, base);
    expect(plan).toEqual({ ok: true, out: path.resolve(base, 'shots') });
  });

  it('defaults to the site next to the repository, or next to the worktrees folder', () => {
    const site = path.resolve(base, '../../qualor.dev/src/assets/screens');
    expect(planSiteScreens(key, (dir) => dir === site, base)).toEqual({ ok: true, out: site });
  });

  it('refuses when there is no site directory and no SITE_SCREENS_OUT', () => {
    const plan = planSiteScreens(key, () => false, base);
    expect(plan).toMatchObject({ ok: false, message: expect.stringContaining('SITE_SCREENS_OUT') });
  });

  it('exits with 1 and starts nothing when run without the key', () => {
    const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const env = { ...process.env, LIVE_OPENAI_API_KEY: '' };
    const run = spawnSync(process.execPath, ['--import', 'tsx', 'tools/ui/site-screens.ts'], {
      cwd: root,
      env,
      encoding: 'utf8',
    });
    expect(run.status).toBe(1);
    expect(run.stderr).toContain('Nothing was started.');
  });
});
