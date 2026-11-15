import { expect } from 'vitest';

const CACHE_PIN = /^actions\/cache\/(restore|save)@[0-9a-f]{40}$/;

/**
 * The vulnerability database cache around a GitHub Actions scan step: the restore step comes before
 * the scan, the save step (on always()) after it; neither holds the token. GitHub.com pins
 * actions/cache by commit; GHES takes the tag, like its checkout, since it may resolve no
 * github.com commit. The CI-setup templates (server) and integrations/github/*.yml (cli) share it.
 */
export function expectDbCache(
  steps: { uses?: string; if?: string; with?: unknown; env?: unknown }[],
  scan: unknown,
  host: 'cloud' | 'self-hosted' = 'cloud',
): void {
  const restore = steps.find((s) => s.uses?.startsWith('actions/cache/restore@'));
  const save = steps.find((s) => s.uses?.startsWith('actions/cache/save@'));
  if (host === 'cloud') {
    expect(restore?.uses).toMatch(CACHE_PIN);
    expect(save?.uses).toMatch(CACHE_PIN);
  } else {
    expect(restore?.uses).toBe('actions/cache/restore@v4');
    expect(save?.uses).toBe('actions/cache/save@v4');
  }
  expect(restore?.with).toEqual({
    path: '.qualor/trivy',
    key: 'qualor-trivy-db-${{ github.run_id }}',
    'restore-keys': 'qualor-trivy-db-',
  });
  expect(save?.with).toEqual({
    path: '.qualor/trivy',
    key: "qualor-trivy-db-${{ hashFiles('.qualor/trivy/server.json') }}",
  });
  expect(save?.if).toBe("always() && hashFiles('.qualor/trivy/server.json') != ''");
  expect(steps.indexOf(restore!)).toBeLessThan(steps.indexOf(scan as never));
  expect(steps.indexOf(save!)).toBeGreaterThan(steps.indexOf(scan as never));
  for (const step of [restore, save]) {
    expect(step?.env).toBeUndefined();
    expect(JSON.stringify(step)).not.toMatch(/QUALOR_TOKEN|secrets\./);
  }
}
