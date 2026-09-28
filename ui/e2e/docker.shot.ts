import { mkdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { Page } from '@playwright/test';
import type { DockerSeed } from './docker-seed';
import { expect, test } from './fixtures';

/**
 * `pnpm deploy:screenshots` (plan 1G): one PNG per screen of the dockerized server, with the data
 * `tools/deploy/screenshots.ts` seeded by scanning this repository (main-branch history and a
 * merge request that fails the gate) and the three fixtures, into the git-ignored
 * `.tmp/screenshots-docker/`. The console guard of fixtures.ts applies, as in the e2e suite.
 */
const OUT = fileURLToPath(new URL('../../.tmp/screenshots-docker/', import.meta.url));
mkdirSync(OUT, { recursive: true });
const seedFile = process.env['QUALOR_DOCKER_SEED'];
if (!seedFile) throw new Error('QUALOR_DOCKER_SEED is not set: run pnpm deploy:screenshots');
const seed = JSON.parse(readFileSync(seedFile, 'utf8')) as DockerSeed;

async function shoot(page: Page, name: string): Promise<void> {
  // Let lazy chunks and data settle so every PNG shows the finished page.
  await page.waitForLoadState('networkidle');
  await page.screenshot({ path: `${OUT}${name}.png`, fullPage: true });
}

test.describe('signed out', () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test('01 login', async ({ page }) => {
    await page.goto('/login');
    await expect(page.getByRole('heading', { name: 'Sign in to Qualor' })).toBeVisible();
    await shoot(page, '01-login');
  });
});

test('02 projects', async ({ page }) => {
  await page.goto('/projects');
  const main = page.getByRole('main');
  await expect(main.getByRole('link', { name: 'Qualor', exact: true })).toBeVisible();
  await expect(main.getByRole('link', { name: seed.fixtures['mixed-secrets'].name })).toBeVisible();
  await shoot(page, '02-projects');
});

test('03 Qualor overview, 04 branches, 05 merge request', async ({ page }) => {
  await page.goto(`/projects/${seed.qualor.id}`);
  await expect(page.getByRole('link', { name: 'All open issues' })).toBeVisible();
  await shoot(page, '03-qualor-overview');
  await page.goto(`/projects/${seed.qualor.id}/branches`);
  await expect(page.locator('tbody tr')).toHaveCount(2);
  await shoot(page, '04-qualor-branches');
  await page.goto(`/projects/${seed.qualor.id}/branches/${seed.qualor.mergeRequestBranchId}`);
  await expect(page.locator('.branch-name')).toBeVisible();
  await shoot(page, '05-qualor-merge-request');
});

test('06 issues, 07 issue', async ({ page }) => {
  await page.goto(`/projects/${seed.fixtures['mixed-secrets'].id}`);
  await page.getByRole('link', { name: 'All open issues' }).click();
  // Every wait after a click names the new page: the overview has tables and headings too.
  await expect(page).toHaveURL(/\/projects\/[^/]+\/issues(\?|$)/);
  await expect(page.getByText('No issue selected')).toBeVisible();
  await expect(page.locator('tbody tr').first()).toBeVisible();
  await shoot(page, '06-issues');
  await page.locator('tbody a').first().click();
  await expect(page).toHaveURL(/\/issues\/[^/?]+/);
  await expect(page.getByRole('region', { name: 'History' })).toBeVisible();
  await shoot(page, '07-issue');
});

test('08 Java fixture overview', async ({ page }) => {
  await page.goto(`/projects/${seed.fixtures['java-basic'].id}`);
  await expect(page.getByRole('link', { name: 'All open issues' })).toBeVisible();
  await shoot(page, '08-java-overview');
});

test('09 gates, 10 gate', async ({ page }) => {
  await page.goto('/gates');
  await expect(page.getByRole('link', { name: 'Qualor way' })).toBeVisible();
  await shoot(page, '09-gates');
  await page.getByRole('link', { name: 'Qualor way' }).click();
  await expect(page).toHaveURL(/\/gates\/[^/?]+/);
  await expect(page.getByRole('heading', { level: 2, name: 'Conditions' })).toBeVisible();
  await shoot(page, '10-gate');
});

test('11 rules, 12 profiles, 13 profile', async ({ page }) => {
  await page.goto('/rules');
  await expect(page.locator('tbody tr').first()).toBeVisible();
  await shoot(page, '11-rules');
  await page.goto('/profiles');
  await expect(page.getByRole('link', { name: 'Qualor way' }).first()).toBeVisible();
  await shoot(page, '12-profiles');
  await page.getByRole('link', { name: 'Qualor way' }).first().click();
  await expect(page).toHaveURL(/\/profiles\/[^/?]+/);
  await expect(page.getByRole('heading', { level: 1, name: 'Qualor way' })).toBeVisible();
  await shoot(page, '13-profile');
});

test('14 tokens, 15 users, 16 webhooks', async ({ page }) => {
  await page.goto('/settings/tokens');
  await expect(page.getByRole('heading', { name: 'Your access tokens' })).toBeVisible();
  await shoot(page, '14-settings-tokens');
  await page.getByRole('link', { name: 'Users' }).click();
  await expect(page).toHaveURL(/\/settings\/users$/);
  await expect(page.getByRole('heading', { level: 2, name: 'Users' })).toBeVisible();
  await expect(page.getByRole('row', { name: /admin/ })).toBeVisible();
  await shoot(page, '15-settings-users');
  await page.getByRole('link', { name: 'Webhooks' }).click();
  await expect(page).toHaveURL(/\/settings\/webhooks$/);
  // The settings tabs share the page's h1: wait for the webhooks tab's own heading.
  await expect(page.getByRole('heading', { level: 2, name: 'Webhooks' })).toBeVisible();
  await shoot(page, '16-settings-webhooks');
});
