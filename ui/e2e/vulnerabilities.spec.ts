import type { APIRequestContext } from '@playwright/test';
import { expect, test } from './fixtures';
import { LEGACY, PAYMENTS, VULNERABILITIES } from './seed-data';

/**
 * Vulnerability monitoring (0.15): the Vulnerabilities tab, triage and the badge, on the rows
 * `seedVulnerabilities` writes. Nothing here depends on the status of the vulnerability database.
 *
 * The seed is per run (serve.ts creates a fresh database for every run), but the tests change it,
 * so `afterAll` puts it back: the critical pair is Open again (its "1 new" returns) and 0.9.0 is
 * unsupported again. A second pass in the same server session starts from the seeded state.
 */
test.describe.configure({ mode: 'serial' });

async function projectId(request: APIRequestContext, key: string): Promise<string> {
  const answer = await request.get('/api/v0/projects?limit=100');
  const { items } = (await answer.json()) as { items: { id: string; key: string }[] };
  return items.find((p) => p.key === key)!.id;
}

test.afterAll(async ({ request }) => {
  const me = (await (await request.get('/api/v0/auth/me')).json()) as { csrfToken: string };
  const headers = { 'x-qualor-csrf': me.csrfToken };
  const payments = await projectId(request, PAYMENTS.key);
  const decision = await request.put(`/api/v0/projects/${payments}/vulnerability-decisions`, {
    headers,
    data: {
      packageName: VULNERABILITIES.critical.package,
      vulnerabilityId: VULNERABILITIES.critical.id,
      scope: { kind: 'project' },
      status: 'open',
    },
  });
  expect(decision.ok()).toBe(true);
  const legacy = await projectId(request, LEGACY.key);
  const versions = await request.get(`/api/v0/projects/${legacy}/versions`);
  const { items } = (await versions.json()) as { items: { id: string; label: string }[] };
  const old = items.find((v) => v.label === VULNERABILITIES.legacy.untracked)!;
  const patch = await request.patch(`/api/v0/projects/${legacy}/versions/${old.id}`, {
    headers,
    data: { tracking: 'unsupported' },
  });
  expect(patch.ok()).toBe(true);
});

test('the projects list shows where vulnerabilities are new', async ({ page }) => {
  await page.goto('/projects');
  const payments = page.getByRole('row', { name: new RegExp(PAYMENTS.name) });
  await expect(payments.getByText('New vulnerabilities in main', { exact: true })).toBeVisible();
  const legacy = page.getByRole('row', { name: new RegExp(LEGACY.name) });
  await expect(legacy.getByText('New vulnerabilities in 1 version')).toBeVisible();
});

test('the tab lists the tracked targets and opens a target as cards', async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  const tabs = page.getByRole('navigation', { name: 'Project' });
  await tabs.getByRole('link', { name: 'Vulnerabilities' }).click();
  await expect(page).toHaveTitle('Vulnerabilities · Qualor');
  await expect(page.locator('.vuln-header')).toContainText(/Vulnerability data from .* checked /);

  const main = page.getByRole('row', { name: /^main/ });
  await expect(main.getByRole('cell').nth(0)).toHaveText('1');
  await expect(main.getByRole('cell').nth(1)).toHaveText('1');
  await expect(main.getByText('1 new')).toBeVisible();

  await main.getByRole('link', { name: 'main' }).click();
  const critical = page.getByRole('listitem').filter({ hasText: VULNERABILITIES.critical.id });
  await expect(critical).toContainText('Critical');
  await expect(critical).toContainText('handlebars');
  await expect(critical).toContainText('4.3.0');
  await expect(
    page.getByRole('listitem').filter({ hasText: VULNERABILITIES.high.id }),
  ).toBeVisible();
});

test('Not affected needs a reason, dims the card and reaches the Trivy issue', async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  await page
    .getByRole('navigation', { name: 'Project' })
    .getByRole('link', { name: 'Vulnerabilities' })
    .click();
  await page.getByRole('row', { name: /^main/ }).getByRole('link', { name: 'main' }).click();
  const critical = page.getByRole('listitem').filter({ hasText: VULNERABILITIES.critical.id });
  await critical.getByRole('button', { name: /^Change status/ }).click();
  const dialog = page.getByRole('dialog', { name: 'Change status' });
  await dialog.getByLabel('Status').selectOption({ label: 'Not affected (false positive)' });
  await dialog.getByLabel('Reason').selectOption({ label: 'The vulnerable code is never called' });
  await dialog.getByLabel('Comment').fill('Only used by the build scripts.');
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Saved.')).toBeVisible();
  await expect(critical).toHaveClass(/dimmed/);
  await expect(critical).toContainText('Not affected');
  await expect(critical).toContainText('The vulnerable code is never called');

  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  await page.getByRole('link', { name: 'All open issues' }).click();
  await page.getByRole('group', { name: 'Status' }).getByLabel('False positive').check();
  await expect(page.getByRole('link', { name: VULNERABILITIES.issueMessage })).toBeVisible();
});

test('an admin pins a version from the fold', async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('link', { name: LEGACY.name }).click();
  await page
    .getByRole('navigation', { name: 'Project' })
    .getByRole('link', { name: 'Vulnerabilities' })
    .click();
  await expect(page.getByText(/0\.9\.0 — not tracked/)).toBeVisible();
  const fold = page.locator('p.untracked');
  await fold.getByRole('button', { name: 'Show' }).click();
  const row = page.getByRole('row', { name: /0\.9\.0/ });
  await expect(row.getByText('Not tracked')).toBeVisible();
  await row.getByRole('button', { name: /Change tracking of 0\.9\.0/ }).click();
  await page.getByRole('button', { name: 'Pin', exact: true }).click();
  await expect(row.getByText('Pinned')).toBeVisible();
  await expect(page.getByText('Not tracked')).toHaveCount(0);
});

test('a community server shows no KEV or EPSS: priority is off and there is no Exploited column', async ({
  page,
}) => {
  const payments = await projectId(page.request, PAYMENTS.key);
  const targets = await page.request.get(`/api/v0/projects/${payments}/vulnerabilities/targets`);
  expect(((await targets.json()) as { priority: boolean }).priority).toBe(false);

  await page.goto(`/projects/${payments}/vulnerabilities`);
  await expect(page.getByRole('columnheader', { name: 'Critical' })).toBeVisible();
  await expect(page.getByRole('columnheader', { name: 'Exploited' })).toHaveCount(0);
});

test('a community server refuses the SBOM and shows no export button', async ({ page }) => {
  const payments = await projectId(page.request, PAYMENTS.key);
  const sbom = await page.request.get(
    `/api/v0/projects/sbom?projectKey=${encodeURIComponent(PAYMENTS.key)}`,
  );
  expect(sbom.status()).toBe(403);

  await page.goto(`/projects/${payments}/vulnerabilities`);
  await expect(page.getByRole('columnheader', { name: 'Critical' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Export SBOM' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Export VEX' })).toHaveCount(0);
});
