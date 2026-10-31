import { expect, test } from './fixtures';
import { LEGACY, PAYMENTS, VULNERABILITIES } from './seed-data';

/**
 * Vulnerability monitoring (0.15): the Vulnerabilities tab, triage and the badge, on the rows
 * `seedVulnerabilities` writes. Nothing here depends on the status of the vulnerability database.
 */
test.describe.configure({ mode: 'serial' });

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
  await page.getByRole('button', { name: 'Show' }).click();
  await expect(page.getByText('Not tracked')).toBeVisible();
  // The trigger has no accessible name in the build today (no aria-label in the DOM), so it is
  // found by its class.
  const trigger = page.getByRole('row', { name: /0.9.0/ }).locator('.menu-trigger');
  await trigger.click();
  await page.getByRole('button', { name: 'Pin', exact: true }).click();
  await expect(page.getByText('Pinned')).toBeVisible();
  await expect(page.getByText('Not tracked')).toHaveCount(0);
});
