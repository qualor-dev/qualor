import type { Page } from '@playwright/test';
import { expect, expectAccessible, test } from './fixtures';
import { PAYMENTS, PROJECT_WEBHOOK_URL } from './seed-data';

/** Payments API → Settings, through the project's own tabs. */
async function openSettings(page: Page): Promise<void> {
  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  await page
    .getByRole('navigation', { name: 'Project' })
    .getByRole('link', { name: 'Settings' })
    .click();
  await expect(page).toHaveURL(/\/projects\/[^/]+\/settings$/);
  await expect(page.getByRole('heading', { name: 'New code', level: 2 })).toBeVisible();
}

test('the settings tab lists its sections and is accessible', async ({ page }) => {
  await openSettings(page);
  const sections = page.getByRole('navigation', { name: 'Settings sections' });
  for (const name of [
    'New code',
    'Quality gate and profiles',
    'Main branch',
    'Analysis tokens',
    'Webhooks',
    'Danger zone',
  ]) {
    await expect(sections.getByRole('link', { name, exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name, level: 2, exact: true })).toBeVisible();
  }
  await expect(page.locator('#main-branch-name')).toHaveValue('main');
  await expectAccessible(page);
});

test('a new code definition of the last 14 days is saved and kept after a reload', async ({
  page,
}) => {
  await openSettings(page);
  const panel = page.locator('#new-code');
  const days = panel.getByRole('radio', { name: /^Last days/ });
  await days.check();
  await panel.locator('#new-code-days').fill('14');
  await panel.getByRole('button', { name: 'Save' }).click();
  await expect(panel.getByRole('status')).toHaveText('New code definition saved.');

  await page.reload();
  await expect(days).toBeChecked();
  await expect(panel.locator('.choice-card.checked')).toContainText('Last days');
  await expect(panel.locator('#new-code-days')).toHaveValue('14');
  await expect(panel.locator('.baseline')).toBeVisible();

  // Back to the default, so the files after this one see the seed's definition.
  await panel.getByRole('radio', { name: /^Default/ }).check();
  await panel.getByRole('button', { name: 'Save' }).click();
  await expect(panel.getByRole('status')).toHaveText('New code definition saved.');
});

test('an analysis token is shown once, then listed, and can be revoked', async ({ page }) => {
  await openSettings(page);
  const panel = page.locator('#tokens');
  await expect(panel.getByRole('row', { name: /ci-main/ })).toBeVisible();
  await panel.getByRole('button', { name: 'New token' }).click();
  const dialog = page.locator('dialog#project-token-dialog');
  await expect(dialog.locator('#project-token-name')).toBeFocused();
  await dialog.locator('#project-token-name').fill('e2e-token');
  await dialog.getByRole('button', { name: 'Create token' }).click();
  const secret = dialog.getByLabel('New token');
  await expect(secret).toHaveValue(/\S{20,}/);
  await expectAccessible(page);
  const value = await secret.inputValue();
  await dialog.getByRole('button', { name: 'Done' }).click();
  await expect(page.locator('#secret-once')).toHaveCount(0);
  const row = panel.getByRole('row', { name: /e2e-token/ });
  await expect(row).toBeVisible();
  await expect(page.locator('body')).not.toContainText(value);

  await row.getByRole('button', { name: 'Revoke' }).click();
  const ask = page.getByRole('dialog', { name: 'Revoke the token' });
  await expect(ask).toContainText('e2e-token');
  await ask.getByRole('button', { name: 'Revoke' }).click();
  await expect(row).toHaveCount(0);
  await expect(panel.getByRole('status')).toHaveText('Token e2e-token revoked.');
});

test("the project's webhook is listed here, and in Settings → Webhooks with its project", async ({
  page,
}) => {
  await openSettings(page);
  const panel = page.locator('#webhooks');
  const hook = panel.getByRole('region', { name: PROJECT_WEBHOOK_URL });
  await expect(hook).toBeVisible();
  await expect(hook.getByText('All projects')).toHaveCount(0);
  // The organisation's webhook for every project is not one of this project's.
  await expect(panel.getByRole('region', { name: 'https://hooks.example.com/qualor' })).toHaveCount(
    0,
  );

  await page.goto('/settings/webhooks');
  const listed = page.getByRole('region', { name: PROJECT_WEBHOOK_URL });
  await expect(listed.locator('.webhook-scope')).toHaveText(`Project: ${PAYMENTS.name}`);
  await expect(listed.getByRole('link', { name: PAYMENTS.name })).toBeVisible();
  await expect(
    page
      .getByRole('region', { name: 'https://hooks.example.com/qualor' })
      .locator('.webhook-scope'),
  ).toHaveText('All projects');
});

/**
 * Ruling R14: the deleted project is one this test creates through the API, never a seeded one
 * (projects.spec.ts and roles.spec.ts read Legacy Billing).
 */
test('deleting a project needs its exact key, then Projects says so', async ({ page }) => {
  const me = (await (await page.request.get('/api/v0/auth/me')).json()) as { csrfToken: string };
  const orgs = (await (await page.request.get('/api/v0/organizations')).json()) as {
    items: { id: string }[];
  };
  const key = `acme/e2e-throwaway-${Date.now()}`;
  const name = 'E2E Throwaway';
  const created = await page.request.post('/api/v0/projects', {
    headers: { 'x-qualor-csrf': me.csrfToken },
    data: { organizationId: orgs.items[0]!.id, key, name },
  });
  expect(created.status()).toBe(201);
  const { id } = (await created.json()) as { id: string };

  await page.goto(`/projects/${id}/settings`);
  await page.getByRole('button', { name: 'Delete project' }).click();
  const dialog = page.locator('dialog#delete-project');
  await expect(dialog).toBeVisible();
  const confirm = dialog.getByRole('button', { name: 'Delete project' });
  await dialog.locator('#delete-confirm-key').fill(key.toUpperCase());
  await expect(confirm).toHaveAttribute('aria-disabled', 'true');
  await dialog.locator('#delete-confirm-key').fill(`${key} `);
  await expect(confirm).toHaveAttribute('aria-disabled', 'true');
  await expectAccessible(page);
  await dialog.locator('#delete-confirm-key').fill(key);
  await expect(confirm).not.toHaveAttribute('aria-disabled');
  await confirm.click();

  await expect(page).toHaveURL(/\/projects$/);
  await expect(
    page.getByRole('status').filter({ hasText: `Project ${name} deleted.` }),
  ).toBeVisible();
  await expect(page.getByRole('link', { name: PAYMENTS.name })).toBeVisible();
  await expect(page.getByRole('link', { name })).toHaveCount(0);
});
