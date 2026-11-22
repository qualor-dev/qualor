import type { Page } from '@playwright/test';
import { expect, expectAccessible, test } from './fixtures';
import { AZURE, LEGACY } from './seed-data';

/**
 * Azure DevOps (sub-plan 2) against the fake Azure DevOps of server/scripts/e2e/serve.ts: the seed
 * holds a connection with a personal access token to AZURE.address, and the server sends its
 * requests to the fake (QUALOR_AZURE_TEST_ORIGIN); the fake Entra answers the service principal.
 * The seeded connection stays; a test deletes only what it created and unmaps what it mapped.
 */
async function csrfToken(page: Page): Promise<string> {
  const me = (await (await page.request.get('/api/v0/auth/me')).json()) as { csrfToken: string };
  return me.csrfToken;
}

/** The connection's own section, by its authentication line (two share the address). */
function section(page: Page, kind: string) {
  return page
    .getByRole('region', { name: AZURE.address })
    .filter({ has: page.locator('dl.app-facts', { hasText: kind }) });
}

test('the seeded Azure DevOps connection is listed and tested', async ({ page }) => {
  await page.goto('/settings/azure-devops');
  await expect(page).toHaveTitle('Azure DevOps · Qualor');
  const pat = section(page, 'Personal access token');
  await expect(pat).toHaveCount(1);
  await expect(pat).toContainText('Azure DevOps Services');
  await expect(pat).toContainText('Not tested yet');
  await pat.getByRole('button', { name: 'Test', exact: true }).click();
  await expect(pat).toContainText(
    /Connected as qualor-bot@example\.com; 2 repositories in 2 projects visible\./,
  );
  await expect(pat.getByText('Connected', { exact: true })).toBeVisible();
  await expectAccessible(page);
});

test('an administrator adds a service principal with a client secret, tests it and deletes it', async ({
  page,
}) => {
  await page.goto('/settings/azure-devops');
  await page.getByRole('button', { name: 'New connection' }).click();
  const create = page.getByRole('dialog', { name: /New Azure DevOps connection/ });
  await create.getByLabel('Address').fill(AZURE.address);
  await create.getByLabel('Directory (tenant) id').fill(AZURE.tenant);
  await create.getByLabel('Application (client) id').fill(AZURE.client);
  await create.getByRole('textbox', { name: 'Client secret' }).fill(AZURE.secret);
  await create.getByRole('button', { name: 'Add connection' }).click();
  await expect(page.getByRole('status')).toHaveText('Azure DevOps connection added.');
  await expect(create).toBeHidden();
  await expect(page.locator('body')).not.toContainText(AZURE.secret);

  const principal = section(page, 'Service principal with a client secret');
  await expect(principal).toHaveCount(1);
  await expect(principal).toContainText(AZURE.client);
  await principal.getByRole('button', { name: 'Test', exact: true }).click();
  await expect(principal).toContainText(
    /Connected as Qualor Azure App; 2 repositories in 2 projects visible\./,
  );

  await principal.getByRole('button', { name: 'Delete' }).click();
  const ask = page.getByRole('dialog', { name: /Delete/ });
  await expect(ask).toContainText(`Delete the Azure DevOps connection to ${AZURE.address}?`);
  await ask.getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByRole('status')).toHaveText(
    `Azure DevOps connection ${AZURE.address} deleted.`,
  );
  await expect(principal).toHaveCount(0);
  // The seeded one is untouched.
  await expect(section(page, 'Personal access token')).toHaveCount(1);
});

test('a project is mapped to a repository listed by Azure DevOps', async ({ page }) => {
  await page.goto('/settings/repositories');
  const row = () => page.getByRole('row', { name: new RegExp(LEGACY.name) });
  await row()
    .getByLabel(`Connection of ${LEGACY.name}`)
    .selectOption({ label: `Azure DevOps · ${AZURE.address}` });
  const choice = row().getByLabel(`Azure DevOps repository of ${LEGACY.name}`);
  await expect(choice.getByRole('option', { name: AZURE.repository.label })).toHaveCount(1);
  await choice.selectOption(AZURE.repository.id);
  await row().getByRole('button', { name: 'Save' }).click();
  await expect(row()).toContainText('Mapped to Azure DevOps.');

  // Saved as the repository's id: still chosen after a reload.
  await page.reload();
  await expect(row().getByLabel(`Azure DevOps repository of ${LEGACY.name}`)).toHaveValue(
    AZURE.repository.id,
  );
  await expectAccessible(page);

  // Unmap it again: later tests start from the seed.
  const projects = (await (await page.request.get('/api/v0/projects?limit=100')).json()) as {
    items: { id: string; key: string; scmProjectRef: string | null }[];
  };
  const legacy = projects.items.find((p) => p.key === LEGACY.key);
  expect(legacy?.scmProjectRef).toBe(AZURE.repository.id);
  const cleared = await page.request.patch(`/api/v0/projects/${legacy?.id}`, {
    headers: { 'x-qualor-csrf': await csrfToken(page) },
    data: { scmConnectionId: null, scmProjectRef: null },
  });
  expect(cleared.status()).toBe(200);
});
