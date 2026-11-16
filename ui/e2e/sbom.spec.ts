import { fileURLToPath } from 'node:url';
import { expect, expectAccessible, test } from './fixtures';
import { SHOP } from './seed-data';

/**
 * 0.16 SBOM: upload an SBOM on a project's Vulnerabilities tab, then find its package on the
 * Packages page and follow the row to the Dependencies tab. The uploaded version is deleted
 * afterwards, so the seed is as the other specs expect it.
 */
const SAMPLE = fileURLToPath(
  new URL('../../packages/shared/test/sbom-samples/cdxgen-node.cdx-1.7.json', import.meta.url),
);
const LABEL = '9.9.9';
const PACKAGE = 'minimist';

test.afterAll(async ({ request }) => {
  const me = (await (await request.get('/api/v0/auth/me')).json()) as { csrfToken: string };
  const projects = await request.get('/api/v0/projects?limit=100');
  const { items } = (await projects.json()) as { items: { id: string; key: string }[] };
  const shop = items.find((p) => p.key === SHOP.key)!;
  const versions = await request.get(`/api/v0/projects/${shop.id}/versions`);
  const list = (await versions.json()) as { items: { id: string; label: string }[] };
  for (const v of list.items.filter((i) => i.label === LABEL)) {
    await request.delete(`/api/v0/projects/${shop.id}/versions/${v.id}`, {
      headers: { 'x-qualor-csrf': me.csrfToken },
    });
  }
});

test('an uploaded SBOM is found on the Packages page and opens its Dependencies tab', async ({
  page,
}) => {
  await page.goto('/projects');
  await page.getByRole('link', { name: SHOP.name }).click();
  await page
    .getByRole('navigation', { name: 'Project' })
    .getByRole('link', { name: 'Vulnerabilities' })
    .click();
  await page.getByRole('button', { name: 'Upload SBOM' }).first().click();
  const dialog = page.getByRole('dialog', { name: 'Upload SBOM' });
  await dialog.getByLabel('SBOM file').setInputFiles(SAMPLE);
  await dialog.getByLabel('Version label').fill(LABEL);
  await dialog.getByRole('button', { name: 'Upload', exact: true }).click();
  await expect(dialog.getByRole('status')).toContainText(LABEL);
  await expect(dialog.getByRole('status')).toContainText(/\d+ packages/);
  await dialog.getByRole('button', { name: 'Done' }).click();

  await page
    .getByRole('navigation', { name: 'Main' })
    .getByRole('link', { name: 'Packages' })
    .click();
  await expect(page).toHaveTitle('Packages · Qualor');
  await expect(page.getByText('Search a package by name or purl')).toBeVisible();
  // An empty search says so and asks nothing.
  await page.getByRole('button', { name: 'Search' }).click();
  await expect(page.getByText('Search needs at least one character')).toBeVisible();

  await page.getByLabel('Package name or purl').fill(PACKAGE);
  await page.getByRole('button', { name: 'Search' }).click();
  await expect(page).toHaveURL(/[?&]q=minimist(&|$)/);
  const table = page.getByRole('table', { name: 'Where the package is used' });
  const row = table.getByRole('row').filter({ hasText: SHOP.name }).filter({ hasText: LABEL });
  await expect(row).toHaveCount(1);
  await expect(row).toContainText('1.2.5');
  await expect(row).toContainText('not checked');
  await expectAccessible(page);

  await row.getByRole('link', { name: PACKAGE, exact: true }).click();
  await expect(page).toHaveURL(/\/projects\/[^/]+\/dependencies\?version=[^&]+&q=minimist$/);
  await expect(page).toHaveTitle('Dependencies · Qualor');
  await expect(page.getByRole('searchbox').first()).toHaveValue(PACKAGE);
  await expect(page.getByRole('table', { name: 'Dependencies with their licences' })).toContainText(
    PACKAGE,
  );
});
