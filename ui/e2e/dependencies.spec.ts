import { expect, expectAccessible, test } from './fixtures';
import { DEPENDENCIES, MERGE_REQUEST, PAYMENTS, VERSION } from './seed-data';

/**
 * 6M §8: the Dependencies tab on the community server. The seed's last analyses of Payments API
 * (main and merge request !42) report a dependency inventory; with no licence policy there are no
 * verdicts, so neither a Policy column nor a Forbidden filter.
 */
test('the Dependencies tab lists the inventory, filters it and opens a lockfile', async ({
  page,
}) => {
  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  const tabs = page.getByRole('navigation', { name: 'Project' });
  await expect(tabs.getByRole('link')).toContainText([
    'Overview',
    'Branches and merge requests',
    'Issues',
    'Vulnerabilities',
    'Dependencies',
    'Code',
  ]);
  await tabs.getByRole('link', { name: 'Dependencies' }).click();
  await expect(page).toHaveTitle('Dependencies · Qualor');

  await expect(page.locator('.deps-summary')).toContainText(
    `${DEPENDENCIES.known} of ${DEPENDENCIES.total} packages have a known licence`,
  );
  const table = page.getByRole('table', { name: 'Dependencies with their licences' });
  await expect(table.getByRole('row')).toHaveCount(DEPENDENCIES.total + 1);
  await expect(table.getByRole('columnheader', { name: 'Policy' })).toHaveCount(0);
  await expect(page.getByLabel('Forbidden only')).toHaveCount(0);
  const gpl = table.getByRole('row', { name: new RegExp(DEPENDENCIES.strongCopyleft.name) });
  await expect(gpl).toContainText(DEPENDENCIES.strongCopyleft.license);
  await expect(gpl).toContainText('Transitive');
  const unknown = table.getByRole('row', { name: new RegExp(DEPENDENCIES.unknown.name) });
  await expect(unknown).toContainText('Unknown');
  await expectAccessible(page);

  // A licence from the summary's list narrows the table, and the URL keeps it.
  await page.getByLabel('Licence', { exact: true }).selectOption('MIT');
  await expect(page).toHaveURL(/[?&]license=MIT(&|$)/);
  await expect(table.getByRole('row')).toHaveCount(3);
  await page.getByLabel('Licence', { exact: true }).selectOption('');
  await page.getByLabel('Licence group').selectOption({ label: 'Strong copyleft' });
  await expect(table.getByRole('row')).toHaveCount(2);
  await expect(table.getByRole('row').nth(1)).toContainText(DEPENDENCIES.strongCopyleft.name);
  await page.getByLabel('Licence group').selectOption('');
  await page.getByLabel('Unknown only').check();
  await expect(table.getByRole('row')).toHaveCount(2);
  await expect(table.getByRole('row').nth(1)).toContainText(DEPENDENCIES.unknown.name);
  // Its lockfile has no line: the link opens the file at its top.
  await table.getByRole('link', { name: DEPENDENCIES.unknown.path, exact: true }).click();
  await expect(page).toHaveURL(/\/code\/file\?.*path=web%2Fpnpm-lock\.yaml$/);
  await expect(page.getByRole('navigation', { name: 'File path' })).toContainText('pnpm-lock.yaml');
  await page.goBack();

  await page.getByLabel('Unknown only').uncheck();
  await page.getByLabel('Search packages').fill('ledger');
  await page.getByRole('button', { name: 'Search' }).click();
  await expect(table.getByRole('row')).toHaveCount(2);
  await table.getByRole('link', { name: /^package-lock\.json:40$/ }).click();
  await expect(page).toHaveURL(/\/code\/file\?.*path=package-lock\.json.*#L40$/);
});

test('the Dependencies tab shows the inventory of a merge request', async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  await page
    .getByRole('navigation', { name: 'Project' })
    .getByRole('link', { name: 'Dependencies' })
    .click();
  await expect(page.locator('.deps-summary')).toBeVisible();
  const request = page.waitForRequest(
    (r) => new URL(r.url()).pathname.endsWith('/dependencies') && r.url().includes('mr='),
  );
  await page
    .getByLabel('Branch')
    .selectOption({ label: `!${MERGE_REQUEST.id} ${MERGE_REQUEST.source} → main` });
  await expect(page).toHaveURL(/[?&]branch=/);
  expect(new URL((await request).url()).searchParams.get('mr')).toBe(MERGE_REQUEST.id);
  await expect(page.locator('.deps-summary')).toContainText(
    `${DEPENDENCIES.known} of ${DEPENDENCIES.total} packages have a known licence`,
  );
  await expectAccessible(page);
});

test('the Dependencies tab shows the inventory of a released version', async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  await page
    .getByRole('navigation', { name: 'Project' })
    .getByRole('link', { name: 'Dependencies' })
    .click();
  await expect(page.locator('.deps-summary')).toBeVisible();
  const request = page.waitForRequest(
    (r) => new URL(r.url()).pathname.endsWith('/dependencies') && r.url().includes('version='),
  );
  await page.getByLabel('Branch').selectOption({ label: VERSION.option });
  await expect(page).toHaveURL(/[?&]version=/);
  expect(new URL((await request).url()).searchParams.has('branch')).toBe(false);
  const table = page.getByRole('table', { name: 'Dependencies with their licences' });
  await expect(table.getByRole('row')).toHaveCount(2);
  await expect(table.getByRole('row', { name: new RegExp(VERSION.package) })).toBeVisible();
  await expectAccessible(page);
});

test('a project without an analysis says it has no inventory yet', async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('link', { name: 'Legacy Billing' }).click();
  await page
    .getByRole('navigation', { name: 'Project' })
    .getByRole('link', { name: 'Dependencies' })
    .click();
  await expect(page.locator('.empty-state')).toHaveText(
    'No dependency inventory yet. Scans with Qualor 0.9 or later record one.',
  );
  await expectAccessible(page);
});
