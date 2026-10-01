import { expect, expectAccessible, test } from './fixtures';
import { PAYMENTS, RELATED_ISSUE_MESSAGE } from './seed-data';

test('the Code tab walks down to a file with its line map and duplicated blocks', async ({
  page,
}) => {
  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  await page
    .getByRole('navigation', { name: 'Project' })
    .getByRole('link', { name: 'Code' })
    .click();
  await expect(page).toHaveURL(/\/projects\/[^/]+\/code(\?|$)/);
  const table = page.getByRole('table', { name: 'Files and directories with their measures' });
  await table.getByRole('link', { name: 'src', exact: true }).click();
  await expect(page.getByRole('navigation', { name: 'Directory' })).toContainText('src');
  await expectAccessible(page);
  await table.getByRole('link', { name: 'refunds', exact: true }).click();
  await table.getByRole('link', { name: 'limits.ts', exact: true }).click();

  await expect(page).toHaveURL(/\/code\/file\?.*path=src%2Frefunds%2Flimits\.ts/);
  await expect(page.getByRole('navigation', { name: 'File path' })).toContainText('limits.ts');
  const map = page.getByRole('region', { name: 'Line map' }).getByRole('img');
  await expect(map).toHaveAttribute('aria-label', /lines/);
  // The seed's duplication group: limits.ts 60–80 and service.ts 30–50.
  const dups = page.getByRole('region', { name: 'Duplicated blocks' });
  await expect(dups.getByRole('link', { name: 'Lines 60–80' })).toBeVisible();
  await expect(dups.getByRole('link', { name: /src\/refunds\/service\.ts 30–50/ })).toBeVisible();
  await expectAccessible(page);
});

test("an issue's related locations open the file page at their line", async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  await page.getByRole('link', { name: 'All open issues' }).click();
  await page.getByRole('link', { name: RELATED_ISSUE_MESSAGE, exact: true }).click();
  await expect(page).toHaveTitle('Issue · Qualor');
  await expect(
    page.getByRole('heading', { level: 2, name: RELATED_ISSUE_MESSAGE, exact: true }),
  ).toBeVisible();

  const related = page.getByRole('region', { name: 'Related locations' });
  const steps = related.getByRole('listitem');
  await expect(steps).toHaveCount(3);
  await expect(steps.nth(0)).toContainText('The policy comes from the order');
  await expect(steps.nth(0)).toContainText('src/refunds/limits.ts:10');
  await expect(steps.nth(1)).toContainText('src/payments/gateway.ts:88–92');
  await expect(steps.nth(1)).toContainText('This file');
  await expect(steps.nth(2)).toContainText('src/payments/gateway.ts:140');
  await expectAccessible(page);

  await steps.nth(1).getByRole('link').click();
  await expect(page).toHaveURL(/\/code\/file\?.*path=src%2Fpayments%2Fgateway\.ts.*#L88$/);
  await expect(page.getByRole('navigation', { name: 'File path' })).toContainText('gateway.ts');
  await expect(page.getByRole('region', { name: 'Line map' })).toBeVisible();
  await expectAccessible(page);
});
