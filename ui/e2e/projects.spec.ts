import { expect, expectAccessible, test } from './fixtures';
import { LEGACY, PAYMENTS, SHOP } from './seed-data';

test('the projects list shows each project with its gate and main-branch measures', async ({
  page,
}) => {
  await page.goto('/projects');
  await expect(page).toHaveTitle('Projects · Qualor');
  const row = (name: string) => page.getByRole('row').filter({ hasText: name });
  await expect(row(PAYMENTS.name)).toContainText('Failed');
  await expect(row(PAYMENTS.name)).toContainText('65.7 %');
  await expect(row(SHOP.name)).toContainText('Passed');
  await expect(row(LEGACY.name)).toContainText('Not analyzed');
  await expectAccessible(page);
});

test('the list is usable with the keyboard alone', async ({ page }) => {
  await page.goto('/projects');
  await expect(page.getByRole('link', { name: PAYMENTS.name })).toBeVisible();
  const search = page.getByRole('searchbox', { name: 'Search projects' });
  await search.focus();
  await page.keyboard.type('web');
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/\/projects\?q=web$/);
  await expect(page.getByRole('link', { name: SHOP.name })).toBeVisible();
  await expect(page.getByRole('link', { name: PAYMENTS.name })).toHaveCount(0);
  await expect(search).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('button', { name: 'Search' })).toBeFocused();
  // The admin's "New project" follows the search in the band, then the list.
  await page.keyboard.press('Tab');
  await expect(page.getByRole('button', { name: 'New project' })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', { name: SHOP.name })).toBeFocused();
});

test('search narrows the list and lives in the URL', async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('searchbox', { name: 'Search projects' }).fill('shop');
  await page.getByRole('button', { name: 'Search' }).click();
  await expect(page).toHaveURL(/\/projects\?q=shop$/);
  await expect(page.getByRole('link', { name: SHOP.name })).toBeVisible();
  await expect(page.getByRole('link', { name: PAYMENTS.name })).toHaveCount(0);
});

test('an expired session sends the next request to the login page', async ({ page, guard }) => {
  // The search after the cookies are gone answers 401, which the browser logs.
  guard.allowFailedLoad('/api/v0/projects', 401);
  await page.goto('/projects');
  await expect(page.getByRole('link', { name: PAYMENTS.name })).toBeVisible();
  await page.context().clearCookies();
  await page.getByRole('searchbox', { name: 'Search projects' }).fill('pay');
  await page.getByRole('button', { name: 'Search' }).click();
  await expect(page).toHaveURL(/\/login\?returnUrl=%2Fprojects%3Fq%3Dpay$/);
});

test('an organization admin creates a project', async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('button', { name: 'New project' }).click();
  await expect(page.getByRole('dialog', { name: 'New project' })).toBeVisible();
  await page.getByLabel('Key').fill('acme/new-service');
  await page.getByLabel('Name').fill('New Service');
  await page.getByRole('button', { name: 'Create project' }).click();
  await expect(page).toHaveURL(/\/projects\/[0-9a-f-]{36}$/);
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('New Service');
  await expect(page.locator('.branch-name')).toHaveText('main');
  await expect(page.getByRole('region', { name: 'Quality gate' })).toContainText(
    'This branch has no analysis yet. Run qualor scan in its CI pipeline.',
  );
});

test("the summary's note on a partial list adds no second hairline, at any width", async ({
  page,
}) => {
  // More projects than one page: the answer says so here (the seed has three).
  await page.route(/\/api\/v0\/projects\?/, async (route) => {
    const response = await route.fetch();
    const body = (await response.json()) as { items: unknown[]; nextCursor: string | null };
    return route.fulfill({ response, json: { ...body, nextCursor: 'e2e-more' } });
  });
  await page.goto('/projects');
  await expect(page.locator('.portfolio-note')).toBeVisible();
  const borders = () =>
    page.locator('.portfolio .kpi').evaluateAll((kpis) =>
      kpis.map((kpi) => {
        const style = getComputedStyle(kpi);
        return `${style.borderRightWidth} ${style.borderBottomWidth}`;
      }),
    );
  // Four columns: hairlines between them only; the note draws its own line above it.
  await page.setViewportSize({ width: 1440, height: 900 });
  expect(await borders()).toEqual(['1px 0px', '1px 0px', '1px 0px', '0px 0px']);
  // Two columns: a line under the first row only.
  await page.setViewportSize({ width: 1000, height: 900 });
  expect((await borders()).map((b) => b.split(' ')[1])).toEqual(['1px', '1px', '0px', '0px']);
  // One column: a line under each but the last.
  await page.setViewportSize({ width: 390, height: 900 });
  expect((await borders()).map((b) => b.split(' ')[1])).toEqual(['1px', '1px', '1px', '0px']);
});
