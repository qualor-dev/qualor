import type { Page } from '@playwright/test';
import { expect, expectAccessible, test } from './fixtures';

/**
 * The setup checklist (onboarding, "The checklist (UI)") on the community server with its seeded
 * data. The seed closes it for the suite's organisation admins (server/scripts/e2e/seed.ts
 * `seedRoles`), as an admin does once the server is set up: these tests open the admin's again,
 * and it is closed again after them.
 */

async function setClosed(page: Page, closed: boolean): Promise<void> {
  const me = (await (await page.request.get('/api/v0/auth/me')).json()) as { csrfToken: string };
  const orgs = (await (await page.request.get('/api/v0/organizations')).json()) as {
    items: { id: string }[];
  };
  const answer = await page.request.put(
    `/api/v0/organizations/${orgs.items[0]!.id}/setup-checklist`,
    {
      headers: { 'x-qualor-csrf': me.csrfToken },
      data: { closed },
    },
  );
  expect(answer.status()).toBe(200);
}

test.describe.configure({ mode: 'serial' });

test.beforeEach(async ({ page }) => {
  await setClosed(page, false);
});

test.afterEach(async ({ page }) => {
  // Whatever happened in the test, the rest of the suite runs with it closed, as seeded.
  await setClosed(page, true);
});

test('the checklist sits in the corner as a labelled region, and collapses and opens again', async ({
  page,
}) => {
  await page.goto('/projects');
  const region = page.getByRole('complementary', { name: 'Set up Qualor' });
  await expect(region).toBeVisible();
  await expect(region.locator('.setup-count')).toHaveText(/^(\d of \d done|All set)$/);
  await expect(region.getByRole('listitem')).toHaveCount(5);
  await expectAccessible(page);

  const collapse = region.getByRole('button', { name: 'Collapse' });
  await collapse.click();
  const corner = region.getByRole('button', { name: /^Set up Qualor, / });
  await expect(corner).toBeFocused();
  await expect(corner).toHaveAttribute('aria-expanded', 'false');
  await expect(region.getByRole('list')).toBeHidden();
  // Remembered in this browser.
  await page.reload();
  await expect(page.getByRole('button', { name: /^Set up Qualor, / })).toBeVisible();
  await expect(
    page.getByRole('complementary', { name: 'Set up Qualor' }).getByRole('list'),
  ).toBeHidden();
  await page.getByRole('button', { name: /^Set up Qualor, / }).click();
  await expect(page.getByRole('button', { name: 'Collapse' })).toBeFocused();
  // Escape collapses it again, focus on the corner button.
  await page.keyboard.press('Escape');
  await expect(page.getByRole('button', { name: /^Set up Qualor, / })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('button', { name: 'Collapse' })).toBeFocused();
});

test.describe('on a phone', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('it is a button in the header row that never covers the page, and the page still fits', async ({
    page,
  }) => {
    await page.goto('/projects');
    const corner = page.getByRole('button', { name: /^Set up Qualor, / });
    await expect(corner).toBeVisible();
    await expect(corner).toHaveAttribute('aria-expanded', 'false');
    // In the header's first row, left of the account button, without touching it.
    const button = (await corner.boundingBox())!;
    const account = (await page.locator('.user-button').boundingBox())!;
    expect(button.x + button.width).toBeLessThanOrEqual(account.x);
    expect(Math.abs(button.y + button.height / 2 - (account.y + account.height / 2))).toBeLessThan(
      2,
    );
    // The page's own actions stay clear of it.
    const add = (await page.getByRole('link', { name: 'Add repositories' }).first().boundingBox())!;
    expect(add.y).toBeGreaterThan(button.y + button.height);
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth),
    ).toBe(false);
    // Open: the panel under the header row, the button still there and pressed.
    await corner.click();
    await expect(corner).toHaveAttribute('aria-expanded', 'true');
    await expect(
      page.getByRole('complementary', { name: 'Set up Qualor' }).getByRole('list'),
    ).toBeVisible();
    await expectAccessible(page);
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth),
    ).toBe(false);
  });
});

test('"Don\'t show again" closes it for good', async ({ page }) => {
  await page.goto('/projects');
  const region = page.getByRole('complementary', { name: 'Set up Qualor' });
  await expect(region).toBeVisible();
  await region.getByRole('button', { name: "Don't show again" }).click();
  await expect(region).toHaveCount(0);
  await expect(page.locator('main')).toBeFocused();
  await page.reload();
  await expect(page.getByRole('heading', { level: 1, name: 'Projects' })).toBeVisible();
  // Given time to load (it waits for the browser to be idle), it still does not come back.
  await page.waitForLoadState('networkidle');
  await expect(page.getByRole('complementary', { name: 'Set up Qualor' })).toHaveCount(0);
});
