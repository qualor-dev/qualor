import { expect, test } from './fixtures';

/**
 * The shell's layout (UI redesign): the top bar's links line up with the page's content column
 * on a wide screen (the maintainer's request, step 11), as the page header and body already do.
 */
test.describe('on a wide screen', () => {
  test.use({ viewport: { width: 1920, height: 1000 } });

  test("the top bar's ends line up with the content column", async ({ page }) => {
    await page.goto('/projects');
    const title = page.getByRole('heading', { level: 1, name: 'Projects' });
    await expect(title).toBeVisible();
    const brand = (await page.locator('.app-header .brand').boundingBox())!;
    const user = (await page.locator('.app-header .user-button').boundingBox())!;
    const heading = (await title.boundingBox())!;
    // The content column: 1360px wide, centred.
    const left = ((await page.evaluate(() => document.documentElement.clientWidth)) - 1360) / 2;
    expect(Math.abs(brand.x - heading.x)).toBeLessThanOrEqual(1);
    expect(Math.abs(brand.x - left)).toBeLessThanOrEqual(1);
    expect(Math.abs(user.x + user.width - (left + 1360))).toBeLessThanOrEqual(1);
  });
});
