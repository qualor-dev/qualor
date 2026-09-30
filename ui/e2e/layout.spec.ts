import { expect, test } from './fixtures';
import { PAYMENTS } from './seed-data';

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

test.describe('on a laptop with two organizations', () => {
  test.use({ viewport: { width: 1040, height: 700 } });

  test('sticky parts stay clear of the top bar when it wraps to two rows', async ({ page }) => {
    // A second organization, in this browser only, brings the switcher: the bar wraps here.
    await page.route(/\/api\/v0\/organizations(\?.*)?$/, async (route) => {
      const response = await route.fetch();
      const body = (await response.json()) as { items: unknown[] };
      const other = {
        id: '0190a6c2-0000-7000-8000-00000000a001',
        key: 'platform',
        name: 'Platform Engineering',
        createdAt: '2026-09-29T09:12:00.000Z',
        updatedAt: '2026-09-29T09:12:00.000Z',
      };
      return route.fulfill({ response, json: { ...body, items: [...body.items, other] } });
    });
    const projects = (await (await page.request.get('/api/v0/projects')).json()) as {
      items: { id: string; key: string; mainBranch: { id: string } | null }[];
    };
    const payments = projects.items.find((p) => p.key === PAYMENTS.key)!;
    const issues = (await (
      await page.request.get(`/api/v0/issues?branchId=${payments.mainBranch!.id}&limit=1`)
    ).json()) as { items: { id: string }[] };
    await page.goto(`/projects/${payments.id}/issues/${issues.items[0]!.id}`);
    await expect(page.getByRole('combobox', { name: 'Organization', exact: true })).toBeVisible();
    const bar = (await page.locator('.app-header').boundingBox())!;
    expect(bar.height).toBeGreaterThan(72);
    // Scrolled, the details column sticks below the bar, not under it.
    const stuck = await page.evaluate(
      () =>
        new Promise<number>((resolve) => {
          window.scrollTo(0, 280);
          requestAnimationFrame(() =>
            resolve(document.querySelector('.issue-aside')!.getBoundingClientRect().y),
          );
        }),
    );
    expect(await page.evaluate(() => window.scrollY)).toBe(280);
    expect(stuck).toBeGreaterThanOrEqual(bar.height);
  });
});
