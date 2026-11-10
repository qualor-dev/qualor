import { expect, expectAccessible, test } from './fixtures';
import { PAYMENTS } from './seed-data';

/**
 * 4E-1 §4: compliance reports on the licensed e2e server (`server/scripts/e2e/serve.ts`, the
 * Enterprise plan's features, with `compliance-export`). Payments API's main branch has the
 * seed's succeeded analyses with open security findings (`seedDemo`), so a report of it builds:
 * the server's worker runs the plugin's `ee.compliance.build` job, and the page polls until the
 * row is ready. Each download is a plain link the browser saves.
 */

test('a project admin creates a compliance report and downloads it in four formats', async ({
  page,
}) => {
  // The build runs in the background; the page polls every 3 s.
  test.setTimeout(60_000);
  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  await page
    .getByRole('navigation', { name: 'Project' })
    .getByRole('link', { name: 'Compliance' })
    .click();
  await expect(page).toHaveURL(/\/projects\/[^/]+\/compliance$/);
  await expect(page.getByLabel('Target')).toHaveValue(/.+/);
  await page.getByRole('button', { name: 'Create report' }).click();
  // The badge, not the announcement ("… appears here as ready …").
  await expect(page.getByText('Ready', { exact: true })).toBeVisible({ timeout: 30_000 });
  await expectAccessible(page);

  for (const [label, type] of [
    ['JSON', 'application/json'],
    ['CSV', 'text/csv'],
    ['PDF', 'application/pdf'],
    // Payments API's main branch has an inventory, and the Enterprise licence has `sbom`.
    ['SBOM', 'application/vnd.cyclonedx+json'],
  ] as const) {
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.getByRole('link', { name: label }).first().click(),
    ]);
    expect(download.suggestedFilename()).toMatch(
      /^qualor-compliance-.+\.(json|csv|pdf|cdx\.json)$/,
    );
    // The server serves one download per person at a time: let the browser's finish first.
    await download.path();
    const res = await page.request.get(download.url());
    expect(res.status()).toBe(200);
    expect(res.headers()['content-type']).toContain(type);
    if (label === 'SBOM') {
      expect(download.suggestedFilename()).toMatch(/\.cdx\.json$/);
      expect(await res.json()).toMatchObject({ bomFormat: 'CycloneDX', specVersion: '1.6' });
    }
  }

  // The summary of the ready report, by standard.
  await page.getByRole('button', { name: /^Summary of the report of / }).click();
  await expect(page.getByRole('region', { name: 'Summary' })).toBeVisible();
  await expect(page.locator('.compliance-counts')).toContainText('Open findings');
});

test.describe('on a phone', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  // The project tabs scroll sideways there: the current one is brought into view, after a
  // navigation and when the screen narrows.
  test('the Compliance tab is in view when it is the current one', async ({ page }) => {
    const tabs = page.getByRole('navigation', { name: 'Project' });
    const compliance = tabs.getByRole('link', { name: 'Compliance' });
    /** Whether the tab is wholly inside the tab bar's visible width. */
    const shown = () =>
      compliance.evaluate((tab) => {
        const bar = tab.closest('nav')!.getBoundingClientRect();
        const box = tab.getBoundingClientRect();
        return box.left >= bar.left - 0.5 && box.right <= bar.right + 0.5;
      });
    await page.goto('/projects');
    await page.getByRole('link', { name: PAYMENTS.name }).click();
    await expect(tabs.getByRole('link', { name: 'Overview' })).toHaveAttribute(
      'aria-current',
      'page',
    );
    expect(await shown()).toBe(false);

    await page.goto(`${new URL(page.url()).pathname}/compliance`);
    await expect(compliance).toHaveAttribute('aria-current', 'page');
    await expect.poll(shown).toBe(true);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(
      390,
    );

    // Chosen on a wide screen, where every tab fits, then narrowed (a turned tablet).
    await page.setViewportSize({ width: 1440, height: 900 });
    await tabs.getByRole('link', { name: 'Overview' }).click();
    await compliance.click();
    await expect(compliance).toHaveAttribute('aria-current', 'page');
    await page.setViewportSize({ width: 390, height: 844 });
    await expect.poll(shown).toBe(true);
  });
});
