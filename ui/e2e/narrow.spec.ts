import type { Locator, Page } from '@playwright/test';
import { expect, test } from './fixtures';
import { PAYMENTS, SHOP } from './seed-data';

/**
 * Narrow screens (UI redesign, step 11): every screen of the community server fits a phone
 * (390px) and a tablet (768px) once its data is in. A wide table scrolls inside its panel, never
 * the page. The settings pages are checked by settings.spec.ts and enterprise.spec.ts.
 */

interface Ids {
  project: string;
  /** Web Shop: the seed gives victor (Viewer) and petra (Project admin) a role on it. */
  shop: string;
  branch: string;
  issue: string;
  gate: string;
  profile: string;
}

async function ids(page: Page): Promise<Ids> {
  const get = async <T>(url: string): Promise<T> =>
    (await (await page.request.get(url)).json()) as T;
  type Listed<T> = { items: T[] };
  const projects =
    await get<
      Listed<{ id: string; key: string; organizationId: string; mainBranch: { id: string } | null }>
    >('/api/v0/projects');
  const payments = projects.items.find((p) => p.key === PAYMENTS.key)!;
  const main = payments.mainBranch!.id;
  const issues = await get<Listed<{ id: string }>>(
    `/api/v0/issues?branchId=${main}&limit=1&sort=severity&status=open`,
  );
  const gates = await get<Listed<{ id: string; name: string }>>(
    `/api/v0/quality-gates?organizationId=${payments.organizationId}&limit=100`,
  );
  const profiles = await get<Listed<{ id: string }>>(
    `/api/v0/quality-profiles?organizationId=${payments.organizationId}&limit=100`,
  );
  return {
    project: payments.id,
    shop: projects.items.find((p) => p.key === SHOP.key)!.id,
    branch: main,
    issue: issues.items[0]!.id,
    gate: gates.items.find((g) => g.name === 'Strict')?.id ?? gates.items[0]!.id,
    profile: profiles.items[0]!.id,
  };
}

function screens(id: Ids): string[] {
  const p = `/projects/${id.project}`;
  return [
    '/projects',
    p,
    `${p}/branches`,
    `${p}/branches/${id.branch}`,
    `${p}/issues`,
    `${p}/issues/${id.issue}`,
    `${p}/access`,
    `${p}/code`,
    `${p}/code/file?branch=${id.branch}&path=${encodeURIComponent('src/refunds/limits.ts')}`,
    `${p}/settings`,
    '/gates',
    `/gates/${id.gate}`,
    '/profiles',
    `/profiles/${id.profile}`,
    '/rules',
    '/nope',
  ];
}

for (const width of [390, 768]) {
  test.describe(`at ${width}px`, () => {
    test.use({ viewport: { width, height: 900 } });

    test('every screen fits the width once its data is in', async ({ page }) => {
      const id = await ids(page);
      for (const path of screens(id)) {
        await page.goto(path);
        await page.waitForLoadState('networkidle');
        const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
        expect.soft(scrollWidth, path).toBeLessThanOrEqual(width);
      }
    });
  });
}

/** Each control ends inside the first panel's scroll box: no sideways scroll hides it. */
async function inPanel(page: Page, controls: Locator[]): Promise<void> {
  const panel = (await page.locator('.panel-scroll').first().boundingBox())!;
  for (const control of controls) {
    const box = (await control.boundingBox())!;
    expect(box.x + box.width).toBeLessThanOrEqual(panel.x + panel.width);
  }
}

test('the Access table fits its panel beside or above the roles legend', async ({ page }) => {
  const id = await ids(page);
  await page.goto(`/projects/${id.shop}/access`);
  const scroll = page.locator('.panel-scroll').first();
  await expect(scroll.locator('tbody tr').first()).toBeVisible();
  for (const width of [1025, 1050, 1075, 1160, 1280]) {
    await page.setViewportSize({ width, height: 900 });
    const { content, box } = await scroll.evaluate((el) => ({
      content: el.scrollWidth,
      box: el.clientWidth,
    }));
    expect(content, `${width}px`).toBeLessThanOrEqual(box);
  }
});

test.describe('on a tablet', () => {
  test.use({ viewport: { width: 768, height: 900 } });

  test("the issue page names the issue's status in its header, one column above the actions", async ({
    page,
  }) => {
    const id = await ids(page);
    await page.goto(`/projects/${id.project}/issues/${id.issue}`);
    await expect(page.locator('.issue-header .issue-status-tag')).toHaveText('Open');
    await page.setViewportSize({ width: 1440, height: 900 });
    // Beside the details at full width, the status is shown there only once.
    await expect(page.locator('.issue-header .issue-status-tag')).toBeHidden();
  });

  test('the branches table fits its panel: its headers wrap', async ({ page }) => {
    const id = await ids(page);
    await page.goto(`/projects/${id.project}/branches`);
    const scroll = page.locator('.panel-scroll').first();
    await expect(scroll.locator('tbody tr').first()).toBeVisible();
    const { content, box } = await scroll.evaluate((el) => ({
      content: el.scrollWidth,
      box: el.clientWidth,
    }));
    expect(content).toBeLessThanOrEqual(box);
  });
});

test.describe('on a phone', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('the header keeps the account beside the brand; the organization switcher has its own row', async ({
    page,
  }) => {
    // A second organization, in this browser only, brings the switcher.
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
    await page.goto('/projects');
    const switcher = page.getByRole('combobox', { name: 'Organization', exact: true });
    await expect(switcher).toBeVisible();
    const brand = (await page.locator('.brand').boundingBox())!;
    const account = (await page.locator('.user-button').boundingBox())!;
    const organization = (await switcher.boundingBox())!;
    const nav = (await page.getByRole('navigation', { name: 'Main' }).boundingBox())!;
    expect(Math.abs(account.y + account.height / 2 - (brand.y + brand.height / 2))).toBeLessThan(4);
    expect(organization.y).toBeGreaterThanOrEqual(account.y + account.height);
    expect(nav.y).toBeGreaterThanOrEqual(organization.y + organization.height);
    expect(organization.x + organization.width).toBeLessThanOrEqual(390);
  });

  test("Access keeps a grant's role and Remove in view; the role changes from its select", async ({
    page,
  }) => {
    const id = await ids(page);
    await page.goto(`/projects/${id.shop}/access`);
    const row = page.getByRole('row', { name: /victor/ });
    const role = row.getByLabel('Role of victor on this project');
    await expect(role).toBeVisible();
    await inPanel(page, [role, row.getByRole('button', { name: 'Remove', exact: true })]);
    // The row says when the role was given, though the column headers are out of sight.
    await expect(row.getByText('Added', { exact: true })).toBeVisible();
    await expect(row).toContainText(/Added \w{3} \d{1,2}, \d{4}/);
    // The select asks at once, so Change role steps aside (nothing is saved here).
    await expect(row.getByRole('button', { name: 'Change role' })).toBeHidden();
    const stored = await role.inputValue();
    await role.selectOption(stored === 'member' ? 'viewer' : 'member');
    const ask = page.getByRole('dialog', { name: 'Change the role' });
    await expect(ask).toContainText(/Change the role of victor on Web Shop to/);
    await ask.getByRole('button', { name: 'Cancel' }).click();
    await expect(ask).toBeHidden();
    await expect(role).toHaveValue(stored);
  });

  test("Members keeps a member's role and Remove in view; the role changes from its select", async ({
    page,
  }) => {
    await page.goto('/settings/members');
    const row = page.getByRole('row', { name: /olga/ });
    const role = row.getByLabel('Role of olga');
    await expect(role).toBeVisible();
    await inPanel(page, [role, row.getByRole('button', { name: 'Remove', exact: true })]);
    await expect(row.getByRole('button', { name: 'Change role' })).toBeHidden();
    const stored = await role.inputValue();
    await role.selectOption(stored === 'member' ? 'viewer' : 'member');
    const ask = page.getByRole('dialog', { name: 'Change the role' });
    await expect(ask).toContainText(/Change the role of olga in Default to/);
    await ask.getByRole('button', { name: 'Cancel' }).click();
    await expect(ask).toBeHidden();
    await expect(role).toHaveValue(stored);
  });

  test("a panel's subtitle lines up with its heading when it wraps under it", async ({ page }) => {
    const id = await ids(page);
    await page.goto(`/gates/${id.gate}`);
    const heading = page.getByRole('heading', { name: 'Conditions', exact: true });
    const sub = page.getByText('The gate fails when any of these conditions is true');
    await expect(sub).toBeVisible();
    const headingBox = (await heading.boundingBox())!;
    const subBox = (await sub.boundingBox())!;
    expect(subBox.y).toBeGreaterThanOrEqual(headingBox.y + headingBox.height);
    expect(Math.abs(subBox.x - headingBox.x)).toBeLessThan(1);
  });

  test("a gate's conditions keep Save and Remove in view", async ({ page }) => {
    const id = await ids(page);
    await page.goto(`/gates/${id.gate}`);
    const row = page.locator('.panel-scroll tbody tr').first();
    // An edit shows Save beside Remove (nothing is saved here).
    await row.locator('input').fill('79');
    const panel = (await page.locator('.panel-scroll').first().boundingBox())!;
    for (const button of [
      row.getByRole('button', { name: /^Save the condition/ }),
      row.getByRole('button', { name: 'Remove', exact: true }),
    ]) {
      const box = (await button.boundingBox())!;
      expect(box.x + box.width).toBeLessThanOrEqual(panel.x + panel.width);
    }
  });
});
