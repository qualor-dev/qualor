import type { APIRequestContext } from '@playwright/test';
import { expect, expectAccessible, test } from './fixtures';
import { STORAGE_STATE } from './seed-data';

/**
 * 0.16 issue #37: an instance admin deletes an organization (confirmed by its key, removed by a
 * queued job) and renames a user, on the community server. The spec makes its own organization and
 * user; `afterAll` removes what is left (users cannot be
 * deleted, so the renamed one is deactivated). `pnpm ui:e2e` starts from a fresh database, and the
 * run suffix keeps a reused one from answering 409.
 */
// Users cannot be deleted, and a database may be reused, so every name carries a run suffix.
const RUN = Date.now().toString(36);
const ORG = { key: `e2e-del-${RUN}`, name: `E2E Delete ${RUN}` };
const PROJECT = { key: `e2e-del/app-${RUN}`, name: 'E2E Delete App' };
const USER = {
  before: `e2e-rename-${RUN}`,
  after: `e2e-renamed-${RUN}`,
  password: 'e2e rename passphrase',
};

async function csrf(request: APIRequestContext): Promise<Record<string, string>> {
  const me = (await (await request.get('/api/v0/auth/me')).json()) as { csrfToken: string };
  return { 'x-qualor-csrf': me.csrfToken };
}

async function organizationId(request: APIRequestContext, key: string): Promise<string | null> {
  const listed = (await (await request.get('/api/v0/organizations?limit=100')).json()) as {
    items: { id: string; key: string }[];
  };
  return listed.items.find((o) => o.key === key)?.id ?? null;
}

test.describe.serial('delete an organization, rename a user', () => {
  test.afterAll(async ({ playwright, baseURL }) => {
    // The admin's own session: the signed-out describe below must not decide who cleans up.
    const request = await playwright.request.newContext({ baseURL, storageState: STORAGE_STATE });
    const headers = await csrf(request);
    const id = await organizationId(request, ORG.key);
    if (id) {
      await request.delete(`/api/v0/organizations/${id}?confirm=${ORG.key}`, { headers });
      await expect.poll(async () => organizationId(request, ORG.key)).toBeNull();
    }
    const users = (await (await request.get('/api/v0/users?limit=100')).json()) as {
      items: { id: string; username: string }[];
    };
    for (const u of users.items.filter((x) => [USER.before, USER.after].includes(x.username))) {
      await request.patch(`/api/v0/users/${u.id}`, { headers, data: { active: false } });
    }
    await request.dispose();
  });

  test('deleting an organization asks for its key and the row goes', async ({ page, request }) => {
    const headers = await csrf(request);
    const created = await request.post('/api/v0/organizations', {
      headers,
      data: { key: ORG.key, name: ORG.name },
    });
    expect(created.status()).toBe(201);
    const { id } = (await created.json()) as { id: string };
    const project = await request.post('/api/v0/projects', {
      headers,
      data: { organizationId: id, key: PROJECT.key, name: PROJECT.name },
    });
    expect(project.status()).toBe(201);

    await page.goto('/settings/organizations');
    const row = page.getByRole('row', { name: new RegExp(ORG.name) });
    await expect(row).toContainText(ORG.key);
    await row.getByRole('button', { name: `Delete ${ORG.name}` }).click();
    const dialog = page.getByRole('dialog', { name: 'Delete the organization' });
    await expect(dialog).toContainText('1 project');
    await expectAccessible(page);
    const confirm = dialog.getByRole('button', { name: 'Delete organization' });
    await expect(confirm).toHaveAttribute('aria-disabled', 'true');
    await dialog.getByLabel(/Type the organization key/).fill(ORG.key);
    await confirm.click();
    await expect(row).toHaveCount(0, { timeout: 30_000 });
    await expect(page.getByRole('row', { name: /Default/ })).toBeVisible();
    expect(await organizationId(request, ORG.key)).toBeNull();
  });

  test('a renamed user shows the new name and the old one is gone', async ({
    page,
    request,
    playwright,
    baseURL,
  }) => {
    const headers = await csrf(request);
    const created = await request.post('/api/v0/users', {
      headers,
      data: { username: USER.before, password: USER.password },
    });
    expect(created.status()).toBe(201);

    await page.goto('/settings/users');
    await page
      .getByRole('row', { name: new RegExp(USER.before) })
      .getByRole('button', { name: 'Edit' })
      .click();
    const dialog = page.getByRole('dialog', { name: `Edit ${USER.before}` });
    await expect(dialog.getByLabel('Username')).toBeFocused();
    await expectAccessible(page);
    await dialog.getByLabel('Username').fill(USER.after);
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByRole('status')).toHaveText(`${USER.after} is saved.`);
    await expect(page.getByRole('row', { name: new RegExp(USER.after) })).toBeVisible();
    await expect(page.getByRole('row', { name: new RegExp(USER.before) })).toHaveCount(0);

    // The new name signs in with the same password; the old one no longer does.
    const fresh = await playwright.request.newContext({ baseURL });
    try {
      const old = await fresh.post('/api/v0/auth/login', {
        data: { username: USER.before, password: USER.password },
      });
      expect(old.status()).toBe(401);
    } finally {
      await fresh.dispose();
    }
  });

  test.describe('signed out', () => {
    test.use({ storageState: { cookies: [], origins: [] } });

    test('the new name signs in', async ({ page }) => {
      await page.goto('/login');
      await page.getByLabel('Username').fill(USER.after);
      await page.getByLabel('Password').fill(USER.password);
      await page.getByRole('button', { name: 'Sign in' }).click();
      // A password set by an administrator must be changed first: reaching that page is the sign-in.
      await expect(page).toHaveURL(/\/change-password$/);
    });
  });
});
