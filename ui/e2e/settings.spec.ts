import { generateKeyPairSync } from 'node:crypto';
import type { Page } from '@playwright/test';
import { expect, expectAccessible, test } from './fixtures';
import { ADMIN, PAYMENTS } from './seed-data';

async function csrfToken(page: Page): Promise<string> {
  const me = (await (await page.request.get('/api/v0/auth/me')).json()) as { csrfToken: string };
  return me.csrfToken;
}

/**
 * The seed's GitLab connection to the fake GitLab on loopback (server/scripts/e2e/serve.ts), which
 * the AI tests (ai.spec.ts) post through: never deleted here, so the files pass in any order.
 */
function seededFake(connection: { baseUrl?: string }): boolean {
  return connection.baseUrl !== undefined && new URL(connection.baseUrl).hostname === '127.0.0.1';
}

/**
 * Deletes every SCM connection of the given provider (or of any), in every organisation, through
 * the API as the signed-in admin, except the seed's fake: a test starts from none of its own,
 * whatever an earlier (interrupted) run left in the shared database. A change needs the session's
 * CSRF token.
 */
async function deleteConnections(page: Page, provider?: 'gitlab' | 'github'): Promise<void> {
  const csrf = await csrfToken(page);
  const orgs = (await (await page.request.get('/api/v0/organizations?limit=100')).json()) as {
    items: { id: string }[];
  };
  for (const org of orgs.items) {
    const listed = (await (
      await page.request.get(`/api/v0/scm-connections?organizationId=${org.id}&limit=100`)
    ).json()) as { items?: { id: string; provider: string; baseUrl?: string }[] };
    const own = (listed.items ?? []).filter(
      (c) => (!provider || c.provider === provider) && !seededFake(c),
    );
    for (const c of own) {
      const deleted = await page.request.delete(`/api/v0/scm-connections/${c.id}`, {
        headers: { 'x-qualor-csrf': csrf },
      });
      expect(deleted.status()).toBe(204);
    }
  }
}

test('the settings navigation groups its entries and marks the current page', async ({ page }) => {
  await page.goto('/settings');
  await expect(page).toHaveTitle('Access tokens · Qualor');
  const nav = page.getByRole('navigation', { name: 'Settings' });
  await expect(
    nav.getByRole('group', { name: 'Your account' }).getByRole('link', { name: 'Access tokens' }),
  ).toHaveAttribute('aria-current', 'page');
  await expect(
    nav.getByRole('group', { name: 'Organization' }).getByRole('link', { name: 'Members' }),
  ).toBeVisible();
  await nav.getByRole('group', { name: 'Instance' }).getByRole('link', { name: 'Users' }).click();
  await expect(page).toHaveTitle('Users · Qualor');
  await expect(nav.getByRole('link', { name: 'Users' })).toHaveAttribute('aria-current', 'page');
  await expect(nav.getByRole('link', { name: 'Access tokens' })).not.toHaveAttribute(
    'aria-current',
  );
  await expectAccessible(page);
});

test.describe('on a phone', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('the settings navigation sits above the page, which never scrolls sideways', async ({
    page,
  }) => {
    await page.goto('/settings/tokens');
    const heading = page.getByRole('heading', { name: 'Your access tokens', level: 2 });
    await expect(heading).toBeVisible();
    const nav = await page.getByRole('navigation', { name: 'Settings' }).boundingBox();
    const title = await heading.boundingBox();
    expect(nav!.y + nav!.height).toBeLessThanOrEqual(title!.y);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(
      390,
    );
    await expectAccessible(page);
  });

  // Each settings page fits the screen once its data is in: a wide table scrolls in its panel.
  for (const path of [
    '/settings/organizations',
    '/settings/users',
    '/settings/members',
    '/settings/webhooks',
    '/settings/gitlab',
    '/settings/github',
    '/settings/repositories',
    '/settings/ai',
    '/settings/license',
  ]) {
    test(`${path} never scrolls sideways`, async ({ page }) => {
      await page.goto(path);
      await expect(page.locator('.settings-head h2')).toBeVisible();
      await page.waitForLoadState('networkidle');
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(
        390,
      );
    });
  }

  test('names in tables keep their words; a table scrolls in its panel instead', async ({
    page,
  }) => {
    /** The cell is at least as wide as the name's longest word: it may wrap between words only. */
    const keepsWords = async (text: string) => {
      const name = page.locator('.name-stack > span', { hasText: text }).first();
      await expect(name).toBeAttached();
      const { width, need } = await name.evaluate((el) => {
        const style = getComputedStyle(el);
        const context = document.createElement('canvas').getContext('2d')!;
        context.font = `${style.fontWeight} ${style.fontSize} ${style.fontFamily}`;
        const words = (el.textContent ?? '').trim().split(/\s+/);
        return {
          width: el.getBoundingClientRect().width,
          need: Math.max(...words.map((word) => context.measureText(word).width)),
        };
      });
      expect(width, text).toBeGreaterThanOrEqual(need - 1);
    };
    await page.goto('/settings/tokens');
    await keepsWords('laptop');
    await page.goto('/settings/repositories');
    await keepsWords('Payments API');
    await keepsWords('Legacy Billing');
  });

  test('a webhook with its recent deliveries open still fits the screen', async ({ page }) => {
    // The seed's webhook has delivered nothing: twenty deliveries are answered in the browser.
    await page.route(/\/api\/v0\/webhooks\/[^/]+\/deliveries(\?.*)?$/, (route) =>
      route.fulfill({
        json: {
          items: Array.from({ length: 20 }, (_, i) => ({
            id: `e2e-delivery-${i}`,
            event: 'analysis.completed',
            status: i === 3 ? 'failed' : 'succeeded',
            attempts: i === 3 ? 3 : 1,
            responseCode: i === 3 ? 502 : 204,
            responseExcerpt: i === 3 ? '<html><body>502 Bad Gateway</body></html>' : null,
            nextAttemptAt: null,
            createdAt: new Date(Date.UTC(2026, 8, 29, 16, 40) - i * 47 * 60e3).toISOString(),
          })),
          nextCursor: null,
        },
      }),
    );
    await page.goto('/settings/webhooks');
    await page.getByText('Recent deliveries').first().click();
    await expect(page.getByRole('table').first()).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(
      390,
    );
  });
});

test('a personal token is shown once in its dialog, then only by its prefix, and can be revoked', async ({
  page,
}) => {
  await page.goto('/settings');
  await expect(page).toHaveURL(/\/settings\/tokens$/);
  await expect(page).toHaveTitle('Access tokens · Qualor');
  await expect(page.getByRole('row', { name: /laptop/ })).toBeVisible();
  // The form is in the "New token" dialog (step 8), which starts on the name.
  await page.getByRole('button', { name: 'New token' }).click();
  const create = page.getByRole('dialog', { name: 'New token' });
  await expect(create.getByLabel('Name')).toBeFocused();
  await create.getByLabel('Name').fill('e2e-script');
  await create.getByLabel('Upload analyses').check();
  await create.getByRole('button', { name: 'Create token' }).click();
  // The same dialog then holds the secret; its field takes focus, so the keyboard is there.
  const shown = page.getByRole('dialog', { name: 'Your new token' });
  const secret = shown.getByLabel('New token');
  await expect(secret).toHaveValue(/^qlr_pat_/);
  await expect(secret).toBeFocused();
  await expectAccessible(page);
  const value = await secret.inputValue();
  await shown.getByRole('button', { name: 'Done' }).click();
  await expect(page.locator('#secret-once')).toHaveCount(0);
  // The page no longer asks to copy a secret it no longer shows.
  await expect(page.getByRole('status')).toHaveText('Token e2e-script created.');
  const row = page.getByRole('row', { name: /e2e-script/ });
  await expect(row).toContainText('Read');
  await expect(row).toContainText('Upload analyses');
  await expect(row).toContainText(value.slice(0, 10));
  await expect(row).not.toContainText(value);
  // Nothing brings it back: a reload shows the prefix only.
  await page.reload();
  await expect(row).toBeVisible();
  await expect(page.locator('body')).not.toContainText(value);

  // The page's own dialog asks (a browser confirm() would fail the guard of fixtures.ts).
  await row.getByRole('button', { name: 'Revoke' }).click();
  const ask = page.getByRole('dialog', { name: 'Revoke the token' });
  await expect(ask).toContainText('Revoke the token "e2e-script"? Scripts using it stop working.');
  await ask.getByRole('button', { name: 'Revoke' }).click();
  await expect(row).toHaveCount(0);
  await expect(page.getByRole('status')).toHaveText('Token e2e-script revoked.');
});

test('an instance admin creates a user who must change the password, and resets it from the row', async ({
  page,
}) => {
  await page.goto('/settings/users');
  await expect(page.getByRole('row', { name: /alice/ })).toBeVisible();
  await page.getByRole('button', { name: 'New user' }).click();
  const create = page.getByRole('dialog', { name: 'New user' });
  await expect(create.getByLabel('Username')).toBeFocused();
  await create.getByLabel('Username').fill('bob');
  await create.getByLabel('Initial password').fill('bob initial passphrase');
  await create.getByRole('button', { name: 'Create user' }).click();
  await expect(create).toBeHidden();
  await expect(page.getByRole('status')).toContainText('bob can sign in now');
  const bob = page.getByRole('row', { name: /bob/ });
  await expect(bob).toContainText('Must change password');
  // The row resets the password in a dialog that names the user (step 8).
  await bob.getByRole('button', { name: 'Reset password' }).click();
  const reset = page.getByRole('dialog', { name: 'Reset the password of bob' });
  await expect(reset.getByLabel('New password')).toBeFocused();
  await expectAccessible(page);
  await reset.getByLabel('New password').fill('bob second passphrase');
  await reset.getByRole('button', { name: 'Reset password' }).click();
  await expect(reset).toBeHidden();
  await expect(page.getByRole('status')).toHaveText(
    'bob must choose a new password at the next sign-in.',
  );
  await expect(bob.getByRole('button', { name: 'Reset password' })).toBeFocused();
  // Keyboard only: the button changes its label in place and keeps the focus.
  await bob.getByRole('button', { name: 'Deactivate' }).press('Enter');
  await expect(bob).toContainText('Deactivated');
  await expect(page.getByRole('status')).toHaveText('bob is deactivated.');
  await expect(bob.getByRole('button', { name: 'Activate' })).toBeFocused();
  await expectAccessible(page);
});

test('an instance admin sees the organizations and creates one in a dialog', async ({ page }) => {
  await page.goto('/settings/organizations');
  await expect(page).toHaveTitle('Organizations · Qualor');
  const current = page.getByRole('row', { name: /Default/ });
  await expect(current).toContainText('default');
  await expect(current).toContainText('Current');
  // The switcher in the header appears with a second organization only.
  await expect(page.getByRole('combobox', { name: 'Organization', exact: true })).toHaveCount(0);

  await page.getByRole('button', { name: 'New organization' }).click();
  const create = page.getByRole('dialog', { name: 'New organization' });
  await expect(create.getByLabel('Name')).toBeFocused();
  await create.getByLabel('Name').fill('E2E Labs');
  await expect(create.getByLabel('Key')).toHaveValue('e2e-labs');
  await expectAccessible(page);

  // The seeded server keeps one organization: the new one lives in this browser only.
  const labs = {
    id: '0190a6c2-0000-7000-8000-0000000000e2',
    key: 'e2e-labs',
    name: 'E2E Labs',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  let created = false;
  await page.route(/\/api\/v0\/organizations(\?.*)?$/, async (route) => {
    if (route.request().method() === 'POST') {
      expect(route.request().postDataJSON()).toEqual({ key: 'e2e-labs', name: 'E2E Labs' });
      created = true;
      return route.fulfill({ status: 201, json: labs });
    }
    const response = await route.fetch();
    const body = (await response.json()) as { items: unknown[]; nextCursor: string | null };
    return route.fulfill({
      response,
      json: created ? { ...body, items: [...body.items, labs] } : body,
    });
  });
  await create.getByRole('button', { name: 'Create organization' }).click();
  await expect(create).toBeHidden();
  await expect(page.getByRole('status')).toHaveText('E2E Labs created. You are its admin.');
  await expect(page.getByRole('row', { name: /E2E Labs/ })).toContainText('e2e-labs');
  await expect(
    page.getByRole('row', { name: /E2E Labs/ }).getByRole('button', { name: 'Switch to E2E Labs' }),
  ).toBeVisible();
  await expect(page.getByRole('combobox', { name: 'Organization', exact: true })).toBeVisible();
  await expectAccessible(page);
});

test('the last instance admin cannot remove their own role (409 LAST_ADMIN)', async ({
  page,
  guard,
}) => {
  const users = await page.request.get('/api/v0/users?limit=100');
  const { items } = (await users.json()) as { items: { id: string; username: string }[] };
  const admin = items.find((u) => u.username === ADMIN.username);
  expect(admin).toBeDefined();
  guard.allowFailedLoad(`/api/v0/users/${admin?.id ?? ''}`, 409);
  await page.goto('/settings/users');
  // The seed gives the signed-in admin a display name, so the row is found by the user's id.
  const row = page.locator(`tbody tr[data-key="${admin?.id ?? ''}"]`);
  await expect(row).toContainText(ADMIN.username);
  await row.getByRole('button', { name: 'Remove admin' }).click();
  const ask = page.getByRole('dialog', { name: 'Remove your admin role' });
  await expect(ask).toContainText(
    'Remove your own instance admin role? You can no longer manage users.',
  );
  await ask.getByRole('button', { name: 'Remove admin' }).click();
  await expect(page.getByRole('alert')).toHaveText(
    'The last active administrator cannot be demoted, removed or deactivated.',
  );
  await expect(row).toContainText('Instance admin');
});

test('an organization admin adds a webhook and sees its secret once', async ({ page, guard }) => {
  guard.allowFailedLoad('/api/v0/webhooks', 422);
  await page.goto('/settings/webhooks');
  await expect(
    page.getByRole('region', { name: 'https://hooks.example.com/qualor' }),
  ).toBeVisible();
  // The form is in the "New webhook" dialog (step 8), which then shows the secret.
  await page.getByRole('button', { name: 'New webhook' }).click();
  const create = page.getByRole('dialog', { name: 'New webhook for every project' });
  await expect(create.getByLabel('URL')).toBeFocused();
  await create.getByLabel('URL').fill('https://ci.example.com/qualor-hook');
  await create.getByRole('button', { name: 'Add webhook' }).click();
  const shown = page.getByRole('dialog', { name: "The webhook's secret" });
  await expect(shown.getByLabel('Webhook secret')).toHaveValue(/^whsec_/);
  await expectAccessible(page);
  await shown.getByRole('button', { name: 'Done' }).click();
  await expect(page.locator('#secret-once')).toHaveCount(0);
  const hook = page.getByRole('region', { name: 'https://ci.example.com/qualor-hook' });
  await expect(hook.getByText('No deliveries yet.')).toBeVisible();
  // Switched off in place: the state says so, the same button now offers Switch on.
  await hook.getByRole('button', { name: 'Switch off' }).click();
  await expect(page.getByRole('status')).toHaveText(
    'Webhook https://ci.example.com/qualor-hook switched off.',
  );
  await expect(hook.getByText('Switched off', { exact: true })).toBeVisible();
  await expect(hook.getByRole('button', { name: 'Switch on' })).toBeFocused();
  // The server's SSRF checks refuse a loopback address: the URL field says why, in the dialog.
  await page.getByRole('button', { name: 'New webhook' }).click();
  await create.getByLabel('URL').fill('https://127.0.0.1/internal');
  await create.getByRole('button', { name: 'Add webhook' }).click();
  await expect(create.getByText('Use an https URL of a public host')).toBeVisible();
  await expect(create.getByLabel('URL')).toHaveAttribute('aria-invalid', 'true');
  await expectAccessible(page);
});

test('an organization admin connects GitLab and maps a project (scm.md §2)', async ({
  page,
  guard,
}) => {
  // No test or check is clicked here: they would make the server call the GitLab host.
  guard.allowFailedLoad('/api/v0/scm-connections', 422);
  // Start from no connection of this test's, whatever an earlier (interrupted) run left. Payments
  // API's mapping (the seed maps it to the fake GitLab) is put back at the end.
  await deleteConnections(page);
  const projects = (await (await page.request.get('/api/v0/projects?limit=100')).json()) as {
    items: {
      id: string;
      key: string;
      scmConnectionId: string | null;
      scmProjectRef: string | null;
    }[];
  };
  const payments = projects.items.find((p) => p.key === PAYMENTS.key);
  expect(payments).toBeDefined();
  await page.goto('/settings/gitlab');
  await expect(page).toHaveTitle('GitLab · Qualor');
  await expect(page.getByRole('region', { name: 'https://gitlab.example.com' })).toHaveCount(0);
  // The short create form is in the "New connection" dialog (step 8).
  await page.getByRole('button', { name: 'New connection' }).click();
  const create = page.getByRole('dialog', { name: 'New GitLab connection' });
  await expect(create.getByLabel('GitLab address')).toBeFocused();
  await create.getByLabel('GitLab address').fill('https://gitlab.example.com');
  await create.getByLabel('Access token').fill('glpat-e2e-token-value');
  await create.getByRole('button', { name: 'Add connection' }).click();
  await expect(page.getByRole('status')).toHaveText('GitLab connection added.');
  await expect(create).toBeHidden();
  await expect(page.locator('#gitlab-token')).toHaveValue('');
  await expect(page.getByRole('region', { name: 'https://gitlab.example.com' })).toBeVisible();
  await expect(page.locator('body')).not.toContainText('glpat-e2e-token-value');

  // Each project's repository is chosen under Repositories (step 11), which the page links to.
  await page.locator('.settings-head').getByRole('link', { name: 'Repositories' }).click();
  await expect(page).toHaveTitle('Repositories · Qualor');
  const row = page.getByRole('row', { name: new RegExp(PAYMENTS.name) });
  await row.getByLabel(`Connection of ${PAYMENTS.name}`).selectOption({
    label: 'GitLab · https://gitlab.example.com',
  });
  await row.getByLabel(`GitLab project of ${PAYMENTS.name}`).fill('acme/payments-api');
  await row.getByRole('button', { name: 'Save' }).click();
  await expect(row).toContainText('Decorated in GitLab.');
  await page.reload();
  await expect(
    page
      .getByRole('row', { name: new RegExp(PAYMENTS.name) })
      .getByLabel(`GitLab project of ${PAYMENTS.name}`),
  ).toHaveValue('acme/payments-api');
  await expectAccessible(page);

  // The server's SSRF rules refuse a loopback GitLab the operator did not list: in the dialog.
  await page.goto('/settings/gitlab');
  await page.getByRole('button', { name: 'New connection' }).click();
  await create.getByLabel('GitLab address').fill('https://localhost');
  await create.getByLabel('Access token').fill('glpat-x');
  await create.getByRole('button', { name: 'Add connection' }).click();
  await expect(create.getByLabel('GitLab address')).toHaveAttribute('aria-invalid', 'true');
  await expect(create.getByText('QUALOR_SCM_INTERNAL_HOSTS')).toBeVisible();
  await expectAccessible(page);
  await create.getByRole('button', { name: 'Cancel' }).click();
  await expect(create).toBeHidden();

  // The connection's own form (token and address), open, is accessible too.
  const connection = page.getByRole('region', { name: 'https://gitlab.example.com' });
  await connection.getByText('Replace the token or change the address').click();
  await expect(connection.getByLabel('New token')).toBeVisible();
  await expectAccessible(page);

  // Clean up the shared e2e database: deleting the connection unmaps Payments API again. The
  // page's own dialog asks (a browser confirm() would fail the guard of fixtures.ts).
  await connection.getByRole('button', { name: 'Delete' }).click();
  const ask = page.getByRole('dialog', { name: 'Delete the connection' });
  await expect(ask).toContainText(
    'Delete the GitLab connection to https://gitlab.example.com? Its projects stop being decorated.',
  );
  await ask.getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByRole('status')).toHaveText(
    'GitLab connection https://gitlab.example.com deleted.',
  );
  await expect(page.getByRole('region', { name: 'https://gitlab.example.com' })).toHaveCount(0);

  // Put Payments API's mapping back as the seed made it.
  if (payments?.scmConnectionId) {
    const restored = await page.request.patch(`/api/v0/projects/${payments.id}`, {
      headers: { 'x-qualor-csrf': await csrfToken(page) },
      data: { scmConnectionId: payments.scmConnectionId, scmProjectRef: payments.scmProjectRef },
    });
    expect(restored.status()).toBe(200);
  }
});

test('an organization admin adds a GitHub App and deletes it (github.md §2.2)', async ({
  page,
}) => {
  // Creating a connection makes no request to GitHub; only Test would, and it is not pressed.
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  const secret = 'e2e-webhook-secret-0123456789';
  // Start from no GitHub connection, whatever the seed or an earlier (interrupted) run left.
  await deleteConnections(page, 'github');
  await page.goto('/settings');
  await page.getByRole('link', { name: 'GitHub' }).click();
  await expect(page).toHaveURL(/\/settings\/github$/);
  await expect(page).toHaveTitle('GitHub · Qualor');
  await expect(page.getByText('No GitHub App yet.')).toBeVisible();
  await expect(page.locator('#github-url')).toHaveValue('https://api.github.com');
  // An address that cannot resolve (RFC 6761): the test never reaches a real GitHub.
  await page.locator('#github-url').fill('https://github.qualor.invalid/api/v3');
  await page.locator('#github-app-id').fill('424242');
  await page.locator('#github-key').fill(privateKey);
  await page.locator('#github-secret').fill(secret);
  await page.getByRole('button', { name: 'Add App' }).click();
  await expect(page.getByRole('status')).toHaveText('GitHub App added.');
  await expect(page.locator('#github-key')).toHaveValue('');
  await expect(page.locator('#github-secret')).toHaveValue('');
  const app = page.getByRole('region', {
    name: 'GitHub App 424242 at https://github.qualor.invalid/api/v3',
  });
  await expect(app).toContainText('App id 424242');
  const body = page.locator('body');
  await expect(body).not.toContainText('PRIVATE KEY');
  await expect(body).not.toContainText(secret);
  expect(await page.evaluate(() => JSON.stringify(localStorage) + location.href)).not.toContain(
    secret,
  );
  await expectAccessible(page);

  // The project mapping names the App by its address and its App id (two Apps may share an
  // address). Only chosen, not saved: nothing is mapped.
  await page.locator('.settings-head').getByRole('link', { name: 'Repositories' }).click();
  const row = page.getByRole('row', { name: new RegExp(PAYMENTS.name) });
  await row.getByLabel(`Connection of ${PAYMENTS.name}`).selectOption({
    label: 'GitHub · https://github.qualor.invalid/api/v3 (App 424242)',
  });
  await expect(row.getByLabel(`GitHub repository of ${PAYMENTS.name}`)).toHaveAttribute(
    'placeholder',
    'owner/repo',
  );
  await page.getByRole('link', { name: 'GitHub', exact: true }).click();

  await app.getByRole('button', { name: 'Delete' }).click();
  const ask = page.getByRole('dialog', { name: 'Delete the GitHub App' });
  await expect(ask).toContainText(
    'Delete the GitHub App 424242 at https://github.qualor.invalid/api/v3? Its projects stop being decorated.',
  );
  await ask.getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByRole('status')).toHaveText(
    'GitHub App 424242 at https://github.qualor.invalid/api/v3 deleted.',
  );
  await expect(page.getByText('No GitHub App yet.')).toBeVisible();
});

test('an organization admin adds a member by name, changes the role and removes them', async ({
  page,
  guard,
}) => {
  // A user of this test's own, in no organization yet (the database is fresh for every run).
  const created = await page.request.post('/api/v0/users', {
    headers: { 'x-qualor-csrf': await csrfToken(page) },
    data: { username: 'dora', password: 'dora initial passphrase' },
  });
  expect(created.status()).toBe(201);
  guard.allowFailedLoad('/api/v0/users/lookup', 404);
  await page.goto('/settings');
  await page.getByRole('link', { name: 'Members' }).click();
  await expect(page).toHaveURL(/\/settings\/members$/);
  await expect(page).toHaveTitle('Members · Qualor');
  await expect(page.getByRole('row', { name: /alice/ })).toContainText('Maintainer');

  // A name nobody has: said on the field, which keeps the focus.
  // The form is in the "Add member" dialog (step 8), which starts on the name.
  await page.getByRole('button', { name: 'Add member' }).click();
  const add = page.getByRole('dialog', { name: 'Add a member' });
  const name = add.getByLabel('User name');
  await expect(name).toBeFocused();
  await name.fill('nobody-by-this-name');
  await add.getByRole('button', { name: 'Add member' }).click();
  await expect(add.getByText('No active user has that name.')).toBeVisible();
  await expect(name).toHaveAttribute('aria-invalid', 'true');
  await expect(name).toBeFocused();

  // Every edition offers the four roles (rbac-audit.md §1.3).
  const role = add.getByLabel('Role', { exact: true });
  await expect(role.locator('option')).toHaveText([
    'Organization admin',
    'Project admin',
    'Maintainer',
    'Viewer',
  ]);
  await name.fill('dora');
  await role.selectOption({ label: 'Maintainer' });
  await add.getByRole('button', { name: 'Add member' }).click();
  await expect(add).toBeHidden();
  await expect(page.getByRole('status')).toHaveText('dora added as Maintainer.');
  const dora = page.getByRole('row', { name: /dora/ });
  await expect(dora.getByLabel('Role of dora')).toHaveValue('member');

  // The page's own dialog asks (a browser confirm() would fail the guard of fixtures.ts).
  await dora.getByLabel('Role of dora').selectOption({ label: 'Organization admin' });
  await dora.getByRole('button', { name: 'Change role' }).click();
  const change = page.getByRole('dialog', { name: 'Change the role of dora' });
  await expect(change).toContainText('Change the role of dora in Default to Organization admin?');
  await expectAccessible(page);
  await change.getByRole('button', { name: 'Change role' }).click();
  await expect(page.getByRole('status')).toHaveText('dora is now Organization admin.');
  await expect(dora.getByLabel('Role of dora')).toHaveValue('admin');
  await expectAccessible(page);

  await dora.getByRole('button', { name: 'Remove' }).click();
  const remove = page.getByRole('dialog', { name: 'Remove dora' });
  await expect(remove).toContainText('Remove dora from Default? They lose access to its projects.');
  await remove.getByRole('button', { name: 'Remove' }).click();
  await expect(page.getByRole('status')).toHaveText('dora removed.');
  await expect(dora).toHaveCount(0);
});
