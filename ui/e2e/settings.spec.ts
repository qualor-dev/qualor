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
});

test('a personal token is shown once, then only by its prefix, and can be revoked', async ({
  page,
  guard,
}) => {
  await page.goto('/settings');
  await expect(page).toHaveURL(/\/settings\/tokens$/);
  await expect(page).toHaveTitle('Access tokens · Qualor');
  await expect(page.getByRole('row', { name: /laptop/ })).toBeVisible();
  await page.getByLabel('Name').fill('e2e-script');
  await page.getByLabel('Upload analyses').check();
  await page.getByRole('button', { name: 'Create token' }).click();
  const secret = page.getByLabel('New token');
  await expect(secret).toHaveValue(/^qlr_pat_/);
  // The one-time field takes focus, so the keyboard is where the secret is.
  await expect(secret).toBeFocused();
  await expect(page.getByRole('status')).toHaveText(
    'Token e2e-script created. Copy it now: it is shown only this once.',
  );
  await expectAccessible(page);
  const value = await secret.inputValue();
  const row = page.getByRole('row', { name: /e2e-script/ });
  await expect(row).toContainText('Read, Upload analyses');
  await expect(row).toContainText(value.slice(0, 10));
  await expect(row).not.toContainText(value);
  await page.getByRole('button', { name: 'Done' }).click();
  await expect(page.getByLabel('New token')).toHaveCount(0);
  // Nothing brings it back: a reload shows the prefix only.
  await page.reload();
  await expect(row).toBeVisible();
  await expect(page.locator('body')).not.toContainText(value);

  guard.expectConfirm(true, 'Revoke the token "e2e-script"? Scripts using it stop working.');
  await row.getByRole('button', { name: 'Revoke' }).click();
  await expect(row).toHaveCount(0);
  await expect(page.getByRole('status')).toHaveText('Token e2e-script revoked.');
});

test('an instance admin creates a user who must change the password', async ({ page }) => {
  await page.goto('/settings/users');
  await expect(page.getByRole('row', { name: /alice/ })).toBeVisible();
  await page.getByLabel('Username').fill('bob');
  await page.getByLabel('Initial password').fill('bob initial passphrase');
  await page.getByRole('button', { name: 'Create user' }).click();
  await expect(page.getByRole('status')).toContainText('bob can sign in now');
  await expect(page.getByLabel('Initial password')).toHaveValue('');
  const bob = page.getByRole('row', { name: /bob/ });
  await expect(bob).toContainText('Must change password');
  // Keyboard only: the button changes its label in place and keeps the focus.
  await bob.getByRole('button', { name: 'Deactivate' }).press('Enter');
  await expect(bob).toContainText('Deactivated');
  await expect(page.getByRole('status')).toHaveText('bob is deactivated.');
  await expect(bob.getByRole('button', { name: 'Activate' })).toBeFocused();
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
  guard.expectConfirm(true, 'Remove your own instance admin role? You can no longer manage users.');
  await row.getByRole('button', { name: 'Remove admin' }).click();
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
  await page.getByLabel('URL').fill('https://ci.example.com/qualor-hook');
  await page.getByRole('button', { name: 'Add webhook' }).click();
  await expect(page.getByLabel('Webhook secret')).toHaveValue(/^whsec_/);
  const hook = page.getByRole('region', { name: 'https://ci.example.com/qualor-hook' });
  await hook.getByLabel('Active').uncheck();
  await expect(hook.getByLabel('Active')).not.toBeChecked();
  await expect(page.getByRole('status')).toHaveText(
    'Webhook https://ci.example.com/qualor-hook switched off.',
  );
  await hook.getByText('Recent deliveries').click();
  await expect(hook.getByText('No deliveries yet.')).toBeVisible();
  // The server's SSRF checks refuse a loopback address: the URL field says why.
  await page.getByLabel('URL').fill('https://127.0.0.1/internal');
  await page.getByRole('button', { name: 'Add webhook' }).click();
  await expect(page.getByText('Use an https URL of a public host')).toBeVisible();
  await expect(page.getByLabel('URL')).toHaveAttribute('aria-invalid', 'true');
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
  await page.getByLabel('GitLab address').fill('https://gitlab.example.com');
  await page.getByLabel('Access token').fill('glpat-e2e-token-value');
  await page.getByRole('button', { name: 'Add connection' }).click();
  await expect(page.getByRole('status')).toHaveText('GitLab connection added.');
  await expect(page.getByLabel('Access token')).toHaveValue('');
  await expect(page.getByRole('region', { name: 'https://gitlab.example.com' })).toBeVisible();
  await expect(page.locator('body')).not.toContainText('glpat-e2e-token-value');

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

  // The server's SSRF rules refuse a loopback GitLab the operator did not list.
  await page.getByLabel('GitLab address').fill('https://localhost');
  await page.getByLabel('Access token').fill('glpat-x');
  await page.getByRole('button', { name: 'Add connection' }).click();
  await expect(page.getByLabel('GitLab address')).toHaveAttribute('aria-invalid', 'true');
  await expect(page.getByText('QUALOR_SCM_INTERNAL_HOSTS').first()).toBeVisible();
  await expectAccessible(page);

  // The connection's own form (token and address), open, is accessible too.
  const connection = page.getByRole('region', { name: 'https://gitlab.example.com' });
  await connection.getByText('Replace the token or change the address').click();
  await expect(connection.getByLabel('New token')).toBeVisible();
  await expectAccessible(page);

  // Clean up the shared e2e database: deleting the connection unmaps Payments API again.
  guard.expectConfirm(
    true,
    'Delete the GitLab connection to https://gitlab.example.com? Its projects stop being decorated.',
  );
  await connection.getByRole('button', { name: 'Delete' }).click();
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
  guard,
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
  await page.getByRole('link', { name: 'GitLab settings' }).click();
  const row = page.getByRole('row', { name: new RegExp(PAYMENTS.name) });
  await row.getByLabel(`Connection of ${PAYMENTS.name}`).selectOption({
    label: 'GitHub · https://github.qualor.invalid/api/v3 (App 424242)',
  });
  await expect(row.getByLabel(`GitHub repository of ${PAYMENTS.name}`)).toHaveAttribute(
    'placeholder',
    'owner/repo',
  );
  await page.getByRole('link', { name: 'GitHub', exact: true }).click();

  guard.expectConfirm(
    true,
    'Delete the GitHub App 424242 at https://github.qualor.invalid/api/v3? Its projects stop being decorated.',
  );
  await app.getByRole('button', { name: 'Delete' }).click();
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
  const name = page.getByLabel('User name');
  await name.fill('nobody-by-this-name');
  await page.getByRole('button', { name: 'Add member' }).click();
  await expect(page.getByText('No active user has that name.')).toBeVisible();
  await expect(name).toHaveAttribute('aria-invalid', 'true');
  await expect(name).toBeFocused();

  // Every edition offers the four roles (rbac-audit.md §1.3).
  const role = page.getByLabel('Role', { exact: true });
  await expect(role.locator('option')).toHaveText([
    'Organization admin',
    'Project admin',
    'Maintainer',
    'Viewer',
  ]);
  await name.fill('dora');
  await role.selectOption({ label: 'Maintainer' });
  await page.getByRole('button', { name: 'Add member' }).click();
  await expect(page.getByRole('status')).toHaveText('dora added as Maintainer.');
  await expect(name).toHaveValue('');
  const dora = page.getByRole('row', { name: /dora/ });
  await expect(dora.getByLabel('Role of dora')).toHaveValue('member');

  await dora.getByLabel('Role of dora').selectOption({ label: 'Organization admin' });
  guard.expectConfirm(true, 'Change the role of dora in Default to Organization admin?');
  await dora.getByRole('button', { name: 'Change role' }).click();
  await expect(page.getByRole('status')).toHaveText('dora is now Organization admin.');
  await expect(dora.getByLabel('Role of dora')).toHaveValue('admin');
  await expectAccessible(page);

  guard.expectConfirm(true, 'Remove dora from Default? They lose access to its projects.');
  await dora.getByRole('button', { name: 'Remove' }).click();
  await expect(page.getByRole('status')).toHaveText('dora removed.');
  await expect(dora).toHaveCount(0);
});
