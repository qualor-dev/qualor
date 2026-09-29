import type { Page } from '@playwright/test';
import { expect, expectAccessible, test } from './fixtures';
import { ENTERPRISE_URL } from './seed-data';

/**
 * Plan 4D (sso-scim.md §18): the single sign-on, sign-in, SCIM and linked-accounts screens on the
 * licensed e2e server (`server/scripts/e2e/serve.ts`, the Enterprise plan's features, with
 * `sso.multi` and `scim`). The seed
 * (`seedSso`) made "Acme SSO" (enabled OIDC), "Staging OIDC" (disabled) and "Corp SAML" (disabled
 * SAML), two mappings and a SCIM token of Acme SSO, and `sso-user`, provisioned through SCIM.
 * Their identity providers are under `.invalid` and never contacted: no test here presses Test,
 * reads metadata or follows a sign-in button.
 */

async function editConnection(page: Page, name: string): Promise<void> {
  await page.goto('/settings/ee/sso');
  await page.getByRole('button', { name: `Edit ${name}` }).click();
  await expect(page.getByRole('heading', { name: new RegExp(`^${name} \\(`) })).toBeVisible();
}

test.describe('signed out', () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test('the sign-in page offers the enabled connection only', async ({ page }) => {
    await page.goto('/login');
    const button = page.getByRole('link', { name: 'Sign in with Acme SSO' });
    await expect(button).toBeVisible();
    await expect(button).toHaveAttribute('href', /^\/api\/v0\/ee\/sso\/[0-9a-f-]{36}\/start\?/);
    await expect(page.getByRole('link', { name: 'Sign in with Staging OIDC' })).toHaveCount(0);
    await expect(page.getByRole('link', { name: 'Sign in with Corp SAML' })).toHaveCount(0);
    // Everyone may still use a password: the form is not folded away.
    await expect(page.getByLabel('Password')).toBeVisible();
  });
});

test('the Single sign-on screen shows a connection and saves a mapping', async ({ page }) => {
  await page.goto('/settings');
  await expect(page.getByRole('link', { name: 'Single sign-on' })).toBeVisible();
  await page.getByRole('link', { name: 'Single sign-on' }).click();
  await expect(page).toHaveURL(/\/settings\/ee\/sso$/);
  await expect(page).toHaveTitle('Single sign-on · Qualor');
  // A panel per connection (step 9), named by the connection.
  const list = page.locator('#sso-connections');
  await expect(list.getByRole('region', { name: 'Acme SSO' })).toContainText('Enabled');
  await expect(list.getByRole('region', { name: 'Staging OIDC' })).toContainText('Disabled');
  await expect(list.getByRole('region', { name: 'Corp SAML' })).toContainText('SAML');
  // sso.multi: every enabled connection is in effect, and the page counts them against the 10.
  await expect(page.locator('#sso-count')).toHaveText('3 of 10 connections');
  await expect(page.locator('#sso-multi-not-licensed')).toHaveCount(0);
  await expect(page.getByText('Not in effect')).toHaveCount(0);
  await expectAccessible(page);

  await editConnection(page, 'Acme SSO');
  await expect(page.getByLabel('Redirect URI')).toHaveValue(
    new RegExp(`^${ENTERPRISE_URL}/api/v0/ee/sso/oidc/[0-9a-f-]{36}/callback$`),
  );
  // The stored client secret is never shown, only that one is set.
  await expect(page.locator('#sso-client-secret')).toHaveCount(0);
  await expect(page.locator('#sso-client-secret-state')).toHaveText(
    'Set. It is never shown again.',
  );
  const mappings = page.locator('#sso-mappings');
  await expect(mappings).toContainText('engineering');
  await expect(mappings).toContainText('acme/web-shop');

  await page.getByLabel('Group', { exact: true }).fill('platform');
  await page
    .getByRole('combobox', { name: 'Organization', exact: true })
    .selectOption({ label: 'Default' });
  await page.getByLabel('Role', { exact: true }).selectOption({ label: 'Maintainer' });
  await page.getByRole('button', { name: 'Add', exact: true }).click();
  await page.getByRole('button', { name: 'Save mappings' }).click();
  await expect(page.getByRole('status')).toHaveText('Group mappings saved.');
  await expectAccessible(page);

  await editConnection(page, 'Acme SSO');
  await expect(page.locator('#sso-mappings').getByRole('row', { name: /platform/ })).toContainText(
    'Maintainer',
  );

  // A SAML connection shows its pinned certificate's SHA-256 fingerprint.
  await editConnection(page, 'Corp SAML');
  await expect(page.locator('#sso-certificates')).toContainText(
    /SHA-256\s+([0-9A-F]{2}:){31}[0-9A-F]{2}/,
  );
  await expect(page.getByLabel('ACS URL')).toHaveValue(
    /\/api\/v0\/ee\/sso\/saml\/[0-9a-f-]{36}\/acs$/,
  );
});

test.describe('on a phone', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test("each kind of connection's form fits the screen: nothing scrolls sideways", async ({
    page,
  }) => {
    await editConnection(page, 'Acme SSO');
    await expect(page.getByLabel('Redirect URI')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(
      390,
    );
    // A long checkbox label wraps beside its box, not under it.
    const option = page.locator('label', { hasText: 'Also read the userinfo endpoint' });
    const box = await option.getByRole('checkbox').boundingBox();
    const words = await option.locator('span').boundingBox();
    expect(words!.x).toBeGreaterThan(box!.x + box!.width);
    expect(words!.y).toBeLessThan(box!.y + box!.height);
    // Group names keep their words: the mappings table scrolls in its panel instead.
    const mappings = page.locator('#sso-mappings');
    const long = await mappings.locator('code', { hasText: 'engineering' }).boundingBox();
    const short = await mappings.locator('code', { hasText: /^qa$/ }).boundingBox();
    expect(long!.height).toBeLessThanOrEqual(short!.height + 1);
    await expectAccessible(page);

    await editConnection(page, 'Corp SAML');
    await expect(page.getByLabel('ACS URL')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(
      390,
    );
  });
});

test('the Sign-in screen lists the instance admins and saves', async ({ page }) => {
  await page.goto('/settings/ee/sign-in');
  await expect(page.getByRole('heading', { name: 'Sign-in', exact: true })).toBeVisible();
  await expect(page.getByLabel('Everyone with a password')).toBeChecked();
  const admin = page.locator('#sign-in-picker label', { hasText: 'admin' });
  await expect(admin.getByRole('checkbox')).toBeEnabled();
  // sso-user is not an instance admin, so it is not offered.
  await expect(page.locator('#sign-in-picker')).not.toContainText('sso-user');
  await expectAccessible(page);
  // The policy stays `everyone`: the other tests sign in with passwords.
  await admin.getByRole('checkbox').check();
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('status')).toHaveText(
    'Saved: everyone with a password may sign in with it.',
  );
});

test('the SCIM screen creates a token and shows it once', async ({ page }) => {
  await page.goto('/settings/ee/scim');
  const acme = page.locator('section', { has: page.getByRole('heading', { name: 'Acme SSO' }) });
  await expect(acme.getByLabel('SCIM base URL')).toHaveValue(`${ENTERPRISE_URL}/api/v0/ee/scim/v2`);
  // The seed's token was used once, to provision sso-user.
  await expect(acme.getByRole('row', { name: /Entra ID provisioning/ })).toContainText('qlr_scim_');
  await expect(acme.getByRole('row', { name: /Entra ID provisioning/ })).not.toContainText(
    'Not used yet',
  );
  await expectAccessible(page);

  // Step 9: New token opens a dialog for the connection, which then holds the token once.
  await acme.getByRole('button', { name: 'New token for Acme SSO' }).click();
  const create = page.getByRole('dialog', { name: 'New token for Acme SSO' });
  await expect(create.getByLabel('Token name')).toBeFocused();
  await create.getByLabel('Token name').fill('Okta');
  await create.getByRole('button', { name: 'Create token' }).click();
  const shown = page.getByRole('dialog', { name: 'Your new SCIM token' });
  const secret = shown.getByLabel('SCIM token');
  await expect(secret).toHaveValue(/^qlr_scim_[0-9A-Za-z]{32}$/);
  await expect(secret).toBeFocused();
  const token = await secret.inputValue();
  await shown.getByRole('button', { name: 'Done' }).click();
  await expect(secret).toHaveCount(0);
  await page.reload();
  await expect(acme.getByRole('row', { name: /Okta/ })).toContainText(token.slice(0, 12));
  expect(await page.content()).not.toContain(token);
});

test('Linked accounts lists your identity; Users marks the SCIM account', async ({ page }) => {
  await page.goto('/settings/ee/linked-accounts');
  await expect(page.getByRole('row', { name: /Acme SSO/ })).toBeVisible();
  await page.goto('/settings/users');
  const row = page.getByRole('row', { name: /sso-user/ });
  await expect(row).toContainText('No password');
  await expect(row).toContainText('SCIM');
});
