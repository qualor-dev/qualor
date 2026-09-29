import type { Page } from '@playwright/test';
import { expect, expectAccessible, test } from './fixtures';
import { OLGA, PAYMENTS, SHOP, VICTOR } from './seed-data';

/**
 * Plan 5B (rbac-audit.md §1.3, §17): the four roles, the Members screen and the Access tab on the
 * community e2e server, with no licence (`server/scripts/e2e/seed.ts` `seedRoles`). The tests of
 * this file run in order on one server: the org admin's grant is what the viewer sees next.
 */

async function signIn(page: Page, user: { username: string; password: string }): Promise<void> {
  await page.goto('/login');
  await page.getByLabel('Username').fill(user.username);
  await page.getByLabel('Password').fill(user.password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/projects$/);
}

test.describe('as people other than the instance admin', () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test('an org admin grants a role on a project', async ({ page }) => {
    await signIn(page, OLGA);
    await page.getByRole('link', { name: PAYMENTS.name }).click();
    await page.getByRole('link', { name: 'Access' }).click();
    await expect(page).toHaveURL(/\/access$/);
    await expect(page).toHaveTitle('Access · Qualor');
    await expect(page.getByText('Organization roles apply on top of these.')).toBeVisible();
    await expect(page.getByText('No one has a role on this project alone yet.')).toBeVisible();
    await expect(page.getByText(/enterprise licence/)).toHaveCount(0);

    // The add form is in the "Add member" dialog (step 5), which starts on the user name.
    await page.getByRole('button', { name: 'Add member' }).click();
    const add = page.getByRole('dialog', { name: 'Give someone a role on this project' });
    await expect(add.getByLabel('User name')).toBeFocused();
    await expectAccessible(page);
    // The four-role select of the organization is not offered here: a grant is never admin.
    const role = add.getByLabel('Role', { exact: true });
    await expect(role.locator('option')).toHaveText(['Project admin', 'Maintainer', 'Viewer']);
    await expect(role).toHaveValue('viewer');
    await page.getByLabel('User name').fill(VICTOR.username);
    await page.getByRole('button', { name: 'Give the role' }).click();
    await expect(page.getByRole('status')).toHaveText(
      'victor now has the role Viewer on this project.',
    );
    await expect(
      page.getByRole('row', { name: /victor/ }).getByLabel('Role of victor on this project'),
    ).toHaveValue('viewer');
    await expectAccessible(page);
  });

  test('a viewer reads the project and its issues but cannot change them', async ({ page }) => {
    await signIn(page, VICTOR);
    // Only the projects of the grants: Web Shop (seeded) and Payments API (the test above).
    await expect(page.getByRole('link', { name: PAYMENTS.name })).toBeVisible();
    await expect(page.getByRole('link', { name: SHOP.name })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Legacy Billing' })).toHaveCount(0);
    await page.getByRole('link', { name: PAYMENTS.name }).click();
    await expect(page.getByRole('link', { name: 'Access' })).toHaveCount(0);
    await page.getByRole('link', { name: 'All open issues' }).click();
    await expect(page.locator('tbody tr').first()).toBeVisible();
    await page.locator('tbody a').first().click();
    await expect(page.getByRole('region', { name: 'History' })).toBeVisible();
    await expect(
      page.getByText('Your role lets you read this issue, not change its status or severity.'),
    ).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Change' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Resolve' })).toHaveCount(0);
    await expectAccessible(page);
  });

  test('an org admin changes a role to Viewer', async ({ page }) => {
    await signIn(page, OLGA);
    await page.goto('/settings/members');
    await expect(page).toHaveTitle('Members · Qualor');
    // Every edition offers the four roles, with no licence note.
    await expect(page.getByLabel('Role', { exact: true }).locator('option')).toHaveText([
      'Organization admin',
      'Project admin',
      'Maintainer',
      'Viewer',
    ]);
    await expect(page.getByText(/enterprise licence/)).toHaveCount(0);
    const pat = page.getByRole('row', { name: /pat/ });
    await expect(pat.getByLabel('Role of pat')).toHaveValue('project_admin');
    await pat.getByLabel('Role of pat').selectOption({ label: 'Viewer' });
    // The page's own dialog asks (a browser confirm() would fail the guard of fixtures.ts).
    await pat.getByRole('button', { name: 'Change role' }).click();
    const ask = page.getByRole('dialog', { name: 'Change the role' });
    await expect(ask).toContainText('Change the role of pat in Default to Viewer?');
    await ask.getByRole('button', { name: 'Change role' }).click();
    await expect(page.getByRole('status')).toHaveText('pat is now Viewer.');
    await expect(pat.getByLabel('Role of pat')).toHaveValue('viewer');
    await expectAccessible(page);
  });
});
