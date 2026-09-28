import { expect, test } from './fixtures';
import { ADMIN, ENTERPRISE_STORAGE_STATE } from './seed-data';

// The licensed server has its own database, so its own admin session (plan 4C).
test('sign in as the admin of the enterprise server', async ({ page }) => {
  await page.goto('/login');
  await page.getByLabel('Username').fill(ADMIN.username);
  await page.getByLabel('Password').fill(ADMIN.password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/projects$/);
  await page.context().storageState({ path: ENTERPRISE_STORAGE_STATE });
});
