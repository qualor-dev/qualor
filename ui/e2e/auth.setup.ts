import { expect, test } from './fixtures';
import { ADMIN, STORAGE_STATE } from './seed-data';

// One sign-in for the whole run (the login is rate-limited to 10 per minute and IP, api.md §2).
test('sign in as the admin', async ({ page }) => {
  await page.goto('/login');
  await page.getByLabel('Username').fill(ADMIN.username);
  await page.getByLabel('Password').fill(ADMIN.password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/projects$/);
  await page.context().storageState({ path: STORAGE_STATE });
});
