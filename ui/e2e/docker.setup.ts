import { DOCKER_STORAGE_STATE } from './docker-seed';
import { expect, test } from './fixtures';

// Plan 1G: one sign-in as the dockerized server's bootstrap admin, whose generated password
// tools/deploy/screenshots.ts passes in the environment.
test('sign in to the dockerized server', async ({ page }) => {
  const password = process.env['QUALOR_DOCKER_ADMIN_PASSWORD'];
  if (!password) throw new Error('QUALOR_DOCKER_ADMIN_PASSWORD is not set');
  await page.goto('/login');
  await page.getByLabel('Username').fill('admin');
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/projects$/);
  await page.context().storageState({ path: DOCKER_STORAGE_STATE });
});
