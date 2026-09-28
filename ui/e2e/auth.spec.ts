import { expect, expectAccessible, test } from './fixtures';
import { ADMIN, ALICE } from './seed-data';

test.describe('signed out', () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test('a deep link asks to sign in, keyboard only, and returns to the page', async ({ page }) => {
    await page.goto('/gates');
    await expect(page).toHaveURL(/\/login\?returnUrl=%2Fgates$/);
    await expect(page).toHaveTitle('Sign in · Qualor');
    await expectAccessible(page);
    await page.keyboard.press('Tab');
    await expect(page.getByLabel('Username')).toBeFocused();
    await page.keyboard.type(ADMIN.username);
    await page.keyboard.press('Tab');
    await page.keyboard.type(ADMIN.password);
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/\/gates$/);
  });

  test('a wrong password is refused with an alert', async ({ page, guard }) => {
    // The refused sign-in answers 401, which the browser logs; the alert is what the user sees.
    guard.allowFailedLoad('/api/v0/auth/login', 401);
    await page.goto('/login');
    await page.getByLabel('Username').fill(ADMIN.username);
    await page.getByLabel('Password').fill('not the password');
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.getByRole('alert')).toHaveText('Invalid username or password.');
  });

  test('an account the admin created must change its password first (ruling R7)', async ({
    page,
  }) => {
    await page.goto('/login');
    await page.getByLabel('Username').fill(ALICE.username);
    await page.getByLabel('Password').fill(ALICE.initialPassword);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page).toHaveURL(/\/change-password$/);
    await expect(page.getByRole('status')).toContainText('An administrator set your password');
    await expectAccessible(page);
    // Nothing else is reachable before the change.
    await page.goto('/projects');
    await expect(page).toHaveURL(/\/change-password$/);
    await page.getByLabel('Current password').fill(ALICE.initialPassword);
    await page.getByLabel('New password', { exact: true }).fill(ALICE.newPassword);
    await page.getByLabel('Repeat the new password').fill(ALICE.newPassword);
    await page.getByRole('button', { name: 'Change password' }).click();
    await expect(page).toHaveURL(/\/projects$/);
  });

  test('signing out ends the session', async ({ page }) => {
    await page.goto('/login');
    await page.getByLabel('Username').fill(ADMIN.username);
    await page.getByLabel('Password').fill(ADMIN.password);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page).toHaveURL(/\/projects$/);
    await page.getByRole('button', { name: 'Sign out' }).click();
    await expect(page).toHaveURL(/\/login$/);
    await page.goto('/projects');
    await expect(page).toHaveURL(/\/login\?returnUrl=%2Fprojects$/);
  });
});

test.describe('signed in', () => {
  test('a page loaded without a valid session asks to sign in again', async ({ page, guard }) => {
    // The session probe of the reload answers 401: the cookie is gone on purpose.
    guard.allowFailedLoad('/api/v0/auth/me', 401);
    await page.goto('/gates');
    await expect(page.getByRole('navigation', { name: 'Main' })).toBeVisible();
    // Wait for the gates list too: a request still in flight when the cookie goes would get the
    // 401 before the reload does (a race of the test, not of the app).
    await expect(page.getByRole('row', { name: /Qualor way/ })).toBeVisible();
    await page.context().clearCookies();
    await page.reload();
    await expect(page).toHaveURL(/\/login\?returnUrl=%2Fgates$/);
  });

  test('the page is served with a nonce CSP and the security headers (api.md §4)', async ({
    page,
  }) => {
    const response = await page.goto('/projects');
    const headers = response?.headers() ?? {};
    const nonce = /script-src 'self' 'nonce-([A-Za-z0-9+/]+=*)'/.exec(
      headers['content-security-policy'] ?? '',
    )?.[1];
    expect(nonce).toBeDefined();
    expect(headers['content-security-policy']).toContain(`style-src 'self' 'nonce-${nonce}'`);
    expect(headers['content-security-policy']).not.toContain('unsafe');
    expect(headers['x-content-type-options']).toBe('nosniff');
    expect(headers['x-frame-options']).toBe('DENY');
    expect(headers['referrer-policy']).toBe('no-referrer');
    expect(headers['cache-control']).toBe('no-store');
    // Component styles arrive as nonce'd <style> elements, which the policy allows.
    await expect(page.getByRole('navigation', { name: 'Main' })).toBeVisible();
    const nonces = await page.locator('style[nonce]').count();
    expect(nonces).toBeGreaterThan(0);
  });

  test('the content-hashed scripts of the build are cached as immutable', async ({ page }) => {
    const scripts: { path: string; cacheControl: string | undefined }[] = [];
    page.on('response', (response) => {
      const path = new URL(response.url()).pathname;
      if (/^\/(?:main|chunk)-[^/]+\.js$/.test(path)) {
        scripts.push({ path, cacheControl: response.headers()['cache-control'] });
      }
    });
    await page.goto('/projects');
    await expect(page.getByRole('navigation', { name: 'Main' })).toBeVisible();
    // main plus the chunks of the shell and the projects page (Angular 22 names like chunk-7S2tK-6Y.js).
    expect(scripts.length).toBeGreaterThan(1);
    for (const script of scripts) {
      expect(script, script.path).toEqual({
        path: script.path,
        cacheControl: 'public, max-age=31536000, immutable',
      });
    }
  });
});
