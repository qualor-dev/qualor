import { expect, expectAccessible, test } from './fixtures';
import { SIEM_URL } from './seed-data';

/**
 * Plan 5D (rbac-audit.md §14.4, §17; sso-scim.md §4.4, §18): the enterprise server's database
 * served under a Business key (`sso`, `audit-log`, `llm.fix-quota`; `server/scripts/e2e/serve.ts`),
 * after the enterprise tests. The stream enterprise.spec.ts configured is kept and paused: its
 * fields and buttons are disabled with the reason, Save sends retention alone, and Remove under
 * Stream status deletes it (the guide's steps, docs/guide/roles-and-audit.md).
 */

test('a Business admin sees the kept stream paused and saves retention without it', async ({
  page,
}) => {
  const info = page.waitForResponse((r) => new URL(r.url()).pathname === '/api/v0/system/info');
  await page.goto('/settings/ee/audit-settings');
  await expect(page).toHaveTitle('Audit settings · Qualor');
  const features = ((await (await info).json()) as { features: string[] }).features;
  expect([...features].sort()).toEqual(['audit-log', 'llm.fix-quota', 'sso']);

  await expect(page.locator('#audit-stream-not-licensed')).toHaveText(
    'Streaming the audit log to a SIEM needs the Enterprise plan.',
  );
  await expect(page.getByLabel('Stream URL')).toHaveValue(SIEM_URL);
  await expect(page.getByLabel('Stream URL')).toBeDisabled();
  await expect(page.locator('#audit-stream-active')).toBeDisabled();
  await expect(page.locator('#audit-stream-paused')).toContainText(
    'The stream is paused: streaming the audit log to a SIEM needs the Enterprise plan.',
  );
  await expect(page.getByRole('button', { name: 'Send test' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Regenerate the secret' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Remove' })).toBeVisible();
  await expectAccessible(page);

  const put = page.waitForRequest(
    (r) => r.method() === 'PUT' && new URL(r.url()).pathname === '/api/v0/ee/audit/settings',
  );
  await page.getByLabel('Keep events for (days)').fill('400');
  await page.getByRole('button', { name: 'Save' }).click();
  expect((await put).postDataJSON()).toEqual({ retentionDays: 400 });
  await expect(page.getByRole('status').first()).toHaveText('Audit settings saved.');
  // The stream is still kept.
  await expect(page.locator('#audit-stream-status')).toBeVisible();
});

test('a Business admin removes the kept stream under Stream status', async ({ page }) => {
  await page.goto('/settings/ee/audit-settings');
  await expect(page.locator('#audit-stream-status')).toBeVisible();
  // The page's own dialog asks (a browser confirm() would fail the guard of fixtures.ts).
  await page.getByRole('button', { name: 'Remove' }).click();
  const ask = page.getByRole('dialog', { name: 'Remove the SIEM stream' });
  await expect(ask).toContainText(
    'Remove the SIEM stream? Events are no longer sent; they stay in the audit log.',
  );
  await ask.getByRole('button', { name: 'Remove' }).click();
  await expect(page.locator('#audit-stream-status')).toHaveCount(0);
  await expect(page.getByLabel('Stream URL')).toHaveValue('');
  await page.reload();
  await expect(page.locator('#audit-stream-status')).toHaveCount(0);
});

test('the Single sign-on screen says the Business plan signs in through one connection', async ({
  page,
}) => {
  await page.goto('/settings/ee/sso');
  await expect(page).toHaveTitle('Single sign-on · Qualor');
  await expect(page.locator('#sso-multi-not-licensed')).toHaveText(
    'Your plan signs people in through one single sign-on connection at a time. Connecting several identity providers needs the Enterprise plan.',
  );
  await expect(page.locator('#sso-count')).toHaveCount(0);
  await expectAccessible(page);
});
