import { readFileSync } from 'node:fs';
import type { Page } from '@playwright/test';
import { expect, expectAccessible, test } from './fixtures';
import { OLGA, PAYMENTS, SIEM_URL } from './seed-data';

/**
 * Plan 4C (rbac-audit.md §17): the audit screens on the licensed e2e server
 * (`server/scripts/e2e/serve.ts`, the Enterprise plan's features). Since 5B the Members
 * screen and the Access tab are tested on the community server (`roles.spec.ts`); here the seed's
 * last grant, olga's Viewer grant to victor on Payments API (`seedEnterprise`), is what the audit
 * log shows.
 */

async function signIn(page: Page, user: { username: string; password: string }): Promise<void> {
  await page.goto('/login');
  await page.getByLabel('Username').fill(user.username);
  await page.getByLabel('Password').fill(user.password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/projects$/);
}

/** Today in UTC as the date inputs take it. */
function today(): string {
  return new Date().toISOString().slice(0, 10);
}

test.describe('as people other than the instance admin', () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test('an organization admin reads the audit log of its own organization', async ({ page }) => {
    await signIn(page, OLGA);
    await page.goto('/settings/members');
    // An org admin reads the audit log of its own organization, not the audit settings.
    await expect(page.getByRole('link', { name: 'Audit log' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Audit settings' })).toHaveCount(0);
    const events = page.waitForRequest((r) =>
      new URL(r.url()).pathname.endsWith('/api/v0/ee/audit/events'),
    );
    await page.getByRole('link', { name: 'Audit log' }).click();
    expect(new URL((await events).url()).searchParams.get('organizationId')).toMatch(
      /^[0-9a-f-]{36}$/,
    );
    await expect(page.getByRole('row', { name: /project_member\.added/ }).first()).toBeVisible();
    await expect(page.getByRole('button', { name: 'Verify chain' })).toHaveCount(0);
    // The organisation filter (instance admins only); the settings navigation has an Organization group.
    await expect(page.getByRole('combobox', { name: 'Organization' })).toHaveCount(0);
    await expectAccessible(page);
  });
});

test('the instance admin filters the audit log, exports a day and verifies the chain', async ({
  page,
}) => {
  await page.goto('/settings');
  await page.getByRole('link', { name: 'Audit log' }).click();
  await expect(page).toHaveURL(/\/settings\/ee\/audit-log$/);
  await expect(page).toHaveTitle('Audit log · Qualor');

  await page.getByLabel('From (UTC)').fill(today());
  await page.getByLabel('To (UTC, included)').fill(today());
  await page.getByLabel('Actions').fill('project_member.*');
  await page.getByRole('button', { name: 'Show events' }).click();
  const rows = page.locator('tbody tr[data-key]');
  await expect(rows.first()).toBeVisible();
  for (const text of await rows.locator('th code').allTextContents()) {
    expect(text).toMatch(/^project_member\./);
  }
  // Olga's grant to victor on Payments API (the seed's last grant) is the newest.
  const newest = rows.first();
  await expect(newest).toContainText('project_member.added');
  await expect(newest).toContainText('olga');
  await newest.getByRole('button', { name: /Details/ }).click();
  await expect(page.locator('.details-row')).toContainText(PAYMENTS.key);
  await expectAccessible(page);

  // The export is a download the browser writes: JSON Lines with the filters and the day.
  const download = page.waitForEvent('download');
  await page.getByRole('link', { name: 'Export JSON Lines' }).click();
  const file = await (await download).path();
  const lines = readFileSync(file, 'utf8').trim().split('\n');
  expect(lines.length).toBeGreaterThanOrEqual(3);
  for (const line of lines) {
    const record = JSON.parse(line) as { action: string; hash: string; prevHash: string };
    expect(record.action).toMatch(/^project_member\./);
    expect(record.hash).toMatch(/^[0-9a-f]{64}$/);
  }

  await expect(page.locator('#audit-head')).toContainText('Newest event:');
  await page.getByRole('button', { name: 'Verify chain' }).click();
  await expect(page.locator('#audit-verify-result')).toHaveText(
    /^The chain is intact \(\d+ events\)\.$/,
  );
});

test('the instance admin streams the audit log and sees the secret once', async ({ page }) => {
  await page.goto('/settings/ee/audit-settings');
  await expect(page).toHaveTitle('Audit settings · Qualor');
  await expect(page.getByLabel('Keep events for (days)')).toHaveValue('365');

  // Enterprise has audit-log.stream: the stream card is not limited.
  await expect(page.locator('#audit-stream-not-licensed')).toHaveCount(0);
  await page.getByLabel('Stream URL').fill(SIEM_URL);
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('status').first()).toHaveText('Audit settings saved.');
  const secret = page.getByLabel('Stream secret');
  await expect(secret).toHaveValue(/^whsec_[0-9A-Za-z]{32}$/);
  const value = await secret.inputValue();
  await expectAccessible(page);
  await page.getByRole('button', { name: 'Done' }).click();
  await expect(page.getByLabel('Stream secret')).toHaveCount(0);

  // Never again: not after a reload, and not in the page's text.
  await page.reload();
  await expect(page.getByLabel('Stream URL')).toHaveValue(SIEM_URL);
  await expect(page.getByText('A signing secret is set; it is never shown again.')).toBeVisible();
  await expect(page.getByLabel('Stream secret')).toHaveCount(0);
  expect(await page.content()).not.toContain(value);

  await page.getByRole('button', { name: 'Send test' }).click();
  await expect(page.locator('#audit-stream-test')).toContainText(
    'The receiver answered HTTP 204: the test passed.',
  );
});
