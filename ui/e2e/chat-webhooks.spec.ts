import { expect, expectAccessible, test } from './fixtures';
import { CHAT_URL } from './seed-data';

/**
 * 6G spec §7: an organisation admin adds a Slack webhook in Settings → Webhooks and sends a test
 * message. The served community server accepts the fake receiver's host for chat kinds
 * (QUALOR_CHAT_TEST_HOSTS, R7) and has QUALOR_PUBLIC_URL set, so no warning shows.
 */
test('a Slack webhook: create, masked in the list, Send test reaches the receiver', async ({
  page,
  request,
}) => {
  await page.goto('/settings/webhooks');
  await expect(page.getByRole('heading', { level: 2, name: 'Webhooks' })).toBeVisible();
  await page.getByRole('button', { name: 'New webhook' }).click();
  const dialog = page.getByRole('dialog', { name: 'New webhook' });
  await dialog.getByRole('radio', { name: 'Slack' }).check();
  await expect(dialog.getByRole('link', { name: 'How to get a Slack webhook URL' })).toBeVisible();
  // The exploited-vulnerability event needs `vuln.alerts` (Business, business.spec.ts).
  await expect(dialog.getByRole('checkbox', { name: 'Weekly security digest' })).toBeVisible();
  await expect(dialog.getByText('Exploited vulnerabilities (at once)')).toHaveCount(0);
  await expect(dialog.getByText('QUALOR_PUBLIC_URL is not set')).toHaveCount(0);
  await dialog.getByLabel('URL').fill(`${CHAT_URL}/services/T0E2E/B0E2E/e2eSecretPart9876`);
  await dialog.getByLabel('Time zone of the weekly digest (Monday 09:00)').fill('Europe/Berlin');
  await expectAccessible(page);
  await dialog.getByRole('button', { name: 'Add webhook' }).click();
  await expect(page.getByText('Webhook added.')).toBeVisible();

  const panel = page
    .locator('section.panel', { has: page.locator('.webhook-kind', { hasText: 'Slack' }) })
    .last();
  await expect(panel.locator('.webhook-url')).toContainText('/…/9876');
  await expect(panel.locator('.webhook-url')).not.toContainText('e2eSecretPart');
  await expect(panel.getByRole('button', { name: 'Rotate secret' })).toHaveCount(0);

  await panel.getByRole('button', { name: 'Send test' }).click();
  await expect(page.getByText(/^Test message queued\./)).toBeVisible();
  await expect
    .poll(async () => (await request.get(`${CHAT_URL}/last`)).status(), { timeout: 15_000 })
    .toBe(200);
  const body = (await (await request.get(`${CHAT_URL}/last`)).json()) as { text: string };
  expect(body.text).toBe('Qualor is connected');
  // Opening "Recent deliveries" reads them again (openDeliveries).
  await panel.locator('summary', { hasText: 'Recent deliveries' }).click();
  await expect(panel.getByRole('cell', { name: 'Test message' })).toBeVisible();
  await expect(panel.locator('.delivery-result', { hasText: 'Delivered' })).toBeVisible({
    timeout: 15_000,
  });
});
