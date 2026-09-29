import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { expect, expectAccessible, test } from './fixtures';
import { LICENSE_KEY_FILE } from './seed-data';

/**
 * A key of the right shape, signed with a throwaway Ed25519 key the server does not know: the
 * e2e server's test bundle accepts only its own `test-e2e` key (enterprise.md §4.1, §14.2), so it
 * answers `unknown-key`. The private key lives in this process only.
 */
function foreignKey(): string {
  const { privateKey } = generateKeyPairSync('ed25519');
  const payload = {
    v: 1,
    id: randomUUID(),
    customer: 'E2E Corporation',
    issued: '2026-01-01T00:00:00.000Z',
    expires: '2099-01-01T00:00:00.000Z',
    features: ['llm.fix-quota'],
  };
  const input = `QLK1.test-e2e-foreign.${Buffer.from(JSON.stringify(payload)).toString('base64url')}`;
  return `${input}.${sign(null, Buffer.from(input, 'ascii'), privateKey).toString('base64url')}`;
}

/** A key as a mail client or a PDF hands it over: wrapped, with a no-break and a zero-width space. */
function wrapped(key: string): string {
  const lines = key.match(/.{1,60}/g) ?? [key];
  return `\ufeff${lines.join('\r\n')}\u00a0\u200b\n`;
}

test.describe('the licence page (enterprise.md §11)', () => {
  test('shows the community edition and rejects keys in plain words', async ({ page, guard }) => {
    await page.goto('/settings');
    await page.getByRole('link', { name: 'Licence', exact: true }).click();
    await expect(page).toHaveURL(/\/settings\/license$/);
    await expect(page).toHaveTitle('Licence · Qualor');
    await expect(page.getByText('Community edition', { exact: true })).toBeVisible();
    // The e2e server starts without a key: nothing is saved, so nothing can be removed.
    await expect(page.getByRole('button', { name: 'Remove' })).toHaveCount(0);
    await expectAccessible(page);

    // The server refuses both keys with 422 LICENSE_INVALID; the page explains each.
    guard.allowFailedLoad('/api/v0/license', 422);
    const field = page.getByLabel('Licence key', { exact: true });
    await expect(field).toHaveAttribute('autocomplete', 'off');
    await expect(field).toHaveAttribute('data-1p-ignore', '');
    await field.fill('QLK1.test-e2e.bm9wZQ.AAAA');
    await page.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByRole('alert')).toContainText('not a Qualor licence key');
    // The key is sent once: the field is empty again.
    await expect(field).toHaveValue('');

    // A wrapped key reaches the server whole (the page strips every kind of space), and the
    // server's reason is named: this build does not accept its signing key.
    const request = page.waitForRequest(
      (r) => r.method() === 'PUT' && new URL(r.url()).pathname === '/api/v0/license',
    );
    const key = foreignKey();
    await field.fill(wrapped(key));
    await page.getByRole('button', { name: 'Save' }).click();
    expect((await request).postDataJSON()).toEqual({ key });
    await expect(page.getByRole('alert')).toContainText(
      'This key was signed with a key this version of Qualor does not accept',
    );
    await expect(page.getByText('Community edition', { exact: true })).toBeVisible();
    await expect(page.getByText(key)).toHaveCount(0);
  });

  test('saves a valid key for the next start, then removes it', async ({ page }) => {
    // Signed by the e2e server's test key (server/scripts/e2e/serve.ts); valid, never shown.
    const valid = readFileSync(LICENSE_KEY_FILE, 'utf8').trim();
    await page.goto('/settings/license');
    await expect(page.getByText('Community edition', { exact: true })).toBeVisible();
    await expect(page.getByText('Restart required.')).toHaveCount(0);

    await page.getByLabel('Licence key', { exact: true }).fill(valid);
    await page.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByText('Saved. Restart the server to apply the new key.')).toBeVisible();
    await expect(page.getByText('Restart required.')).toBeVisible();
    // The key applies at the next start: until then the server runs as it did.
    await expect(page.getByText('Community edition', { exact: true })).toBeVisible();
    await expect(page.getByLabel('Licence key', { exact: true })).toHaveValue('');
    await expect(page.getByText(valid)).toHaveCount(0);
    await expectAccessible(page);

    // The page's own dialog asks (a browser confirm() would fail the guard of fixtures.ts).
    await page.getByRole('button', { name: 'Remove' }).click();
    const ask = page.getByRole('dialog', { name: 'Remove the licence key' });
    await expect(ask).toContainText(
      'Remove the saved licence key? At the next start the server runs as the community edition. ' +
        'Nothing is deleted.',
    );
    await ask.getByRole('button', { name: 'Remove' }).click();
    // The server started without a key, so removing the saved one leaves nothing to restart for.
    await expect(page.getByText('Removed. No key is saved in Qualor.')).toBeVisible();
    await expect(page.getByText('Restart required.')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Remove' })).toHaveCount(0);
    await expect(page.getByText('Community edition', { exact: true })).toBeVisible();
  });
});
