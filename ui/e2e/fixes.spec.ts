import type { APIRequestContext } from '@playwright/test';
import { expect, expectAccessible, test } from './fixtures';
import { PAYMENTS, VULNERABILITIES } from './seed-data';

/**
 * 0.16 fix MRs (spec §6.3, §8): an admin allows fix MRs on the seeded GitLab connection, switches
 * them on for a project, and asks for a fix of its `lodash` row on the main branch, then cancels it.
 * No fix job runs here, so the fix stays "Waiting for the fix job".
 *
 * The seeded vulnerabilities belong to Payments API alone (seed.ts writes them straight into the
 * database; a project made by the test would have none), so this spec uses that project. Ruling
 * F17: `afterAll` puts back everything it changed: fixes switched off, the connection's switch off,
 * and any fix of the project cancelled, so no neighbouring spec sees them.
 */
test.describe.configure({ mode: 'serial' });

interface Settings {
  enabled: boolean;
  autoCreate: { minSeverity: string | null; exploited: boolean };
  maxOpen: number;
}

async function csrf(request: APIRequestContext): Promise<Record<string, string>> {
  const me = (await (await request.get('/api/v0/auth/me')).json()) as { csrfToken: string };
  return { 'x-qualor-csrf': me.csrfToken };
}

async function paymentsId(request: APIRequestContext): Promise<string> {
  const answer = await request.get('/api/v0/projects?limit=100');
  const { items } = (await answer.json()) as { items: { id: string; key: string }[] };
  return items.find((p) => p.key === PAYMENTS.key)!.id;
}

test.afterAll(async ({ request }) => {
  const headers = await csrf(request);
  const id = await paymentsId(request);
  // Fixes first: a fix still waiting is cancelled, then the project's switch goes off.
  const list = await request.get(`/api/v0/projects/${id}/fixes`);
  expect(list.ok()).toBe(true);
  const { items } = (await list.json()) as { items: { id: string; state: string }[] };
  for (const fix of items.filter((f) => ['requested', 'preparing', 'open'].includes(f.state))) {
    const cancelled = await request.delete(`/api/v0/fixes/${fix.id}`, { headers });
    expect(cancelled.status()).toBe(202);
  }
  const current = await request.get(`/api/v0/projects/${id}/fixes/settings`);
  const { settings } = (await current.json()) as { settings: Settings };
  const off = await request.put(`/api/v0/projects/${id}/fixes/settings`, {
    headers,
    data: {
      enabled: false,
      autoCreate: {
        minSeverity: settings.autoCreate.minSeverity,
        exploited: settings.autoCreate.exploited,
      },
      maxOpen: settings.maxOpen,
    },
  });
  expect(off.ok()).toBe(true);
  const project = (await (await request.get(`/api/v0/projects/${id}`)).json()) as {
    scmConnectionId: string | null;
  };
  expect(project.scmConnectionId).not.toBeNull();
  const connection = await request.patch(`/api/v0/scm-connections/${project.scmConnectionId}`, {
    headers,
    data: { fixMrsAllowed: false },
  });
  expect(connection.ok()).toBe(true);
});

test('an admin allows fix MRs on the GitLab connection', async ({ page }) => {
  await page.goto('/settings/gitlab');
  await expect(page).toHaveTitle('GitLab · Qualor');
  const allow = page.getByRole('switch', { name: /Allow fix MRs/ });
  await expect(allow).not.toBeChecked();
  await allow.check();
  await expect(page.getByRole('status')).toContainText('Fix MRs are on for');
  await expect(allow).toBeChecked();
});

test('the project switches fix MRs on and waits for the fix job', async ({ page, request }) => {
  await page.goto(`/projects/${await paymentsId(request)}/settings`);
  const panel = page.locator('section#fixes');
  await expect(panel.getByRole('heading', { name: 'Fix MRs' })).toBeVisible();
  const enabled = panel.getByRole('switch', { name: 'Enabled', exact: true });
  await enabled.check();
  await panel.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(panel.getByRole('status')).toHaveText(/Saved/);
  await expect(panel.getByText('Waiting for the fix job', { exact: true })).toBeVisible();
  await expect(panel.getByText('0 open, 0 of 5 in progress')).toBeVisible();
  await expectAccessible(page);
});

test('a fix is requested from the main branch and cancelled', async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  await page
    .getByRole('navigation', { name: 'Project' })
    .getByRole('link', { name: 'Vulnerabilities' })
    .click();
  await expect(page).toHaveTitle('Vulnerabilities · Qualor');
  await page.getByRole('row', { name: /main/ }).getByRole('link', { name: 'main' }).click();
  const lodash = page.getByRole('listitem').filter({ hasText: VULNERABILITIES.high.id });
  await expect(lodash).toBeVisible();

  await lodash.getByRole('button', { name: 'Create fix MR for lodash' }).click();
  await expect(lodash.getByText('Waiting for the fix job', { exact: true })).toBeVisible();
  await expect(page.locator('.vuln-fixes')).toHaveText('1 of 5 fix MRs in progress');
  await expectAccessible(page);

  await lodash.getByRole('button', { name: 'Cancel the fix MR for lodash' }).click();
  const ask = page.getByRole('dialog', { name: 'Cancel the fix MR' });
  await ask.getByRole('button', { name: 'Cancel the fix' }).click();
  await expect(
    lodash.getByRole('button', { name: 'Create again: the fix MR for lodash' }),
  ).toBeVisible();
  await expect(page.locator('.vuln-fixes')).toHaveText('0 of 5 fix MRs in progress');
  await expectAccessible(page);
});
