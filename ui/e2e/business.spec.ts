import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import type { APIRequestContext, Page } from '@playwright/test';
import { expect, expectAccessible, test } from './fixtures';
import { BUSINESS_URL, DEPENDENCIES, PAYMENTS, PAYMENTS_REPORT_FILE, SIEM_URL } from './seed-data';

/**
 * Plan 5D (rbac-audit.md §14.4, §17; sso-scim.md §4.4, §18): the enterprise server's database
 * served under a Business key (`sso`, `audit-log`, `support-bundle`, `license-policy`, `vuln.priority`, `vuln.alerts`, `sbom`; `server/scripts/e2e/serve.ts`),
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
  expect([...features].sort()).toEqual([
    'audit-log',
    'license-policy',
    'sbom',
    'sso',
    'support-bundle',
    'vuln.alerts',
    'vuln.priority',
  ]);

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

// 4E-1 §4: compliance reports are Enterprise only (`compliance-export`), so the reports the
// enterprise tests made stay in the database but out of sight.
test('the Business plan shows no compliance reports', async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  const tabs = page.getByRole('navigation', { name: 'Project' });
  await expect(tabs.getByRole('link', { name: 'Overview' })).toBeVisible();
  await expect(tabs.getByRole('link', { name: 'Compliance' })).toHaveCount(0);

  await page.goto('/settings/ee/compliance');
  await expect(page).toHaveTitle('Compliance reports · Qualor');
  await expect(page.locator('.settings-head')).toContainText(
    'Compliance reports need an enterprise licence with the compliance-export feature.',
  );
  await expect(page.getByRole('link', { name: 'Compliance reports' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Create report' })).toHaveCount(0);
  await expectAccessible(page);
});

// 4E-2 §4: the portfolio is Enterprise only (`portfolio`): no main-menu entry, and its address
// says so without asking the enterprise API anything.
test('the Business plan has no portfolio', async ({ page }) => {
  const portfolioCalls: string[] = [];
  page.on('request', (r) => {
    const path = new URL(r.url()).pathname;
    if (path.startsWith('/api/v0/ee/portfolio')) portfolioCalls.push(path);
  });
  const info = page.waitForResponse((r) => new URL(r.url()).pathname === '/api/v0/system/info');
  await page.goto('/projects');
  const body = (await (await info).json()) as {
    features: string[];
    extensions: { id: string; point: string }[];
  };
  expect(body.features).not.toContain('portfolio');
  expect(body.extensions.filter((e) => e.point === 'main.nav')).toEqual([]);
  // The plugin's entries come with the system info, as does the version under the user menu:
  // once that is there, the main menu is complete.
  await expect(page.locator('.menu-version')).toBeAttached();
  const nav = page.getByRole('navigation', { name: 'Main' });
  await expect(nav.getByRole('link', { name: 'Quality gates' })).toBeVisible();
  await expect(nav.getByRole('link', { name: 'Portfolio' })).toHaveCount(0);

  await page.goto('/portfolio');
  await expect(page).toHaveTitle('Portfolio · Qualor');
  await expect(page.locator('.page-body')).toHaveText(
    'Portfolio reports need an enterprise licence with the portfolio feature.',
  );
  await expect(page.getByRole('button', { name: 'All organisations' })).toHaveCount(0);
  await expect(page.getByRole('link', { name: 'CSV' })).toHaveCount(0);
  await expectAccessible(page);
  expect(portfolioCalls).toEqual([]);
});

// 4E-3a §2, §4: automatic fix suggestions are Enterprise only (`llm.auto-fix`). The organisation's
// switch-on and the project's opt-out that enterprise.spec.ts saved are kept but not offered: the
// organisation's AI page has no section for them, and its status says they are Enterprise; the
// instance page names no fix suggestions among what the organisation's admins switched on, and
// the project's AI panel has no Fixes line.
test('the Business plan shows no fix suggestions section, and the status says they are Enterprise', async ({
  page,
}) => {
  await page.goto('/settings/auto-fix');
  await expect(page).toHaveURL(/\/settings\/ai-review#fix-suggestions$/);
  await expect(page).toHaveTitle('AI · Qualor');
  await expect(page.locator('li[data-key="community"]')).toHaveText(
    'Automatic fix suggestions are part of Qualor Enterprise.',
  );
  await expect(page.locator('#fix-suggestions')).toHaveCount(0);
  await expect(page.getByLabel('Post fix suggestions automatically')).toHaveCount(0);
  await expect(page.getByRole('navigation', { name: 'On this page' }).getByRole('link')).toHaveText(
    ['AI review', 'Assistant'],
  );
  await expect(page.getByRole('link', { name: 'Automatic fixes' })).toHaveCount(0);
  await expectAccessible(page);

  await page.goto('/settings/ai');
  const row = page.locator('section#organizations tbody tr').filter({ hasText: 'Default' });
  await expect(row).toBeVisible();
  await expect(row.locator('td[data-label="Switched on by its admins"]')).toHaveText('—');

  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  await page
    .getByRole('navigation', { name: 'Project' })
    .getByRole('link', { name: 'Settings' })
    .click();
  const panel = page.locator('section#ai');
  await expect(panel.locator('[data-line="review"]')).toBeVisible();
  await expect(panel.locator('[data-line="fixes"]')).toHaveCount(0);
  await expect(panel.getByRole('switch')).toHaveCount(0);
});

// 4E-3b: the support bundle is a Business feature too (`support-bundle`).
test('a Business admin downloads the support bundle', async ({ page }) => {
  await page.goto('/settings/ee/support');
  await expect(page).toHaveTitle('Support · Qualor');
  await expect(page.getByRole('link', { name: 'Support', exact: true })).toBeVisible();
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('link', { name: 'Download support bundle' }).click(),
  ]);
  expect(download.suggestedFilename()).toMatch(/^qualor-support-\d{8}-\d{6}\.zip$/);
  const archive = readFileSync((await download.path())!);
  expect(archive.subarray(0, 2).toString()).toBe('PK');
  expect(archive.toString('latin1')).toContain('manifest.json');
  await expectAccessible(page);
});

/**
 * 6M: the seed's last report of Payments API's main branch, ingested again as a new analysis (a
 * new revision, today's date) with a project analysis token, as the CLI would upload it; resolves
 * once the server has analysed it.
 */
async function ingestAgain(page: Page, request: APIRequestContext): Promise<void> {
  const me = (await (await page.request.get('/api/v0/auth/me')).json()) as { csrfToken: string };
  const projects = (await (await page.request.get('/api/v0/projects?limit=100')).json()) as {
    items: { id: string; key: string }[];
  };
  const payments = projects.items.find((p) => p.key === PAYMENTS.key);
  expect(payments).toBeDefined();
  const created = await page.request.post(`/api/v0/projects/${payments!.id}/tokens`, {
    headers: { 'x-qualor-csrf': me.csrfToken },
    data: { name: 'licence policy e2e' },
  });
  expect(created.status()).toBe(201);
  const { token } = (await created.json()) as { token: string };

  const report = JSON.parse(readFileSync(PAYMENTS_REPORT_FILE, 'utf8')) as {
    analysisDate: string;
    scm: { revision: string };
  };
  report.analysisDate = new Date().toISOString();
  report.scm.revision = randomBytes(20).toString('hex');
  const upload = await request.post(
    `/api/v0/analyses?projectKey=${encodeURIComponent(PAYMENTS.key)}`,
    {
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/vnd.qualor.report+json',
        'content-encoding': 'gzip',
      },
      data: gzipSync(Buffer.from(JSON.stringify(report), 'utf8')),
    },
  );
  expect(upload.status()).toBe(202);
  const { analysisId } = (await upload.json()) as { analysisId: string };
  await expect
    .poll(
      async () => {
        const res = await request.get(`/api/v0/analyses/${analysisId}`, {
          headers: { authorization: `Bearer ${token}` },
        });
        return ((await res.json()) as { status: string }).status;
      },
      { timeout: 60_000 },
    )
    .toBe('succeeded');
}

// 6M §5, §8: the licence policy is a Business feature (`license-policy`). The admin forbids strong
// copyleft; the Dependencies tab judges the inventory at once, and the next analysis of the branch
// reports the forbidden licence as a Licensing issue on its lockfile line.
test('a Business admin forbids strong copyleft, and the next analysis reports it', async ({
  page,
  playwright,
}) => {
  await page.goto('/settings/license-policy');
  await expect(page).toHaveTitle('Licence policy · Qualor');
  await expect(page.getByRole('link', { name: 'Licence policy' })).toBeVisible();
  await expect(page.getByLabel('Forbid listed licences')).toBeChecked();
  // A group's members show on demand.
  const members = page.locator('#license-policy-members-strong-copyleft');
  await expect(members).toBeHidden();
  await page.getByRole('button', { name: /licences in Strong copyleft$/ }).click();
  await expect(members).toBeVisible();
  await expect(members).toContainText('GPL-3.0-only');
  await page.getByRole('checkbox', { name: 'Strong copyleft' }).check();
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('status').first()).toHaveText(
    "The licence policy was saved. It applies from each project's next analysis.",
  );
  await expect(page.getByRole('button', { name: 'Remove policy' })).toBeVisible();
  await expectAccessible(page);

  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  await page
    .getByRole('navigation', { name: 'Project' })
    .getByRole('link', { name: 'Dependencies' })
    .click();
  const table = page.getByRole('table', { name: 'Dependencies with their licences' });
  await expect(table.getByRole('columnheader', { name: 'Policy' })).toBeVisible();
  const forbidden = table.getByRole('row', {
    name: new RegExp(DEPENDENCIES.strongCopyleft.name),
  });
  await expect(forbidden).toContainText('Forbidden');
  await expect(table.getByRole('row', { name: /dual-licensed-math/ })).toContainText('Allowed');
  await page.getByLabel('Forbidden only').check();
  await expect(table.getByRole('row')).toHaveCount(2);
  await expectAccessible(page);

  const request = await playwright.request.newContext({ baseURL: BUSINESS_URL });
  try {
    await ingestAgain(page, request);
  } finally {
    await request.dispose();
  }

  const { name, version, license } = DEPENDENCIES.strongCopyleft;
  await forbidden.getByRole('link', { name: `Issues of ${name} ${version}` }).click();
  await expect(page).toHaveURL(/\/issues\?.*rule=license:forbidden/);
  const message = `${name} ${version} is licensed ${license}, which the organisation's licence policy forbids (Strong copyleft).`;
  await expect(page.getByRole('link', { name: message, exact: true })).toBeVisible();
  const quality = page.locator('fieldset[data-facet="quality"]');
  await expect(quality.getByText('Licensing')).toBeVisible();
  await quality.getByRole('checkbox', { name: /Licensing/ }).check();
  await expect(page).toHaveURL(/[?&]quality=licensing(&|$)/);
  await expect(page.getByRole('link', { name: message, exact: true })).toBeVisible();
  await expectAccessible(page);

  await page.getByRole('link', { name: message, exact: true }).click();
  await expect(page).toHaveTitle('Issue · Qualor');
  const details = page.locator('dl.details-list');
  await expect(details).toContainText('Licensing');
  await expect(details.getByRole('link', { name: 'package-lock.json:40' })).toBeVisible();
});
