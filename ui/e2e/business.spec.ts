import { createHmac, hkdfSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { Page } from '@playwright/test';
import { expect, expectAccessible, test } from './fixtures';
import { ingestAgain, paymentsReport, projectId } from './report';
import {
  BUSINESS_URL,
  CHAT_URL,
  DEPENDENCIES,
  JIRA_PROJECT,
  JIRA_TOKEN,
  JIRA_URL,
  PAYMENTS,
  SIEM_URL,
} from './seed-data';

/**
 * Plan 5D (rbac-audit.md §14.4, §17; sso-scim.md §4.4, §18): the enterprise server's database
 * served under a Business key (`sso`, `audit-log`, `support-bundle`, `license-policy`,
 * `vuln.priority`, `vuln.alerts`, `sbom`; `server/scripts/e2e/serve.ts`), after the enterprise
 * tests. The stream enterprise.spec.ts configured is kept and paused: its fields and buttons are
 * disabled with the reason, Save sends retention alone, and Remove under Stream status deletes it
 * (the guide's steps, docs/guide/roles-and-audit.md).
 */

/** D26-2: the branch the empty-inventory test analyses (no other test knows it). */
const EMPTY_BRANCH = 'e2e-no-deps';

/**
 * The QUALOR_SECRET_KEY all e2e servers share (server/scripts/e2e/serve.ts), built at run time as
 * notifications.spec.ts does: Gitleaks scans the repository (tools/deploy/gitleaks.test.ts), and
 * the allowlist pins the literal to serve.ts alone.
 */
const E2E_SECRET_KEY = `e2e-secret-key-${'that-is-at-least-32-characters-long'}`;

/**
 * 4b: a vulnerability email's stop-link token, made as server/src/notifications/unsubscribe.ts
 * makes it (the UI's tests never import server code): base64url("<userId>") "."
 * base64url(HMAC-SHA256 under HKDF-SHA256(secret, salt "qualor", info "unsubscribe vulnerabilities
 * v1")). The server's unit tests pin the algorithm; if the two drift, the stop step fails.
 */
function vulnerabilityUnsubscribeToken(userId: string): string {
  const key = Buffer.from(
    hkdfSync('sha256', E2E_SECRET_KEY, 'qualor', 'unsubscribe vulnerabilities v1', 32),
  );
  const payload = Buffer.from(userId, 'utf8').toString('base64url');
  return `${payload}.${createHmac('sha256', key).update(payload).digest('base64url')}`;
}

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
// instance page names no fix suggestions among what the organisation's admins switched on, and the
// project's AI panel has no Fixes line.
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

function paymentsId(page: Page): Promise<string> {
  return projectId(page.request, PAYMENTS.key);
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
    await ingestAgain(page.request, request, PAYMENTS.key, paymentsReport());
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

// D25-1: the seed turned the server's monitoring switch off (seedVulndbOff), and nothing here turns
// it on: the tab says it is the server's switch, and shows an instance admin where it is.
test('a Business server answers the Vulnerabilities tab with priority on', async ({ page }) => {
  const payments = await paymentsId(page);
  const targets = await page.request.get(`/api/v0/projects/${payments}/vulnerabilities/targets`);
  expect(targets.status()).toBe(200);
  const summary = (await targets.json()) as { priority: boolean; offBy: string | null };
  expect(summary.priority).toBe(true);
  expect(summary.offBy).toBe('instance');

  await page.goto(`/projects/${payments}/vulnerabilities`);
  await expect(
    page.getByText('Vulnerability monitoring is turned off for this server.', { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole('link', { name: 'Settings → Vulnerability database', exact: true }),
  ).toHaveAttribute('href', '/settings/vulnerability-db');
  await expectAccessible(page);
});

// D27-1: the project's Vulnerability monitoring panel says the same, and offers no way to the tab.
test("a Business project's settings say the server's monitoring is off", async ({ page }) => {
  await page.goto(`/projects/${await paymentsId(page)}/settings`);
  const panel = page.locator('section#vulnerabilities');
  await expect(
    panel.getByRole('heading', { name: 'Vulnerability monitoring', exact: true }),
  ).toBeVisible();
  await expect(
    panel.getByText('Vulnerability monitoring is turned off for this server.', { exact: true }),
  ).toBeVisible();
  await expect(panel.getByRole('link', { name: 'Manage in Vulnerabilities' })).toHaveCount(0);
});

// D26-1: Export SBOM on the Dependencies tab downloads the branch shown.
test('a Business admin downloads the SBOM from the Dependencies tab', async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  await page
    .getByRole('navigation', { name: 'Project' })
    .getByRole('link', { name: 'Dependencies' })
    .click();
  await expect(page.locator('.deps-summary')).toBeVisible();
  await page.getByRole('button', { name: 'Export SBOM', exact: true }).click();
  const menu = page.getByRole('group', { name: 'Export SBOM', exact: true });
  const cyclonedx = menu.getByRole('link', { name: 'CycloneDX 1.6 (JSON)', exact: true });
  await expect(cyclonedx).toHaveAttribute('href', /[?&]branch=main&format=cyclonedx$/);
  await expectAccessible(page);
  const [download] = await Promise.all([page.waitForEvent('download'), cyclonedx.click()]);
  const bom = JSON.parse(readFileSync((await download.path())!, 'utf8')) as { bomFormat: string };
  expect(bom.bomFormat).toBe('CycloneDX');
});

// D26-2 (C-v): a branch whose analysis found no package, made here rather than in the shared seed
// (a seeded branch would move the branch lists and counts other tests pin). An empty list is an
// inventory: the tab says it is empty and still exports it. The branch and its token stay on
// purpose: the Business project runs last, on a database of its own.
test('a branch with an empty inventory says it has no packages and exports its SBOM', async ({
  page,
  playwright,
}) => {
  const report = paymentsReport();
  const request = await playwright.request.newContext({ baseURL: BUSINESS_URL });
  try {
    await ingestAgain(page.request, request, PAYMENTS.key, {
      ...report,
      scm: { ...report.scm, branch: EMPTY_BRANCH },
      dependencies: [],
    });
  } finally {
    await request.dispose();
  }

  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  await page
    .getByRole('navigation', { name: 'Project' })
    .getByRole('link', { name: 'Dependencies' })
    .click();
  await expect(page.locator('.deps-summary')).toBeVisible();
  await page.getByLabel('Branch').selectOption({ label: EMPTY_BRANCH });
  await expect(page.getByText('This branch or version has no packages.')).toBeVisible();
  await page.getByRole('button', { name: 'Export SBOM', exact: true }).click();
  await expect(
    page
      .getByRole('group', { name: 'Export SBOM', exact: true })
      .getByRole('link', { name: 'CycloneDX 1.6 (JSON)', exact: true }),
  ).toHaveAttribute('href', new RegExp(`[?&]branch=${EMPTY_BRANCH}&format=cyclonedx$`));
  await expectAccessible(page);
});

test('a Business server exports the SBOM of a project with an inventory', async ({ page }) => {
  const key = encodeURIComponent(PAYMENTS.key);
  const cyclonedx = await page.request.get(`/api/v0/projects/sbom?projectKey=${key}`);
  expect(cyclonedx.status()).toBe(200);
  expect(((await cyclonedx.json()) as { bomFormat: string }).bomFormat).toBe('CycloneDX');
  const spdx = await page.request.get(`/api/v0/projects/sbom?projectKey=${key}&format=spdx`);
  expect(spdx.status()).toBe(200);
  expect(((await spdx.json()) as { spdxVersion: string }).spdxVersion).toBe('SPDX-2.3');
});

// 6-15 (D28-3): a chat webhook offers the exploited-vulnerability event with `vuln.alerts`. The
// licensed servers accept the fake Slack receiver's host too (QUALOR_CHAT_TEST_HOSTS, serve.ts);
// nothing is posted to it until such an event. The test removes its webhook.
test('a Business admin creates a Slack webhook for exploited vulnerabilities', async ({ page }) => {
  await page.goto('/settings/webhooks');
  await expect(page.getByRole('heading', { level: 2, name: 'Webhooks' })).toBeVisible();
  await page.getByRole('button', { name: 'New webhook' }).click();
  const dialog = page.getByRole('dialog', { name: 'New webhook' });
  await dialog.getByRole('radio', { name: 'Slack' }).check();
  await dialog.getByLabel('URL').fill(`${CHAT_URL}/services/T0E2E/B0E2E/e2eExploitedPart4321`);
  const exploited = dialog.getByRole('checkbox', { name: 'Exploited vulnerabilities (at once)' });
  await exploited.check();
  await expect(exploited).toBeChecked();
  const created = page.waitForResponse(
    (r) => r.request().method() === 'POST' && new URL(r.url()).pathname === '/api/v0/webhooks',
  );
  await dialog.getByRole('button', { name: 'Add webhook' }).click();
  const answer = await created;
  expect(answer.status()).toBe(201);
  const webhook = (await answer.json()) as { id: string; organizationId: string };
  const me = (await (await page.request.get('/api/v0/auth/me')).json()) as { csrfToken: string };
  try {
    await expect(page.getByText('Webhook added.')).toBeVisible();
    const list = await page.request.get(
      `/api/v0/webhooks?organizationId=${webhook.organizationId}`,
    );
    const { items } = (await list.json()) as { items: { id: string; events: string[] }[] };
    expect(items.find((w) => w.id === webhook.id)?.events).toContain('vulnerabilities.exploited');
  } finally {
    const removed = await page.request.delete(`/api/v0/webhooks/${webhook.id}`, {
      headers: { 'x-qualor-csrf': me.csrfToken },
    });
    expect(removed.status()).toBe(204);
  }
});

// 4ab#71 (D28-4): the fourth Watch box and the stop link of a vulnerability email, which turns
// that box off on every watch of the user and keeps the watches. The test removes its watch.
test('a Business user stops vulnerability emails from the link', async ({ page }) => {
  const me = (await (await page.request.get('/api/v0/auth/me')).json()) as {
    user: { id: string };
    csrfToken: string;
  };
  const headers = { 'x-qualor-csrf': me.csrfToken };
  const projectId = await paymentsId(page);
  const watch = async () =>
    (await (await page.request.get(`/api/v0/projects/${projectId}/watch`)).json()) as {
      watching: boolean;
      events: { newVulnerabilities: boolean };
    };
  // An earlier, interrupted run may have left the watch.
  await page.request.delete(`/api/v0/projects/${projectId}/watch`, { headers });
  try {
    await page.goto(`/projects/${projectId}`);
    await page.getByRole('button', { name: 'Watch', exact: true }).click();
    const menu = page.getByRole('group', { name: 'Email notifications for this project' });
    const box = menu.getByRole('checkbox', { name: 'New vulnerabilities in tracked versions' });
    await box.check();
    await expect(box).toBeChecked();
    await expect.poll(async () => (await watch()).events.newVulnerabilities).toBe(true);

    await page.goto(`/unsubscribe/vulnerabilities#t=${vulnerabilityUnsubscribeToken(me.user.id)}`);
    await expect(page.getByRole('heading', { name: 'Stop vulnerability emails?' })).toBeVisible();
    await expectAccessible(page);
    await page.getByRole('button', { name: 'Stop emails' }).click();
    await expect(page.getByText('You no longer get vulnerability emails.')).toBeVisible();
    expect(await watch()).toMatchObject({
      watching: true,
      events: { newVulnerabilities: false },
    });
  } finally {
    await page.request.delete(`/api/v0/projects/${projectId}/watch`, { headers });
  }
});

// 0.16 Jira (spec §6.2, §6.11): the automatic rule's exploited option needs `vuln.priority`, which
// the Business plan has. The connection to the fake Jira (serve.ts) and Payments API's mapping are
// made through the API; the panel then offers the option, and saving it answers 200. The test
// removes the connection, and with it the mapping.
test('a Business project turns on Jira issues for exploited vulnerabilities', async ({
  page,
  request,
}) => {
  const me = (await (await request.get('/api/v0/auth/me')).json()) as { csrfToken: string };
  const headers = { 'x-qualor-csrf': me.csrfToken };
  const orgs = (await (await request.get('/api/v0/organizations')).json()) as {
    items: { id: string }[];
  };
  const organizationId = orgs.items[0]!.id;
  const payments = await projectId(request, PAYMENTS.key);
  const connected = await request.put(`/api/v0/organizations/${organizationId}/jira`, {
    headers,
    data: { deployment: 'data_center', siteUrl: JIRA_URL, token: JIRA_TOKEN },
  });
  expect(connected.status()).toBe(200);
  try {
    const mapped = await request.put(`/api/v0/projects/${payments}/jira`, {
      headers,
      data: {
        jiraProject: { id: JIRA_PROJECT.id, key: JIRA_PROJECT.key, name: JIRA_PROJECT.name },
        issueType: { id: JIRA_PROJECT.bug, name: 'Bug' },
        labels: [],
        priorities: null,
        autoCreate: { minSeverity: null, exploited: false },
      },
    });
    expect(mapped.status()).toBe(200);

    await page.goto(`/projects/${payments}/settings`);
    const panel = page.locator('section#jira');
    const exploited = panel.getByRole('switch', { name: 'Exploited vulnerabilities (CISA KEV)' });
    await expect(exploited).toBeEnabled();
    await exploited.check();
    const saved = page.waitForResponse(
      (r) =>
        r.request().method() === 'PUT' &&
        new URL(r.url()).pathname === `/api/v0/projects/${payments}/jira`,
    );
    await panel.getByRole('button', { name: 'Save' }).click();
    expect((await saved).status()).toBe(200);
    await expect(panel.getByRole('status')).toHaveText('Saved.');
    await expect(exploited).toBeChecked();
  } finally {
    const removed = await request.delete(`/api/v0/organizations/${organizationId}/jira`, {
      headers,
    });
    expect(removed.status()).toBe(204);
  }
});
