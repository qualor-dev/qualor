import type { APIRequestContext } from '@playwright/test';
import { expect, expectAccessible, test } from './fixtures';
import { ingestAgain, paymentsReport } from './report';
import { JIRA_PROJECT, JIRA_TOKEN, JIRA_URL } from './seed-data';

/**
 * 0.16 Jira (spec §6.9, §9): the organisation connects the fake Jira Data Center serve.ts runs
 * (QUALOR_JIRA_INTERNAL_HOSTS lists it), a project of its own is mapped to the Jira project QUAL,
 * and its issues get Jira issues: one from the issue page, two from the Issues list's bulk bar.
 * The sync pass reads a status changed in Jira and comments on the Jira issue of a finding the
 * next analysis no longer reports; a PUT of the connection with its token runs the waiting pass at
 * once (plan ruling R5), so no test waits 15 minutes.
 *
 * The project gets the seed's last report of Payments API's main branch. It is deleted after the
 * tests, and the connection removed, so no other spec sees the connection, the links or the
 * closed issue.
 */
const PROJECT = { key: 'jira-e2e', name: 'Jira E2E' };
/** The issue that gets QUAL-1 from its page, and that the next analysis no longer reports. */
const LINKED = 'Unexpected console statement.';
/** The issues the bulk bar sends to Jira. */
const BULK = [
  "'refundCap' is assigned a value but never used.",
  "'rounding' is defined but never used.",
];
/** How long a create job or a sync pass, and the page's reading of its result, may take. */
const JOB_TIMEOUT = 30_000;

async function csrf(request: APIRequestContext): Promise<Record<string, string>> {
  const me = (await (await request.get('/api/v0/auth/me')).json()) as { csrfToken: string };
  return { 'x-qualor-csrf': me.csrfToken };
}

test.describe.serial('Jira', () => {
  let organizationId = '';
  let projectId = '';
  /** The page of the issue that gets QUAL-1. */
  let linkedIssueUrl = '';

  /** R5: the connection saved again with its token; the organisation's sync pass runs now. */
  async function syncNow(request: APIRequestContext): Promise<void> {
    const saved = await request.put(`/api/v0/organizations/${organizationId}/jira`, {
      headers: await csrf(request),
      data: { deployment: 'data_center', siteUrl: JIRA_URL, token: JIRA_TOKEN },
    });
    expect(saved.status()).toBe(200);
  }

  test.beforeAll(async ({ request, playwright, baseURL }) => {
    const headers = await csrf(request);
    const orgs = (await (await request.get('/api/v0/organizations')).json()) as {
      items: { id: string }[];
    };
    organizationId = orgs.items[0]!.id;
    const created = await request.post('/api/v0/projects', {
      headers,
      data: { organizationId, key: PROJECT.key, name: PROJECT.name },
    });
    expect(created.status()).toBe(201);
    projectId = ((await created.json()) as { id: string }).id;
    const upload = await playwright.request.newContext({ baseURL });
    try {
      await ingestAgain(request, upload, PROJECT.key, paymentsReport());
    } finally {
      await upload.dispose();
    }
  });

  test.afterAll(async ({ request }) => {
    const headers = await csrf(request);
    // The connection takes the mapping and the links with it; none if the first test failed.
    const removed = await request.delete(`/api/v0/organizations/${organizationId}/jira`, {
      headers,
    });
    expect([204, 404]).toContain(removed.status());
    if (!projectId) return;
    const deleted = await request.delete(
      `/api/v0/projects/${projectId}?confirm=${encodeURIComponent(PROJECT.key)}`,
      { headers },
    );
    expect(deleted.status()).toBe(204);
  });

  test('an organisation admin connects Jira Data Center and tests it', async ({ page }) => {
    await page.goto('/settings/jira');
    await expect(page).toHaveTitle('Jira · Qualor');
    await page.getByRole('radio', { name: /^Jira Data Center or Server/ }).check();
    await page.getByLabel('Address', { exact: true }).fill(JIRA_URL);
    await page.getByLabel('Personal access token').fill(JIRA_TOKEN);
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(
      page.getByText('Jira connection saved. Test it to check the token.'),
    ).toBeVisible();
    await page.getByRole('button', { name: 'Test', exact: true }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Connected as' })).toHaveText(
      'Connected as Qualor Service; 1 project visible',
    );
    await expectAccessible(page);
  });

  test('the project is mapped to a Jira project and an issue type it can create', async ({
    page,
  }) => {
    await page.goto(`/projects/${projectId}/settings`);
    const panel = page.locator('section#jira');
    await panel.getByLabel('Jira project').fill(JIRA_PROJECT.key);
    await panel
      .getByRole('button', { name: `${JIRA_PROJECT.key} · ${JIRA_PROJECT.name}`, exact: true })
      .click();
    const type = panel.getByLabel('Jira issue type');
    const story = type.getByRole('option', { name: /^Story/ });
    await expect(story).toHaveText('Story — needs: Components');
    await expect(story).toBeDisabled();
    await type.selectOption({ label: 'Bug' });
    // The exploited option needs `vuln.priority`, which the Community edition has not.
    await expect(
      panel.getByRole('switch', { name: 'Exploited vulnerabilities (CISA KEV)' }),
    ).toBeDisabled();
    await panel.getByRole('button', { name: 'Save' }).click();
    await expect(panel.getByRole('status')).toHaveText('Saved.');
    await expectAccessible(page);
  });

  test('an issue gets a Jira issue from its page', async ({ page }) => {
    await page.goto(`/projects/${projectId}/issues`);
    await page.getByRole('link', { name: LINKED, exact: true }).click();
    await expect(page).toHaveTitle('Issue · Qualor');
    linkedIssueUrl = page.url();
    const card = page.getByRole('region', { name: 'Jira' });
    await card.getByRole('button', { name: 'Create Jira issue' }).click();
    await expect(card.getByRole('status')).toHaveText('Creating…');
    // The page reads the issue again every 3 s while its link is pending (R22).
    const key = card.getByRole('link', { name: 'QUAL-1', exact: true });
    await expect(key).toBeVisible({ timeout: JOB_TIMEOUT });
    await expect(key).toHaveAttribute('href', `${JIRA_URL}/browse/QUAL-1`);
    await expect(key).toHaveAttribute('target', '_blank');
    await expect(key).toHaveAttribute('rel', 'noopener noreferrer');
    await expect(card.locator('.jira-status')).toHaveText('To Do');
  });

  test('a status changed in Jira shows after the next sync pass', async ({ page, request }) => {
    const moved = await request.post(`${JIRA_URL}/__fake/issues/QUAL-1/status`, {
      data: { name: 'In Progress', category: 'indeterminate' },
    });
    expect(moved.status()).toBe(204);
    await syncNow(request);
    await page.goto(linkedIssueUrl);
    const status = page.getByRole('region', { name: 'Jira' }).locator('.jira-status');
    await expect
      .poll(
        async () => {
          await page.reload();
          return (await status.textContent())?.trim();
        },
        { timeout: JOB_TIMEOUT },
      )
      .toBe('In Progress');
  });

  test('the next analysis without the finding comments on its Jira issue', async ({
    request,
    playwright,
    baseURL,
  }) => {
    const report = paymentsReport();
    const upload = await playwright.request.newContext({ baseURL });
    try {
      await ingestAgain(request, upload, PROJECT.key, {
        ...report,
        findings: report.findings.filter((f) => f.message !== LINKED),
      });
    } finally {
      await upload.dispose();
    }
    await syncNow(request);
    await expect
      .poll(
        async () => {
          const issues = (await (await request.get(`${JIRA_URL}/__fake/issues`)).json()) as {
            key: string;
            comments: string[];
          }[];
          return issues.find((i) => i.key === 'QUAL-1')?.comments;
        },
        { timeout: JOB_TIMEOUT },
      )
      .toEqual([expect.stringMatching(/^Qualor no longer finds this issue on main/)]);
  });

  test('two issues get Jira issues from the bulk bar of the Issues list', async ({ page }) => {
    await page.goto(`/projects/${projectId}/issues`);
    for (const message of BULK) {
      await page.getByRole('checkbox', { name: message, exact: true }).check();
    }
    await page.getByRole('button', { name: 'Create Jira issues' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'queued' })).toHaveText('2 queued');
    // The list is read again every 3 s while a link is pending (R22).
    const keys: string[] = [];
    for (const message of BULK) {
      const row = page
        .getByRole('row')
        .filter({ has: page.getByRole('link', { name: message, exact: true }) });
      const key = row.getByRole('link', { name: /^QUAL-\d+$/ });
      await expect(key).toBeVisible({ timeout: JOB_TIMEOUT });
      keys.push((await key.textContent())!.trim());
    }
    expect(keys.sort()).toEqual(['QUAL-2', 'QUAL-3']);
  });
});
