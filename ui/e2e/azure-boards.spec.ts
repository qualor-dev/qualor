import type { APIRequestContext } from '@playwright/test';
import { expect, expectAccessible, test } from './fixtures';
import { ingestAgain, paymentsReport } from './report';
import { AZURE } from './seed-data';

/**
 * Azure Boards (sub-plan 8) against the fake Azure DevOps of server/scripts/e2e/serve.ts: a project
 * of its own is mapped, on the seed's PAT connection, to the Agile project AZURE.boards.project,
 * with type Bug and the area below its root; an issue gets a work item from its page and two more
 * from the Issues list's bulk bar. The server's boards worker sends the creates to the fake, whose
 * Bug starts in the state New. The admin's session holds the project's settings and triage
 * permissions, as a Project admin's does.
 *
 * The project gets the seed's last report of Payments API's main branch. It is deleted after the
 * tests, and its mapping and links with it, so no other spec sees them.
 */
const PROJECT = { key: 'boards-e2e', name: 'Boards E2E' };
/** The issue that gets a work item from its page. */
const LINKED = 'Unexpected console statement.';
/** The issues the bulk bar sends to Azure Boards. */
const BULK = [
  "'refundCap' is assigned a value but never used.",
  "'rounding' is defined but never used.",
];
/** How long a create job, and the page's reading of its result, may take. */
const JOB_TIMEOUT = 30_000;

async function csrf(request: APIRequestContext): Promise<Record<string, string>> {
  const me = (await (await request.get('/api/v0/auth/me')).json()) as { csrfToken: string };
  return { 'x-qualor-csrf': me.csrfToken };
}

test.describe.serial('Azure Boards', () => {
  let projectId = '';

  test.beforeAll(async ({ request, playwright, baseURL }) => {
    const orgs = (await (await request.get('/api/v0/organizations')).json()) as {
      items: { id: string }[];
    };
    const created = await request.post('/api/v0/projects', {
      headers: await csrf(request),
      data: { organizationId: orgs.items[0]!.id, key: PROJECT.key, name: PROJECT.name },
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
    if (!projectId) return;
    const deleted = await request.delete(
      `/api/v0/projects/${projectId}?confirm=${encodeURIComponent(PROJECT.key)}`,
      { headers: await csrf(request) },
    );
    expect(deleted.status()).toBe(204);
  });

  test('a project admin maps a project to Azure Boards and creates a work item from an issue', async ({
    page,
    request,
  }) => {
    await page.goto(`/projects/${projectId}/settings`);
    const panel = page.locator('section#boards');
    await expect(
      panel.getByRole('link', { name: 'Details and the rights it needs' }),
    ).toHaveAttribute('href', '/docs/azure-devops#azure-boards');
    // One Azure DevOps connection: no connection to choose.
    await expect(panel.getByLabel('Connection')).toHaveCount(0);
    await panel.getByLabel('Azure DevOps project').selectOption({ label: AZURE.boards.project });
    await panel.getByLabel('Work item type').selectOption({ label: 'Bug' });
    await panel.getByLabel('Area path').selectOption({ label: AZURE.boards.area });
    await expect(panel.getByLabel('Iteration path')).toHaveValue('');
    const tags = panel.getByLabel('Tags', { exact: true });
    await tags.fill('security');
    await tags.press('Enter');
    await expect(panel.getByRole('button', { name: 'Remove the tag security' })).toBeVisible();
    // The exploited option needs `vuln.priority`, which the Community edition has not.
    await expect(
      panel.getByRole('switch', { name: 'Exploited vulnerabilities (CISA KEV)' }),
    ).toBeDisabled();
    await panel.getByRole('button', { name: 'Save' }).click();
    await expect(panel.getByRole('status')).toHaveText('Saved.');
    await expectAccessible(page);

    const settings = (await (await request.get(`/api/v0/projects/${projectId}/boards`)).json()) as {
      mapping: {
        azureProject: { id: string; name: string };
        workItemType: { name: string };
        areaPath: string | null;
        iterationPath: string | null;
        tags: string[];
      } | null;
    };
    expect(settings.mapping).toMatchObject({
      azureProject: { name: AZURE.boards.project },
      workItemType: { name: 'Bug' },
      areaPath: AZURE.boards.area,
      iterationPath: null,
      tags: ['security'],
    });
    const azureProjectId = settings.mapping!.azureProject.id;

    await page.goto(`/projects/${projectId}/issues`);
    await page.getByRole('link', { name: LINKED, exact: true }).click();
    await expect(page).toHaveTitle('Issue · Qualor');
    const card = page.getByRole('region', { name: 'Azure Boards' });
    await card.getByRole('button', { name: 'Create work item' }).click();
    await expect(card.getByRole('status')).toHaveText('Creating…');
    // The page reads the issue again every 3 s while its link is pending.
    const id = card.getByRole('link', { name: /^#\d+$/ });
    await expect(id).toBeVisible({ timeout: JOB_TIMEOUT });
    const workItemId = (await id.textContent())!.trim().slice(1);
    await expect(id).toHaveAttribute(
      'href',
      `${AZURE.address}/${azureProjectId}/_workitems/edit/${workItemId}`,
    );
    await expect(id).toHaveAttribute('target', '_blank');
    await expect(id).toHaveAttribute('rel', 'noopener noreferrer');
    const state = card.locator('.boards-state');
    await expect(state).toHaveText('New');
    await expect(state).toHaveClass(/boards-state-proposed/);
    await expect(card.getByRole('button', { name: 'Unlink' })).toBeVisible();
    await expectAccessible(page);
  });

  test('two issues get work items from the bulk bar of the Issues list', async ({ page }) => {
    await page.goto(`/projects/${projectId}/issues`);
    for (const message of BULK) {
      await page.getByRole('checkbox', { name: message, exact: true }).check();
    }
    await page.getByRole('button', { name: 'Create Azure Boards work items' }).click();
    await expect(page.locator('.boards-result')).toHaveText('2 work items queued');
    // The list is read again every 3 s while a link is pending.
    const ids: string[] = [];
    for (const message of BULK) {
      const row = page
        .getByRole('row')
        .filter({ has: page.getByRole('link', { name: message, exact: true }) });
      const id = row.getByRole('link', { name: /^#\d+$/ });
      await expect(id).toBeVisible({ timeout: JOB_TIMEOUT });
      await expect(row.locator('.boards-state')).toHaveText('New');
      ids.push((await id.textContent())!.trim());
    }
    expect(new Set(ids).size).toBe(2);
  });
});
