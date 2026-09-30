import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { Page } from '@playwright/test';
import { expect, test } from './fixtures';
import { ENTERPRISE_STORAGE_STATE, ENTERPRISE_URL, SHOP, SIEM_URL } from './seed-data';

/**
 * `pnpm ui:screenshots`: one PNG per screen, with the seeded demo data, into the git-ignored
 * `.tmp/screenshots/` at the repository root. Not a test of behaviour: the e2e project is. The
 * console guard still applies, so a screen that logs an error is not shot as if it were fine.
 */
const OUT = fileURLToPath(new URL('../../.tmp/screenshots/', import.meta.url));
mkdirSync(OUT, { recursive: true });

async function shoot(page: Page, name: string): Promise<void> {
  // Let lazy chunks and data settle so every PNG shows the finished page.
  await page.waitForLoadState('networkidle');
  await page.screenshot({ path: `${OUT}${name}.png`, fullPage: true });
}

test.describe('signed out', () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test('01 login', async ({ page }) => {
    await page.goto('/login');
    await expect(page.getByRole('heading', { name: 'Sign in to Qualor' })).toBeVisible();
    await shoot(page, '01-login');
  });
});

test('02 projects', async ({ page }) => {
  await page.goto('/projects');
  await expect(page.getByRole('link', { name: 'Payments API' })).toBeVisible();
  await shoot(page, '02-projects');
});

test('03 project overview, 04 branches, 05 merge request', async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('link', { name: 'Payments API' }).click();
  await expect(page.getByRole('img', { name: /^Issues went from/ })).toBeVisible();
  await shoot(page, '03-project-overview');
  await page.getByRole('link', { name: 'Branches and merge requests' }).click();
  await expect(page.getByRole('link', { name: /^!42/ })).toBeVisible();
  await shoot(page, '04-branches');
  await page.getByRole('link', { name: /^!42/ }).click();
  await expect(page.locator('.branch-name')).toBeVisible();
  await shoot(page, '05-merge-request');
});

test('06 issues, 07 issue', async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('link', { name: 'Payments API' }).click();
  await page.getByRole('link', { name: 'All open issues' }).click();
  await expect(page.locator('tbody tr').first()).toBeVisible();
  await shoot(page, '06-issues');
  await page.locator('tbody a').first().click();
  await expect(page.getByRole('region', { name: 'History' })).toBeVisible();
  await shoot(page, '07-issue');
});

test('08 gates, 09 gate', async ({ page }) => {
  await page.goto('/gates');
  await expect(page.getByRole('link', { name: 'Strict' })).toBeVisible();
  await shoot(page, '08-gates');
  await page.getByRole('link', { name: 'Strict' }).click();
  await expect(page.getByRole('button', { name: 'Add condition' })).toBeVisible();
  await shoot(page, '09-gate');
});

test('10 rules, 11 profiles, 12 profile', async ({ page }) => {
  await page.goto('/rules');
  await expect(page.locator('tbody tr').first()).toBeVisible();
  await page.getByText('Require === and !==').click();
  await shoot(page, '10-rules');
  await page.goto('/profiles');
  await expect(page.getByRole('link', { name: 'Payments TypeScript' })).toBeVisible();
  await shoot(page, '11-profiles');
  await page.getByRole('link', { name: 'Payments TypeScript' }).click();
  await expect(page.getByRole('row', { name: /eslint:no-console/ })).toBeVisible();
  await shoot(page, '12-profile');
});

test('13 tokens, 14 users, 15 webhooks, 16 GitLab, 17 GitHub', async ({ page }) => {
  await page.goto('/settings/tokens');
  await expect(page.getByRole('row', { name: /laptop/ })).toBeVisible();
  await shoot(page, '13-settings-tokens');
  await page.getByRole('link', { name: 'Users' }).click();
  await expect(page.getByRole('row', { name: /alice/ })).toBeVisible();
  await shoot(page, '14-settings-users');
  await page.getByRole('link', { name: 'Webhooks' }).click();
  await expect(page.getByText('https://hooks.example.com/qualor')).toBeVisible();
  await shoot(page, '15-settings-webhooks');
  await page.getByRole('link', { name: 'GitLab' }).click();
  await expect(page.getByRole('heading', { name: 'GitLab', level: 2 })).toBeVisible();
  await shoot(page, '16-settings-gitlab');
  await page.getByRole('link', { name: 'GitHub', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'GitHub', level: 2 })).toBeVisible();
  // Two seeded Apps: one with its webhook URL, one stored under an earlier server key.
  await expect(
    page.getByRole('region', { name: 'GitHub App 424200 at https://github.qualor.invalid/api/v3' }),
  ).toContainText(/Webhook URL:\s*http:\/\/127\.0\.0\.1:\d+\/api\/v0\/github\/webhooks\//);
  await expect(
    page.getByRole('region', { name: 'GitHub App 424201 at https://github.qualor.invalid/api/v3' }),
  ).toContainText('The private key can no longer be read: set it again.');
  await shoot(page, '17-settings-github');
});

// Plan 5B (rbac-audit.md §1.3): the four roles and the Access tab on the community server.
test('22 members, 23 project access', async ({ page }) => {
  await page.goto('/settings/members');
  await expect(page.getByRole('row', { name: /alice/ })).toBeVisible();
  await expect(page.getByRole('row', { name: /vera/ })).toBeVisible();
  await shoot(page, '22-settings-members');

  // Web Shop has the seed's grants: victor (Viewer) and petra (Project admin).
  await page.goto('/projects');
  await page.getByRole('link', { name: SHOP.name }).click();
  await page.getByRole('link', { name: 'Access' }).click();
  await expect(page.getByRole('row', { name: /petra/ })).toBeVisible();
  await shoot(page, '23-project-access');
});

test('18 AI assistant settings, 19 issue with the AI panel', async ({ page }) => {
  await page.goto('/settings/ai');
  await expect(page.getByText('An API key is set')).toBeVisible();
  await shoot(page, '18-settings-ai');
  // The eqeqeq issue of merge request !42: the fake LLM (serve.ts) explains, triages and fixes it.
  await page.goto('/projects');
  await page.getByRole('link', { name: 'Payments API' }).click();
  await page.getByRole('link', { name: 'All open issues' }).click();
  await page.getByLabel('Branch').selectOption({ label: '!42 feature/refund-limits → main' });
  await page
    .getByRole('link', { name: "Expected '===' and instead saw '=='.", exact: true })
    .click();
  const panel = page.getByRole('region', { name: 'AI assistant' });
  await panel.getByRole('button', { name: 'Explain' }).click();
  await expect(panel.getByText('Loose equality compares after type coercion.')).toBeVisible();
  await panel.getByRole('button', { name: 'Suggest triage' }).click();
  await expect(panel.getByText('Likely a true positive')).toBeVisible();
  await panel.getByRole('button', { name: 'Suggest a fix' }).click();
  await expect(page.locator('#ai-fix-after')).toContainText('===');
  await shoot(page, '19-issue-ai');
});

test('20 licence, 21 licence in its grace period with the admin banner', async ({ page }) => {
  await page.goto('/settings/license');
  await expect(page.getByText('Community edition')).toBeVisible();
  await shoot(page, '20-settings-license');
  // The e2e server has no key, so the grace period is the API's answer as a test key would give
  // it (enterprise.md §9.1): the page and the banner under the header both read it.
  await page.route('**/api/v0/license', (route) =>
    route.fulfill({
      json: {
        edition: 'enterprise',
        state: 'grace',
        reason: null,
        source: 'uploaded',
        license: {
          id: '0192f5a4-0000-7000-8000-000000000001',
          keyId: 'test-e2e',
          customer: 'Acme Corporation',
          issued: '2026-10-01T00:00:00.000Z',
          expires: '2027-10-01T00:00:00.000Z',
          graceEndsAt: '2027-10-15T00:00:00.000Z',
          features: ['llm.fix-quota'],
          test: true,
        },
        expiresSoon: false,
        restartRequired: true,
        activeFeatures: ['llm.fix-quota'],
        plugins: [
          { name: 'qualor-enterprise', state: 'loaded', features: ['llm.fix-quota'], error: null },
        ],
      },
    }),
  );
  await page.reload();
  await expect(page.getByText('Grace period: enterprise features stop on')).toBeVisible();
  await expect(
    page.getByRole('status').filter({ hasText: 'The Qualor licence expired on' }),
  ).toBeVisible();
  await shoot(page, '21-settings-license-grace');
});

/**
 * Plan 4C: the enterprise screens, on the licensed server (`audit-log`, and since plan 4D `sso`
 * and `scim`) and its session.
 */
test.describe('enterprise', () => {
  test.use({ baseURL: ENTERPRISE_URL, storageState: ENTERPRISE_STORAGE_STATE });

  test('24 audit log, 25 audit settings', async ({ page }) => {
    await page.goto('/settings/ee/audit-log');
    await expect(page.locator('#audit-head')).toContainText('Newest event:');
    await expect(page.locator('tbody tr[data-key]').first()).toBeVisible();
    await page
      .locator('tbody tr[data-key]')
      .first()
      .getByRole('button', { name: /Details/ })
      .click();
    // A click scrolled the page; a full-page shot from the top keeps the sticky header in place.
    await page.evaluate(() => window.scrollTo(0, 0));
    await shoot(page, '24-settings-audit-log');

    await page.goto('/settings/ee/audit-settings');
    await page.getByLabel('Stream URL').fill(SIEM_URL);
    await page.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByLabel('Stream secret')).toHaveValue(/^whsec_/);
    await page.getByRole('button', { name: 'Done' }).click();
    await page.getByRole('button', { name: 'Send test' }).click();
    await expect(page.locator('#audit-stream-test')).toContainText('the test passed');
    // A click scrolled the page; a full-page shot from the top keeps the sticky header in place.
    await page.evaluate(() => window.scrollTo(0, 0));
    await shoot(page, '25-settings-audit-settings');
  });

  // Plan 4D (sso-scim.md §18): the seed's connections, whose identity providers are never called.
  test.describe('signed out', () => {
    test.use({ storageState: { cookies: [], origins: [] } });

    test('26 sign-in with single sign-on', async ({ page }) => {
      await page.goto('/login');
      await expect(page.getByRole('link', { name: 'Sign in with Acme SSO' })).toBeVisible();
      await shoot(page, '26-sign-in-sso');
    });
  });

  test('27 single sign-on, 28 sign-in, 29 SCIM, 30 linked accounts', async ({ page }) => {
    await page.goto('/settings/ee/sso');
    await page.getByRole('button', { name: 'Edit Acme SSO' }).click();
    await expect(page.locator('#sso-mappings')).toContainText('engineering');
    await page.evaluate(() => window.scrollTo(0, 0));
    await shoot(page, '27-settings-sso');

    await page.goto('/settings/ee/sign-in');
    await expect(page.locator('#sign-in-picker')).toContainText('admin');
    await shoot(page, '28-settings-sign-in');

    await page.goto('/settings/ee/scim');
    await expect(page.getByLabel('SCIM base URL').first()).toBeVisible();
    await shoot(page, '29-settings-scim');

    await page.goto('/settings/ee/linked-accounts');
    await expect(page.getByRole('row', { name: /Acme SSO/ })).toBeVisible();
    await shoot(page, '30-linked-accounts');
  });
});
