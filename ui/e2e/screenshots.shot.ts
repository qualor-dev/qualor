import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { Page } from '@playwright/test';
import { expect, test } from './fixtures';
import {
  ENTERPRISE_STORAGE_STATE,
  ENTERPRISE_URL,
  PAYMENTS,
  PROJECT_WEBHOOK_URL,
  RELATED_ISSUE_MESSAGE,
  SHOP,
  SIEM_URL,
} from './seed-data';

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

/**
 * A screen in the light and the dark theme, on a desktop and on a phone (390px): `name`,
 * `name-dark`, `name-narrow` and `name-narrow-dark`. The page keeps its state between them.
 */
async function shootThemes(page: Page, name: string): Promise<void> {
  const desktop = page.viewportSize();
  for (const colorScheme of ['light', 'dark'] as const) {
    await page.emulateMedia({ colorScheme });
    for (const [width, suffix] of [
      [desktop?.width ?? 1440, ''],
      [390, '-narrow'],
    ] as const) {
      await page.setViewportSize({ width, height: desktop?.height ?? 900 });
      await page.evaluate(() => window.scrollTo(0, 0));
      await shoot(page, `${name}${suffix}${colorScheme === 'dark' ? '-dark' : ''}`);
    }
  }
  await page.emulateMedia({ colorScheme: 'light' });
  if (desktop) await page.setViewportSize(desktop);
}

/**
 * Default's AI review settings as they are now, through the API, and `restore`, which puts them
 * back switched off with the same projects and budgets (the seed's review is off).
 */
async function reviewOfDefault(page: Page): Promise<{ restore(): Promise<void> }> {
  const orgs = (await (await page.request.get('/api/v0/organizations?limit=100')).json()) as {
    items: { id: string; key: string }[];
  };
  const id = orgs.items.find((o) => o.key === 'default')?.id;
  if (id === undefined) throw new Error('The seed has no default organization.');
  const url = `/api/v0/organizations/${id}/ai/review`;
  const before = (await (await page.request.get(url)).json()) as {
    scope: string;
    projectIds: string[];
    budgets: object;
  };
  return {
    restore: async () => {
      const me = (await (await page.request.get('/api/v0/auth/me')).json()) as {
        csrfToken: string;
      };
      const restored = await page.request.put(url, {
        headers: { 'x-qualor-csrf': me.csrfToken },
        data: {
          enabled: false,
          scope: before.scope,
          projectIds: before.projectIds,
          budgets: before.budgets,
        },
      });
      expect(restored.status(), await restored.text()).toBe(200);
    },
  };
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

test('18 AI provider settings, 18b organization AI settings, 19 issue with the AI panel', async ({
  page,
}) => {
  await page.goto('/settings/ai');
  await expect(page.getByRole('heading', { name: 'AI provider', level: 2 })).toBeVisible();
  await expect(page.getByText('An API key is set.')).toBeVisible();
  await shoot(page, '18-settings-ai');

  // Default's AI page with its review on for Payments API, switched on through the dialog; off
  // again after the shot, as it was, through the API even should the shot fail.
  const defaultReview = await reviewOfDefault(page);
  try {
    await page.goto('/settings/ai-review');
    const review = page.locator('li[data-key="review"]');
    await page.getByRole('button', { name: 'Add projects' }).click();
    await page.getByRole('checkbox', { name: /^Payments API/ }).check();
    await page.getByRole('button', { name: 'Add 1 project' }).click();
    await review.getByRole('button', { name: 'Switch on AI review…' }).click();
    await page.getByRole('button', { name: /^Switch on and send code to / }).click();
    await expect(review.locator('.badge')).toHaveText('On');
    await expect(page.locator('#review .foot-status')).toContainText('Saved at');
    await page.evaluate(() => window.scrollTo(0, 0));
    await shoot(page, '18b-settings-ai-review');
  } finally {
    await defaultReview.restore();
  }

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

// E1 spec: a configured server (the seed's, which nothing answers) with one failed test message.
test('42 email settings', async ({ page }) => {
  await page.goto('/settings/email');
  await expect(page.getByRole('heading', { name: 'Email', level: 2 })).toBeVisible();
  await expect(page.getByText('On · the last message failed')).toBeVisible();
  await shoot(page, '42-settings-email');
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
  await expect(page.getByText('Grace period ends', { exact: true })).toBeVisible();
  await expect(
    page.getByRole('status').filter({ hasText: 'The Qualor licence expired on' }),
  ).toBeVisible();
  await shoot(page, '21-settings-license-grace');
});

// The project's Settings tab, its Code tab and a file, an issue's related locations, and the
// webhooks of every project with their scope.
test('31 project settings, 32 code tree, 33 code file, 34 issue related, 35 webhooks scope', async ({
  page,
}) => {
  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  const tabs = page.getByRole('navigation', { name: 'Project' });
  await tabs.getByRole('link', { name: 'Settings' }).click();
  await expect(page.locator('#tokens').getByRole('row', { name: /ci-main/ })).toBeVisible();
  await expect(page.locator('#webhooks').getByText(PROJECT_WEBHOOK_URL)).toBeVisible();
  await shoot(page, '31-project-settings');

  await tabs.getByRole('link', { name: 'Code' }).click();
  const table = page.getByRole('table', { name: 'Files and directories with their measures' });
  await table.getByRole('link', { name: 'src', exact: true }).click();
  await expect(table.getByRole('link', { name: 'refunds', exact: true })).toBeVisible();
  await shoot(page, '32-code-tree');
  await table.getByRole('link', { name: 'refunds', exact: true }).click();
  await table.getByRole('link', { name: 'limits.ts', exact: true }).click();
  await expect(
    page.getByRole('region', { name: 'Duplicated blocks' }).getByRole('link').first(),
  ).toBeVisible();
  await shoot(page, '33-code-file');

  await tabs.getByRole('link', { name: 'Overview' }).click();
  await page.getByRole('link', { name: 'All open issues' }).click();
  await page.getByRole('link', { name: RELATED_ISSUE_MESSAGE, exact: true }).click();
  await expect(
    page.getByRole('region', { name: 'Related locations' }).getByRole('listitem'),
  ).toHaveCount(3);
  await shoot(page, '34-issue-related');

  await page.goto('/settings/webhooks');
  await expect(
    page.getByRole('region', { name: PROJECT_WEBHOOK_URL }).locator('.webhook-scope'),
  ).toHaveText(`Project: ${PAYMENTS.name}`);
  await shoot(page, '35-webhooks-scope');
});

// 6M §8: Payments API's dependency inventory on the community server (no policy, no verdicts).
test('40 project dependencies', async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  await page
    .getByRole('navigation', { name: 'Project' })
    .getByRole('link', { name: 'Dependencies' })
    .click();
  await expect(page.locator('.deps-summary')).toContainText('packages have a known licence');
  await shootThemes(page, '40-project-dependencies');
});

// 0.15 (plan 2b): the Vulnerabilities tab of Payments API, By version, with the new marker.
test('43 project vulnerabilities', async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name, exact: true }).click();
  await page
    .getByRole('navigation', { name: 'Project' })
    .getByRole('link', { name: 'Vulnerabilities' })
    .click();
  await expect(page.getByRole('row', { name: /^main/ }).getByText('1 new')).toBeVisible();
  await shootThemes(page, '43-project-vulnerabilities');
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

  // 4E-1 §4 (`compliance-export`): a ready report of Payments API's main branch with its summary
  // shown, then the organisation's reports in Settings, each built by the server's worker.
  test('36 project compliance, 37 compliance reports', async ({ page }) => {
    await page.goto('/projects');
    await page.getByRole('link', { name: PAYMENTS.name }).click();
    await page
      .getByRole('navigation', { name: 'Project' })
      .getByRole('link', { name: 'Compliance' })
      .click();
    await page.getByRole('button', { name: 'Create report' }).click();
    await expect(page.getByText('Ready', { exact: true })).toBeVisible({ timeout: 30_000 });
    await page.getByRole('button', { name: /^Summary of the report of / }).click();
    await expect(page.locator('.compliance-categories')).toBeVisible();
    await shootThemes(page, '36-project-compliance');

    await page.goto('/settings/ee/compliance');
    await page.getByRole('button', { name: 'Create report' }).click();
    await expect(page.getByText('Ready', { exact: true })).toBeVisible({ timeout: 30_000 });
    await page.getByRole('button', { name: /^Summary of the report of / }).click();
    await expect(page.locator('.compliance-categories')).toBeVisible();
    await shootThemes(page, '37-settings-compliance');
  });

  // 4E-2 §4 (`portfolio`): the default organisation's portfolio by week, then every
  // organisation's by month, with the seed's three projects.
  test('38 portfolio, 39 portfolio of all organisations', async ({ page }) => {
    const ready = async () => {
      await expect(page.locator('[data-card="projects"] .kpi-value')).toHaveText('3');
      await expect(
        page
          .getByRole('region', { name: 'Projects', exact: true })
          .getByRole('link', { name: PAYMENTS.name, exact: true }),
      ).toBeVisible();
    };
    await page.goto('/portfolio');
    await ready();
    await shootThemes(page, '38-portfolio');

    await page.goto('/portfolio?scope=all&granularity=month');
    await ready();
    await expect(page.getByRole('region', { name: 'Organisations', exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Trend over 12 months' })).toBeVisible();
    await shootThemes(page, '39-portfolio-all');
  });

  // 6M §8 (`license-policy`): a policy that forbids strong copyleft and one more licence, after
  // the portfolio, whose figures it must not change.
  test('41 licence policy', async ({ page }) => {
    await page.goto('/settings/license-policy');
    await page.getByRole('checkbox', { name: 'Strong copyleft' }).check();
    await page.getByRole('checkbox', { name: 'Network copyleft' }).check();
    const forbidden = page.getByRole('combobox', { name: 'Forbidden licences' });
    await forbidden.fill('CC-BY-SA-4.0');
    await forbidden.press('Enter');
    await page.getByRole('button', { name: /licences in Strong copyleft$/ }).click();
    await page.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByRole('status').first()).toContainText('The licence policy was saved.');
    await page.evaluate(() => window.scrollTo(0, 0));
    await shootThemes(page, '41-settings-license-policy');
  });
});
