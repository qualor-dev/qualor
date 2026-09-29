import { expect, expectAccessible, test } from './fixtures';
import { MERGE_REQUEST, PAYMENTS, XSS_MESSAGE, XSS_RULE_TEXT } from './seed-data';

test.beforeEach(async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  await page.getByRole('link', { name: 'All open issues' }).click();
  await expect(page).toHaveTitle('Issues · Qualor');
});

test('the issues list shows server text as text, with facets', async ({ page }) => {
  // The message carries an <img onerror>: it must be text, and no dialog may open (fixtures.ts).
  await expect(page.getByRole('link', { name: XSS_MESSAGE })).toBeVisible();
  await expect(page.locator('tbody img')).toHaveCount(0);
  const severity = page.getByRole('group', { name: 'Severity' });
  await expect(severity.getByText('Blocker')).toBeVisible();
  await expectAccessible(page);
});

test('a facet filters the list through the URL', async ({ page }) => {
  await page.getByRole('group', { name: 'Severity' }).getByLabel('High').check();
  await expect(page).toHaveURL(/severity=high/);
  await expect(page.locator('tbody .badge-high').first()).toBeVisible();
  await expect(page.locator('tbody .badge-medium')).toHaveCount(0);
  await page.getByRole('group', { name: 'Severity' }).getByLabel('High').uncheck();
  await expect(page).not.toHaveURL(/severity=/);
});

test('a crafted URL is clamped, never sent as a request the server rejects', async ({ page }) => {
  // Any 4xx would log a failed load, which the guard (fixtures.ts) turns into a failure.
  const url = new URL(page.url());
  url.search = new URLSearchParams([
    ['branch', 'not-a-uuid'],
    ['severity', 'catastrophic'],
    ['rule', 'r'.repeat(600)],
    ['engine', 'nul\u0000engine'],
    ['q', `${'a'.repeat(199)}\u{1F600}`],
    ['sort', 'random'],
    ...Array.from({ length: 30 }, (_, i) => ['path', `src/${i}/`]),
  ]).toString();
  await page.goto(url.toString());
  await expect(page.getByText('No issue matches.')).toBeVisible();
  await expect(page.getByRole('searchbox', { name: 'Search issue messages' })).toHaveValue(
    'a'.repeat(199),
  );
  await expect(page.getByRole('group', { name: 'File path' }).getByRole('checkbox')).toHaveCount(
    20,
  );
});

test('an issue: rule text stays text, a status change needs its comment, history records it', async ({
  page,
}) => {
  await page.getByRole('link', { name: XSS_MESSAGE }).click();
  await expect(page).toHaveTitle('Issue · Qualor');
  await expect(page.getByRole('heading', { level: 2 })).toHaveText(XSS_MESSAGE);
  await expect(page.getByText(XSS_RULE_TEXT)).toBeVisible();
  const docs = page.getByRole('link', { name: 'Rule documentation' });
  await expect(docs).toHaveAttribute('href', 'https://eslint.org/docs/latest/rules/eqeqeq');
  await expect(docs).toHaveAttribute('rel', 'noopener noreferrer');
  await expect(docs).toHaveAttribute('target', '_blank');
  await expectAccessible(page);
  const wontFix = page.getByRole('button', { name: "Won't fix" });
  await expect(wontFix).toBeDisabled();
  await page.getByLabel('Comment').fill('Refund notes are escaped before display.');
  // Keyboard only: the button disappears with the change, so focus moves to the section heading
  // and the result is announced in a live region.
  await wontFix.focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: 'Change', level: 3 })).toBeFocused();
  // The AI panel (llm.md §18) has a live region of its own: this one is the Change section's.
  await expect(page.getByRole('region', { name: 'Change' }).getByRole('status')).toHaveText(
    "Status changed to Won't fix.",
  );
  const history = page.getByRole('region', { name: 'History' });
  await expect(history).toContainText("Status: Open → Won't fix");
  await expect(history).toContainText('Refund notes are escaped before display.');
  await page.getByRole('button', { name: 'Reopen' }).click();
  await expect(history).toContainText("Status: Won't fix → Open");
  await page.getByLabel('Severity', { exact: true }).selectOption({ label: 'Blocker' });
  await page.getByRole('button', { name: 'Set severity' }).click();
  await expect(history).toContainText('Severity: High → Blocker');
  await expect(page.getByText('(set by a person)')).toBeVisible();
});

test('checking an issue never moves the list, and focus never hides under the bars', async ({
  page,
}) => {
  const rows = page.locator('tbody tr');
  const second = rows.nth(1);
  const before = (await second.boundingBox())!.y;
  await rows.nth(0).getByRole('checkbox').check();
  const bar = page.locator('form.bulk');
  await expect(bar).toBeVisible();
  expect((await second.boundingBox())!.y).toBe(before);
  // Scrolling to a focused control keeps it clear of the sticky header and the floating bar.
  const padding = await page.evaluate(() => {
    const style = getComputedStyle(document.documentElement);
    return {
      top: parseFloat(style.scrollPaddingTop),
      bottom: parseFloat(style.scrollPaddingBottom),
    };
  });
  expect(padding.top).toBe(72);
  expect(padding.bottom).toBeGreaterThanOrEqual((await bar.boundingBox())!.height);
});

test('the right column of an issue keeps its end in reach on a short screen', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 800 });
  await page.getByRole('link', { name: XSS_MESSAGE }).click();
  await expect(page).toHaveTitle('Issue · Qualor');
  await expect(page.getByRole('heading', { level: 2 })).toHaveText(XSS_MESSAGE);
  // A long story on the left keeps the right column stuck while the page scrolls.
  await page.evaluate(() => {
    const spacer = document.createElement('div');
    spacer.style.height = '3000px';
    document.querySelector('.issue-main')?.append(spacer);
  });
  await page.mouse.wheel(0, 900);
  const severity = page.getByLabel('Severity', { exact: true });
  await severity.focus();
  await expect(severity).toBeInViewport({ ratio: 1 });
  await expect(page.getByRole('button', { name: 'Set severity' })).toBeInViewport({ ratio: 1 });
});

test('the issues of a merge request change status in bulk', async ({ page }) => {
  await page
    .getByLabel('Branch')
    .selectOption({ label: `!${MERGE_REQUEST.id} ${MERGE_REQUEST.source} → main` });
  await expect(page).toHaveURL(/branch=/);
  await page.getByLabel('Select all issues on this page').check();
  await expect(page.getByText(/\d+ issues selected/)).toBeVisible();
  await page.getByLabel('New status').selectOption({ label: 'Resolve' });
  await page.getByRole('button', { name: 'Change status' }).press('Enter');
  await expect(page.getByRole('status')).toContainText(/\d+ issues changed\./);
  // The button is disabled once the selection is empty: focus stays on the result.
  await expect(page.getByRole('status')).toBeFocused();
  await expect(page.getByText('No issue matches.')).toBeVisible();
});
