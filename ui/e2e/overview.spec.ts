import { expect, expectAccessible, test } from './fixtures';
import { MERGE_REQUEST, PAYMENTS } from './seed-data';

test('the project overview shows the failed gate, measures and trends', async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(PAYMENTS.name);
  await expect(page).toHaveTitle('Overview · Qualor');
  const gate = page.getByRole('region', { name: /Quality gate/ });
  await expect(gate.getByRole('heading')).toContainText('Qualor way');
  await expect(gate.locator('q-gate-badge')).toHaveText('Failed');
  await expect(
    gate.getByRole('row', { name: /Issues on new code is greater than 0/ }),
  ).toContainText('Failed');
  // The history starts in June (the seed's earlier analyses) and switches between metrics.
  const history = page.getByRole('region', { name: 'History' });
  await expect(
    history.getByRole('img', {
      name: /^Issues went from \d+ on Jun 2, 2026 to \d+ on Sep 15, 2026$/,
    }),
  ).toBeVisible();
  await history.getByRole('button', { name: 'Coverage' }).click();
  await expect(history.getByRole('button', { name: 'Coverage' })).toHaveAttribute(
    'aria-pressed',
    'true',
  );
  await expect(
    history.getByRole('img', { name: /^Coverage went from [\d.]+ % on Jun 2, 2026/ }),
  ).toBeVisible();
  await history.getByRole('button', { name: 'Lines of code' }).click();
  await expect(history.getByRole('img', { name: /^Lines of code went from/ })).toBeVisible();
  await expectAccessible(page);
});

test('the branches tab lists the merge request, which has its own view', async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  await page.getByRole('link', { name: 'Branches and merge requests' }).click();
  const title = `!${MERGE_REQUEST.id} ${MERGE_REQUEST.source} → main`;
  await expect(page.getByRole('row', { name: /main Main branch/ })).toContainText('Failed');
  await page
    .getByRole('group', { name: 'Show' })
    .getByRole('button', { name: 'Merge requests' })
    .click();
  await expect(page.getByRole('row', { name: /Main branch/ })).toHaveCount(0);
  await page.getByRole('link', { name: title }).click();
  await expect(page.locator('.branch-name')).toHaveText(title);
  await expect(page.getByRole('region', { name: /Quality gate/ })).toBeVisible();
  await expectAccessible(page);
});

test('deleting a merge request asks first, and Cancel leaves it', async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  await page.getByRole('link', { name: 'Branches and merge requests' }).click();
  const title = `!${MERGE_REQUEST.id} ${MERGE_REQUEST.source} → main`;
  // The main branch cannot be deleted: only the merge request offers it.
  await expect(page.getByRole('button', { name: /^Delete / })).toHaveCount(1);
  const remove = page.getByRole('button', { name: `Delete ${title}` });
  await remove.click();
  const dialog = page.getByRole('dialog', { name: 'Delete this merge request?' });
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText('This cannot be undone.');
  // A destructive dialog starts on its safe choice.
  await expect(dialog.getByRole('button', { name: 'Cancel' })).toBeFocused();
  await expectAccessible(page);
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
  await expect(remove).toBeFocused();
  await expect(page.getByRole('link', { name: title })).toBeVisible();
});

test('the project tabs work with the keyboard and mark the current one', async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  const tabs = page.getByRole('navigation', { name: 'Project' });
  await expect(tabs.getByRole('link', { name: 'Overview' })).toHaveAttribute(
    'aria-current',
    'page',
  );
  await tabs.getByRole('link', { name: 'Branches and merge requests' }).focus();
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/\/projects\/[0-9a-f-]{36}\/branches$/);
  await expect(page).toHaveTitle('Branches and merge requests · Qualor');
  // The new page takes the focus, so the next Tab starts inside it.
  await expect(page.locator('main')).toBeFocused();
  await expect(tabs.getByRole('link', { name: 'Branches and merge requests' })).toHaveAttribute(
    'aria-current',
    'page',
  );
  await expectAccessible(page);
});

test('an unknown project or branch says so instead of failing', async ({ page, guard }) => {
  // The malformed project id answers 422, which the browser logs; the page shows an alert. An
  // unknown branch is found missing by the UI itself (no request fails).
  guard.allowFailedLoad('/api/v0/projects/not-a-project', 422);
  await page.goto('/projects/not-a-project');
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Project unavailable');
  await expect(page.getByRole('alert')).toHaveText(
    'This item does not exist, or you cannot see it.',
  );
  await expectAccessible(page);
  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(PAYMENTS.name);
  await page.goto(`${new URL(page.url()).pathname}/branches/no-such-branch`);
  await expect(page.getByRole('alert')).toHaveText(
    'This item does not exist, or you cannot see it.',
  );
  await expectAccessible(page);
});

test('an unknown page and the unavailable page say so, accessibly', async ({ page }) => {
  await page.goto('/no-such-page');
  await expect(page).toHaveTitle('Page not found · Qualor');
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Page not found');
  await expectAccessible(page);
  // The page the guards open when the server cannot be reached (opened directly here).
  await page.goto('/unavailable?returnUrl=%2Fprojects');
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Qualor is not available');
  await expect(page.getByRole('alert')).toContainText('The server could not be reached.');
  await expectAccessible(page);
  await page.getByRole('button', { name: 'Try again' }).click();
  await expect(page).toHaveURL(/\/projects$/);
});

test.describe('on a phone', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('the overview and the user menu stay accessible at 390 px', async ({ page }) => {
    await page.goto('/projects');
    await page.getByRole('link', { name: PAYMENTS.name }).click();
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(PAYMENTS.name);
    // The name is hidden on a phone, visually only: the button keeps it.
    await expect(page.getByRole('button', { name: 'Administrator' })).toBeVisible();
    await expectAccessible(page);
  });
});
