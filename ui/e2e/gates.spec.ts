import { expect, expectAccessible, test } from './fixtures';

test('the gates list shows the default built-in gate and the seeded copy', async ({ page }) => {
  await page.goto('/gates');
  await expect(page).toHaveTitle('Quality gates · Qualor');
  const builtin = page.getByRole('row', { name: /Qualor way/ });
  await expect(builtin).toContainText('Default');
  await expect(builtin).toContainText('Built-in');
  await expect(builtin.getByRole('button', { name: 'Delete' })).toHaveCount(0);
  await expect(page.getByRole('row', { name: /Strict/ })).toBeVisible();
  await expectAccessible(page);
});

test('an admin edits the conditions of a custom gate', async ({ page }) => {
  await page.goto('/gates');
  await page.getByRole('link', { name: 'Strict' }).click();
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Strict');
  await page.getByLabel('Metric').selectOption({ label: 'Duplicated lines (%)' });
  await expect(page.getByLabel('Fails when the value')).toHaveValue('gt');
  // A percentage above 100 is refused before the server is asked.
  await page.getByLabel('Threshold').fill('150');
  await page.getByRole('button', { name: 'Add condition' }).click();
  await expect(page.getByText('Enter a number from 0 to 100.')).toBeVisible();
  await expect(page.getByLabel('Threshold')).toHaveAttribute('aria-invalid', 'true');
  await page.getByLabel('Threshold').fill('5');
  await page.getByRole('button', { name: 'Add condition' }).click();
  const row = page.getByRole('row', { name: /^Duplicated lines \(%\) is greater than 5 %/ });
  await expect(row).toBeVisible();
  await expect(page.getByRole('status')).toHaveText(
    'Condition added: Duplicated lines (%) is greater than 5 %.',
  );
  await expectAccessible(page);
  // Keyboard only: the Remove button goes with its row, so focus moves to the next row's.
  await row.getByRole('button', { name: 'Remove' }).press('Enter');
  await expect(row).toHaveCount(0);
  await expect(page.getByRole('status')).toHaveText('Condition removed: Duplicated lines (%).');
  await expect(
    page
      .getByRole('row', { name: /^Coverage on new code/ })
      .getByRole('button', { name: 'Remove' }),
  ).toBeFocused();
});

test('copying the built-in gate opens an editable copy', async ({ page }) => {
  await page.goto('/gates');
  await page
    .getByRole('row', { name: /Qualor way/ })
    .getByRole('button', { name: 'Copy' })
    .click();
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Qualor way (copy)');
  await expect(page.getByRole('button', { name: 'Add condition' })).toBeVisible();
});

test('an admin makes a new gate the default, then deletes it after a confirmation that says gating stops', async ({
  page,
  guard,
}) => {
  await page.goto('/gates');
  await page.getByLabel('New gate').fill('Release candidate');
  await page.getByRole('button', { name: 'Create gate' }).click();
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Release candidate');
  await expect(page.getByText('No conditions: this gate always passes.')).toBeVisible();

  await page.getByRole('link', { name: 'All quality gates' }).click();
  const created = page.getByRole('row', { name: /^Release candidate/ });
  // Keyboard only: "Make default" disappears from the row, so focus moves to the row's Copy.
  await created.getByRole('button', { name: 'Make default' }).press('Enter');
  await expect(page.getByRole('status')).toHaveText(
    'Release candidate is now the default quality gate.',
  );
  await expect(created).toContainText('Default');
  await expect(created.getByRole('button', { name: 'Copy' })).toBeFocused();
  await expect(page.getByRole('row', { name: /^Qualor way Built-in/ })).toBeVisible();

  // Deleting the default gate leaves the organization without one: the question says so.
  const question =
    'Delete the default quality gate "Release candidate"? The organization is then left without a default gate: every project that uses the default is no longer gated until you make another gate the default.';
  guard.expectConfirm(false, question);
  await created.getByRole('button', { name: 'Delete' }).click();
  await expect(created).toBeVisible();
  guard.expectConfirm(true, question);
  await created.getByRole('button', { name: 'Delete' }).press('Enter');
  await expect(created).toHaveCount(0);
  await expect(page.getByRole('status')).toHaveText('Quality gate Release candidate deleted.');
  await expect(page.locator('body')).not.toBeFocused();

  // Give the default back to the built-in gate, which the other tests expect.
  await page
    .getByRole('row', { name: /^Qualor way Built-in/ })
    .getByRole('button', { name: 'Make default' })
    .click();
  await expect(page.getByRole('row', { name: /^Qualor way Default/ })).toBeVisible();
  await expectAccessible(page);
});
