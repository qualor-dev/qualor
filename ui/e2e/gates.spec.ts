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
  // The add row closes the conditions panel; each condition's own fields are "… of <metric>".
  await page.getByLabel('Metric', { exact: true }).selectOption({ label: 'Duplicated lines (%)' });
  await expect(page.getByLabel('Fails when the value', { exact: true })).toHaveValue('gt');
  // A percentage above 100 is refused before the server is asked.
  await page.getByLabel('Threshold', { exact: true }).fill('150');
  await page.getByRole('button', { name: 'Add condition' }).click();
  await expect(page.getByText('Enter a number from 0 to 100.')).toBeVisible();
  await expect(page.getByLabel('Threshold', { exact: true })).toHaveAttribute(
    'aria-invalid',
    'true',
  );
  await page.getByLabel('Threshold', { exact: true }).fill('5');
  await page.getByRole('button', { name: 'Add condition' }).click();
  // "Duplicated lines (%) on new code" has a row too: the exact labels tell them apart.
  const threshold = page.getByLabel('Threshold of Duplicated lines (%)', { exact: true });
  await expect(threshold).toHaveValue('5');
  await expect(page.getByLabel('Operator of Duplicated lines (%)', { exact: true })).toHaveValue(
    'gt',
  );
  const row = page.getByRole('row').filter({ has: threshold });
  await expect(page.getByRole('status')).toHaveText(
    'Condition added: Duplicated lines (%) is greater than 5 %.',
  );
  await expectAccessible(page);
  // Typed key by key, a decimal stays whole in place (a number field emptied itself at "2.").
  await threshold.fill('');
  await threshold.pressSequentially('2.5');
  await expect(threshold).toHaveValue('2.5');
  await row
    .getByRole('button', { name: 'Save the condition on Duplicated lines (%)', exact: true })
    .click();
  await expect(page.getByRole('status')).toHaveText(
    'Condition changed: Duplicated lines (%) is greater than 2.5 %.',
  );
  // Keyboard only: the Remove button goes with its row, so focus moves to the next row's.
  await row.getByRole('button', { name: 'Remove' }).press('Enter');
  await expect(row).toHaveCount(0);
  await expect(page.getByRole('status')).toHaveText('Condition removed: Duplicated lines (%).');
  // (The rest of the in-place edit is covered by the unit tests of gates.spec.ts.)
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
}) => {
  await page.goto('/gates');
  // The form is in the "New gate" dialog (step 6), which starts on the name.
  await page.getByRole('button', { name: 'New gate' }).click();
  await expect(page.getByLabel('Name', { exact: true })).toBeFocused();
  await expectAccessible(page);
  await page.getByLabel('Name', { exact: true }).fill('Release candidate');
  await page.getByRole('button', { name: 'Create gate' }).click();
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Release candidate');
  await expect(page.getByText('No conditions: this gate always passes.')).toBeVisible();

  await page
    .getByRole('navigation', { name: 'Breadcrumb' })
    .getByRole('link', { name: 'Quality gates' })
    .click();
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
  // The page's own dialog asks (a browser confirm() would fail the guard of fixtures.ts).
  await created.getByRole('button', { name: 'Delete' }).click();
  const ask = page.getByRole('dialog', { name: 'Delete the quality gate' });
  await expect(ask).toContainText(question);
  await expect(ask.getByRole('button', { name: 'Cancel' })).toBeFocused();
  // A dialog's close event comes a task after close(): wait for it, as a person always does, or
  // it would cancel the question asked again at machine speed.
  const closed = ask.evaluate(
    (dialog) =>
      new Promise<void>((done) => dialog.addEventListener('close', () => done(), { once: true })),
  );
  await ask.getByRole('button', { name: 'Cancel' }).click();
  await closed;
  await expect(created).toBeVisible();
  await created.getByRole('button', { name: 'Delete' }).press('Enter');
  await ask.getByRole('button', { name: 'Delete' }).click();
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
