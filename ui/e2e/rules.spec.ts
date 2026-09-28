import { expect, expectAccessible, test } from './fixtures';
import { XSS_RULE_TEXT } from './seed-data';

test('the rules the organization met, searchable, with descriptions as text', async ({ page }) => {
  await page.goto('/rules');
  await expect(page).toHaveTitle('Rules · Qualor');
  await page.getByRole('searchbox', { name: 'Search rules' }).fill('eqeqeq');
  await page.getByRole('button', { name: 'Search' }).click();
  await expect(page.locator('tbody tr')).toHaveCount(1);
  await page.getByText('Require === and !==').click();
  await expect(page.getByText(XSS_RULE_TEXT)).toBeVisible();
  await expect(page.getByRole('link', { name: 'Rule documentation' })).toHaveAttribute(
    'href',
    'https://eslint.org/docs/latest/rules/eqeqeq',
  );
  await expect(page.getByRole('link', { name: 'Rule documentation' })).toHaveAttribute(
    'rel',
    'noopener noreferrer',
  );
  await expectAccessible(page);
});

test('the profiles by language, with the seeded copy inheriting nothing', async ({ page }) => {
  await page.goto('/profiles');
  const ts = page.getByRole('region', { name: 'TypeScript' });
  await expect(ts.getByRole('row', { name: /Qualor way/ })).toContainText('Default');
  await expect(ts.getByRole('link', { name: 'Payments TypeScript' })).toBeVisible();
  await expect(page.getByRole('region', { name: 'Other engines' })).toBeVisible();
  await expectAccessible(page);
});

test('an admin switches rules of a custom profile and lets one inherit again', async ({ page }) => {
  await page.goto('/profiles');
  await page.getByRole('link', { name: 'Payments TypeScript' }).click();
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Payments TypeScript');
  // Seeded: eslint:no-console is off in this profile.
  const noConsole = page.getByRole('row', { name: /eslint:no-console/ });
  await expect(noConsole.getByRole('checkbox')).not.toBeChecked();
  await expect(noConsole).toContainText('Set here');
  const eqeqeq = page.getByRole('row', { name: /eslint:eqeqeq/ });
  const severity = eqeqeq.getByRole('combobox');
  await severity.focus();
  await severity.selectOption({ label: 'Blocker' });
  await expect(eqeqeq).toContainText('Set here');
  await expect(page.getByRole('status')).toHaveText('Severity of eslint:eqeqeq set to Blocker.');
  await expect(severity).toBeFocused();
  await expectAccessible(page);

  // Keyboard only: Space switches a rule and focus stays on it, twice in a row.
  const reassign = page
    .getByRole('row', { name: /eslint:no-param-reassign/ })
    .getByRole('checkbox');
  await reassign.focus();
  await page.keyboard.press('Space');
  await expect(page.getByRole('status')).toHaveText(
    'eslint:no-param-reassign is now inactive in this profile.',
  );
  await expect(reassign).not.toBeChecked();
  await expect(reassign).toBeFocused();
  await page.keyboard.press('Space');
  await expect(page.getByRole('status')).toHaveText(
    'eslint:no-param-reassign is now active in this profile.',
  );
  await expect(reassign).toBeChecked();
  await expect(reassign).toBeFocused();
  await page
    .getByRole('row', { name: /eslint:no-param-reassign/ })
    .getByRole('button', { name: 'Inherit again' })
    .press('Enter');
  await expect(reassign).toBeFocused();

  // "Inherit again" disappears with the setting: focus goes to the same rule's checkbox.
  await noConsole.getByRole('button', { name: 'Inherit again' }).press('Enter');
  await expect(noConsole.getByRole('checkbox')).toBeChecked();
  await expect(noConsole).not.toContainText('Set here');
  await expect(page.getByRole('status')).toHaveText(
    'eslint:no-console follows the parent profile again.',
  );
  await expect(noConsole.getByRole('checkbox')).toBeFocused();
});

test('an admin decides a rule no analysis reported yet (ruling X5)', async ({ page }) => {
  await page.goto('/profiles');
  await page.getByRole('link', { name: 'Payments TypeScript' }).click();
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Payments TypeScript');
  const row = page.getByRole('row', { name: /eslint:no-alert/ });
  await expect(page.getByRole('row', { name: /eslint:eqeqeq/ })).toBeVisible();
  await expect(row).toHaveCount(0);
  await page.getByLabel('Rule key').fill('eslint:no-alert');
  await page.getByRole('checkbox', { name: 'Active', exact: true }).uncheck();
  await page.getByLabel('Rule key').press('Enter');
  await expect(row.getByRole('checkbox')).not.toBeChecked();
  await expect(row).toContainText('Set here');
  await expect(page.getByRole('status')).toHaveText(
    'eslint:no-alert is now inactive in this profile.',
  );
  await expect(page.getByLabel('Rule key')).toBeFocused();
  // The rule leaves the list once nothing sets it: focus moves to the next row's checkbox.
  await row.getByRole('button', { name: 'Inherit again' }).press('Enter');
  await expect(row).toHaveCount(0);
  await expect(
    page.getByRole('row', { name: /eslint:no-console/ }).getByRole('checkbox'),
  ).toBeFocused();
});

test('a new profile inherits from a parent, which cannot be deleted while it has children', async ({
  page,
  guard,
}) => {
  await page.goto('/profiles');
  const parentLink = page.getByRole('link', { name: 'Payments TypeScript' });
  const parentId = (await parentLink.getAttribute('href'))?.split('/').at(-1);
  expect(parentId).toBeTruthy();

  // The built-in name is refused in any spelling, before the server is asked.
  await page.getByLabel('Name', { exact: true }).fill('qualor-WAY');
  await page.getByRole('button', { name: 'Create profile' }).click();
  await expect(page.getByText('This name is reserved for the built-in profiles.')).toBeVisible();

  await page.getByLabel('Name', { exact: true }).fill('Refunds TypeScript');
  await page.getByLabel('Inherits from').selectOption({ label: 'Payments TypeScript' });
  await page.getByRole('button', { name: 'Create profile' }).click();
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Refunds TypeScript');
  // Inherited: the parent switched eqeqeq to Blocker in an earlier test.
  await expect(page.getByRole('row', { name: /eslint:eqeqeq/ })).toContainText('Inherited');

  await page.getByRole('link', { name: 'All quality profiles' }).click();
  const ts = page.getByRole('region', { name: 'TypeScript' });
  const child = ts.getByRole('row', { name: /^Refunds TypeScript/ });
  await expect(child).toContainText('Payments TypeScript');
  guard.allowFailedLoad(`/api/v0/quality-profiles/${parentId}`, 409);
  guard.expectConfirm();
  await ts
    .getByRole('row', { name: /^Payments TypeScript/ })
    .getByRole('button', { name: 'Delete' })
    .click();
  await expect(page.getByRole('alert')).toHaveText(
    'Other profiles inherit from this one; delete them first.',
  );
  guard.expectConfirm();
  await child.getByRole('button', { name: 'Delete' }).click();
  await expect(child).toHaveCount(0);
  await expect(ts.getByRole('link', { name: 'Payments TypeScript' })).toBeVisible();
  await expectAccessible(page);
});
