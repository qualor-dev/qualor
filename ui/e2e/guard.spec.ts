import { expect, test } from './fixtures';

/**
 * The console, CSP and dialog guard of fixtures.ts, tested on the real app: each case makes the
 * page misbehave on purpose, then checks the guard noticed (and clears what it recorded).
 */
test.describe('the end-to-end guard', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/projects');
    await expect(page.getByRole('navigation', { name: 'Main' })).toBeVisible();
  });

  test('reports a Content Security Policy violation', async ({ page, guard }) => {
    await page.evaluate(() => {
      const script = document.createElement('script');
      script.textContent = 'window.injected = true';
      document.body.append(script);
    });
    await expect.poll(() => guard.takeProblems().join('\n')).toMatch(/csp: script-src-elem/);
    expect(await page.evaluate(() => 'injected' in window)).toBe(false);
  });

  test('reports an unexpected confirm and dismisses it, answers an expected one', async ({
    page,
    guard,
  }) => {
    expect(await page.evaluate(() => confirm('Delete everything?'))).toBe(false);
    expect(guard.takeProblems()).toEqual(['unexpected confirm dialog: Delete everything?']);
    guard.expectConfirm();
    expect(await page.evaluate(() => confirm('Delete this one?'))).toBe(true);
    guard.expectPrompt('acme/payments-api');
    expect(await page.evaluate(() => prompt('Type the key'))).toBe('acme/payments-api');
    expect(guard.takeProblems()).toEqual([]);
  });

  test('reports a confirm that asks something else than announced', async ({ page, guard }) => {
    guard.expectConfirm(false, 'Delete this one?');
    expect(await page.evaluate(() => confirm('Delete all of them?'))).toBe(false);
    expect(guard.takeProblems()).toEqual([
      'confirm asked "Delete all of them?", expected "Delete this one?"',
    ]);
    guard.expectConfirm(true, 'Delete this one?');
    expect(await page.evaluate(() => confirm('Delete this one?'))).toBe(true);
    expect(guard.takeProblems()).toEqual([]);
  });

  test('watches popups too', async ({ page, guard }) => {
    const [popup] = await Promise.all([
      page.waitForEvent('popup'),
      page.evaluate(() => void window.open('/projects')),
    ]);
    await popup.evaluate(() => console.error('broken in a popup'));
    await expect.poll(() => guard.takeProblems().join('\n')).toContain('broken in a popup');
    await popup.close();
  });
});
