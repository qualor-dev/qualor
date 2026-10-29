import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { type Browser, type Page, request } from '@playwright/test';
import { setProvider } from './ai-provider';
import { expect, test } from './fixtures';
import { PAYMENTS, STORAGE_STATE } from './seed-data';

/**
 * The qualor.dev site's product screens with the seeded data: overview, issues, issue-ai and gate,
 * as viewport captures in the dark theme at the site's sizes, 1440 wide at DPR 2 (the height of the
 * screen) and 390×844 at DPR 3. Opt-in, never part of `pnpm ui:e2e`: `pnpm site:screens` runs it
 * (tools/ui/site-screens.ts), which refuses to start without LIVE_OPENAI_API_KEY and writes to
 * SITE_SCREENS_OUT.
 *
 * issue-ai asks the real model: the assistant is set to api.openai.com (gpt-6.1-terra, the
 * Responses API) for that screen alone, and the fake provider is put back afterwards, also when the
 * capture fails. The key lives only in the throwaway e2e database; the project records no trace and
 * no video, and nothing here logs or asserts on it.
 *
 * Checking the navigation without the real model (what a test of this file does, never the
 * script): SITE_SCREENS_FAKE=1 without the key keeps the fake provider and expects its answer.
 */
const KEY = process.env['LIVE_OPENAI_API_KEY'] ?? '';
const FAKE = KEY === '' && process.env['SITE_SCREENS_FAKE'] === '1';
const OUT = process.env['SITE_SCREENS_OUT'] ?? '';
/** The fake LLM's key (server/test/fake-llm.ts), which the restore stores again. */
const FAKE_KEY = ['fake', 'llm', 'key', '0123456789'].join('-');
const FAKE_ANSWER = 'Loose equality compares after type coercion.';
const MODEL = 'gpt-6.1-terra';

const VIEWS = [
  { suffix: '', width: 1440, deviceScaleFactor: 2 },
  { suffix: '-phone', width: 390, deviceScaleFactor: 3 },
] as const;

async function inEachView(
  browser: Browser,
  baseURL: string | undefined,
  name: string,
  open: (page: Page) => Promise<void>,
  desktopHeight = 900,
  /** The phone view starts this far above the first level-2 heading instead of at the top. */
  phoneAboveTitle?: number,
): Promise<void> {
  for (const view of VIEWS) {
    const phone = view.suffix !== '';
    const context = await browser.newContext({
      baseURL,
      storageState: STORAGE_STATE,
      colorScheme: 'dark',
      locale: 'en-US',
      timezoneId: 'UTC',
      viewport: { width: view.width, height: phone ? 844 : desktopHeight },
      deviceScaleFactor: view.deviceScaleFactor,
    });
    try {
      const page = await context.newPage();
      await open(page);
      await page.waitForLoadState('networkidle');
      if (phone && phoneAboveTitle !== undefined) {
        const above = phoneAboveTitle;
        await page
          .getByRole('heading', { level: 2 })
          .first()
          .evaluate((el, offset) => {
            window.scrollTo({
              top: el.getBoundingClientRect().top + scrollY - offset,
              behavior: 'instant',
            });
          }, above);
      } else {
        await page.evaluate(() => window.scrollTo(0, 0));
      }
      await page.waitForTimeout(500);
      await page.screenshot({ path: path.join(OUT, `${name}${view.suffix}.png`) });
    } finally {
      await context.close();
    }
  }
}

async function openPayments(page: Page): Promise<void> {
  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
}

test('site screens', async ({ browser, baseURL }) => {
  test.setTimeout(600_000);
  if (KEY === '' && !FAKE) {
    throw new Error('The site screens need LIVE_OPENAI_API_KEY: run pnpm site:screens.');
  }
  if (OUT === '') throw new Error('The site screens need SITE_SCREENS_OUT.');
  mkdirSync(OUT, { recursive: true });

  await inEachView(
    browser,
    baseURL,
    'overview',
    async (page) => {
      await openPayments(page);
      await expect(page.getByRole('img', { name: /^Issues went from/ })).toBeVisible();
    },
    1180,
  );
  await inEachView(browser, baseURL, 'issues', async (page) => {
    await openPayments(page);
    await page.getByRole('link', { name: 'All open issues' }).click();
    await expect(page.locator('tbody tr').first()).toBeVisible();
  });

  const admin = await request.newContext({ baseURL, storageState: STORAGE_STATE });
  const stored = (await (await admin.get('/api/v0/system/llm')).json()) as {
    provider: { baseUrl: string; model: string; api: 'chat_completions' | 'responses' };
  };
  let failure: unknown;
  try {
    if (!FAKE) {
      await setProvider(admin, {
        baseUrl: 'https://api.openai.com/v1',
        model: MODEL,
        api: 'responses',
        apiKey: KEY,
      });
    }
    await inEachView(
      browser,
      baseURL,
      'issue-ai',
      async (page) => {
        await openPayments(page);
        await page.getByRole('link', { name: 'All open issues' }).click();
        await page.getByLabel('Branch').selectOption({ label: '!42 feature/refund-limits → main' });
        await page
          .getByRole('link', { name: "Expected '===' and instead saw '=='.", exact: true })
          .click();
        const panel = page.getByRole('region', { name: 'AI assistant' });
        // The first view of an issue shows the Explain button, a cached answer Ask again: either
        // way a fresh answer is asked for.
        const ask = panel.getByRole('button', { name: /^(Explain|Ask again)/ });
        await expect(ask).toBeVisible();
        // The answer on the page may be the one cached before: wait for the one this ask makes.
        const answered = page.waitForResponse(
          async (res) =>
            res.request().method() === 'GET' &&
            /\/api\/v0\/ai-requests\/[^/]+$/.test(new URL(res.url()).pathname) &&
            ((await res.json()) as { status?: string }).status === 'succeeded',
          { timeout: 120_000 },
        );
        await ask.click();
        await answered;
        await expect(panel.getByText('Asking the model…')).toHaveCount(0, { timeout: 120_000 });
        if (FAKE) {
          await expect(panel.getByText(FAKE_ANSWER)).toBeVisible();
        } else {
          await expect(panel.getByText(`api.openai.com (${MODEL})`)).toBeVisible();
          await expect(panel.getByText(new RegExp(`${MODEL} · `))).toBeVisible({
            timeout: 120_000,
          });
          await expect(panel.getByText(FAKE_ANSWER)).toHaveCount(0);
        }
      },
      900,
      28,
    );
  } catch (error) {
    failure = error;
  }
  // The fake provider goes back as it was stored, also when the capture failed. A failed restore
  // never hides the capture's own error; after a good capture it fails the run.
  try {
    await setProvider(admin, {
      baseUrl: stored.provider.baseUrl,
      model: stored.provider.model,
      api: stored.provider.api,
      apiKey: FAKE_KEY,
    });
  } catch (error) {
    if (failure === undefined) throw error;
    console.error(`site:screens could not restore the fake provider: ${String(error)}`);
  } finally {
    await admin.dispose();
  }
  if (failure !== undefined) throw failure;

  await inEachView(browser, baseURL, 'gate', async (page) => {
    await page.goto('/gates');
    await page.getByRole('link', { name: 'Strict' }).click();
    await expect(page.getByRole('button', { name: 'Add condition' })).toBeVisible();
  });
});
