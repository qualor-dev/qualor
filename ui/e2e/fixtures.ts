import AxeBuilder from '@axe-core/playwright';
import {
  type BrowserContext,
  type ConsoleMessage,
  type Dialog,
  expect,
  type Page,
  test as base,
} from '@playwright/test';

/**
 * Every end-to-end test fails when any page of its browser context (popups included) logs an
 * error, throws, violates the Content Security Policy or opens a dialog it did not expect: an
 * `alert()` would mean HTML from the server ran as code.
 *
 * - CSP violations are caught twice: the browser's console error, and a `securitypolicyviolation`
 *   listener every page gets before its own scripts run.
 * - Dialogs: every `alert` fails the test. A `confirm` or `prompt` fails it too, unless the test
 *   announced it first with `guard.expectConfirm()` / `guard.expectPrompt()`. The dialog is then
 *   answered as announced, so an unexpected one fails with a clear message, never a timeout.
 * - Failed loads: the browser logs its own "Failed to load resource" error for every 4xx answer,
 *   which the app cannot suppress. A signed-out context (no stored session) may get the 401 of
 *   `GET /api/v0/auth/me`, the session probe (see auth.service.ts). Any other failed load must be
 *   named by the test with `guard.allowFailedLoad(path, status)`.
 *
 * Sessions: tests run on the admin session `auth.setup.ts` stores once per run (STORAGE_STATE),
 * because the login is rate-limited to 10 per minute and IP (api.md §2). A new test signs in
 * itself only when signing in is what it tests; see README.md.
 */
export interface Guard {
  /** Accept the browser's error line for this answer (same origin, exact path and status). */
  allowFailedLoad(path: string, status: number): void;
  /**
   * The next `confirm()` is expected; it is accepted (or dismissed with `accept: false`). With
   * `message`, a confirm that asks anything else is reported (and still answered as announced).
   */
  expectConfirm(accept?: boolean, message?: string): void;
  /** The next `prompt()` is expected and answered with `text`. */
  expectPrompt(text: string): void;
  /** The guard's own tests only: the problems recorded so far, which are then forgotten. */
  takeProblems(): string[];
}

const FAILED_LOAD = /^Failed to load resource: the server responded with a status of (\d{3})\b/;
const SIGNED_OUT_PROBE = '401 /api/v0/auth/me';
const REPORT_BINDING = '__qualorGuardReport';

type Expected =
  { type: 'confirm'; accept: boolean; message?: string } | { type: 'prompt'; text: string };

/** The problem a console message reports, or null when it is an allowed failed load. */
function consoleProblem(
  message: ConsoleMessage,
  origin: string,
  allowed: ReadonlySet<string>,
): string | null {
  if (message.type() !== 'error') return null;
  const where = message.location().url;
  const status = FAILED_LOAD.exec(message.text())?.[1];
  if (status && where) {
    const url = new URL(where);
    if (url.origin === origin && allowed.has(`${status} ${url.pathname}`)) return null;
  }
  return `console: ${message.text()}${where ? ` (${where})` : ''}`;
}

/** No stored session: the setup project, and tests that `use` an empty storage state. */
function isSignedOut(storageState: unknown): boolean {
  if (storageState === undefined) return true;
  if (typeof storageState === 'string') return false;
  const cookies = (storageState as { cookies?: unknown[] }).cookies;
  return !cookies || cookies.length === 0;
}

async function watch(
  context: BrowserContext,
  origin: string,
  allowed: ReadonlySet<string>,
  expected: Expected[],
  problems: string[],
): Promise<void> {
  const answer = async (dialog: Dialog): Promise<void> => {
    const type = dialog.type();
    const next = expected[0];
    if (next && next.type === type) {
      expected.shift();
      if (
        next.type === 'confirm' &&
        next.message !== undefined &&
        next.message !== dialog.message()
      ) {
        problems.push(`confirm asked "${dialog.message()}", expected "${next.message}"`);
      }
      if (next.type === 'confirm' && next.accept) await dialog.accept();
      else if (next.type === 'prompt') await dialog.accept(next.text);
      else await dialog.dismiss();
      return;
    }
    problems.push(`unexpected ${type} dialog: ${dialog.message()}`);
    await dialog.dismiss();
  };
  const attach = (page: Page): void => {
    page.on('console', (message) => {
      const problem = consoleProblem(message, origin, allowed);
      if (problem) problems.push(problem);
    });
    page.on('pageerror', (error) => problems.push(`page error: ${error.message}`));
    page.on('dialog', (dialog) => void answer(dialog));
  };
  await context.exposeBinding(REPORT_BINDING, (_source, report: string) => {
    problems.push(`csp: ${report}`);
  });
  await context.addInitScript((binding: string) => {
    document.addEventListener('securitypolicyviolation', (event) => {
      const report = (window as unknown as Record<string, (text: string) => void>)[binding];
      report?.(
        `${event.effectiveDirective} blocked ${event.blockedURI || 'inline'} ` +
          `(${event.sourceFile || 'page'}:${event.lineNumber})`,
      );
    });
  }, REPORT_BINDING);
  context.pages().forEach(attach);
  context.on('page', attach);
}

export const test = base.extend<{ guard: Guard }>({
  guard: [
    async ({ context, baseURL, storageState }, use) => {
      const origin = new URL(baseURL ?? 'http://127.0.0.1').origin;
      const allowed = new Set<string>(isSignedOut(storageState) ? [SIGNED_OUT_PROBE] : []);
      const expected: Expected[] = [];
      const problems: string[] = [];
      await watch(context, origin, allowed, expected, problems);
      await use({
        allowFailedLoad: (path, status) => {
          allowed.add(`${status} ${path}`);
        },
        expectConfirm: (accept = true, message?: string) => {
          expected.push({ type: 'confirm', accept, ...(message === undefined ? {} : { message }) });
        },
        expectPrompt: (text) => {
          expected.push({ type: 'prompt', text });
        },
        takeProblems: () => problems.splice(0),
      });
      expect(problems).toEqual([]);
      expect(
        expected.map((e) => e.type),
        'announced dialogs that never opened',
      ).toEqual([]);
    },
    { auto: true },
  ],
});

export { expect };

/** axe-core with the WCAG 2 A and AA rules: no serious or critical violation. */
export async function expectAccessible(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();
  const blocking = results.violations
    .filter((v) => v.impact === 'serious' || v.impact === 'critical')
    .map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`);
  expect(blocking).toEqual([]);
}
