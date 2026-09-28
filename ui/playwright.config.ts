import { fileURLToPath } from 'node:url';
import { defineConfig, devices } from '@playwright/test';
import {
  ADMIN,
  ALICE,
  BUSINESS_PORT,
  BUSINESS_URL,
  ENTERPRISE_PORT,
  ENTERPRISE_STORAGE_STATE,
  ENTERPRISE_URL,
  LICENSE_KEY_FILE,
  OLGA,
  SIEM_PORT,
  STORAGE_STATE,
  VICTOR,
} from './e2e/seed-data';

/**
 * UI end-to-end tests and screenshots (plan 1F) against a real server with seeded data:
 * `webServer` builds the UI, then `server/scripts/e2e/serve.ts` starts PostgreSQL (a database in
 * QUALOR_TEST_DATABASE_URL, else Testcontainers), seeds it and serves the build on :4280. Every
 * run starts from a fresh database. Chromium only, the build Playwright 1.63.0 pins (installed
 * with `playwright install chromium`, never by `pnpm install`).
 */
const PORT = Number(process.env.QUALOR_E2E_PORT ?? '4280');
const baseURL = `http://127.0.0.1:${PORT}`;
const chrome = { ...devices['Desktop Chrome'], locale: 'en-US', timezoneId: 'UTC' };

export default defineConfig({
  testDir: './e2e',
  outputDir: '../.tmp/playwright/results',
  // One seeded server whose data the tests change: run the files one after another.
  workers: 1,
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  // No retries, in CI either: the tests share one seeded server and change its data (a created
  // project, a changed password), so a retry would start from state the first attempt left and
  // cannot recover, only fail differently. A failure keeps its trace; fix the flake instead.
  retries: 0,
  reporter: process.env.CI
    ? [['list'], ['html', { open: 'never', outputFolder: '../.tmp/playwright/report' }]]
    : 'list',
  use: { baseURL, trace: 'retain-on-failure', colorScheme: 'light' },
  projects: [
    { name: 'setup', testMatch: /auth\.setup\.ts/, use: chrome },
    {
      name: 'e2e',
      testMatch: /.*\.spec\.ts/,
      testIgnore: /(enterprise|sso|business)\.spec\.ts/,
      dependencies: ['setup'],
      use: { ...chrome, storageState: STORAGE_STATE },
    },
    // Plan 4C: the enterprise screens, on the licensed server (audit-log) and its session; plan
    // 4D adds single sign-on and SCIM (sso.spec.ts, features sso and scim). Since 5B the Members
    // and Access tests run on the community server (roles.spec.ts, in the e2e project).
    {
      name: 'enterprise-setup',
      testMatch: /enterprise\.setup\.ts/,
      use: { ...chrome, baseURL: ENTERPRISE_URL },
    },
    {
      name: 'enterprise',
      testMatch: /(enterprise|sso)\.spec\.ts/,
      dependencies: ['enterprise-setup'],
      use: { ...chrome, baseURL: ENTERPRISE_URL, storageState: ENTERPRISE_STORAGE_STATE },
    },
    // Plan 5D: the enterprise server's database under a Business key, after the enterprise tests.
    {
      name: 'business',
      testMatch: /business\.spec\.ts/,
      dependencies: ['enterprise'],
      use: { ...chrome, baseURL: BUSINESS_URL, storageState: ENTERPRISE_STORAGE_STATE },
    },
    {
      name: 'screenshots',
      testMatch: /screenshots\.shot\.ts/,
      dependencies: ['setup', 'enterprise-setup'],
      use: { ...chrome, storageState: STORAGE_STATE, viewport: { width: 1440, height: 900 } },
    },
  ],
  webServer: {
    command:
      'pnpm --filter @qualor/ui build && pnpm --filter @qualor/enterprise build && pnpm --filter @qualor/server e2e:serve',
    url: `${baseURL}/readyz`,
    timeout: 300_000,
    reuseExistingServer: false,
    stdout: 'pipe',
    // serve.ts stops the server and its container (or drops its database) on SIGTERM; Windows
    // ignores this and ends the process tree (Testcontainers' reaper removes the container).
    gracefulShutdown: { signal: 'SIGTERM', timeout: 15_000 },
    env: {
      QUALOR_E2E_PORT: String(PORT),
      QUALOR_UI_DIR: fileURLToPath(new URL('./dist', import.meta.url)),
      QUALOR_E2E_ADMIN_PASSWORD: ADMIN.password,
      QUALOR_E2E_ALICE_PASSWORD: ALICE.initialPassword,
      QUALOR_E2E_LICENSE_KEY_FILE: LICENSE_KEY_FILE,
      QUALOR_E2E_ENTERPRISE_PORT: String(ENTERPRISE_PORT),
      QUALOR_E2E_SIEM_PORT: String(SIEM_PORT),
      QUALOR_E2E_BUSINESS_PORT: String(BUSINESS_PORT),
      // Built by the command above (`pnpm --filter @qualor/enterprise build`).
      QUALOR_E2E_ENTERPRISE_PLUGIN: fileURLToPath(
        new URL('../enterprise/dist/plugin.js', import.meta.url),
      ),
      QUALOR_E2E_OLGA_PASSWORD: OLGA.password,
      QUALOR_E2E_VICTOR_PASSWORD: VICTOR.password,
    },
  },
});
