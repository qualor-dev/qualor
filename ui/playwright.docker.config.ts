import { defineConfig, devices } from '@playwright/test';
import { DOCKER_STORAGE_STATE } from './e2e/docker-seed';

/**
 * `pnpm deploy:screenshots` (plan 1G): screenshots of the dockerized server. Unlike
 * playwright.config.ts there is no web server here: `tools/deploy/screenshots.ts` brings up the
 * compose stack, scans this repository and the fixtures into it, and passes the server's address,
 * the admin password and a file describing what it seeded in the environment. Chromium only.
 */
const baseURL = process.env['QUALOR_DOCKER_URL'];
if (!baseURL) throw new Error('QUALOR_DOCKER_URL is not set: run pnpm deploy:screenshots');
const chrome = { ...devices['Desktop Chrome'], locale: 'en-US', timezoneId: 'UTC' };

export default defineConfig({
  testDir: './e2e',
  outputDir: '../.tmp/playwright/docker-results',
  workers: 1,
  fullyParallel: false,
  retries: 0,
  reporter: 'list',
  use: { baseURL, trace: 'retain-on-failure', colorScheme: 'light' },
  projects: [
    { name: 'docker-setup', testMatch: /docker\.setup\.ts/, use: chrome },
    {
      name: 'docker-screenshots',
      testMatch: /docker\.shot\.ts/,
      dependencies: ['docker-setup'],
      use: {
        ...chrome,
        storageState: DOCKER_STORAGE_STATE,
        viewport: { width: 1440, height: 900 },
      },
    },
  ],
});
