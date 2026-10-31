import { fileURLToPath } from 'node:url';

/**
 * What `server/scripts/e2e/seed.ts` creates, as the end-to-end tests see it. The passwords are
 * passed to the seeding server by playwright.config.ts, so they are defined only here. They are
 * test-only: a real deployment has no default admin password (QUALOR_BOOTSTRAP_ADMIN_PASSWORD is
 * required) and never uses these.
 */
export const ADMIN = { username: 'admin', password: 'e2e admin passphrase' };
export const ALICE = {
  username: 'alice',
  initialPassword: 'alice initial passphrase',
  newPassword: 'alice chose this passphrase',
};

export const PAYMENTS = { key: 'acme/payments-api', name: 'Payments API' };
export const SHOP = { key: 'acme/web-shop', name: 'Web Shop' };
export const LEGACY = { key: 'acme/legacy-billing', name: 'Legacy Billing' };
export const MERGE_REQUEST = { id: '42', source: 'feature/refund-limits' };

/** An issue message and a rule description that carry HTML; both must stay text. */
export const XSS_MESSAGE =
  'Using <img src="/receipt.png" onerror="alert(1)"> could result in slower LCP and higher bandwidth. Consider using <Image /> from next/image to automatically optimize images.';
export const XSS_RULE_TEXT = '<img src="/logo.png" onerror="alert(\x27rule\x27)">';
/**
 * The open issue of Payments API with three related locations (seed.ts): src/refunds/limits.ts:10,
 * src/payments/gateway.ts:88–92 and src/payments/gateway.ts:140.
 */
export const RELATED_ISSUE_MESSAGE = 'Detected eval() with a non-literal argument.';
/**
 * The finding of the AI review on merge request !42 of Payments API (seed.ts `seedAiFinding`): an
 * issue of the `ai` engine whose body carries markup that must stay text, with a one-line
 * suggestion.
 */
export const AI_FINDING = {
  message: 'Loose equality lets a value of another type pass for the euro.',
  bodyMarkup: '<img src=x onerror="alert(1)">',
  assumption: 'order.currency is always a string.',
  suggestedLine: '  if (order.currency === "EUR") {',
  reviewedCommit: 'dddddddddddd',
};
/** Payments API's own webhook and second analysis token (seed.ts). */
export const PROJECT_WEBHOOK_URL = 'https://hooks.example.com/payments';

export const STORAGE_STATE = '../.tmp/playwright/admin.json';

/**
 * enterprise.md §14.2: the e2e server is a test bundle that also accepts keys signed by its
 * throwaway `test-e2e` key; `server/scripts/e2e/serve.ts` writes one such key here before it is
 * ready (playwright.config.ts passes the path) and removes it when it stops.
 */
export const LICENSE_KEY_FILE = fileURLToPath(
  new URL('../../.tmp/playwright/e2e-license-key', import.meta.url),
);

/**
 * 6M: the last report of Payments API's main branch, with its dependency inventory, which
 * `server/scripts/e2e/serve.ts` writes here (playwright.config.ts passes the path) so the Business
 * test can ingest it again after setting a licence policy. Removed when the server stops.
 */
export const PAYMENTS_REPORT_FILE = fileURLToPath(
  new URL('../../.tmp/playwright/e2e-payments-report.json', import.meta.url),
);
/**
 * 6M: Payments API's dependency inventory (seed.ts PAYMENTS_DEPENDENCIES): seven entries, six with
 * a known licence; `ledger-gpl` is strong copyleft.
 */
export const DEPENDENCIES = {
  known: 6,
  total: 7,
  strongCopyleft: { name: 'ledger-gpl', version: '2.1.0', license: 'GPL-3.0-only' },
  unknown: { name: 'left-pad-internal', path: 'web/pnpm-lock.yaml' },
};

/**
 * Vulnerability monitoring: the tag scan of Payments API (seed.ts, tag `v1.0.0`) stored as a
 * released version with one package that no branch has.
 */
export const VERSION = { option: '1.0.0 (tracked)', package: 'legacy-queue' };

/**
 * Plan 4C (rbac-audit.md §17): the licensed e2e server `server/scripts/e2e/serve.ts` starts next
 * to the community one, with the Enterprise plan's features (`ENTERPRISE_FEATURES`, plan 5D:
 * `audit-log.stream` and `sso.multi` among them), its own database and its own admin session
 * (`enterprise.setup.ts`), and the local receiver its audit stream may post to.
 *
 * Plan 5D: a third server on BUSINESS_PORT serves the enterprise server's database under a
 * Business key (`sso`, `audit-log`, `support-bundle`, `license-policy`, `vuln.priority`,
 * `vuln.alerts`, `sbom`), as a replica would after a move to the Business plan. It shares that
 * database's sessions, so the enterprise admin's session works there too (cookies do not depend
 * on the port). `business.spec.ts` runs after the enterprise tests, so it sees the stream they
 * configured, kept and paused.
 */
const E2E_PORT = Number(process.env.QUALOR_E2E_PORT ?? '4280');
export const ENTERPRISE_PORT = E2E_PORT + 1;
export const ENTERPRISE_URL = `http://127.0.0.1:${ENTERPRISE_PORT}`;
export const SIEM_PORT = E2E_PORT + 2;
export const SIEM_URL = `http://127.0.0.1:${SIEM_PORT}/qualor-audit`;
export const ENTERPRISE_STORAGE_STATE = '../.tmp/playwright/enterprise-admin.json';
export const BUSINESS_PORT = E2E_PORT + 3;
export const BUSINESS_URL = `http://127.0.0.1:${BUSINESS_PORT}`;
/** Mail E2: serve.ts's reader of pending account emails (community server). */
export const MAIL_PORT = E2E_PORT + 4;
export const MAIL_URL = `http://127.0.0.1:${MAIL_PORT}`;
/** 6G: the fake Slack receiver (server/scripts/e2e/serve.ts `chatReceiver`). */
export const CHAT_PORT = E2E_PORT + 5;
export const CHAT_URL = `http://127.0.0.1:${CHAT_PORT}`;
/** An organisation admin of Default who is not an instance admin, on both servers (seedRoles). */
export const OLGA = { username: 'olga', password: 'olga e2e passphrase' };
/** A user in no organisation, with a Viewer grant on Web Shop only (seed.ts seedRoles). */
export const VICTOR = { username: 'victor', password: 'victor e2e passphrase' };
/**
 * A user with a Project admin grant on Web Shop only (seed.ts seedRoles). The seed leaves her the
 * initial password the admin set, so she must change it at her first sign-in (ruling R7);
 * `password` is the one `project-settings.spec.ts` gives her, which no other test uses.
 */
export const PETRA = {
  username: 'petra',
  initialPassword: 'petra initial passphrase',
  password: 'petra e2e passphrase',
};
/**
 * An organisation Viewer of Default, a member without `org.ai.manage` (seed.ts seedRoles). The seed
 * leaves her the initial password the admin set, so she must change it at her first sign-in (ruling
 * R7); `password` is the one `ai-review.spec.ts` gives her, which no other test uses.
 */
export const VERA = {
  username: 'vera',
  initialPassword: 'vera initial passphrase',
  password: 'vera e2e passphrase',
};

/**
 * Vulnerability monitoring (seed.ts `seedVulnerabilities`): Payments API main has a critical
 * `handlebars` row that is new and a high `lodash` row that is not, with an open Trivy issue for
 * the critical one. Legacy Billing has a tracked version 1.0.0 with a new row, and an unsupported
 * version 0.9.0 (the fold).
 */
export const VULNERABILITIES = {
  critical: { id: 'CVE-2019-19919', package: 'handlebars' },
  high: { id: 'CVE-2020-8203', package: 'lodash' },
  legacy: { id: 'CVE-2024-99001', package: 'legacy-queue', tracked: '1.0.0', untracked: '0.9.0' },
  issueMessage:
    'handlebars 4.0.11: CVE-2019-19919 Prototype pollution in handlebars (fixed in 4.3.0)',
};
