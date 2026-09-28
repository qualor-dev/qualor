# @qualor/ui

The Qualor web app: Angular 22 (standalone components, signals, zoneless), plain CSS, no UI kit
(brief �2.3). The server serves the built app from the same origin (`QUALOR_UI_DIR`, api.md �4).

- `pnpm ui:build` builds `ui/dist`; `QUALOR_UI_DIR=ui/dist` makes the server serve it.
- `pnpm --filter @qualor/ui start` runs `ng serve` on :4200 with `/api` proxied to a server on :8080.
- `pnpm --filter @qualor/ui test` runs the component tests (Vitest, jsdom); `pnpm test` runs them too.
- `pnpm --filter @qualor/ui i18n:extract` rewrites `src/locale/messages.json` (commit it).
- `pnpm ui:e2e` runs the Playwright suite (`e2e/*.spec.ts`) against a real server with seeded
  data (`server/scripts/e2e/serve.ts`: Testcontainers, or a database in
  `QUALOR_TEST_DATABASE_URL`); `pnpm ui:screenshots` writes one PNG per screen to
  `.tmp/screenshots/`. Both need `pnpm --filter @qualor/ui exec playwright install chromium` once
  (`pnpm install` never downloads browsers) and, on Windows, PowerShell (Testcontainers). Every
  test fails on a console error, a page error, a CSP violation or an unexpected dialog; the only
  browser error line allowed without asking is the 401 of `GET /api/v0/auth/me` in a signed-out
  context, and
  a test that provokes another failed request on purpose names it with `guard.allowFailedLoad()`.
  CSP violations are caught in popups too, and a `confirm`/`prompt` must be announced with
  `guard.expectConfirm()`/`guard.expectPrompt()` (`e2e/fixtures.ts`).
- End-to-end tests run on the admin session `e2e/auth.setup.ts` stores once per run: the login is
  rate-limited to 10 per minute and IP (api.md §2), so a new test signs in itself only when signing
  in is what it tests. The tests share one seeded server and change its data, so they run one after
  another and are never retried (`playwright.config.ts`).
- The enterprise screens (plan 4C: the audit log and its settings; plan 4D: single sign-on and
  SCIM) run on a second, licensed server that `serve.ts` starts on the next port (`audit-log`,
  `sso` and `scim`, its own database, the plugin built by `pnpm --filter @qualor/enterprise build`,
  a local SIEM receiver on the port after): the Playwright projects `enterprise-setup` (its own
  admin session) and `enterprise` (`e2e/enterprise.spec.ts`, `e2e/sso.spec.ts`), and shots 24
  to 30. Plan 5D: a third server, on the port after the receiver, serves the licensed server's
  database under a Business key (`sso`, `audit-log`, `llm.fix-quota`); the Playwright project
  `business` (`e2e/business.spec.ts`) runs there after `enterprise`, on the same admin session.
  The roles, the Members screen and the Access tab are in every edition since plan 5B:
  `e2e/roles.spec.ts` and shots 22 and 23 run on the community server.

Look: the one of qualor.dev (ink navy, cobalt, Schibsted Grotesk and JetBrains Mono), in
`src/styles.css`. The fonts are the `@fontsource-variable` packages (SIL OFL 1.1), bundled and served
from the same origin, so the CSP's `font-src 'self'` holds. The illustrations in `public/art/` are the
site's two-colour screen prints, made by the site's generator: their prompts are the `ui-*` slots in
`qualor.dev/scripts/generate-images.ts`, and `npm run images:gen -- ui-band --force` there rewrites
`public/art/band.webp` here (`QUALOR_UI_ART_DIR` points it at a worktree).

Rules: every user-facing string is marked for i18n with a stable `@@id` (`i18n="@@area.key"` in
templates, `` $localize`:@@area.key:Text` `` in code); templates live in `.html` files; no
`innerHTML` and no sanitizer bypass. `ui/tools/templates.test.ts` checks all three on every
`pnpm test`.
