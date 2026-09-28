# AGENTS.md: rules for AI agents working on Qualor

## Commands

- `pnpm install`: install dependencies
- `pnpm lint`, `pnpm typecheck`, `pnpm test`, `pnpm format:check`: must all pass before a PR
- `pnpm schemas`: regenerate `packages/shared/schema/*.json` (CI fails if they are stale)
- `pnpm fixtures`: run the fixture suite
- `pnpm ui:e2e`, `pnpm ui:screenshots`: the UI's Playwright tests against a seeded server, and one PNG per screen in `.tmp/screenshots/` (see `ui/README.md`)
- `pnpm helm:test`, `pnpm helm:smoke`: the Helm chart's render tests (in the release toolbox image), and an install on k3s in Docker (needs a built `qualor/server:dev`)
- `pnpm release:test`, `pnpm release:dry-run`, `pnpm release:verify <dir>`: the release tools' tests, a complete local release in `.tmp/release/<version>/` signed with a throwaway key (nothing is published), and its verification
- `pnpm license:keygen`, `pnpm license:sign`, `pnpm license:inspect <key or ->`: the offline licence tool: an Ed25519 signing key pair written outside any repository, a signed licence key, and a key decoded and verified against the compiled public keys (a private key is never committed)

## Rules

1. Discuss first: a new module or a change of behaviour starts from an agreed description of its purpose, contract and acceptance criteria.
2. Tests are the contract. Never skip tests. Add a fixture for every new capability.
3. One task = one focused PR that states what changed, how it was tested, and open questions.
4. No telemetry and no network calls except to the configured server and SCM; the webhook URLs an administrator configured; the LLM provider an instance administrator configured (from the server only, and only for an AI action a person started); the identity provider an instance administrator configured for single sign-on (the OIDC issuer and the endpoints its discovery document names; a SAML metadata URL only when the administrator asks), from the server only; and, only while `qualor import sonarqube` runs, read-only (`GET`) calls to the SonarQube `--url` the user names.
5. Boundaries (enforced by ESLint): core never imports `enterprise/`; `cli/` and `ui/` never import `server/`; `packages/shared` imports no other workspace package.
6. Security: validate every input, size-limit uploads, hash tokens, never log secrets.
7. Ask before: changing the data model after migrations exist, adding a runtime dependency > 1 MB, changing the licence boundary, or anything irreversible.
8. Everything outside `enterprise/` is MIT.
9. Docs and site stay current, in the same PR as the change (see below). A change is not done until they are.

## User documentation

- **`docs/guide/`** is the user documentation: Markdown, in plain English, for people who install and use Qualor (not for Qualor's developers). `docs/guide/README.md` is its index: the numbered list of pages is the site's navigation order, so a new page gets a line there. `docs/guide/ai-prompts.md` holds copy-paste prompts that let an AI agent set Qualor up; each prompt is a fenced block with the language `prompt`.
- **Every change a user can notice updates `docs/guide/` in the same PR:** a CLI command, flag, exit code or `qualor.yml` key; a server variable; a UI screen or label the guide names; an API endpoint the guide shows; an image, a default, a limit, an analyzer or a language; a CI template (`templates/`, `integrations/`). Update the prompts in `ai-prompts.md` when their steps change. The PR description lists which guide pages changed, or says why none had to.
- Write the guide for the released behaviour on `main`. Describe features that are not shipped yet as not yet, never as done. Installation always uses the published images (`qualor/server`, `qualor/scanner`, `qualor/scanner-dotnet` on Docker Hub, tagged with the major and the full version) and the catalog component `gitlab.com/qualor/qualor`; the guide never asks users to clone the repository or build images (building is in `deploy/README.md`, for contributors). The guide's `compose.yml` (`docs/guide/install-server.md`) runs one `server` service with the embedded PostgreSQL; its "External PostgreSQL" example follows `deploy/docker-compose.yml`. When the server's variables, hardening or that file's services change, change the guide's copies too. Links inside the guide are relative (`./gitlab.md#anchor`); links to other repository files are relative paths (`../../deploy/README.md`), and the site turns them into GitHub links.
- The guide is also published at `https://qualor.dev/docs`, with each page's raw Markdown at `/docs/<page>.md` for AI agents; the maintainer syncs it from `main`.
