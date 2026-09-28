# Contributing to Qualor

Thank you for helping. Qualor is an open-source, self-hosted code quality platform. This page
covers how to set up the repository, how changes are made, and the terms under which they are
accepted. The user documentation is in `docs/guide/` and at <https://qualor.dev/docs>.

## Setup

- Node.js 22 (22.22.3 or later) or 24 (24.15 or later), and pnpm through corepack
  (`corepack enable`; the version is pinned in `package.json`).
- Docker, for the database tests (Testcontainers), the images, the Helm chart tests and the
  release tools.
- Bun 1.3.13, only to build the `qualor` binary.

```sh
pnpm install
pnpm lint && pnpm typecheck && pnpm test && pnpm format:check
```

## Commands

- `pnpm install`: install dependencies
- `pnpm lint`, `pnpm typecheck`, `pnpm test`, `pnpm format:check`: must all pass before a pull
  request
- `pnpm schemas`: regenerate `packages/shared/schema/*.json` (CI fails if they are stale)
- `pnpm fixtures`: run the fixture suite
- `pnpm ui:e2e`, `pnpm ui:screenshots`: the UI's Playwright tests, and one screenshot per screen
  (see `ui/README.md`)
- `pnpm helm:test`, `pnpm helm:smoke`: the Helm chart's render tests, and an install on k3s in
  Docker
- `pnpm release:test`, `pnpm release:dry-run`, `pnpm release:verify`: the release tools' tests, a
  complete local release signed with a throwaway key (nothing is published), and its verification
- `pnpm license:keygen`, `pnpm license:sign`, `pnpm license:inspect`: the offline licence tool: an
  Ed25519 signing key pair written outside any repository, a signed licence key, and a key decoded
  and verified against the compiled public keys (a private key is never committed)

## How changes are made

1. **Discuss first.** A new module or a change of behaviour starts as an issue that states its
   purpose, API contract, data shapes and acceptance criteria.
2. **Tests are the contract.** Every capability has tests, and every new capability a fixture in
   `fixtures/`. A bug fix comes with a regression test. Nothing is skipped.
3. **One focused pull request per change.** Its description states what changed, how it was
   tested, which guide pages changed (or why none had to), and any open question.
4. **Boundaries**, enforced by ESLint: the core never imports `enterprise/`; `cli/` and `ui/` never
   import `server/`; `packages/shared` imports no other workspace package.
5. **Security:** validate every input, limit upload sizes, hash tokens, never log secrets. Report
   vulnerabilities as `SECURITY.md` says, never in a public issue.
6. **No telemetry**, and no network calls except those `AGENTS.md` rule 4 lists.
7. **Docs in the same pull request.** A change a user can notice updates `docs/guide/` in the same
   pull request. The website renders those pages at qualor.dev/docs; the maintainers sync it after
   a merge.
8. **Ask first** in an issue before changing the data model, adding a runtime dependency over
   1 MB, touching the licence boundary, or doing anything that cannot be undone.

Commit messages follow the conventional style the history uses (`feat(scope): …`, `fix: …`,
`docs: …`, `test: …`, `ci: …`), and each commit is signed off (below).

## Licence and sign-off

Everything outside `enterprise/` is under the MIT licence (`LICENSE`), and so are your
contributions to it.

`enterprise/` is not MIT. It has its own licence (`enterprise/LICENSE`), whose final terms are not
decided yet. Contributions to `enterprise/` are not accepted from outside the project.

Every commit carries a `Signed-off-by` line, which certifies the
[Developer Certificate of Origin 1.1](https://developercertificate.org/): that you wrote the change
or have the right to submit it under the MIT licence. `git commit -s` adds the line:

```
Signed-off-by: Ada Lovelace <ada@example.com>
```

Use your real name and an email address you can be reached at. The `dco` job of CI checks every
commit of a pull request or merge request, merges excepted. A pull request whose commits lack
the line cannot be merged; `git commit --amend -s` or `git rebase --signoff` adds it afterwards.
