# qualor/scanner

Short description: Qualor CI scanner: the qualor CLI with ESLint, PMD, SpotBugs, OpenGrep, Gitleaks and Trivy.

## Overview

Qualor is an open-source, self-hosted, GitLab-first code quality platform: a SonarQube
alternative without lines-of-code licensing. This image runs the analysis in your CI: the
`qualor` CLI runs the analyzers on the checkout, uploads one report to your Qualor server
([`qualor/server`](https://hub.docker.com/r/qualor/server)) and exits with the quality gate's
verdict.

- Source, documentation and issues: <https://github.com/qualor-dev/qualor>
- Configuration reference (`qualor.yml`, environment, exit codes):
  <https://qualor.dev/docs/configuration>

### What is inside

- The `qualor` CLI (entrypoint `qualor`, default command `scan`), a single binary built with Bun.
- Node.js 22.23.2 with npm and corepack, to run the project's own ESLint from its `node_modules`.
- Eclipse Temurin JRE 17.0.20+8, for PMD and SpotBugs.
- git, with `safe.directory '*'`, since CI runners check out as another user.
- The pinned analyzers in `/opt/qualor/bin`: PMD 7.27.0, SpotBugs 4.10.4, OpenGrep 1.30.0,
  Gitleaks 8.30.1 and Trivy 0.74.0, with a snapshot of Trivy's vulnerability database (the scan
  never downloads one). No Semgrep or OpenGrep rules are bundled yet (`/opt/qualor/rules/semgrep` is
  empty): name your own rule files in `qualor.yml`, or that analyzer is skipped.
- Runs as the user `node` (uid 1000) in `/src`; about 3.0 GB. Every base image is pinned by
  digest.

### GitLab CI

```yaml
qualor:
  image: { name: qualor/scanner:<tag>, entrypoint: [''] }
  variables: { GIT_DEPTH: 0 }
  script: [qualor scan]
```

### GitHub Actions

```yaml
qualor:
  runs-on: ubuntu-latest
  container: { image: qualor/scanner:<tag>, options: --user 1001 }
  steps:
    - uses: actions/checkout@v4 # pin it to a commit SHA
      with: { fetch-depth: 0 }
    - run: qualor scan
      env: { QUALOR_URL: '${{ vars.QUALOR_URL }}', QUALOR_TOKEN: '${{ secrets.QUALOR_TOKEN }}' }
```

The scan needs the full git history (`GIT_DEPTH: 0`, `fetch-depth: 0`). Install a JavaScript or
TypeScript project's dependencies before `qualor scan`, and build a Java project first (SpotBugs
analyses compiled classes).

### Environment

| Variable                                | Meaning                                                                       |
| --------------------------------------- | ----------------------------------------------------------------------------- |
| `QUALOR_URL`                            | the Qualor server's base URL                                                  |
| `QUALOR_TOKEN`                          | a project analysis token or a personal access token (keep it a masked secret) |
| `QUALOR_CA_FILE`                        | a PEM file with the CA of a server whose certificate a private CA issued      |
| `QUALOR_PROJECT_KEY`                    | overrides `project.key` of `qualor.yml`                                       |
| `QUALOR_CONFIG`                         | the path of the config file (default `qualor.yml` at the repository root)     |
| `QUALOR_LOG_LEVEL`                      | `error`, `warn`, `info` (default) or `debug`                                  |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | the proxy for the upload (`http://` proxy URLs only)                          |

The token is only ever sent to a server URL that came from `QUALOR_URL` or `--server-url`, never
to one that only the repository's `qualor.yml` names. TLS certificates are always verified.

### Exit codes

| Code | Meaning                                                                                       |
| ---- | --------------------------------------------------------------------------------------------- |
| 0    | report accepted and the gate passed (or the gate is not awaited, or the project has none)     |
| 1    | the gate failed (or ended in `error` with `failOnError: true`)                                |
| 2    | usage or configuration error: invalid `qualor.yml`, missing URL or token, not a git work tree |
| 3    | a required analyzer failed                                                                    |
| 4    | server unreachable, upload rejected, gate polling timed out, or an internal error             |
| 5    | authentication or authorisation failure (401 or 403)                                          |

An interrupted scan exits 128 plus the signal number (130 for SIGINT, 143 for SIGTERM).

### Licences

The Qualor CLI is MIT-licensed. The image bundles third-party software under its own licences:
OpenGrep and SpotBugs (LGPL-2.1), PMD (BSD-style, with Apache-2.0 parts), Gitleaks (MIT), the
Temurin JRE (GPL-2.0 with the Classpath Exception), Node.js (MIT), and the Bun runtime inside the
`qualor` binary (MIT; it links JavaScriptCore/WebKit and TinyCC, LGPL). The notices are in
`/opt/qualor/NOTICE.md` and the licence texts in `/opt/qualor/licenses/`. The complete
corresponding source of every copyleft component is published as
[`qualor/scanner-sources`](https://hub.docker.com/r/qualor/scanner-sources) with the same tag;
`/opt/qualor/SOURCES.md` is its index.

### Trademarks

SonarQube and SonarCloud are trademarks of SonarSource SA. Qualor is an independent project and is
not affiliated with, sponsored or endorsed by SonarSource. Their names are used only to describe
compatibility and to compare features.
