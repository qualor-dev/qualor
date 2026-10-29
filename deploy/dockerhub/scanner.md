# qualor/scanner

Short description: Code quality scanner: JS/TS, Java, Kotlin, Swift, Python, PHP, Ruby, Go, C/C++, HTML, CSS; one gate

Categories: Developer tools, Integration & delivery, Security

## Overview

The CI scanner of [Qualor](https://qualor.dev), the open-source, self-hosted SonarQube alternative
with no lines-of-code licence. One job in your pipeline runs the analyzers on the checkout, works
out which lines the merge request changed, and sends one report to your Qualor server
([`qualor/server`](https://hub.docker.com/r/qualor/server)). It waits for the verdict and fails
the job when the quality gate fails. When AI review is switched on for the project, it also sends
the repository snapshot that the review reads.

Website: <https://qualor.dev> · Documentation: <https://qualor.dev/docs> · Source and issues:
<https://github.com/qualor-dev/qualor> · Configuration reference (`qualor.yml`, environment, exit
codes): <https://qualor.dev/docs/configuration>

### Tags

Every release has its full version tag, such as `0.13.0`, and a minor tag, such as `0.13`, that
follows its patch releases. There is no `latest` tag. For C#, use
[`qualor/scanner-dotnet`](https://hub.docker.com/r/qualor/scanner-dotnet) with the same tag.

### GitLab CI

The component from the GitLab CI/CD catalog is the shortest way, and it also shows the findings
in GitLab's merge request widget:

```yaml
include:
  - component: gitlab.com/qualor/qualor/qualor@0.13
    inputs:
      image-tag: '0.13'
```

Or run the image in a job of your own:

```yaml
qualor:
  image: { name: qualor/scanner:0.13, entrypoint: [''] }
  variables: { GIT_DEPTH: 0 }
  script: [qualor scan]
```

Either way, add the CI/CD variables `QUALOR_URL` and `QUALOR_TOKEN` (masked, not protected, so
that merge request pipelines get the token too). The GitLab guide: <https://qualor.dev/docs/gitlab>.

### GitHub Actions

```yaml
qualor:
  runs-on: ubuntu-latest
  container: { image: qualor/scanner:0.13, options: --user 1001 }
  steps:
    - uses: actions/checkout@v4 # pin it to a commit SHA
      with: { fetch-depth: 0 }
    - run: qualor scan
      env: { QUALOR_URL: '${{ vars.QUALOR_URL }}', QUALOR_TOKEN: '${{ secrets.QUALOR_TOKEN }}' }
```

Before `qualor scan`:

- Check out the full git history (`GIT_DEPTH: 0`, `fetch-depth: 0`).
- JavaScript and TypeScript: install the project's dependencies (ESLint runs from `node_modules`).
- Java: build the project (SpotBugs reads compiled classes).
- PHP: run `composer install --no-scripts --no-plugins` (PHPStan reads `vendor/`, never runs it).
- Go: run `go mod download` or vendor the dependencies. Qualor never downloads modules.
- C and C++: nothing for cppcheck. For clang-tidy, scan in the job that built the project, with your
  own clang-tidy and its `compile_commands.json`.

### What is inside

The `qualor` CLI (entrypoint `qualor`, default command `scan`) is a single binary built with
Bun. It runs as the user `node` (uid 1000) in `/src`. The image is about 4.1 GB, and every base
image is pinned by digest.

| Tool                       | Version                                               | For                                                  |
| -------------------------- | ----------------------------------------------------- | ---------------------------------------------------- |
| PMD                        | 7.27.0                                                | Java                                                 |
| SpotBugs with FindSecBugs  | 4.10.4, 1.14.0                                        | Java bytecode, security rules                        |
| detekt                     | 1.23.8                                                | Kotlin                                               |
| SwiftLint                  | 0.65.1 (static Linux build)                           | Swift                                                |
| Ruff                       | 0.16.9                                                | Python                                               |
| PHPStan                    | 2.2.16, on Debian's PHP 8.2                           | PHP                                                  |
| RuboCop                    | RuboCop 1.91.0 on Ruby 4.0.7                          | Ruby                                                 |
| staticcheck, go vet, gosec | 2026.2.1, Go 1.27.1, 2.29.0                           | Go, offline                                          |
| cppcheck                   | 2.22.0 (built from source)                            | C, C++                                               |
| eslint-plugin-sonarjs      | 2.0.4, on Qualor's own ESLint 9                       | SonarQube-compatible JavaScript and TypeScript rules |
| stylelint, HTMLHint        | 17.15, 1.9.2                                          | CSS, SCSS, HTML                                      |
| OpenGrep                   | 1.30.0                                                | Qualor's security rules and your own rule files      |
| Gitleaks                   | 8.30.1                                                | secrets                                              |
| Trivy                      | 0.74.0, with a snapshot of its vulnerability database | dependencies                                         |
| qualor-rules               | 2026.10.6                                             | Qualor's security rules                              |

The project's own ESLint runs on the bundled Node.js 22.23.4 (with npm and corepack). PMD, SpotBugs
and detekt run on the Eclipse Temurin JRE 17.0.20+8. git is configured with `safe.directory '*'`,
since CI runners check out as another user. The scan never downloads Trivy's database. Not
included: clang-tidy (scan in the job that built your project to use your own), the C#
analyzers (use [`qualor/scanner-dotnet`](https://hub.docker.com/r/qualor/scanner-dotnet)), and
Semgrep or OpenGrep rules of your own (name your rule files in `qualor.yml`).

**Qualor's security rules** (source-available) cover JavaScript and TypeScript, Python, Java, Go
and C#. They follow HTTP request data into SQL, NoSQL, shell commands, code and template
evaluation, file paths, LDAP and XPath queries, regular expressions, outgoing requests, redirects
and HTML responses. They also report disabled TLS verification, XXE, zip slip, unsafe
deserialization and broken ciphers. Weak hashes, cookies without their flags, raw HTML in React,
unsafe tar extraction and XML parsers that load DTDs are reported as security hotspots to review.

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

The Qualor CLI is MIT-licensed. Qualor's security rules are under PolyForm Shield 1.0.0
(source-available, not MIT). The bundled software keeps its own licences:

| Component                        | Licence                                                                                                                         |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| OpenGrep, SpotBugs               | LGPL-2.1                                                                                                                        |
| FindSecBugs                      | LGPL-3.0                                                                                                                        |
| PMD                              | BSD-style, with Apache-2.0 parts                                                                                                |
| Gitleaks, Trivy                  | MIT and Apache-2.0, with MPL-2.0 Go modules                                                                                     |
| Ruff                             | MIT, with three MPL-2.0 crates compiled in                                                                                      |
| detekt                           | Apache-2.0; Trove4J (LGPL-2.1) inside its jar                                                                                   |
| PHPStan                          | MIT; its Composer packages MIT, BSD-3-Clause and Apache-2.0                                                                     |
| PHP 8.2 (Debian)                 | PHP License 3.01                                                                                                                |
| Go                               | BSD-3-Clause with Google's patent grant                                                                                         |
| staticcheck                      | MIT                                                                                                                             |
| gosec                            | Apache-2.0                                                                                                                      |
| SwiftLint                        | MIT; its static build links the Swift runtime, libc++, musl, curl, BoringSSL, libxml2, zlib and mimalloc, none of them copyleft |
| Ruby 4.0.7, RuboCop and its gems | Ruby under its BSD-2-Clause option; the gems MIT, Ruby or BSD-2-Clause                                                          |
| cppcheck 2.22.0                  | GPL-3.0-or-later, built from source                                                                                             |
| eslint-plugin-sonarjs 2.0.4      | LGPL-3.0, the last release before the SONAR Source-Available License; its npm dependency tree includes axe-core (MPL-2.0)       |
| Temurin JRE                      | GPL-2.0 with the Classpath Exception                                                                                            |
| Node.js                          | MIT                                                                                                                             |
| Bun, inside the `qualor` binary  | MIT; it links JavaScriptCore/WebKit and TinyCC (LGPL)                                                                           |

The notices are in `/opt/qualor/NOTICE.md` and the licence texts in `/opt/qualor/licenses/`. The
complete corresponding source of every copyleft component is published as
[`qualor/scanner-sources`](https://hub.docker.com/r/qualor/scanner-sources) with the same tag;
`/opt/qualor/SOURCES.md` is its index.

### Trademarks

SonarQube and SonarCloud are trademarks of SonarSource SA. Qualor is an independent project and is
not affiliated with, sponsored or endorsed by SonarSource. Their names are used only to describe
compatibility and to compare features.
