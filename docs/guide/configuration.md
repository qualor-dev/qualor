# Configuration reference

The scanner needs only `QUALOR_URL` and `QUALOR_TOKEN`. A repository with no `qualor.yml` still gets
a useful scan. Add `qualor.yml` at the repository root when your team makes a choice: coverage report
paths, excludes, rulesets or SARIF files.

An editor can autocomplete `qualor.yml` from the JSON Schema in
[`packages/shared/schema/qualor.schema.json`](../../packages/shared/schema/qualor.schema.json).

## Precedence

From highest to lowest:

1. command-line flags (`--project-key`, `--sarif`, …)
2. environment variables (`QUALOR_*`)
3. `qualor.yml` (or the file named by `--config` / `QUALOR_CONFIG`)
4. values detected from GitLab CI or GitHub Actions
5. built-in defaults

**Secrets never come from `qualor.yml`.** The token is read only from `QUALOR_TOKEN` or
`--token-file`, and a file with a `token` key is refused. The token is also sent only to a server URL
from `QUALOR_URL` or `--server-url`, never to `server.url` from the file. A merge request can edit the
file, so it must not be able to redirect the token.

## `qualor.yml`

Only `version` is required. Unknown keys are an error, so typos are caught.

```yaml
version: 1                          # required; only 1 is valid

project:
  key: acme/payments-api            # default: CI_PROJECT_PATH / GITHUB_REPOSITORY
  name: Payments API                # default: last segment of the key
  version: ${CI_COMMIT_TAG}         # optional label; used by the "previous_version" new-code definition

server:
  timeoutSeconds: 30                # per HTTP request

sources:
  include: ['**/*']
  exclude: ['generated/**', 'coverage/**']   # added to the built-in excludes
  useGitignore: true
tests:
  include: ['**/*.test.*', '**/*.spec.*', '**/__tests__/**', '**/src/test/**', '**/*Tests/**',
            '**/test_*.py', '**/*_test.py', '**/conftest.py']
  exclude: []

languages: auto                     # or [typescript, javascript, java, csharp, python, html, css]

analyzers:
  eslint:    { enabled: auto, configFile: null, args: [], timeoutSeconds: 900 }
  sonarjs:   { enabled: auto, timeoutSeconds: 900, typeChecking: auto }
  ruff:      { enabled: auto, select: [qualor-default], ignore: [], timeoutSeconds: 600 }
  pmd:       { enabled: auto, rulesets: [qualor-default], timeoutSeconds: 900 }
  spotbugs:  { enabled: auto, classDirs: [target/classes, build/classes/java/main], auxClasspathFile: null, timeoutSeconds: 1200 }
  semgrep:   { enabled: auto, binary: auto, configs: [qualor-default], timeoutSeconds: 900 }
  gitleaks:  { enabled: true, configFile: null, timeoutSeconds: 300 }
  trivy:     { enabled: auto, timeoutSeconds: 600 }
  roslyn:    { enabled: auto, bundledAnalyzers: true, sonarAnalyzer: true }
  stylelint: { enabled: auto, configFile: null, timeoutSeconds: 600 }   # configFile: qualor-default forces Qualor's default
  htmlhint:  { enabled: auto, configFile: null, timeoutSeconds: 300 }

sarif:
  - path: reports/osv.sarif
    engine: osv-scanner

coverage:
  reports:
    - path: coverage/lcov.info      # globs allowed
      format: auto                  # auto | lcov | cobertura | jacoco
  pathPrefixes: []

duplication:
  enabled: true
  minTokens: 100
  minLines: 10
  exclude: []

newCode:
  referenceBranch: null             # branches other than main compare with this; default: the main branch

scm:
  autoFetch: true                   # fetch missing baseline commits when the clone is shallow
  mainBranch: null                  # default: CI_DEFAULT_BRANCH / the server's setting

gate:
  wait: true                        # wait for the verdict and use it for the exit code
  timeoutSeconds: 300
  failOnError: true                 # a gate in "error" fails the job
```

### Variables in values

`${VAR}` and `${VAR:-default}` are replaced from the environment. Variables whose names look like
secrets (`*TOKEN`, `*SECRET`, `*PASSWORD`, `*API_KEY`, `*PRIVATE_KEY`, `*_PASS`, …) always resolve to
an empty string. That keeps a secret from leaking into the report through the config.

### Built-in excludes

These always apply, and you can only add to them: `node_modules`, `.git`, `dist`, `build`, `target`
(sources only; SpotBugs still reads the classes), `vendor`, `*.min.js`, `*.min.css`, `.qualor/`, .NET `obj/`,
`bin/Debug`, `bin/Release`, generated C# (`*.g.cs`, `*.g.i.cs`, `*.Designer.cs`), Python virtual
environments and caches (`.venv`, `venv`, `.tox`, `.nox`, `__pycache__`, `__pypackages__`, `.eggs`,
`site-packages`), binary files, and nested git repositories. Files over 1 MiB are skipped for
metrics and duplication, but analyzers still see them.

## Environment variables (scanner)

The server's variables (such as `QUALOR_PUBLIC_URL`, `QUALOR_SCM_INTERNAL_HOSTS` and
`QUALOR_LLM_INTERNAL_HOSTS`) are in [Install the server](./install-server.md#server-settings).

| Variable | Meaning |
|---|---|
| `QUALOR_URL` | server base URL (`https://…`) |
| `QUALOR_TOKEN` | project analysis token or personal token |
| `QUALOR_PROJECT_KEY` | overrides `project.key` |
| `QUALOR_CONFIG` | path to the config file |
| `QUALOR_CA_FILE` | a PEM CA bundle for the server's certificate. Keep it outside the checkout |
| `QUALOR_LOG_LEVEL` | `error`, `warn`, `info` (default) or `debug` |
| `QUALOR_CACHE_DIR` | cache directory (default `~/.cache/qualor`) |
| `QUALOR_TRIVY_CACHE_DIR` | another Trivy database directory (absolute, outside the checkout) |
| `QUALOR_SONARJS_DIR` | another location for Qualor's sonarjs pass (absolute, outside the checkout; default `/opt/qualor/sonarjs`, set in `qualor/scanner`) |
| `QUALOR_WEBLINT_DIR` | directory of the HTML and CSS linters (default `/opt/qualor/weblint`, in the `qualor/scanner` image); absolute and outside the repository |
| `QUALOR_DOTNET_ANALYZERS` | directory of the bundled Roslyn analyzer DLLs (set in `qualor/scanner-dotnet`) |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | a proxy between the runner and the server (`http://` proxies) |

Values read from CI, when present: the revision, the branch, the MR/PR id and its target, the default
branch and the project path, from `CI_*` on GitLab and `GITHUB_*` plus the event payload on GitHub.
Outside CI, the scanner uses `git rev-parse HEAD` and the current branch, and never assumes a merge
request.

## Examples

Minimal, with coverage:

```yaml
version: 1
coverage:
  reports: [{ path: coverage/lcov.info }]
```

Java with a custom PMD ruleset, osv-scanner SARIF and JaCoCo:

```yaml
version: 1
analyzers:
  pmd: { rulesets: [config/pmd.xml] }
  spotbugs: { classDirs: [target/classes] }
sarif:
  - { path: osv-scanner.sarif, engine: osv-scanner }
coverage:
  reports: [{ path: '**/jacoco.xml', format: jacoco }]
```

Monorepo with one Qualor project per service. Each service has its own config file, and each CI job
passes `--config`:

```yaml
# services/billing/qualor.yml
version: 1
project: { key: acme/monorepo-billing, name: Billing }
sources:
  include: ['services/billing/**']
coverage:
  reports: [{ path: services/billing/coverage/lcov.info }]
```

```sh
qualor scan --config services/billing/qualor.yml
```
