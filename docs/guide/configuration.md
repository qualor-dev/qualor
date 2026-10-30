# Configuration reference

The scanner needs only `QUALOR_URL` and `QUALOR_TOKEN`: a repository without `qualor.yml` still gets
a useful scan. Add `qualor.yml` at the repository root to set coverage report paths, excludes,
rulesets or SARIF files. Editors can autocomplete it from the JSON Schema in
[`packages/shared/schema/qualor.schema.json`](../../packages/shared/schema/qualor.schema.json).

## Precedence

From highest to lowest:

1. command-line flags (`--project-key`, `--sarif`, …)
2. environment variables (`QUALOR_*`)
3. `qualor.yml` (or the file named by `--config` or `QUALOR_CONFIG`)
4. values detected from GitLab CI or GitHub Actions
5. built-in defaults

**Secrets never come from `qualor.yml`.** A merge request can edit the file, so it must not be able
to redirect the token:

- The token is read only from `QUALOR_TOKEN` or `--token-file`. A file with a `token` key is
  refused.
- The token is sent only to a server URL from `QUALOR_URL` or `--server-url`, never to `server.url`
  from the file.

## `qualor.yml`

Only `version` is required. Unknown keys are an error, so typos are caught.

```yaml
version: 1                          # required; only 1 is valid

project:
  key: acme/payments-api            # default: CI_PROJECT_PATH / GITHUB_REPOSITORY
  name: Payments API                # default: last segment of the key
  version: ${CI_COMMIT_TAG}         # optional label; a tag scan's version, and "previous_version" new code

server:
  timeoutSeconds: 30                # per HTTP request

sources:
  include: ['**/*']
  exclude: ['generated/**', 'coverage/**']   # added to the built-in excludes
  useGitignore: true
tests:
  include: ['**/*.test.*', '**/*.spec.*', '**/__tests__/**', '**/src/test/**', '**/*Tests/**',
            '**/test_*.py', '**/*_test.py', '**/conftest.py', '**/*Test.php',
            '**/src/androidTest/**', '**/src/*Test/**', '**/*_spec.rb', '**/*_test.rb',
            '**/spec/**/*.rb', '**/test/**/*.rb', '**/*_test.go']
  exclude: []

languages: auto                     # or [typescript, javascript, java, csharp, python, html, css, kotlin, swift, php, ruby, go, c, cpp]

analyzers:
  eslint:    { enabled: auto, configFile: null, args: [], timeoutSeconds: 900 }
  sonarjs:   { enabled: auto, timeoutSeconds: 900, typeChecking: auto }
  ruff:      { enabled: auto, select: [qualor-default], ignore: [], timeoutSeconds: 600 }
  pmd:       { enabled: auto, rulesets: [qualor-default], timeoutSeconds: 900 }
  spotbugs:  { enabled: auto, classDirs: [target/classes, build/classes/java/main], auxClasspathFile: null, timeoutSeconds: 1200 }
  detekt:    { enabled: auto, configFile: null, timeoutSeconds: 900 }
  swiftlint: { enabled: auto, configFile: null, timeoutSeconds: 600 }
  rubocop:   { enabled: auto, select: [qualor-default], ignore: [], targetRubyVersion: '4.0', timeoutSeconds: 600 }
  staticcheck: { enabled: auto, timeoutSeconds: 900 }
  govet:     { enabled: auto, timeoutSeconds: 900 }
  gosec:     { enabled: auto, exclude: [G104, G115, G304], timeoutSeconds: 900 }   # [] runs every gosec rule
  cppcheck:                          # C and C++: cppcheck 2.22.0 in qualor/scanner
    enabled: auto
    enable: [warning, performance, portability]   # cppcheck --enable groups (errors always); add style for more
    select: []                       # turn back on ids off by default: only uninitMemberVar, uninitMemberVarPrivate, uninitMemberVarNoCtor
    includePaths: []                 # repository directories for -I, used without a compile database
    defines: []                      # NAME or NAME=value for -D, used without a compile database
    compileCommands: null            # null: compile_commands.json, then build/compile_commands.json; false: none; or a repository path
    timeoutSeconds: 1800
  clang-tidy:                        # C and C++: the clang-tidy (LLVM 14+) on PATH, never bundled
    enabled: auto
    configFile: null                 # default: .clang-tidy at the repository root; qualor-default: Qualor's checks
    compileCommands: null            # as for cppcheck
    timeoutSeconds: 3600
  semgrep:   { enabled: auto, binary: auto, configs: [qualor-default], timeoutSeconds: 900 }
  qualor:    { enabled: auto, timeoutSeconds: 900 }   # Qualor's security rules
  gitleaks:  { enabled: true, configFile: null, timeoutSeconds: 300 }
  trivy:                             # dependency vulnerabilities, and a second pass for licences
    enabled: auto
    timeoutSeconds: 600
    licenses: auto                   # the licence pass: auto (whenever Trivy runs), true (also warn when it cannot run) or false
    licenseTimeoutSeconds: 300       # the licence pass's own timeout; it reads node_modules and the Go module cache
  roslyn:    { enabled: auto, bundledAnalyzers: true, sonarAnalyzer: true }
  stylelint: { enabled: auto, configFile: null, timeoutSeconds: 600 }   # configFile: qualor-default forces Qualor's default
  htmlhint:  { enabled: auto, configFile: null, timeoutSeconds: 300 }
  phpstan:   { enabled: auto, level: 2, memoryLimit: 2G, timeoutSeconds: 900 }   # level: 0-10 or max; never reads your phpstan.neon

sarif:
  - path: reports/osv.sarif
    engine: osv-scanner

coverage:
  reports:
    - path: coverage/lcov.info      # globs allowed
      format: auto                  # auto | lcov | cobertura | jacoco | gocover
  pathPrefixes: []

duplication:
  enabled: true
  minTokens: 100
  minLines: 10
  exclude: []

newCode:
  referenceBranch: null             # branches other than main compare with this; default: the main branch

scm:
  autoFetch: true                   # fetch missing baseline commits when the clone is shallow; false fetches nothing
  mainBranch: null                  # default: CI_DEFAULT_BRANCH / the server's setting

gate:
  wait: true                        # wait for the verdict and use it for the exit code
  timeoutSeconds: 300
  failOnError: true                 # a gate in "error" fails the job
```

There is no licence policy in `qualor.yml`: an organisation admin sets it on the server. For
`analyzers.trivy.licenses` and `licenseTimeoutSeconds`, see
[Dependency licences](./dependency-licenses.md#settings).

### Variables in values

`${VAR}` and `${VAR:-default}` are replaced from the environment. A variable whose name looks like a
secret (`*TOKEN`, `*SECRET`, `*PASSWORD`, `*API_KEY`, `*PRIVATE_KEY`, `*_PASS`, …) always resolves
to an empty string, so a secret cannot leak into the report through the config.

### Built-in excludes

These always apply. You can add to them, but not remove them.

| Kind | Excluded |
| --- | --- |
| Dependencies and build output | `node_modules`, `vendor`, `dist`, `build`, `target` (sources only: SpotBugs still reads the classes) |
| Minified files | `*.min.js`, `*.min.css`, `*.min.mjs`, `*.min.cjs` |
| Git and Qualor | `.git`, nested git repositories, `.qualor/` |
| .NET | `obj/`, `bin/Debug`, `bin/Release`, generated C# (`*.g.cs`, `*.g.i.cs`, `*.Designer.cs`) |
| Python | virtual environments and caches: `.venv`, `venv`, `.tox`, `.nox`, `__pycache__`, `__pypackages__`, `.eggs`, `site-packages` |
| Swift | `Pods/`, `Carthage/`, `.build/` |
| Ruby | Bundler's `.bundle/`, Rails' `db/schema.rb` |
| Go | generated `*.pb.go` files, and `testdata/` directories in every language, so secret and dependency scanning skip them too |
| C and C++ | CMake's `CMakeFiles/`, CLion's `cmake-build-*/` and FetchContent's `_deps/` |
| Other | binary files |

Files over 1 MiB are skipped for metrics and duplication. Analyzers still see them, except detekt
and SwiftLint, which are not given Kotlin or Swift files over 1 MiB.

OpenGrep sometimes selects the files itself: for the `semgrep` analyzer, and when the file list is
too long for one command line (about 1 MB on Linux, about 24 kB on Windows). It is then given, as
`--exclude` arguments, the built-in excludes and the `sources.exclude` patterns that start with
`**/`, so it never parses vendored and minified bundles, which can take it minutes. Other patterns
are not passed, because OpenGrep matches every pattern at any depth. Their findings are still
dropped after the scan.

## Environment variables (scanner)

The server's variables, such as `QUALOR_PUBLIC_URL`, `QUALOR_SCM_INTERNAL_HOSTS`,
`QUALOR_LLM_INTERNAL_HOSTS` and `QUALOR_SMTP_URL`, are in
[Install the server](./install-server.md#server-settings).

| Variable | Meaning |
| --- | --- |
| `QUALOR_URL` | server base URL (`https://…`) |
| `QUALOR_TOKEN` | project analysis token or personal token |
| `QUALOR_PROJECT_KEY` | overrides `project.key` |
| `QUALOR_CONFIG` | path to the config file |
| `QUALOR_CA_FILE` | a PEM CA bundle for the server's certificate. Keep it outside the checkout |
| `QUALOR_LOG_LEVEL` | `error`, `warn`, `info` (default) or `debug` |
| `QUALOR_TRIVY_CACHE_DIR` | another Trivy database directory (absolute, outside the checkout) |
| `QUALOR_SONARJS_DIR` | another location for Qualor's sonarjs pass (absolute, outside the checkout; default `/opt/qualor/sonarjs`, set in `qualor/scanner`) |
| `QUALOR_WEBLINT_DIR` | directory of the HTML and CSS linters (absolute, outside the checkout; default `/opt/qualor/weblint`, in `qualor/scanner`) |
| `QUALOR_DETEKT_JAR` | another location for detekt's jar (absolute, outside the checkout; default `/opt/qualor/lib/detekt/detekt-cli.jar`, set in `qualor/scanner`) |
| `QUALOR_PHPSTAN_PHAR` | another PHPStan phar, PHPStan 2.2 (absolute, outside the checkout; default `/opt/qualor/lib/phpstan/phpstan.phar`, set in `qualor/scanner`) |
| `QUALOR_RULES_DIR` | directory of Qualor's security rules (absolute, outside the checkout; default `/opt/qualor/rules/qualor`, where `qualor/scanner` installs them) |
| `QUALOR_RUBOCOP_DIR` | directory of the RuboCop pass (absolute, outside the checkout; default `/opt/qualor/rubocop`, in `qualor/scanner`) |
| `QUALOR_GO_DIR` | directory of Qualor's Go runner for staticcheck, go vet and gosec (absolute, outside the checkout; default `/opt/qualor/go`, in `qualor/scanner`) |
| `QUALOR_DOTNET_ANALYZERS` | directory of the bundled Roslyn analyzer DLLs (set in `qualor/scanner-dotnet`) |
| `QUALOR_MSBUILD_USER_DIR` | MSBuild's user extensions directory, where `qualor dotnet begin` installs its hook (absolute, outside the checkout; default: the one MSBuild uses) |
| `QUALOR_TAINT_TIME_LIMIT` | time budget of Qualor's Roslyn taint engine in `qualor dotnet end`, in seconds (default `600`) |
| `QUALOR_TAINT_MEMORY_LIMIT` | memory budget of the same engine, in megabytes (default: half of the job's memory, at least 4096 and leaving 1024 free; see [Languages and analyzers](./languages-and-analyzers.md)) |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | a proxy between the runner and the server (`http://` proxies) |

`SEMGREP_*` and `OPENGREP_*` variables are never passed to OpenGrep or Semgrep, by the `semgrep` or
the `qualor` engine. `SEMGREP_BASELINE_REF` and `SEMGREP_BASELINE_COMMIT` would silently hide every
finding older than that commit.

### Values read from CI

When present, the scanner reads the revision, the branch, the merge or pull request id and its
target, the default branch and the project path: from `CI_*` on GitLab, and from `GITHUB_*` and the
event payload on GitHub. Outside CI, it uses `git rev-parse HEAD` and the current branch, and never
assumes a merge request.

For [AI review](./ai-review.md#what-your-ci-needs) it also reads three values. They go into the AI
review snapshot only, never into the report.

| Value | GitLab | GitHub (the event) |
| --- | --- | --- |
| the merge request's last commit | `CI_MERGE_REQUEST_SOURCE_BRANCH_SHA` in a merged-result or merge-train pipeline, else `CI_COMMIT_SHA` | `pull_request.head.sha` |
| its title | `CI_MERGE_REQUEST_TITLE` | `pull_request.title` |
| its description | `CI_MERGE_REQUEST_DESCRIPTION` | `pull_request.body` |

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
