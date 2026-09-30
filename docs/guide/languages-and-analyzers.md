# Languages and analyzers

Qualor has no rule engine of its own. It runs well-known open-source analyzers, reads their SARIF
output, and turns their findings into tracked issues. For the supported languages it also computes
size, complexity, duplication and coverage.

| Area | Analyzer | Runs when |
|---|---|---|
| JavaScript, TypeScript | **ESLint**, the project's own config and plugins | the repository has an ESLint config and its dependencies are installed |
| JavaScript, TypeScript | **sonarjs**: SonarQube-compatible rules (eslint-plugin-sonarjs 2.0.4, LGPL-3.0) | JS/TS files are in scope, run by the `qualor/scanner` image |
| Python | **Ruff** (Qualor's rule selection: Pyflakes, pycodestyle errors, flake8-bugbear, Pylint errors, flake8-bandit's security rules) | .py files are in scope, run by the qualor/scanner image or any Ruff 0.16 on PATH |
| Java | **PMD 7** (source) and **SpotBugs** (bytecode) | `.java` files exist. SpotBugs also needs compiled classes |
| C# | **Roslyn** analyzers of the .NET SDK, plus **Roslynator** and **SonarAnalyzer.CSharp** (SonarQube-compatible rules) | through `qualor dotnet begin` / `end` around your build, with `qualor/scanner-dotnet` |
| Security patterns (SAST) | **OpenGrep** (or Semgrep) | you name rule files in `qualor.yml`. No rules are bundled yet |
| Secrets | **Gitleaks** | always (`enabled: true` by default) |
| Vulnerable dependencies | **Trivy** | lockfiles or manifests exist |
| Anything else | any tool that writes **SARIF 2.1.0** | you pass `--sarif file` or list it in `qualor.yml` |

Metrics (lines of code, functions, classes, cyclomatic and cognitive complexity) and duplication
detection cover TypeScript, JavaScript, Java, C# and Python. Other files still get findings from
Gitleaks, Trivy, OpenGrep and external SARIF.

Each analyzer has `enabled: auto | true | false` in `qualor.yml`:

- `auto` runs it when its language is present and its tool is available. Otherwise it is skipped,
  with one log line saying why.
- `true` makes it required: if it cannot run or it crashes, the scan exits with code 3.
- `false` turns it off.

The analyzers run in parallel (at most 4 at once) and offline. No analyzer downloads rules, databases
or plugins during a scan.

## JavaScript and TypeScript (ESLint)

ESLint runs **from the project's own `node_modules`** with the project's own config, because that is
the only way plugin rules resolve. So:

1. Install the dependencies before the scan (`npm ci`, `pnpm install --frozen-lockfile`,
   `yarn install --immutable`). The scanner image has Node.js, npm and corepack.
2. Keep an ESLint config at the repository root: `eslint.config.js` (or `.mjs`, `.cjs`, `.ts`), or a
   legacy `.eslintrc*`. ESLint 9+ reads only flat configs. Without a config, ESLint is skipped, because
   no default config is bundled.

```yaml
analyzers:
  eslint:
    configFile: config/eslint.config.js   # optional; default: ESLint's own lookup
    args: ['--ext', '.ts,.tsx']           # optional; appended to the command line
```

ESLint runs the config and plugins from the checkout, so it runs repository code. Never scan
untrusted merge requests (for example from forks) in a job that holds secrets.

## SonarQube-compatible rules (sonarjs)

SonarQube-compatible rules (SonarAnalyzer.CSharp 9.32, eslint-plugin-sonarjs 2.0.4, LGPL-3.0)
add a second, independent pass over JavaScript and TypeScript: `sonarjs`, which runs
eslint-plugin-sonarjs on its own bundled ESLint. It never loads your `eslint.config.js`, your
plugins or your `node_modules`; it reads only your source files and `tsconfig.json`, so it still
reports what it can when your own config or dependencies are missing or your `tsconfig.json`
does not parse. Type-aware rules just sit out until it does.

```yaml
analyzers:
  sonarjs:
    enabled: auto          # true, false, or auto: on when JS/TS files are in scope
    timeoutSeconds: 900     # optional
    typeChecking: auto      # optional; false skips rules that need type information
```

When the same problem turns up in both your ESLint config and sonarjs (a setter without a getter,
an empty function, and a few others), only your ESLint's finding is kept; sonarjs is a fallback,
not a duplicate. Turn sonarjs off entirely with `analyzers.sonarjs.enabled: false`. Without the
`qualor/scanner` image it is skipped, the same as a project without Trivy's vulnerability database.

## Python (Ruff)

Ruff runs with Qualor's own rule selection, `qualor-default`: Pyflakes (unused imports, undefined
names and the like), pycodestyle's error checks (not its style checks), flake8-bugbear, Pylint's
error rules, and a security subset of flake8-bandit's rules. A handful of noisy or opinionated
bandit rules are left out of the default selection (for example the ones about bare `assert`,
`try`/`except`/`pass`, and subprocess calls). Everything else Ruff can check — pycodestyle's style
rules, pyupgrade, flake8-simplify, and its other rule families — stays off until you turn it on.

Choose your own rules with `select` and `ignore` (Ruff's own rule prefixes and codes, or
`qualor-default` for the bundled selection):

```yaml
analyzers:
  ruff:
    select: [qualor-default, UP, SIM]   # add pyupgrade and flake8-simplify
    ignore: []
    timeoutSeconds: 600                  # optional
```

A code you list in `select` is never left out by `ignore`, even one `qualor-default` normally
leaves out.

Ruff never reads the project's own `ruff.toml`, `.ruff.toml` or `pyproject.toml` (the checkout's, a
parent directory's, or yours): a scan must not run with settings a merge request itself controls.
`# noqa` comments in the source are still honoured. Virtual environments and Python caches
(`.venv`, `venv`, `.tox`, `.nox`, `__pycache__`, `__pypackages__`, `.eggs`, `site-packages`) are
never scanned.

Python files get the same metrics as the other languages (lines of code, functions, classes,
cyclomatic and cognitive complexity) and count in duplication detection; a docstring counts as a
comment, not as code.

## Java (PMD and SpotBugs)

- **PMD** reads the source. The default ruleset `qualor-default` is PMD's own
  `rulesets/java/quickstart.xml`. Use your own with `analyzers.pmd.rulesets: [config/pmd.xml]`, or
  PMD's built-in categories (`category/java/bestpractices.xml`).
- **SpotBugs** reads **compiled classes**. Build first (`mvn -B -DskipTests package` or
  `./gradlew classes`). It looks in `target/classes` and `build/classes/java/main` by default. When
  those are empty it is skipped, with the reason `no compiled classes … (build the project before
  qualor scan)`.

```yaml
analyzers:
  pmd: { rulesets: [config/pmd.xml] }
  spotbugs:
    classDirs: [app/target/classes, lib/target/classes]
    auxClasspathFile: target/classpath.txt   # optional: one classpath entry per line
```

For a better SpotBugs result on a Maven project, write the classpath first:
`mvn dependency:build-classpath -Dmdep.outputFile=target/classpath.txt`. That file has one line
separated by `:`. Convert it to one entry per line, for example with `tr ':' '\n'`.

## C#

Roslyn analyzers need the compiler's semantic model, so Qualor hooks into **your own build** instead
of building anything itself. SonarScanner for .NET works the same way:

```sh
qualor dotnet begin                 # installs an MSBuild hook for this checkout
dotnet build --no-incremental       # your build: its SDK, restore, feeds and arguments
qualor dotnet end                   # removes the hook, reads the Roslyn logs, runs qualor scan
```

Use the **`qualor/scanner-dotnet`** image. It adds the .NET 8 and .NET 10 SDKs, Roslynator and
SonarAnalyzer.CSharp 9.32 (SonarQube-compatible rules, LGPL-3.0) to the scanner. GitLab:

```yaml
qualor:
  image: { name: qualor/scanner-dotnet:0.1, entrypoint: [''] }
  variables: { GIT_DEPTH: 0 }
  script:
    - qualor dotnet begin
    - dotnet build MySolution.sln --no-incremental
    - qualor dotnet end
  after_script:
    - if [ -d .qualor/dotnet ]; then qualor dotnet abort; fi
```

With the GitLab component, set `inputs: { dotnet: true, image: qualor/scanner-dotnet,
build-command: 'dotnet build MySolution.sln --no-incremental' }`. For GitHub, use
`integrations/github/qualor-dotnet.yml` ([GitHub](./github.md#2-the-workflow)).

- **`--no-incremental`** matters. A project that is not recompiled writes no log, and you get the
  warning `ROSLYN_PROJECT_NOT_ANALYZED`.
- Inside the scan job, the hook turns off *warnings as errors*, so the extra rules cannot break a build
  that passes without them. Compiler errors still fail it. If your pipeline must fail on warnings,
  keep a separate build job for that.
- The repository's `.editorconfig` and `.globalconfig` still decide severities. A rule set to `none`
  stays off. If the project references Roslynator or SonarAnalyzer.CSharp itself, its own version
  is used instead of the bundled one, so there is never a duplicate-analyzer build error.
- Turn the bundled SonarAnalyzer.CSharp off with `analyzers.roslyn.sonarAnalyzer: false`.
- `qualor dotnet abort` cleans up when the build fails, so no hook is left behind.
- A plain `qualor scan` does not analyse C#.

## Secrets (Gitleaks)

Gitleaks scans the working tree with its built-in rules, or with `.gitleaks.toml` at the repository
root. It honours `.gitleaksignore` and `gitleaks:allow` comments. The secret itself never reaches the
report or the server: the finding's message is the rule's text.

Gitleaks is `enabled: true` by default, so a scan outside the scanner image without Gitleaks exits 3.
Set `analyzers.gitleaks.enabled: auto` to make it optional.

## Dependencies (Trivy)

Trivy reads lockfiles and manifests (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `pom.xml`,
`gradle.lockfile`, and Go, Python, Ruby, Rust, PHP and .NET lockfiles) and reports packages with known
vulnerabilities. Development dependencies are left out. A vulnerability counts as **new code** only
when the merge request adds the package or changes its version. So a database update never fails a
merge request that did not touch the dependency.

- Ignore a vulnerability by id in `.trivyignore` at the repository root.
- The vulnerability database comes from the image and is never downloaded during a scan. It is as
  old as the scanner release you run, so keep the scanner current (the minor tag `0.1` does that
  for its patch releases), or fetch a fresh database in the job:

```yaml
script:
  - trivy image --download-db-only --cache-dir /tmp/trivy   # add --db-repository <your mirror> if needed
  - QUALOR_TRIVY_CACHE_DIR=/tmp/trivy qualor scan
```

`QUALOR_TRIVY_CACHE_DIR` must be absolute and outside the checkout. Jobs that run repository code must
not be able to write it.

## SAST patterns (OpenGrep / Semgrep)

No rules are bundled yet. To use OpenGrep, keep rule files in the repository and name them:

```yaml
analyzers:
  semgrep:
    configs: [.semgrep/]            # local files or directories only
```

Registry ids such as `p/default` are refused (exit 2), because they would fetch rules over the
network.

## External SARIF

Any tool that writes SARIF 2.1.0 can feed Qualor: osv-scanner, Checkov, tfsec, Bandit, golangci-lint,
Hadolint and others. Run it before the scan, then:

```sh
qualor scan --sarif reports/osv.sarif --sarif reports/checkov.sarif
```

Or permanently in `qualor.yml`:

```yaml
sarif:
  - path: reports/osv.sarif
    engine: osv-scanner            # optional; default: the SARIF tool name
```

## Coverage

Qualor imports **LCOV**, **Cobertura XML** and **JaCoCo XML**. Run your tests with coverage before the
scan, then list the reports:

```yaml
coverage:
  reports:
    - path: coverage/lcov.info                          # Jest, Vitest, nyc, c8
    - path: '**/target/site/jacoco/jacoco.xml'          # Maven + JaCoCo
      format: jacoco
    - path: '**/coverage.cobertura.xml'                 # .NET: coverlet / dotnet-coverage
      format: cobertura
  pathPrefixes: []   # prefixes to strip or try when report paths do not match repository paths
```

Or pass `--coverage <path>` on the command line. Test files are excluded from coverage. If a scan
imports no coverage report at all, the coverage conditions have **no value**, and they do not fail the
gate. The UI shows a warning instead.

## What is scanned

Every file in the working tree (`sources.include`, default `**/*`), minus what `.gitignore` ignores,
minus the built-in excludes (`node_modules`, `dist`,
`build`, `target`, `vendor`, `*.min.js`, .NET `obj/` and generated `*.g.cs` / `*.Designer.cs`,
Python's `.venv`, `venv`, `.tox`, `.nox`, `__pycache__`, `__pypackages__`, `.eggs` and
`site-packages`, and binary files), minus your own `sources.exclude`. Test files are recognised by
`tests.include` (by default `*.test.*`, `*.spec.*`, `__tests__/`, `src/test/`, `*Tests/`,
`test_*.py`, `*_test.py`, `conftest.py`).
A committed `coverage/` directory is not excluded automatically. Add it to `sources.exclude` if
yours is generated output.
