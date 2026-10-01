# Languages and analyzers

Qualor has no rule engine of its own. It runs well-known open-source analyzers, reads their SARIF
output, and turns their findings into tracked issues. For the supported languages it also computes
size, complexity, duplication and coverage.

| Area | Analyzer | Runs when |
|---|---|---|
| JavaScript, TypeScript | **ESLint**, the project's own config and plugins | the repository has an ESLint config and its dependencies are installed |
| JavaScript, TypeScript | **sonarjs**: SonarQube-compatible rules (eslint-plugin-sonarjs 2.0.4, LGPL-3.0) | JS/TS files are in scope, run by the `qualor/scanner` image |
| Python | **Ruff** (Qualor's rule selection: Pyflakes, pycodestyle errors, flake8-bugbear, Pylint errors, flake8-bandit's security rules) | .py files are in scope, run by the qualor/scanner image or any Ruff 0.16 on PATH |
| HTML | **HTMLHint** 1.9.2, the project's `.htmlhintrc` or Qualor's rule set | `.html` files are in scope, run by the `qualor/scanner` image |
| CSS, SCSS | **stylelint** 17.15, the project's JSON/YAML config or Qualor's default | `.css` or `.scss` files are in scope, run by the `qualor/scanner` image |
| Kotlin | **detekt** 1.23.8 (Apache-2.0), your `detekt.yml` or detekt's default rule set with the settings detekt recommends for Jetpack Compose | `.kt` or `.kts` files are in scope, run by the `qualor/scanner` image |
| Swift | **SwiftLint** 0.65.1 (MIT), your `.swiftlint.yml` or SwiftLint's default rules with a few adjustments | `.swift` files are in scope, run by the `qualor/scanner` image |
| Go | **staticcheck** 2026.2.1 (MIT), **go vet** (Go 1.27.1) and **gosec** 2.29.0 (Apache-2.0, security), offline | `.go` files and a `go.mod` are in scope, run by the `qualor/scanner` image |
| Java | **PMD 7** (source) and **SpotBugs** (bytecode) | `.java` files exist. SpotBugs also needs compiled classes |
| C# | **Roslyn** analyzers of the .NET SDK, plus **Roslynator** and **SonarAnalyzer.CSharp** (SonarQube-compatible rules) | through `qualor dotnet begin` / `end` around your build, with `qualor/scanner-dotnet` |
| Security patterns (SAST) | **OpenGrep** (or Semgrep) | you name rule files in `qualor.yml`. No rules are bundled yet |
| Secrets | **Gitleaks** | always (`enabled: true` by default) |
| Vulnerable dependencies | **Trivy** | lockfiles or manifests exist |
| Anything else | any tool that writes **SARIF 2.1.0** | you pass `--sarif file` or list it in `qualor.yml` |

Metrics (lines of code, functions, classes, cyclomatic and cognitive complexity) and duplication
detection cover TypeScript, JavaScript, Java, Kotlin, Swift, Go, C#, Python, HTML and CSS; SCSS gets
findings only. Other files still get findings from Gitleaks, Trivy, OpenGrep and external SARIF.

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

A code you list in `select` is never left out by qualor-default's own ignores. A selector Ruff
0.16 does not know (a typo such as `SIMM`) is a configuration error.

Ruff never reads the project's own `ruff.toml`, `.ruff.toml` or `pyproject.toml` (the checkout's, a
parent directory's, or yours): a scan must not run with settings a merge request itself controls.
`# noqa` comments in the source are still honoured. Virtual environments and Python caches
(`.venv`, `venv`, `.tox`, `.nox`, `__pycache__`, `__pypackages__`, `.eggs`, `site-packages`) are
never scanned.

Only `.py` files are analysed: `.pyi` stubs and `.ipynb` notebooks are not.

Qualor now runs Ruff itself, so if you imported your own Ruff SARIF before, remove that import
(`--sarif` or the `qualor.yml` `sarif:` entry). `ruff` is a reserved engine id: a `sarif:` entry
with `engine: ruff` is a configuration error. A Ruff SARIF you still import is reported as
`ext-ruff`, and each of its findings counts once with the built-in `ruff` finding of the same
code on the same line.

Python files get the same metrics as the other languages (lines of code, functions, classes,
cyclomatic and cognitive complexity) and count in duplication detection; a docstring counts as a
comment, not as code.

## HTML (HTMLHint)

`htmlhint` checks `.html` and `.htm` files. With a `.htmlhintrc` at the repository root it uses
your rules. Without one it uses a set that works on full pages and on Angular or Vue templates
alike: `tag-pair`, `attr-no-duplication`, `src-not-empty`, `alt-require`, `attr-unsafe-chars`,
`doctype-html5`, `html-lang-require`, `title-require`, `meta-charset-require`, `tag-no-obsolete`
and `frame-title-require`. `<!-- htmlhint … -->` comments in a file work as in HTMLHint. Custom
rules (`--rulesdir`) are not supported.

Server-side templates (Django, Jinja, Twig and the like) are not HTML until they are rendered:
`{% if %}…{% else %}…{% endif %}` around tags gives `tag-pair` findings that are not real. In a
project with such templates, leave them out with `sources.exclude` (for example
`templates/**`), or put a `.htmlhintrc` at the repository root with the rules that suit them.

Qualor now runs HTMLHint itself, so if you imported your own HTMLHint SARIF before, remove that
import (`--sarif` or the `qualor.yml` `sarif:` entry). `htmlhint` is a reserved engine id: a
`sarif:` entry with `engine: htmlhint` is a configuration error. An HTMLHint SARIF you still import
is reported as `ext-htmlhint`, and each of its findings counts once with the built-in `htmlhint`
finding of the same code on the same line.

## CSS and SCSS (stylelint)

`stylelint` checks `.css` and `.scss` files. It uses your configuration when it is data: a
`.stylelintrc`, `.stylelintrc.json`, `.stylelintrc.yaml` or `.yml`, or a `stylelint` key in
`package.json`, at the repository root. It may extend `stylelint-config-recommended`,
`stylelint-config-standard` and their `-scss` versions, and use the `stylelint-scss` plugin and the
`postcss-scss` syntax; Qualor bundles exactly these. A configuration written in JavaScript or
TypeScript (`stylelint.config.js`, `.stylelintrc.mjs`, …), or one that needs another package, is not
run: stylelint is skipped and the scan log says why. Set `analyzers.stylelint.configFile:
qualor-default` to use Qualor's configuration instead.

Without a configuration, Qualor uses `stylelint-config-recommended`, the rules that catch mistakes,
plus `stylelint-config-recommended-scss` for SCSS. It leaves out `no-descending-specificity`, and it
accepts framework syntax those configurations do not know: Angular's `::ng-deep`; Vue's `:deep()`,
`:slotted()`, `:global()` and `::v-deep`; CSS Modules' `:global`, `:local`, `:export`, `:import`
and `composes`; and Tailwind's at-rules (`@tailwind`, `@apply`, `@config`, `@theme`, `@utility`,
`@variant`, `@custom-variant`, `@plugin`, `@source`, `@reference`, `@screen`) and functions
(`theme()`, `screen()`, `--alpha()`, `--spacing()`). Findings of those rules are reliability issues of
medium severity; findings of other rules (conventions such as `stylelint-config-standard`'s) are
maintainability issues of low severity. SCSS is parsed with `postcss-scss` even when your
configuration does not say so. Less and indented Sass (`.sass`) are not checked, and SCSS files get
no size or duplication metrics.

Qualor now runs stylelint itself, so if you imported your own stylelint SARIF before, remove that
import (`--sarif` or the `qualor.yml` `sarif:` entry). `stylelint` is a reserved engine id: a
`sarif:` entry with `engine: stylelint` is a configuration error. A stylelint SARIF you still
import is reported as `ext-stylelint`, and each of its findings counts once with the built-in
`stylelint` finding of the same code on the same line.

## Kotlin (detekt)

detekt checks `.kt` and `.kts` files (Gradle Kotlin scripts too). With a detekt config in the
repository, `config/detekt/detekt.yml` (the detekt Gradle plugin's default), `config/detekt.yml`,
`detekt.yml` or `.detekt.yml` (the first one found), Qualor reads it and uses it on top of detekt's
defaults, the way `buildUponDefaultConfig = true` does in Gradle. A config file that is a symbolic
link is fine while it points at a file inside the repository. Without a config file, detekt runs
its default rule set with the settings detekt recommends for Jetpack Compose, so a composable's
name or a private `@Preview` is not a finding:

```yaml
naming:
  FunctionNaming:
    ignoreAnnotated: ['Composable']
  TopLevelPropertyNaming:
    constantPattern: '[A-Z][A-Za-z0-9]*'
complexity:
  LongParameterList:
    ignoreDefaultParameters: true
style:
  MagicNumber:
    ignorePropertyDeclaration: true
    ignoreCompanionObjectPropertyDeclaration: true
  UnusedPrivateMember:
    ignoreAnnotated: ['Preview']
```

A config file of your own replaces these six settings: detekt then runs as your own Gradle build
does. Copy them into your config if you want them there too.

```yaml
analyzers:
  detekt:
    enabled: auto              # true, false, or auto: on when Kotlin files are in scope
    configFile: lint/detekt.yml  # optional: another location for your config
    timeoutSeconds: 900         # optional
```

`configFile` must stay inside the repository (a path outside it stops the scan with exit 2). A
`configFile` that does not exist makes detekt skip, with the reason in the scan log; under
`enabled: true` the scan fails with exit 3.

Qualor does not build your project, so detekt runs without its classpath: rules that need type
information (about a third of detekt's rules, such as `UnsafeCast` or `UnreachableCode`) report
nothing. A detekt baseline file is not used, since Qualor has its own new-code gate. Plugins your
config or build refers to are never loaded, because that would run code from the repository.
`AbsentOrWrongFileLicense` never runs, because it would read the file your config names as its
license template. Keys detekt does not know (a config written for another detekt version, for
example) are ignored instead of failing the scan, and findings keep the severity your config gives
each rule. A key detekt knows with a value of the wrong type (`maxLineLength: abc`) fails detekt,
with detekt's reason in the scan log.

Qualor reads the config as data. A config file that is not valid YAML or not a YAML mapping, has a
duplicate key, an explicit YAML tag or more than 50 aliases, is not UTF-8, is larger than 1 MiB,
or is a link that leaves the repository makes detekt skip with the reason in the scan log
(`enabled: auto`), or fail the scan with exit 3 (`enabled: true`). Kotlin files larger than
1 MiB, and files reached through a symbolic link, are not passed to detekt; the log says how many.
Without the `qualor/scanner` image detekt is skipped.

Qualor now runs detekt itself, so if you imported your own detekt SARIF before, remove that import
(`--sarif` or the `qualor.yml` `sarif:` entry). `detekt` is a reserved engine id: a `sarif:` entry
with `engine: detekt` is a configuration error. A detekt SARIF you still import is reported as
`ext-detekt`, and each of its findings counts once with the built-in `detekt` finding of the same
rule on the same line.

Kotlin files get the same metrics as the other languages (lines of code, functions, classes,
cyclomatic and cognitive complexity) and count in duplication detection. Test sources such as
`src/test`, `src/androidTest` and Kotlin Multiplatform's `src/*Test` are test files by default.

## Swift (SwiftLint)

The `qualor/scanner` image runs SwiftLint 0.65.1 on your `.swift` files. It is SwiftLint's own
static Linux build, so no Swift toolchain is needed and nothing is built. The rules that need
SourceKit (such as `unused_import`, `explicit_self` and `statement_position`) do not run, and
neither do your `custom_rules`; the other 244 rules do. When a configuration asks for rules that
cannot run, the scan log names them.

Your `.swiftlint.yml` at the repository root is used: Qualor reads it as data and writes a cleaned
copy for SwiftLint. It keeps what chooses and configures rules (`disabled_rules`, `opt_in_rules`,
`only_rules`, `enabled_rules` and the settings of each rule) and uses `included` and `excluded`
only to narrow the Swift files that are checked. Qualor leaves out what would write files, fetch
from the network or change the exit code (`reporter`, `strict`, `baseline`, `write_baseline`,
`cache_path`, `check_for_updates` and similar), `analyzer_rules`, and every key SwiftLint does not
know; the scan log lists them. A rule id in the rule lists that SwiftLint does not know is
ignored by SwiftLint, and a rule setting it cannot read makes it use that rule's defaults; the
scan log warns about both. A warning stays a warning: Qualor's own gate decides what fails.
Configurations in subdirectories (a nested `.swiftlint.yml`) are not read. A configuration with
`parent_config` or `child_config` makes SwiftLint skip, because Qualor does not fetch or follow
other configurations: make it self-contained, or use Qualor's default.

Without a `.swiftlint.yml`, SwiftLint's default rules run with the adjustments below, so a
project is not buried in style findings about code that Xcode, `swift package init`, swift-format
and SwiftFormat write: blank-line indentation, `// TODO`, short loop names, SwiftUI's
`Button(action:) { … }`, trailing commas, `//===----===//` file headers, `{` on its own line
after a wrapped condition, and types nested two deep (`Feature.Action.Alert`):

```yaml
disabled_rules:
  - todo
  - multiple_closures_with_trailing_closure
  - trailing_comma
  - comment_spacing
trailing_whitespace:
  ignores_empty_lines: true
identifier_name:
  excluded: [i, j, k, x, 'y', z, id]
line_length:
  ignores_urls: true
  ignores_comments: true
opening_brace:
  ignore_multiline_statement_conditions: true
  ignore_multiline_type_headers: true
  ignore_multiline_function_signatures: true
nesting:
  type_level: 2
```

A configuration of your own replaces them: SwiftLint then runs as your own configuration says.
Copy the ones you want into it.

```yaml
analyzers:
  swiftlint:
    enabled: auto              # true, false, or auto: on when Swift files are in scope
    configFile: config/swiftlint.yml  # optional: another location; or qualor-default
    timeoutSeconds: 600         # optional
```

`configFile` must be a path inside the repository: a URL, or a path outside it, stops the scan with
exit 2. `configFile: qualor-default` ignores your `.swiftlint.yml` and uses the defaults above,
which is the way out of a configuration Qualor cannot use. Every other problem with the
configuration makes SwiftLint skip, with the reason in the scan log (`enabled: auto`), or fail the
scan with exit 3 (`enabled: true`): a `configFile` that does not exist, a file that is not valid
YAML or not a mapping, is not UTF-8, is larger than 1 MiB or is a link that leaves the repository,
`only_rules` combined with `disabled_rules`, `opt_in_rules` or `enabled_rules`, and `parent_config`
or `child_config`. The regular expressions in your rule settings are run by SwiftLint as written, so
`timeoutSeconds` is what stops one that never finishes.

SwiftLint checks the `.swift` files in scope whose names end in exactly `.swift`. Files larger than
1 MiB, files reached through a symbolic link, and names with a line break are not passed; the log
says how many. `Pods/`, `Carthage/` and `.build/` are never scanned. SwiftLint gets files with
Windows (CRLF) line ends as LF, so its line numbers match yours on a `core.autocrlf` checkout too.
SwiftLint is skipped when no swiftlint 0.65.x is on the `PATH` or in the image.

An error in SwiftLint is a high-severity issue. A warning is medium for SwiftLint's `lint` rules
(the ones about correctness) and low for its style, idiomatic, metrics and performance rules.
Rule keys look like `swiftlint:force_cast`.

Qualor runs SwiftLint itself, so if you imported your own SwiftLint SARIF before, remove that
import (`--sarif` or the `qualor.yml` `sarif:` entry). `swiftlint` is a reserved engine id: a
`sarif:` entry with `engine: swiftlint` is a configuration error. A SwiftLint SARIF you still
import is reported as `ext-swiftlint`, and each of its findings counts once with the built-in
`swiftlint` finding of the same rule on the same line.

Swift files get the same metrics as the other languages (lines of code, functions, classes,
cyclomatic and cognitive complexity) and count in duplication detection. `*Tests/**` folders
are test files by default.

## Go (staticcheck, go vet, gosec)

The `qualor/scanner` image runs three Go analyzers on every Go module in your repository (each
`go.mod` and the `.go` files below it): **staticcheck** 2026.2.1, **go vet** of Go 1.27.1, and
**gosec** 2.29.0 for security. Your `staticcheck.conf`, `//lint:ignore` and `#nosec` comments are
honoured; `.golangci.yml` is not read.

They type-check your code, so they need your dependencies. Qualor never downloads them: it runs
offline. Give them to it in the scan job:

```yaml
# GitLab: the scan job, image qualor/scanner
qualor:
  image: qualor/scanner:<version>
  script:
    - go mod download     # in each module directory, or vendor your dependencies
    - qualor scan
```

A module cache of your own works too: point `GOMODCACHE` at it (outside the repository). A
package whose dependencies are missing is not analysed, and the scan log says which and why.
Files that use cgo (`import "C"`) are left out (cgo is switched off, `CGO_ENABLED=0`), so a
package that needs them is reported the same way.

For safety, Qualor never runs anything the repository asks for: no `go generate`, no other Go
toolchain (`toolchain` and `GOTOOLCHAIN` are ignored), no C compiler, no module download. A module
whose `go` line needs a newer Go than 1.27.1, whose `replace` points at a directory outside the
repository, or that contains a symbolic link out of it, is skipped with a log line.

One case is not covered. Qualor does not look for links inside the directories Go itself ignores
(names starting with `.` or `_`, `testdata`) or inside Qualor's built-in excluded directories
(`node_modules` and the like). If your code explicitly imports a package from one of them, `go`
could compile a file that is linked outside the repository. Findings on files outside the
repository are dropped, so only a compiler message could repeat a line of such a file in the scan
log or in the report. Don't scan repositories you do not trust in a job that can read secrets or
host files (the same rule as for ESLint above).

```yaml
analyzers:
  gosec:
    exclude: [G104, G115]   # the default: unchecked errors and integer-conversion overflow; [] runs every rule
```

Severity: staticcheck's correctness and concurrency checks (`SA5…`, `SA2…`) are high, its other
bug checks medium, unused code medium, simplifications and style low; go vet findings are medium;
gosec findings take gosec's own HIGH/MEDIUM/LOW. Where go vet and staticcheck report the same
mistake on one line (`printf`/`SA5009`, `bools`/`SA4000`), the server keeps one issue.
`testdata/` directories and generated `*.pb.go` files are never scanned, and `*_test.go` files are
tests.

Go files get the same metrics as the other languages (lines of code, functions, types,
cyclomatic and cognitive complexity) and count in duplication detection. The three analyzers are
skipped, with the reason in the scan log, when no Go module is in scope, when no `go`,
`staticcheck` or `gosec` of the supported version is available (outside the image), or when every
module is left out for the reasons above. Qualor runs these tools itself: a SARIF file of your own
from staticcheck or gosec is counted once with the built-in finding of the same code on the same
line, and `engine: staticcheck`, `govet` or `gosec` in a `sarif:` entry is a configuration error.

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
  image: { name: qualor/scanner-dotnet:0.3, entrypoint: [''] }
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
  old as the scanner release you run, so keep the scanner current (the minor tag `0.3` does that
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

The engine ids of the built-in analyzers (`eslint`, `ruff`, `semgrep`, `stylelint`, `htmlhint`,
`detekt`, `swiftlint` and the others) are reserved: `engine: ruff` is a configuration error, and a
SARIF file from a tool Qualor runs itself is reported under `ext-<tool>`. Don't import Ruff,
stylelint, HTMLHint, detekt, SwiftLint, staticcheck or gosec SARIF any more: Qualor runs Ruff (see
[Python](#python-ruff)), stylelint and HTMLHint (see [CSS and SCSS](#css-and-scss-stylelint) and
[HTML](#html-htmlhint)) and detekt (see [Kotlin](#kotlin-detekt)) and SwiftLint (see
[Swift](#swift-swiftlint)) and staticcheck and gosec (see [Go](#go-staticcheck-go-vet-gosec))
itself; a SARIF file you still import for one of them counts once with the built-in finding of the
same code on the same line.

## Coverage

Qualor imports **LCOV**, **Cobertura XML**, **JaCoCo XML** and **Go coverage profiles**. Run your
tests with coverage before the scan, then list the reports:

```yaml
coverage:
  reports:
    - path: coverage/lcov.info                          # Jest, Vitest, nyc, c8
    - path: '**/target/site/jacoco/jacoco.xml'          # Maven + JaCoCo
      format: jacoco
    - path: '**/coverage.cobertura.xml'                 # .NET: coverlet / dotnet-coverage
      format: cobertura
    - path: coverage.out                                # go test -coverprofile=coverage.out ./... (Go)
      format: gocover
  pathPrefixes: []   # prefixes to strip or try when report paths do not match repository paths
```

A Go profile names files by import path; Qualor finds them by their path suffix. Use
`-coverpkg=./...` to count code that other packages' tests run. A profile that holds more than 20
million lines is read as far as that limit, and the import warns that it was truncated.

Or pass `--coverage <path>` on the command line. Test files are excluded from coverage. If a scan
imports no coverage report at all, the coverage conditions have **no value**, and they do not fail the
gate. The UI shows a warning instead.

## What is scanned

Every file in the working tree (`sources.include`, default `**/*`), minus what `.gitignore` ignores,
minus the built-in excludes (`node_modules`, `dist`,
`build`, `target`, `vendor`, `*.min.js`, `*.min.css`, .NET `obj/` and generated `*.g.cs` / `*.Designer.cs`,
Python's `.venv`, `venv`, `.tox`, `.nox`, `__pycache__`, `__pypackages__`, `.eggs` and
`site-packages`, and binary files), minus your own `sources.exclude`. Test files are recognised by
`tests.include` (by default `*.test.*`, `*.spec.*`, `__tests__/`, `src/test/`, `*Tests/`,
`test_*.py`, `*_test.py`, `conftest.py`, `src/androidTest/`, `src/*Test/`). `src/*Test/` is meant
for Kotlin Multiplatform's `commonTest` and `jvmTest`, but applies to every language: a Gradle
`src/integrationTest` or `src/functionalTest` is test code too, and leaves lines of code,
complexity, duplication and coverage.
A committed `coverage/` directory is not excluded automatically. Add it to `sources.exclude` if
yours is generated output.
