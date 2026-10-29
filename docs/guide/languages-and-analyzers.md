# Languages and analyzers

The `qualor/scanner` image runs pinned open-source analyzers and
[Qualor's own security rules](#security-rules-qualor), and Qualor tracks their findings as issues.
Most analyzers need no setup. A few need the project prepared first: installed dependencies for
ESLint and PHPStan, compiled classes for SpotBugs, downloaded modules for Go, and your own build for
C#.

| Area | Analyzer | Runs when |
|---|---|---|
| [JavaScript, TypeScript](#eslint) | **ESLint**, with the project's own config and plugins | the repository has an ESLint config and its dependencies are installed |
| [JavaScript, TypeScript](#sonarjs) | **sonarjs**: SonarQube-compatible rules (eslint-plugin-sonarjs 2.0.4, LGPL-3.0) | JS/TS files are in scope |
| [Python](#python-ruff) | **Ruff** (Qualor's rule selection: Pyflakes, pycodestyle errors, flake8-bugbear, Pylint errors, flake8-bandit's security rules) | `.py` files are in scope; outside the image, a Ruff 0.16 is on the `PATH` |
| [HTML](#html-htmlhint) | **HTMLHint** 1.9.2, with the project's `.htmlhintrc` or Qualor's rule set | `.html` or `.htm` files are in scope |
| [CSS, SCSS](#css-and-scss-stylelint) | **stylelint** 17.15, with the project's JSON or YAML config or Qualor's default | `.css` or `.scss` files are in scope |
| [Kotlin](#kotlin-detekt) | **detekt** 1.23.8 (Apache-2.0), with your `detekt.yml` or detekt's default rule set with the settings detekt recommends for Jetpack Compose | `.kt` or `.kts` files are in scope |
| [Swift](#swift-swiftlint) | **SwiftLint** 0.65.1 (MIT), with your `.swiftlint.yml` or SwiftLint's default rules with a few adjustments | `.swift` files are in scope |
| [PHP](#php-phpstan) | **PHPStan** 2.2 (MIT) at level 2, with Qualor's own configuration | `.php` files are in scope |
| [Ruby](#ruby-rubocop) | **RuboCop** 1.91 (MIT), with Qualor's selection: RuboCop's Lint and Security cops | Ruby files are in scope (`.rb`, `.rake`, `.gemspec`, `.ru`, `Gemfile`, `Rakefile`) |
| [Go](#go-staticcheck-go-vet-gosec) | **staticcheck** 2026.2.1 (MIT), **go vet** (Go 1.27.1) and **gosec** 2.29.0 (Apache-2.0, security), offline | `.go` files and a `go.mod` are in scope |
| [Java](#java-pmd-spotbugs-and-findsecbugs) | **PMD 7** (source), **SpotBugs** (bytecode) with **FindSecBugs** 1.14.0 (LGPL-3.0, security) | `.java` files exist; SpotBugs also needs compiled classes |
| [C#](#c) | **Roslyn** analyzers of the .NET SDK, **Roslynator** and **SonarAnalyzer.CSharp** (SonarQube-compatible rules) | your build runs between `qualor dotnet begin` and `end`, with `qualor/scanner-dotnet` |
| [C](#c-and-c-cppcheck-clang-tidy) | **cppcheck** 2.22.0 (GPL-3.0-or-later); **clang-tidy** (yours, LLVM 14+, with a compile database) | `.c` or `.h` files exist |
| [C++](#c-and-c-cppcheck-clang-tidy) | the same | `.cpp`, `.cc`, `.cxx`, `.hpp`, `.h` … files exist |
| [Security rules](#security-rules-qualor) | **Qualor's own rules** on OpenGrep, for JavaScript, TypeScript, Python, Java, Go and C# (PolyForm Shield 1.0.0, source-available) | files of those languages are in scope |
| [Security patterns (SAST)](#sast-patterns-opengrep-semgrep) | **OpenGrep** (or Semgrep), with rule files you keep in the repository; none are bundled | you name rule files in `qualor.yml` |
| [Secrets](#secrets-gitleaks) | **Gitleaks** | always (`enabled: true` by default) |
| [Vulnerable dependencies](#dependencies-trivy) | **Trivy** | lockfiles or manifests exist |
| [Anything else](#external-sarif) | any tool that writes **SARIF 2.1.0** | you pass `--sarif file` or list it in `qualor.yml` |

The `qualor/scanner` image holds every analyzer except three: ESLint runs from your `node_modules`,
clang-tidy comes from your job, and the C# analyzers run in your build with `qualor/scanner-dotnet`.

## How analyzers run

Each analyzer has `enabled: auto | true | false` in `qualor.yml`:

- `auto` runs it when its language is present and its tool is available. Otherwise it is skipped,
  with one log line saying why.
- `true` makes it required: if it cannot run or it crashes, the scan exits with code 3.
- `false` turns it off.

The analyzers run in parallel, at most 4 at once, and offline: no analyzer downloads rules,
databases or plugins during a scan. Every setting and its default is in the
[configuration reference](./configuration.md#qualoryml).

## Metrics and duplication

Qualor computes lines of code, functions, classes, cyclomatic and cognitive complexity, and
duplication for TypeScript, JavaScript, Java, Kotlin, Swift, C, C++, C#, Python, PHP, Ruby, Go, HTML
and CSS. SCSS gets findings only. Other files still get findings from Gitleaks, Trivy, OpenGrep and
external SARIF.

- Python: a docstring counts as a comment, not as code.
- Ruby: functions are `def` and `def self.` methods, and classes are `class` and `module`
  definitions. Blocks and lambdas are not counted as functions.
- Go: classes are struct and interface types.

Test files do not count in these measures: see [What is scanned](#what-is-scanned).

## JavaScript and TypeScript (ESLint, sonarjs)

Two passes check JavaScript and TypeScript: your own ESLint, and `sonarjs`, an independent pass with
SonarQube-compatible rules.

### ESLint

ESLint runs from the project's own `node_modules` with the project's own config, so that plugin
rules resolve. Prepare the job:

1. Install the dependencies before the scan: `npm ci`, `corepack pnpm install --frozen-lockfile` or
   `corepack yarn install --immutable`. The scanner image has Node.js, npm, Yarn 1 and corepack.
   Installed dependencies also give Qualor their licences
   ([Dependency licences](./dependency-licenses.md)).
2. Keep an ESLint config at the repository root: `eslint.config.js` (or `.mjs`, `.cjs`, `.ts`), or a
   legacy `.eslintrc*`. ESLint 9 and later read only flat configs. Without a config, ESLint is
   skipped: Qualor bundles no default config.

```yaml
analyzers:
  eslint:
    configFile: config/eslint.config.js   # optional; default: ESLint's own lookup
    args: ['--ext', '.ts,.tsx']           # optional; appended to the command line
```

ESLint runs your config and plugins from the checkout, so it runs repository code. Never scan
untrusted merge requests, such as those from forks, in a job that holds secrets.

### sonarjs

`sonarjs` runs eslint-plugin-sonarjs 2.0.4 (LGPL-3.0) on its own bundled ESLint. It reads only your
source files and `tsconfig.json`, never your ESLint config, plugins or `node_modules`, so it still
reports when those are missing. While your `tsconfig.json` does not parse, only the rules that need
type information sit out.

```yaml
analyzers:
  sonarjs:
    enabled: auto           # true, false, or auto: on when JS/TS files are in scope
    timeoutSeconds: 900     # optional
    typeChecking: auto      # optional; false skips rules that need type information
```

- When your ESLint and sonarjs report the same problem (a setter without a getter, an empty
  function and a few others), only your ESLint's finding is kept.
- Outside the `qualor/scanner` image, sonarjs is skipped.
- S2430, the rule for constructors called without `new`, does not report calls to HTTP-verb methods
  such as `client.GET()` or `api.POST()`, the request methods of openapi-fetch style clients.

## Python (Ruff)

Ruff runs with Qualor's own rule selection, `qualor-default`:

- Pyflakes (unused imports, undefined names and the like)
- pycodestyle's error checks, not its style checks
- flake8-bugbear
- Pylint's error rules
- a security subset of flake8-bandit, without a few noisy or opinionated rules such as those about
  bare `assert`, `try`/`except`/`pass` and subprocess calls

Ruff's other rule families, such as pycodestyle's style rules, pyupgrade and flake8-simplify, stay
off until you select them:

```yaml
analyzers:
  ruff:
    select: [qualor-default, UP, SIM]   # add pyupgrade and flake8-simplify
    ignore: []
    timeoutSeconds: 600                  # optional
```

`select` and `ignore` take Ruff's rule prefixes and codes, or `qualor-default`. A code you list in
`select` is never removed by `qualor-default`'s own ignores. A selector Ruff 0.16 does not know,
such as the typo `SIMM`, is a configuration error.

Limits:

- Ruff never reads a `ruff.toml`, `.ruff.toml` or `pyproject.toml`, whether in the checkout, a
  parent directory or your home directory: a merge request must not control the scan's settings.
  `# noqa` comments in the source are still honoured.
- Only `.py` files are analysed, not `.pyi` stubs or `.ipynb` notebooks.
- Virtual environments and Python caches are never scanned
  ([built-in excludes](./configuration.md#built-in-excludes)).

## HTML (HTMLHint)

HTMLHint checks `.html` and `.htm` files. With a `.htmlhintrc` at the repository root it uses your
rules. Without one it uses a set that works on full pages and on Angular or Vue templates alike:
`tag-pair`, `attr-no-duplication`, `src-not-empty`, `alt-require`, `attr-unsafe-chars`,
`doctype-html5`, `html-lang-require`, `title-require`, `meta-charset-require`, `tag-no-obsolete`
and `frame-title-require`. `<!-- htmlhint … -->` comments in a file work as in HTMLHint.

Limits:

- Custom rules (`--rulesdir`) are not supported.
- Server-side templates (Django, Jinja, Twig and the like) are not HTML until they are rendered.
  `{% if %}…{% else %}…{% endif %}` around tags gives false `tag-pair` findings. Leave such
  templates out with `sources.exclude` (for example `templates/**`), or put a `.htmlhintrc` with
  rules that suit them at the repository root.

## CSS and SCSS (stylelint)

stylelint checks `.css` and `.scss` files. It uses your configuration when it is data, at the
repository root: a `.stylelintrc`, `.stylelintrc.json`, `.stylelintrc.yaml` or `.yml`, or a
`stylelint` key in `package.json`. The configuration may extend `stylelint-config-recommended`,
`stylelint-config-standard` and their `-scss` versions, and use the `stylelint-scss` plugin and the
`postcss-scss` syntax. Qualor bundles exactly these.

A configuration written in JavaScript or TypeScript (`stylelint.config.js`, `.stylelintrc.mjs`,
…), or one that needs another package, is not run: stylelint is skipped and the scan log says why.
Set `analyzers.stylelint.configFile: qualor-default` to use Qualor's configuration instead.

Without a configuration, Qualor uses `stylelint-config-recommended`, the rules that catch mistakes,
plus `stylelint-config-recommended-scss` for SCSS, and leaves out `no-descending-specificity`. It
accepts framework syntax those configurations do not know:

| Framework | Accepted syntax |
|---|---|
| Angular | `::ng-deep` |
| Vue | `:deep()`, `:slotted()`, `:global()`, `::v-deep` |
| CSS Modules | `:global`, `:local`, `:export`, `:import`, `composes` |
| Tailwind | the at-rules `@tailwind`, `@apply`, `@config`, `@theme`, `@utility`, `@variant`, `@custom-variant`, `@plugin`, `@source`, `@reference`, `@screen`, and the functions `theme()`, `screen()`, `--alpha()`, `--spacing()` |

Findings of the recommended configurations' rules are reliability issues of medium severity.
Findings of other rules, such as the conventions of `stylelint-config-standard`, are
maintainability issues of low severity. SCSS is parsed with `postcss-scss` even when your
configuration does not say so.

Less and indented Sass (`.sass`) are not checked.

## Kotlin (detekt)

detekt checks `.kt` and `.kts` files, Gradle Kotlin scripts included. Qualor does not build your
project, so detekt runs without its classpath.

Qualor uses the first detekt config it finds in the repository: `config/detekt/detekt.yml` (the
detekt Gradle plugin's default), `config/detekt.yml`, `detekt.yml` or `.detekt.yml`. It applies the
config on top of detekt's defaults, as `buildUponDefaultConfig = true` does in Gradle. A config file
may be a symbolic link to a file inside the repository.

Without a config file, detekt runs its default rule set with the settings detekt recommends for
Jetpack Compose, so a composable's name or a private `@Preview` is not a finding:

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

A config file of your own replaces these six settings, and detekt then runs as your own Gradle build
does. Copy them into your config if you want them there too.

```yaml
analyzers:
  detekt:
    enabled: auto                # true, false, or auto: on when Kotlin files are in scope
    configFile: lint/detekt.yml  # optional: another location for your config
    timeoutSeconds: 900          # optional
```

- `configFile` must stay inside the repository. A path outside it stops the scan with exit 2.
- Qualor reads the config as data. detekt is skipped, with the reason in the scan log, when the
  `configFile` does not exist, or when the config file:
  - is not valid YAML or not a YAML mapping
  - has a duplicate key, an explicit YAML tag or more than 50 aliases
  - is not UTF-8 or is larger than 1 MiB
  - is a link that leaves the repository

  Under `enabled: true`, these fail the scan with exit 3 instead.
- Keys detekt does not know, such as those of a config written for another detekt version, are
  ignored instead of failing the scan.
- A key detekt knows with a value of the wrong type (`maxLineLength: abc`) fails detekt, with
  detekt's reason in the scan log.
- Findings keep the severity your config gives each rule.

Limits:

- Rules that need type information report nothing. That is about a third of detekt's rules, such
  as `UnsafeCast` or `UnreachableCode`.
- A detekt baseline file is not used: Qualor's new-code gate does that job.
- Plugins your config or build refers to are never loaded, because that would run code from the
  repository.
- `AbsentOrWrongFileLicense` never runs, because it would read the file your config names as its
  licence template.
- Kotlin files larger than 1 MiB, and files reached through a symbolic link, are not passed to
  detekt. The log says how many.
- Outside the `qualor/scanner` image, detekt is skipped.

## Swift (SwiftLint)

The `qualor/scanner` image runs SwiftLint 0.65.1 on your `.swift` files. It is SwiftLint's own
static Linux build, so no Swift toolchain is needed and nothing is built. Outside the image,
SwiftLint runs only when a swiftlint 0.65.x is on the `PATH`.

Your `.swiftlint.yml` at the repository root is used. Qualor reads it as data and writes a cleaned
copy for SwiftLint:

- It keeps what chooses and configures rules: `disabled_rules`, `opt_in_rules`, `only_rules`,
  `enabled_rules` and the settings of each rule.
- It uses `included` and `excluded` only to narrow the Swift files that are checked.
- It leaves out what would write files, fetch from the network or change the exit code
  (`reporter`, `strict`, `baseline`, `write_baseline`, `cache_path`, `check_for_updates` and
  similar), `analyzer_rules`, and every key SwiftLint does not know. The scan log lists them.
- SwiftLint ignores a rule id it does not know, and uses a rule's defaults when it cannot read that
  rule's settings. The scan log warns about both.
- A warning stays a warning: Qualor's quality gate decides what fails.
- Configurations in subdirectories (a nested `.swiftlint.yml`) are not read.
- `parent_config` or `child_config` makes SwiftLint skip, because Qualor does not fetch or follow
  other configurations. Make the configuration self-contained, or use Qualor's default.

Without a `.swiftlint.yml`, SwiftLint's default rules run with the adjustments below. They keep a
project from being buried in style findings about code that Xcode, `swift package init`,
swift-format and SwiftFormat write: blank-line indentation, `// TODO`, short loop names, SwiftUI's
`Button(action:) { … }`, trailing commas, `//===----===//` file headers, `{` on its own line after
a wrapped condition, and types nested two deep (`Feature.Action.Alert`).

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

A configuration of your own replaces them: SwiftLint then runs as your configuration says. Copy the
ones you want into it.

```yaml
analyzers:
  swiftlint:
    enabled: auto                     # true, false, or auto: on when Swift files are in scope
    configFile: config/swiftlint.yml  # optional: another location; or qualor-default
    timeoutSeconds: 600               # optional
```

- `configFile` must be a path inside the repository. A URL, or a path outside it, stops the scan
  with exit 2.
- `configFile: qualor-default` ignores your `.swiftlint.yml` and uses the defaults above. It is the
  way out of a configuration Qualor cannot use.
- Every other configuration problem makes SwiftLint skip, with the reason in the scan log. Under
  `enabled: true` it fails the scan with exit 3 instead. These problems are:
  - a `configFile` that does not exist
  - a file that is not valid YAML or not a mapping, is not UTF-8, is larger than 1 MiB or is a link
    that leaves the repository
  - `only_rules` combined with `disabled_rules`, `opt_in_rules` or `enabled_rules`
  - `parent_config` or `child_config`
- SwiftLint runs the regular expressions in your rule settings as written. `timeoutSeconds` is what
  stops one that never finishes.

An error is a high-severity issue. A warning is medium for SwiftLint's `lint` rules (the ones about
correctness) and low for its style, idiomatic, metrics and performance rules. Rule keys look like
`swiftlint:force_cast`.

Limits:

- The rules that need SourceKit (such as `unused_import`, `explicit_self` and `statement_position`)
  do not run, and neither do your `custom_rules`. The other 244 rules do. When a configuration asks
  for rules that cannot run, the scan log names them.
- Only files whose names end in exactly `.swift` are checked. Files larger than 1 MiB, files reached
  through a symbolic link, and names with a line break are not passed. The log says how many.
- `Pods/`, `Carthage/` and `.build/` are never scanned
  ([built-in excludes](./configuration.md#built-in-excludes)).
- SwiftLint gets files with Windows (CRLF) line ends as LF, so its line numbers match yours on a
  `core.autocrlf` checkout too.

## PHP (PHPStan)

The `qualor/scanner` image runs PHPStan 2.2 (MIT) on your `.php` files, on Debian's PHP 8.2. It runs
at **level 2**, which checks for undefined variables, calls with the wrong number of arguments,
using the result of a call that returns nothing (`void`), calls on values that are not objects, and
invalid PHPDoc.

**Install your dependencies before the scan.** PHPStan needs to know the classes your code extends
and calls. Run `composer install --no-scripts --no-plugins` in the job first. That is enough. Qualor
reads the PHP files in `vendor/` as data, to learn their symbols. It never runs them, nor Composer's
autoloader, scripts or plugins. A custom `config.vendor-dir` in `composer.json` is followed.

PHPStan is skipped, with the reason in the scan log, in two cases:

- `composer.json` requires packages and `vendor/` is not installed. Every inherited class would give
  a false finding. A project that requires no packages runs without `vendor/`.
- The installed dependencies are larger than 1 GiB or hold more than 200,000 files. Reading only
  part of them would flood the result with false findings.

Raise the level for stricter checks, from 0 to 10 or `max`:

```yaml
analyzers:
  phpstan:
    enabled: auto        # true, false, or auto: on when PHP files are in scope
    level: 5             # 0-10 or max; default 2
    memoryLimit: 2G      # PHPStan's --memory-limit; raise it for a big project
    timeoutSeconds: 900  # optional
```

Qualor never reads your `phpstan.neon` (or `phpstan.neon.dist`) and never loads PHPStan
extensions, bootstrap files or Composer's autoloader: they are PHP code that a merge request
controls. The level and the other settings come from `qualor.yml`. `@phpstan-ignore` comments in
the code are honoured.

PHPStan runs on a copy of your sources. It and its worker processes use a `php.ini` of Qualor's own
instead of yours or the system's, read no additional `.ini` files, and get none of your `PHPRC`,
`PHP_INI_SCAN_DIR`, `COMPOSER*`, `PHPSTAN_*` and `XDEBUG_*` variables. `QUALOR_PHPSTAN_PHAR` names
another PHPStan phar ([Configuration](./configuration.md)). It must be PHPStan 2.2.

Rule keys are `phpstan:` and PHPStan's identifier, for example `phpstan:variable.undefined`.

Limits:

- Qualor never reports unknown classes, methods or functions, nor the matching property, constant,
  trait and interface checks, nor unknown named arguments. Whether a symbol is known depends on
  what your job installed, and on framework magic that PHPStan understands only with extensions such
  as Larastan, which Qualor does not load. Run your own PHPStan for those checks.
- A file PHPStan cannot parse is left out with a warning in the scan log, and PHPStan runs again on
  the rest. One broken file does not hide the other findings.
- Only files whose name ends in `.php` are analysed, not `.phtml` or `.inc` files. Files larger
  than 1 MiB or reached through a symbolic link are not analysed either.

## Ruby (RuboCop)

The `qualor/scanner` image runs RuboCop 1.91 on your Ruby files: `.rb`, `.rake`, `.gemspec`, `.ru`,
`Gemfile` and `Rakefile`. It has its own Ruby, so no Ruby, gem or bundle is needed on the runner
and nothing is installed or built.

Qualor chooses the cops itself. The project's `.rubocop.yml` is **never read**, and neither is
`.rubocop_todo.yml` or a configuration in a subdirectory or your home directory. RuboCop runs Ruby
code that a configuration file names (ERB, `require`, plugins), and a scan must not run code from
the checkout. Choose cops in `qualor.yml` instead.

Inline comments in your code are honoured: `# rubocop:disable Lint/Foo` (and `# rubocop:todo`)
silences that cop on that line or block. A `# rubocop:enable` comment does not turn on a cop that is
not selected.

`qualor-default` runs RuboCop's Lint and Security cops that RuboCop enables by default: the ones
that find bugs and security problems, not style. It leaves out the 12 cops below, because they
misfire in a Qualor scan. Select any of them by name if you want it.

- `Lint/CopDirectiveSyntax`, `Lint/MissingCopEnableDirective`,
  `Lint/RedundantCopDisableDirective` and `Lint/RedundantCopEnableDirective` judge your
  `rubocop:` comments against a configuration Qualor does not use.
- `Lint/AmbiguousBlockAssociation`, `Lint/AssignmentInCondition`, `Lint/ConstantDefinitionInBlock`,
  `Lint/MissingSuper`, `Lint/UnderscorePrefixedVariableName`, `Lint/UnusedBlockArgument` and
  `Lint/UnusedMethodArgument` flag idioms that are normal in Rails callbacks, RSpec and DSL blocks.
- `Lint/ScriptPermission` checks file permissions, which Qualor does not keep when it reads your
  files, so it would flag every Ruby script with a `#!` line.

```yaml
analyzers:
  rubocop:
    enabled: auto              # true, false, or auto: on when Ruby files are in scope
    select: [qualor-default, Style, Naming]   # departments, cop names, or qualor-default
    ignore: [Style/Documentation]             # departments or cop names to leave out
    targetRubyVersion: '3.3'   # the Ruby syntax RuboCop parses; default 4.0
    timeoutSeconds: 600        # optional
```

- `select` takes RuboCop departments (`Lint`, `Security`, `Style`, `Layout`, `Naming`, `Metrics`
  and the others), cop names (`Style/StringLiterals`) and `qualor-default`. A department means the
  cops RuboCop enables by default in it. A cop name turns that cop on even if RuboCop leaves it
  disabled or pending.
- `ignore` removes departments or cops from the result.
- `targetRubyVersion` accepts the versions RuboCop 1.91 parses: 2.0 to 4.1.
- An unknown department or cop, or a `targetRubyVersion` that RuboCop 1.91 does not parse, is a
  configuration error: the scan stops with exit 2.

Rule keys look like `rubocop:Lint/UselessAssignment`.

Limits:

- `.erb` templates are not analysed.
- A file that RuboCop cannot parse gets no findings. A syntax error is not reported as an issue.
- Plugin cops (`rubocop-rails`, `rubocop-rspec`, `rubocop-performance`) do not run: the plugins are
  not installed, and a configuration cannot load them.
- Files larger than 1 MiB, files reached through a symbolic link, and names with a line break are
  not passed. `.bundle/` directories and `db/schema.rb` are never scanned
  ([built-in excludes](./configuration.md#built-in-excludes)).
- RuboCop runs offline, with Qualor's own configuration and a clean environment (no `RUBYOPT`,
  `GEM_*` or `BUNDLE_*`).
- RuboCop is skipped, with the reason in the scan log, when the image's RuboCop is missing or is a
  different minor version than 1.91.

## Go (staticcheck, go vet, gosec)

The `qualor/scanner` image runs three Go analyzers on every Go module in your repository (each
`go.mod` and the `.go` files below it): **staticcheck** 2026.2.1, **go vet** of Go 1.27.1, and
**gosec** 2.29.0 for security.

They type-check your code, so they need your dependencies, and Qualor never downloads them.
Download them in the scan job:

```yaml
# GitLab: the scan job, image qualor/scanner
qualor:
  image: qualor/scanner:<version>
  script:
    - go mod download     # in each module directory, or vendor your dependencies
    - qualor scan
```

A module cache of your own works too: point `GOMODCACHE` at it, outside the repository. A package
whose dependencies are missing is not analysed, and the scan log says which and why.

Your `staticcheck.conf`, `//lint:ignore` and `#nosec` comments are honoured. staticcheck reads
`staticcheck.conf` as a settings file only; nothing in it is run. `.golangci.yml` is not read.

```yaml
analyzers:
  gosec:
    exclude: [G104, G115, G304]   # the default; [] runs every rule
```

The default leaves out G104 (unchecked errors), G115 (integer-conversion overflow) and G304 (file
path provided as taint input). G304 flags idiomatic file reads on real projects almost every time.
To turn it back on, list only the rules you want to skip, for example `exclude: [G104, G115]`, or
set `exclude: []`.

| Findings | Severity |
|---|---|
| staticcheck's correctness and concurrency checks (`SA5…`, `SA2…`) | high |
| staticcheck's other bug checks, and unused code | medium |
| staticcheck's simplifications and style checks | low |
| go vet | medium |
| gosec | gosec's own HIGH, MEDIUM or LOW |

Where go vet and staticcheck report the same mistake on one line (`printf` and `SA5009`, `bools`
and `SA4000`), the server keeps one issue.

Qualor never runs anything the repository asks for:

- No `go generate`, no other Go toolchain (`toolchain` and `GOTOOLCHAIN` are ignored), no C
  compiler and no module download.
- `GOFLAGS` from the CI job is emptied and `GOWORK=off` is set, so a `go.work` file is ignored and
  each module is analysed on its own.
- cgo is switched off (`CGO_ENABLED=0`). Files that use cgo (`import "C"`) are left out, and a
  package that needs them is reported as not analysed.

A module is skipped, with a log line, when its `go` line needs a newer Go than 1.27.1, when its
`replace` points at a directory outside the repository, or when it contains a symbolic link out of
the repository.

One case is not covered. Qualor does not look for links inside the directories Go itself ignores
(names starting with `.` or `_`, and `testdata`) or inside `node_modules`. If your code explicitly
imports a package from one of them, `go` could compile a file that is linked from outside the
repository. Findings on files outside the repository are dropped, so only a compiler message could
repeat a line of such a file, in the scan log or in the report. Do not scan repositories you do not
trust in a job that can read secrets or host files.

Limits:

- `testdata/` directories and generated `*.pb.go` files are never scanned
  ([built-in excludes](./configuration.md#built-in-excludes)).
- The three analyzers are skipped, with the reason in the scan log, when no Go module is in scope,
  when no `go`, `staticcheck` or `gosec` of the supported version is available (outside the image),
  or when every module is left out for the reasons above.

## Java (PMD, SpotBugs and FindSecBugs)

**PMD** reads the source. **SpotBugs** reads compiled classes, and **FindSecBugs** 1.14.0,
SpotBugs' security plugin, runs inside it in the `qualor/scanner` image.

Build before the scan (`mvn -B -DskipTests package` or `./gradlew classes`), so SpotBugs has
classes to read. It looks in `target/classes` and `build/classes/java/main` by default. When those
are empty, it is skipped with the reason
`no compiled classes … (build the project before qualor scan)`.

On a Maven project, SpotBugs gives a better result with the classpath. Write it with
`mvn dependency:build-classpath -Dmdep.outputFile=target/classpath.txt`. That file holds one line,
with entries separated by `:`. Convert it to one entry per line, for example with `tr ':' '\n'`.

```yaml
analyzers:
  pmd: { rulesets: [config/pmd.xml] }
  spotbugs:
    classDirs: [app/target/classes, lib/target/classes]
    auxClasspathFile: target/classpath.txt   # optional: one classpath entry per line
```

PMD's default ruleset, `qualor-default`, is PMD's own `rulesets/java/quickstart.xml`. Name your own
ruleset files in `rulesets`, or PMD's built-in categories (`category/java/bestpractices.xml`).

FindSecBugs follows untrusted data (request parameters, headers, files, the command line) into SQL,
shell commands, file paths, LDAP, XPath, XML parsers and outgoing URLs. It also flags weak
cryptography, hard-coded passwords and unsafe configuration.

- Its rules are SpotBugs rules (`spotbugs:SQL_INJECTION_JDBC`), so the Java quality profile turns
  each one on or off.
- Injections and definite misuse (an XML parser open to XXE, a trust-all TLS manager, DES or ECB, a
  hard-coded password) are **issues** and count in the quality gate.
- Findings that ask you to review a usage are **security hotspots**: listed, never counted. Examples
  are a non-cryptographic random number, a cookie without its flags, a permissive CORS policy, a
  weak hash, object deserialisation, and request parameters and endpoints.
- Where SpotBugs' own rule and FindSecBugs report the same problem on one line (SQL built from a
  variable, a constant database password, a request parameter in a file path or a servlet
  response), Qualor shows one issue: SpotBugs' own.
- Qualor drops `findsecbugs*` environment variables before it runs SpotBugs, so a custom
  FindSecBugs configuration named there is not read.
- A SpotBugs installed outside the image runs without the plugin, unless you put its jar into
  SpotBugs' `plugin/` directory. The scan's SpotBugs version says whether it ran (for example
  `4.10.4 + FindSecBugs 1.14.0`).

## C#

Roslyn analyzers need the compiler's semantic model, so Qualor hooks into **your own build** instead
of building anything itself, as SonarScanner for .NET does:

```sh
qualor dotnet begin                 # installs an MSBuild hook for this checkout
dotnet build --no-incremental       # your build: its SDK, restore, feeds and arguments
qualor dotnet end                   # removes the hook, reads the Roslyn logs, runs qualor scan
```

Use the **`qualor/scanner-dotnet`** image. It adds the .NET 8 and .NET 10 SDKs, Roslynator and
SonarAnalyzer.CSharp 9.32 (SonarQube-compatible rules, LGPL-3.0) to the scanner. GitLab:

```yaml
qualor:
  image: { name: qualor/scanner-dotnet:0.12, entrypoint: [''] }
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

### The build hook

- Build with **`--no-incremental`**. A project that is not recompiled writes no log, and you get
  the warning `ROSLYN_PROJECT_NOT_ANALYZED`.
- Inside the scan job, the hook turns off _warnings as errors_, so the extra rules cannot break a
  build that passes without them. Compiler errors still fail it. If your pipeline must fail on
  warnings, keep a separate build job for that.
- The SDK's analyzers run in the **Recommended** mode, with every security rule on. The noisy rules
  that the stricter _All_ mode adds, such as CA2007 and CA1508 (which can stall the build of a
  large solution), are not reported. Set a rule's severity in your `.editorconfig` to turn it back
  on.
- The repository's `.editorconfig` and `.globalconfig` still decide severities. A rule set to
  `none` stays off.
- If the project references Roslynator or SonarAnalyzer.CSharp itself, its own version is used
  instead of the bundled one, so there is never a duplicate-analyzer build error.
- Turn the bundled SonarAnalyzer.CSharp off with `analyzers.roslyn.sonarAnalyzer: false`.
- `qualor dotnet abort` cleans up when the build fails, so no hook is left behind.
- A plain `qualor scan` does not run the Roslyn analyzers. It still runs Qualor's C# security rules
  on OpenGrep.
- A checkout path that contains a semicolon (`;`) makes the compiler reject its log option, so
  `qualor dotnet begin` refuses it. C# is then not analysed, and under `enabled: true` the scan
  exits 3. A comma in the path only warns that the Roslyn logs will be missing.
- On Windows, the build writes the code it generates for Razor views under
  `.qualor\dotnet\generated` in the checkout. A deep checkout path with long view names can pass the
  260-character path limit (`MAX_PATH`), and the compiler then fails to write the file. Check out
  to a short path (for example `C:\w\repo`) or turn on long paths in Windows.

### Qualor's C# security rules

Under `qualor dotnet begin` and `end`, the hook also records each project's compiler inputs.
`qualor dotnet end` then runs Qualor's Roslyn taint engine, part of the rules release, on the whole
solution. For the `.cs` files, its findings take the place of the OpenGrep C# rules, under the same
rule keys (`qualor:csharp/<name>`).

- Flows are followed across methods, files and projects, through fields, properties and interface
  or virtual calls.
- The engine follows what the code does, not how the application is wired. Services registered for
  dependency injection are found through their interfaces, but handlers the framework calls by
  convention (MediatR handlers, hosted services) are not entered from the request.
- `ViewData`, `ViewBag` and `HttpContext.Items` entries are followed into the views of the same
  request, also under a key built at run time.
- Razor views and components are analysed through the C# code the build generates for them: MVC and
  Razor Pages views (`.cshtml`), where findings point at the view's own line, and Blazor components
  (`.razor`). Blazor's `MarkupString` is not modelled as a sink, so raw HTML in a component is not
  reported.
- A `.cs` file that belongs to no project the build compiled (a script, a project left out of the
  build) is still analysed by the OpenGrep C# rules.
- Each finding shows the path from the request data to the dangerous call as its related
  locations, followed by any other request data that reaches the same call.

**Confidence.** A finding is marked **Possible** when its path goes through one of these:

- stored data (a field or property set elsewhere in the same request)
- a lookup whose key comes from the request
- a `ViewData` entry under a key built at run time
- a view the engine could not tell from its name
- an interface or virtual call it could not narrow down to one implementation

The engine shows a direct path when it finds one. Check Possible findings with more care before you
act on them. The mark shows in the issue list, on the issue page (a **Confidence** line in its
details), in a file's issue list, after the finding's quality in merge request and pull request
comments, and as `Possible: ` at the start of its entry in the GitLab Code Quality and SAST reports.
Possible findings count like any other in the quality gate and the issue counts. The engine's other
findings have high confidence and no mark. The OpenGrep rules and the other analyzers set no
confidence, so their findings never show the mark.

**Time and memory.** The engine has a budget:

- Time: 10 minutes by default. Set `QUALOR_TAINT_TIME_LIMIT` (seconds) to change it.
- Memory: by default half of the job's memory, at least 4096 MB, but always leaving 1024 MB for the
  build and the other analyzers, and never less than 1024 MB. Set `QUALOR_TAINT_MEMORY_LIMIT`
  (megabytes) to choose it yourself.

The job's memory is the smaller of the machine's memory and the container's limit, read from the
process's own cgroup and its parents. When the runner hides the limit, set
`QUALOR_TAINT_MEMORY_LIMIT` yourself. The log line `taint engine memory limit` in
`qualor dotnet end` shows the value and where it came from.

| Job's memory | Engine's default limit |
|---|---|
| 16 GB runner | 8192 MB |
| 6 GB container | 4096 MB |
| 4 GB container | 3072 MB |
| 2 GB container | 1024 MB |

A solution the size of nopCommerce needs about 3.5 GB; smaller ones need far less. Give the job more
memory if the solution is large.

**Fallback.** When the engine cannot give a complete result, the OpenGrep C# rules run as in a
plain scan, and the report carries the warning `TAINT_ENGINE_FALLBACK` with the reason. The log line
says more. The scan's exit code is the same either way.

| Reason | Meaning |
|---|---|
| `budget` | the engine went over its time or memory budget. Raise `QUALOR_TAINT_TIME_LIMIT` or `QUALOR_TAINT_MEMORY_LIMIT` and run again |
| `load` | the sources of a project could not all be loaded, so part of its code would go unanalysed |
| `crash` | the engine failed |
| `no-inputs` | the build recorded no compiler inputs |
| `dotnet-missing` | `dotnet` is not installed |
| `no-engine` | the rules release has no engine, or its manifest describes it wrongly |
| `engine-mismatch` | the engine's files do not match the release's checksums. The engine is never run then |

- A fallback run closes the issues only the engine finds (flows across files, or through generated
  Razor code), because the OpenGrep rules cannot see them. They reopen with their earlier status at
  the next run in which the engine completes.
- Files of a project the engine could not load are analysed by neither engine: they leave the
  OpenGrep rules because the build compiled them.
- A project that loads but has compile errors or unresolved references is still analysed as far as
  its compilation allows. The report then carries the warning `TAINT_ENGINE_PROJECT_ERRORS` (the
  number of projects), and the log names each project with its first error. Restore the packages
  and build the project without errors to get its full analysis.
- If the scan is interrupted (Ctrl+C or a cancelled job), the engine's temporary directory is
  removed.

## C and C++ (cppcheck, clang-tidy)

The `qualor/scanner` image runs **cppcheck** 2.22.0 on your C and C++ files, with no build and no
setup: errors plus the `warning`, `performance` and `portability` checks. Add `style` for more (it
is much noisier):

```yaml
analyzers:
  cppcheck:
    enable: [warning, style, performance, portability]
    includePaths: [include]          # used when there is no compile_commands.json
    defines: [HAVE_CONFIG_H]
```

When your repository has a `compile_commands.json` (at the root or in `build/`, or named by
`compileCommands`), Qualor gives cppcheck its include paths, defines and language standard. Inline
suppressions (`// cppcheck-suppress nullPointer`) work.

`uninitMemberVar`, `uninitMemberVarPrivate` and `uninitMemberVarNoCtor` are off by default, since
they mostly flag union members. Turn them on with `select: [uninitMemberVar]` under `cppcheck`.

**clang-tidy** runs when the job that scans also has `clang-tidy` (LLVM 14 or newer) on the `PATH`
and a compile database. That is typically the job that built your project:

```sh
cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON && cmake --build build
qualor scan          # finds build/compile_commands.json
```

No Qualor image bundles clang-tidy: it needs your build's headers and flags. Use a clang-tidy of the
same LLVM major as your compiler where you can.

Your `.clang-tidy` at the repository root is used for `Checks`, `CheckOptions` and the header and
implementation file extensions. A `.clang-tidy` that sets its own `Checks` replaces Qualor's default
checks. Without one, Qualor runs the bug-finding groups (`bugprone-*`, `clang-analyzer-*`,
`performance-*`, `portability-*`, `concurrency-*`), minus a few noisy checks. Qualor ignores:

- settings that pass compiler arguments, load other configurations or turn warnings into errors
  (`ExtraArgs`, `InheritParentConfig`, `WarningsAsErrors`...)
- nested `.clang-tidy` files
- analyzer options that name a file (`clang-analyzer-...:Config`)

The scan log says what was left out.

Qualor never runs your build. It reads `compile_commands.json` itself and passes on only include
paths, defines, the language standard and harmless flags (`-I`, `-D`, `-U`, `-std` and a short list
of others). The compiler is never taken from the database. Plugins, `-Xclang` options and response
files (`@file`) are dropped.

Only code of your repository is reported. A finding that clang-tidy or cppcheck places in a system
header or in a directory outside the checkout is dropped, and a path outside the repository that a
message quotes is replaced by a placeholder. Headers you include from outside the repository (an
absolute `-I`) are still read for the analysis.

Rule keys look like `cppcheck:nullPointer` and `clang-tidy:bugprone-use-after-move`.

Limits:

- Code the tools cannot compile (a missing generated header, an unknown macro) is reported as a
  warning, not as an issue.
- A `.h` file counts as C++ when your repository has any C++ file in scope, a fuzzer included.
  Otherwise it counts as C.
- `CMakeFiles/`, `cmake-build-*/` and `_deps/` are never scanned.
- Both tools are skipped, with the reason in the scan log, when they are missing, when cppcheck is
  not version 2.22, when clang-tidy is older than LLVM 14, or when there is no compile database for
  clang-tidy. Under `enabled: true` the scan fails with exit 3 instead.

## Secrets (Gitleaks)

Gitleaks scans the working tree with its built-in rules, or with `.gitleaks.toml` at the repository
root. It honours `.gitleaksignore` and `gitleaks:allow` comments. The secret itself never reaches
the report or the server: the finding's message is the rule's text.

Gitleaks is `enabled: true` by default, so a scan outside the scanner image without Gitleaks
exits 3. Set `analyzers.gitleaks.enabled: auto` to make it optional.

## Dependencies (Trivy)

Trivy reads lockfiles and manifests (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `pom.xml`,
`gradle.lockfile`, and Go, Python, Ruby, Rust, PHP and .NET lockfiles) and reports packages with
known vulnerabilities. Development dependencies are left out.

A vulnerability counts as **new code** only when the merge request adds the package or changes its
version. So a database update never fails a merge request that did not touch the dependency.

Ignore a vulnerability by id in `.trivyignore` at the repository root.

The vulnerability database comes from the image and is never downloaded during a scan. It is as old
as the scanner release you run. Keep the scanner current (the minor tag `0.12` follows its patch
releases), or fetch a fresh database in the job:

```yaml
script:
  - trivy image --download-db-only --cache-dir /tmp/trivy   # add --db-repository <your mirror> if needed
  - QUALOR_TRIVY_CACHE_DIR=/tmp/trivy qualor scan
```

`QUALOR_TRIVY_CACHE_DIR` must be absolute and outside the checkout. Jobs that run repository code
must not be able to write it.

A second Trivy pass reads the **licences** of your dependencies, offline and without the database.
It gives every project a dependency inventory (the **Dependencies** tab) and, with a licence policy
(Business and Enterprise), licence issues. See [Dependency licences](./dependency-licenses.md) for
which lockfiles give licences and why to install your dependencies first.
`analyzers.trivy.licenses` and `licenseTimeoutSeconds` control the pass
([Configuration](./configuration.md#qualoryml)).

## Security rules (Qualor)

Qualor has its own security rules for JavaScript, TypeScript, Python, Java, Go and C#: 69 rules that
run in every edition. They run as the `qualor` engine on OpenGrep. Under `qualor dotnet end`, the C#
rules run on Qualor's own Roslyn taint engine instead (see [C#](#c)). The `qualor/scanner` image,
and `qualor/scanner-dotnet`, which builds on it, include them. There are three kinds:

- **Taint rules** follow data from an HTTP request (a query parameter, a form field, a header, a
  cookie, a JSON body) or the name of an archive entry to a dangerous call (an SQL query, a shell
  command, a file path, a template, an outgoing request, a redirect). They report it when nothing
  made it safe on the way.
- **Misuse rules** report unsafe settings and APIs whatever the data, such as disabled TLS
  certificate verification, an XML parser that resolves external entities or a broken cipher.
- **Hotspots** point at code to review, where only you can tell whether it is safe: a weak hash, a
  cookie without its flags, raw HTML in React, a tar archive extracted without a safe filter.

Qualor's security rules analyse application code. Test files, the files `tests.include` names, are
not scanned by them.

Each rule knows the frameworks and libraries in its row. **JavaScript and TypeScript** (the `js`
rules apply to both):

| Rule | Finds | Frameworks and libraries |
|---|---|---|
| `qualor:js/sql-injection` | SQL built from request data | Express, Next.js, Fastify; `pg`, `mysql2`, Knex, Sequelize, Prisma, TypeORM |
| `qualor:js/nosql-injection` | MongoDB filters, query operators or server-side JavaScript (`$where`) from request data | Express, Next.js, Fastify; MongoDB driver, Mongoose |
| `qualor:js/command-injection` | an OS command or shell script built from request data (also after `cmd /c` and PowerShell's `-Command`, `-EncodedCommand` or `-File`) | Express, Next.js, Fastify; `child_process` |
| `qualor:js/code-injection` | request data run as JavaScript (`eval`, `Function`, `node:vm`) | Express, Next.js, Fastify, Node.js `http` |
| `qualor:js/template-injection` | request data used as a template, or as the whole data object of an EJS render | Express, Next.js, Fastify; EJS, Pug, Handlebars, Nunjucks, lodash `template` |
| `qualor:js/path-traversal` | a file path built from request data | Express, Next.js, Fastify; `fs` |
| `qualor:js/ssrf` | a server-side request whose URL, scheme or host comes from the request | Express, Next.js, Fastify, Node.js `http`; `fetch`, axios, got, undici |
| `qualor:js/open-redirect` | a redirect whose target, scheme or host comes from the request | Express, Next.js, Fastify, Node.js `http` |
| `qualor:js/xss` | request data written into an HTML response without escaping | Express, Next.js, Fastify, Node.js `http` |
| `qualor:js/regex-injection` | a regular expression built from request data (ReDoS) | Express, Next.js, Fastify, Node.js `http` |
| `qualor:js/prototype-pollution` | nested property writes with keys from the request (`obj[a][b] = v`) | Express, Next.js, Fastify |
| `qualor:js/tls-verification-disabled` | `rejectUnauthorized: false` (also in the TLS options of other client libraries), MongoDB's `tlsAllowInvalidCertificates` or `tlsInsecure`, or `NODE_TLS_REJECT_UNAUTHORIZED` set to `0` | `https`, `tls`, `http2`, axios, undici, node-postgres, knex, mysql2, Sequelize, TypeORM, nodemailer, got, `ws`, MongoDB driver, Mongoose |
| `qualor:js/react-dangerous-html` (hotspot) | raw HTML given to `dangerouslySetInnerHTML` | React, Next.js |
| `qualor:js/insecure-cookie` (hotspot) | a cookie set without `Secure` or `HttpOnly` | Express, express-session, cookie-session, Fastify (`@fastify/cookie`), Next.js |

**Python:**

| Rule | Finds | Frameworks and libraries |
|---|---|---|
| `qualor:python/sql-injection` | SQL built from request data | Flask, Django (also `raw`, `extra`, `RawSQL`), Starlette; DB-API, SQLAlchemy, psycopg |
| `qualor:python/command-injection` | a shell command, or the program to run, built from request data (also after `cmd /c` and PowerShell's `-Command`, `-CommandWithArgs`, `-EncodedCommand` or `-File`, and the program of `os.exec*()` and `os.spawn*()`) | Flask, Django, FastAPI, Starlette; `os`, `subprocess`, `asyncio` |
| `qualor:python/code-injection` | request data run as Python (`eval`, `exec`, `compile`) | Flask, Django, FastAPI, Starlette |
| `qualor:python/unsafe-deserialization` | request data loaded with pickle, marshal, shelve, dill, jsonpickle or an unsafe YAML loader | Flask, Django, FastAPI, Starlette |
| `qualor:python/template-injection` | request data used as the source of a Jinja or Django template | Flask, Django, FastAPI, Starlette; Jinja2 |
| `qualor:python/path-traversal` | a file path built from request data | Flask, Django, FastAPI, Starlette; Werkzeug, `pathlib`, `shelve`, `dbm` |
| `qualor:python/ssrf` | a server-side request whose URL, scheme or host comes from the request | Flask, Django, FastAPI, Starlette; requests, httpx, aiohttp, `urllib` |
| `qualor:python/open-redirect` | a redirect or `Location` header whose target, scheme or host comes from the request (in middleware, also from the request's path) | Flask, Django (also `RedirectView`), FastAPI, Starlette |
| `qualor:python/xss` | request data written into an HTML response without escaping, or marked safe | Flask, Django, FastAPI, Starlette; MarkupSafe, bleach, nh3 |
| `qualor:python/xpath-injection` | an XPath expression built from request data | Flask, Django, FastAPI, Starlette; lxml, ElementTree |
| `qualor:python/regex-injection` | a regular expression built from request data (ReDoS) | Flask, Django, FastAPI, Starlette |
| `qualor:python/xxe` | an XML parser set to resolve external entities or to use the network | lxml, `xml.sax`, `xml.dom` |
| `qualor:python/tls-verification-disabled` | `verify=False`, `ssl=False`, an unverified `ssl` context, `CERT_NONE`, a host name check turned off, or an SDK switch that skips certificate checks | requests, httpx, aiohttp, `ssl`, urllib3, boto3, Elasticsearch, OpenSearch, PyMongo, Motor, redis-py, hvac |
| `qualor:python/xxe-dtd-options` (hotspot) | an lxml parser that loads the document's DTD (`load_dtd`, `dtd_validation`, `attribute_defaults`) or lifts its size limits (`huge_tree`) | lxml |
| `qualor:python/tar-extraction` (hotspot) | a tar archive extracted without a safe extraction filter or a check of each member | `tarfile`, `shutil.unpack_archive` |

**Java:**

| Rule | Finds | Frameworks and libraries |
|---|---|---|
| `qualor:java/sql-injection` | SQL built from request data | Servlets, Spring MVC, JAX-RS; JDBC, Spring JDBC, JPA |
| `qualor:java/command-injection` | an OS command, its program or its environment built from request data | Servlets, Spring MVC, JAX-RS |
| `qualor:java/expression-injection` | request data evaluated as an expression | Servlets, Spring MVC, JAX-RS; Spring SpEL, Jakarta EL, OGNL, MVEL |
| `qualor:java/template-injection` | request data used as template source (or as a Thymeleaf template name) | Servlets, Spring MVC, JAX-RS; FreeMarker, Velocity, Thymeleaf |
| `qualor:java/unsafe-deserialization` | request data read with Java serialization or `XMLDecoder` | Servlets, Spring MVC, JAX-RS |
| `qualor:java/ldap-injection` | an LDAP search filter built from request data | Servlets, Spring MVC, JAX-RS; JNDI, Spring LDAP |
| `qualor:java/xpath-injection` | an XPath expression built from request data | Servlets, Spring MVC, JAX-RS; `javax.xml.xpath` |
| `qualor:java/regex-injection` | a regular expression built from request data (ReDoS) | Servlets, Spring MVC, JAX-RS; `java.util.regex`, `String` regex methods |
| `qualor:java/path-traversal` | a file path built from request data | Servlets, Spring MVC, JAX-RS |
| `qualor:java/ssrf` | a server-side request whose URL, scheme or host comes from the request | Servlets, Spring MVC, JAX-RS; `java.net.URL`, `java.net.http`, Spring `RestTemplate`, `RestClient`, `WebClient` |
| `qualor:java/open-redirect` | a redirect whose target comes from the request | Servlets, Spring MVC, JAX-RS |
| `qualor:java/xss` | request data written into an HTML response without encoding | Servlets, Spring MVC, JAX-RS |
| `qualor:java/xxe` | an XML parser used without disabling DTDs or external entities | JAXP (DOM, SAX, StAX, `TransformerFactory`, `SchemaFactory`, `Validator`), dom4j, JDOM |
| `qualor:java/zip-slip` | an archive entry name used as an extraction path | `java.util.zip`, `java.util.jar`, Commons Compress |
| `qualor:java/tls-verification-disabled` | a trust manager or trust strategy that accepts any certificate, or a host name verifier that accepts any host (also Apache HttpClient's `NoopHostnameVerifier` and `TrustAllStrategy`) | `javax.net.ssl`, OkHttp, Apache HttpClient, Jakarta REST client |
| `qualor:java/weak-cipher` | DES, Triple DES, RC2, RC4, Blowfish or RC5 (also in PBE names), ECB mode, RSA without padding, or `NullCipher` | `javax.crypto` |

**Go:**

| Rule | Finds | Frameworks and libraries |
|---|---|---|
| `qualor:go/sql-injection` | SQL built from request data | `net/http`, Gin, Echo, chi, gorilla/mux; `database/sql`, GORM |
| `qualor:go/command-injection` | a shell script or program name built from request data (also after PowerShell's `-Command`, `-CommandWithArgs`, `-EncodedCommand` or `-File`) | `net/http`, Gin, Echo, chi, gorilla/mux; `os/exec` |
| `qualor:go/template-injection` | request data parsed as Go template text | `net/http`, Gin, Echo, chi, gorilla/mux; `html/template`, `text/template` |
| `qualor:go/path-traversal` | a file path built from request data | `net/http`, Gin, Echo, chi, gorilla/mux; `os` |
| `qualor:go/ssrf` | a server-side request or reverse proxy whose URL, scheme or host comes from the request | `net/http`, Gin, Echo, chi, gorilla/mux; `net/http/httputil` |
| `qualor:go/open-redirect` | a redirect whose target, scheme or host comes from the request | `net/http`, Gin, Echo, chi, gorilla/mux |
| `qualor:go/xss` | request data written into an HTML response without escaping (also through a buffer, `text/template` or `template.HTML`), or the request body copied into it | `net/http`, Gin, Echo, chi, gorilla/mux; `html/template`, `text/template`, bluemonday |
| `qualor:go/zip-slip` | an archive entry name used as an extraction path | `archive/zip`, `archive/tar`, `os` |
| `qualor:go/tls-verification-disabled` | `InsecureSkipVerify: true` | `crypto/tls`, `net/http` |
| `qualor:go/weak-cipher` | DES, Triple DES or RC4, or an insecure TLS cipher suite in a `tls.Config` | `crypto/des`, `crypto/rc4`, `crypto/tls` |
| `qualor:go/weak-hash` (hotspot) | MD5 or SHA-1 | `crypto/md5`, `crypto/sha1`, `crypto` |
| `qualor:go/insecure-cookie` (hotspot) | a cookie set without `Secure` or `HttpOnly` | `net/http`, Gin, Echo |

**C#:**

| Rule | Finds | Frameworks and libraries |
|---|---|---|
| `qualor:csharp/sql-injection` | SQL built from request data | ASP.NET Core (controllers, Minimal APIs, Razor Pages); ADO.NET, Dapper, Entity Framework Core |
| `qualor:csharp/command-injection` | the program started, or a shell's command line, built from request data (not the arguments of other programs) | ASP.NET Core; `System.Diagnostics.Process` |
| `qualor:csharp/path-traversal` | a file path built from request data | ASP.NET Core; `System.IO` |
| `qualor:csharp/ssrf` | a server-side request whose URL, scheme or host comes from the request | ASP.NET Core; `HttpClient`, `HttpRequestMessage`, `WebRequest` and `HttpWebRequest` |
| `qualor:csharp/xss` | request data written into an HTML response without encoding | ASP.NET Core |
| `qualor:csharp/open-redirect` | a redirect whose target comes from the request | ASP.NET Core |
| `qualor:csharp/ldap-injection` | an LDAP search filter built from request data | ASP.NET Core; `System.DirectoryServices` |
| `qualor:csharp/xpath-injection` | an XPath expression built from request data | ASP.NET Core; `System.Xml` (`SelectNodes`, `XPathNavigator`) and LINQ to XML (`XPathSelectElement`) |
| `qualor:csharp/regex-injection` | a regular expression built from request data (ReDoS) | ASP.NET Core; `System.Text.RegularExpressions` |
| `qualor:csharp/unsafe-deserialization` | a deserializer that lets the data choose the types to create, whatever the data is (it needs no request) | `BinaryFormatter` and the other formatters, Json.NET `TypeNameHandling` other than `None`, `JavaScriptSerializer` with `SimpleTypeResolver` |
| `qualor:csharp/xxe` | an XML parser given an `XmlUrlResolver` while it processes DTDs, whatever the document (it needs no request) | `System.Xml` (`XmlReaderSettings`, `XmlDocument`, `XmlTextReader`) |
| `qualor:csharp/tls-verification-disabled` | a certificate or host name validation callback that accepts anything | `HttpClientHandler`, `SocketsHttpHandler`, `SslStream`, `ServicePointManager` |

### How findings count

- Issues (from taint and misuse rules) are Security issues and count in the quality gate. Hotspots
  are **security hotspots**: listed, never counted.
- Where another analyzer reports the same problem on the same line, Qualor's issue is the one shown
  and the other is its duplicate. That holds for rules with the same CWE, and for these matching
  rules that carry none or another one: Ruff's flake8-bandit rules (`S608` with the SQL injection
  rule, `S307` with code injection, and so on), the SonarJS hotspots `S2077`, `S4721` and `S1523`,
  gosec's `G107`, `G708` and `G710`, and SpotBugs' path traversal, XSS and expression language
  rules.
- If you had marked that other issue as a false positive or won't fix, Qualor's new issue starts
  with that status when it is first created. A later reopen is kept. The new issue's history names
  the other rule and repeats the comment on that status, if there was one.

### What the rules follow

Taint rules follow data **through the functions of one file**: a value that goes into a helper
function in the same file and comes back out of it is still followed. A value that passes through
another file is not followed, except by the [Roslyn taint engine](#qualors-c-security-rules) for C#.

The C# rules on OpenGrep run in a plain `qualor scan`, in a fallback under `qualor dotnet end`, and
on a `.cs` file of no compiled project. Unlike the Roslyn taint engine, they have these limits:

- Razor views (`.cshtml`, `.razor`) are not analysed.
- OpenGrep 1.30 does not parse C# 12 body-less type declarations and some collection expressions,
  so parts of such files are skipped.
- Data does not flow out of expression-bodied members or property getters.

### Rule pages and versions

The messages of the OpenGrep rules say why the code is unsafe and how to fix it. The C# findings of
the Roslyn taint engine name the sink they reach, with the engine's internal rule id
(`csharp.sql-injection`, with a dot, for the rule `csharp/sql-injection`), and the rule's page gives
the fix.

Each rule has its own page in the qualor-rules repository, under `docs/rules/<lang>/<name>.md`. For
`qualor:go/sql-injection` it is
<https://github.com/qualor-dev/qualor-rules/blob/main/docs/rules/go/sql-injection.md>. The rule's
documentation link opens it: on the issue page, in the rules list, and on the rule's key in merge
request and pull request comments.

The engine's version in a scan names the rules release, for example
`1.30.0 + qualor-rules 2026.10.6`. When the Roslyn taint engine analysed only C# files, it is
`qualor-taint 2026.10.6 + qualor-rules 2026.10.6`.

### Settings

- Turn a rule off in the language's quality profile. The `js` rules apply to JavaScript and
  TypeScript files: turn them off in both profiles.
- A `nosemgrep` comment does not hide these findings, and a `.semgrepignore` file does not apply to
  them: they scan exactly the files Qualor scans (`sources` in `qualor.yml`). Mark a finding as a
  false positive in Qualor instead.
- Configure the engine with `analyzers.qualor` (`enabled`, `timeoutSeconds`). `QUALOR_RULES_DIR`
  names another directory with the unpacked rules ([Configuration](./configuration.md)).
- `SEMGREP_*` and `OPENGREP_*` environment variables never reach OpenGrep.

### Licence

The rules are source-available, not open source: they are under the PolyForm Shield License 1.0.0,
not the MIT licence of the Qualor CLI. You may use, change and share them for any purpose, free of
charge and in any Qualor edition, except to provide a product that competes with Qualor or with
the rules themselves. If you pass them on, pass on the licence terms too. In an image that includes
the rules, the licence text is at `/opt/qualor/licenses/qualor-rules/LICENSE`.

### Outside the image

Rules releases are published at <https://github.com/qualor-dev/qualor-rules/releases>, each with its
SHA-256. Unpack one, set `QUALOR_RULES_DIR` to it, and put the OpenGrep version that its
`manifest.json` names (`opengrep`) on the `PATH`. With another version, the scan logs a warning.

Without the rules, the engine is skipped with the message "Qualor's security rules are not
installed" (see [Troubleshooting](./troubleshooting.md)), and nothing else changes. A rules release
that holds C# rules needs Qualor 0.9.0 or later: Qualor 0.8.0 and older refuse the whole pack. The
images pin their own pack, so they are not affected.

## SAST patterns (OpenGrep, Semgrep)

The `semgrep` analyzer bundles no rules. To use OpenGrep with your own patterns, keep the rule files
in the repository and name them:

```yaml
analyzers:
  semgrep:
    configs: [.semgrep/]            # local files or directories only
```

Registry ids such as `p/default` are refused (exit 2), because they would fetch rules over the
network.

## External SARIF

Any tool that writes SARIF 2.1.0 can feed Qualor: osv-scanner, Checkov, tfsec, Bandit,
golangci-lint, Hadolint and others. Run it before the scan, then pass its output:

```sh
qualor scan --sarif reports/osv.sarif --sarif reports/checkov.sarif
```

Or list it permanently in `qualor.yml`:

```yaml
sarif:
  - path: reports/osv.sarif
    engine: osv-scanner            # optional; default: the SARIF tool name
```

These engine ids are reserved:

- the built-in analyzers: `eslint`, `sonarjs`, `ruff`, `pmd`, `spotbugs`, `semgrep`, `gitleaks`,
  `trivy`, `roslyn`, `stylelint`, `htmlhint`, `detekt`, `swiftlint`, `phpstan`, `rubocop`,
  `staticcheck`, `govet`, `gosec`, `cppcheck`, `clang-tidy` and `qualor`
- `license`, the engine of the [licence policy](./dependency-licenses.md#licence-issues)'s issues
- `trivy-licenses`, the scanner's licence pass
- `ai`, the engine of [AI review](./ai-review.md) findings. Only the server creates them, and they
  stay outside the measures and the quality gate.

`engine:` with a reserved id (`engine: ruff`, `engine: license`, `engine: ai`) is a configuration
error. A SARIF file whose tool has a reserved name is reported under `ext-<name>`, such as
`ext-ruff`, `ext-license` or `ext-ai`.

Do not import SARIF from the tools Qualor runs itself. If you imported Ruff, stylelint, HTMLHint,
detekt, SwiftLint, PHPStan, RuboCop, staticcheck, gosec, cppcheck or clang-tidy SARIF before, remove
that `--sarif` option or `sarif:` entry. Until you do, each of its findings counts once with the
built-in finding of the same rule on the same line.

**Brakeman**, the Rails security scanner, is not bundled, because its licence restricts commercial
use. If your use is covered by that licence, run it yourself and import its SARIF:

```sh
brakeman -f sarif -o brakeman.sarif
```

```yaml
sarif:
  - path: brakeman.sarif
```

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
    - path: coverage/cobertura.xml                      # PHPUnit: --coverage-cobertura coverage/cobertura.xml (needs pcov or Xdebug)
      format: cobertura
    - path: coverage/coverage.xml                       # Ruby: SimpleCov + simplecov-cobertura
      format: cobertura
    - path: coverage.out                                # go test -coverprofile=coverage.out ./... (Go)
      format: gocover
  pathPrefixes: []   # prefixes to strip or try when report paths do not match repository paths
```

Or pass `--coverage <path>` on the command line.

- For Ruby, add `gem "simplecov-cobertura"` to the test group of your Gemfile and
  `SimpleCov.formatter = SimpleCov::Formatter::CoberturaFormatter` to the test helper.
- A Go profile names files by import path; Qualor finds them by their path suffix. Use
  `-coverpkg=./...` to count code that other packages' tests run. A profile that holds more than 20
  million lines is read up to that limit, and the import warns that it was truncated. A profile
  larger than 128 MiB is ignored with a warning.
- Test files are excluded from coverage ([What is scanned](#what-is-scanned)).
- If a scan imports no coverage report at all, the coverage conditions have **no value** and do not
  fail the gate. The UI shows a warning instead.

### C and C++

Use gcovr (GCC) or llvm-cov (Clang). Qualor reads both without options:

```sh
gcovr -r . --cobertura coverage.xml          # or: --lcov coverage.info
llvm-cov export -format=lcov -instr-profile=default.profdata ./tests > coverage.info
```

The report names the files as the build saw them. When the build ran outside the checkout (another
directory or another machine), those paths do not match the repository: set `pathPrefixes` to the
directory the report names, for example `pathPrefixes: [/build/src]`.

## What is scanned

Qualor scans every file in the working tree that matches `sources.include` (default `**/*`), minus
what `.gitignore` ignores, the [built-in excludes](./configuration.md#built-in-excludes) and your
own `sources.exclude`. A committed `coverage/` directory is not excluded automatically: add it to
`sources.exclude` if yours is generated output.

Test files are recognised by `tests.include`. By default these are `*.test.*`, `*.spec.*`,
`__tests__/`, `src/test/`, `*Tests/`, `test_*.py`, `*_test.py`, `conftest.py`, `*Test.php`,
`src/androidTest/`, `src/*Test/`, `*_spec.rb`, `*_test.rb`, `spec/**/*.rb`, `test/**/*.rb` and
`*_test.go`. Test code does not count in lines of code, complexity, duplication or coverage.

`src/*Test/` is meant for Kotlin Multiplatform's `commonTest` and `jvmTest`, but it applies to every
language: a Gradle `src/integrationTest` or `src/functionalTest` is test code too.
