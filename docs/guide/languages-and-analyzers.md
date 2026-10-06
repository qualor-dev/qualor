# Languages and analyzers

Qualor mostly runs well-known open-source analyzers, reads their SARIF output, and turns their
findings into tracked issues. It also has security rules of its own (see Security rules). For the
supported languages it also computes size, complexity, duplication and coverage.

| Area | Analyzer | Runs when |
|---|---|---|
| JavaScript, TypeScript | **ESLint**, the project's own config and plugins | the repository has an ESLint config and its dependencies are installed |
| JavaScript, TypeScript | **sonarjs**: SonarQube-compatible rules (eslint-plugin-sonarjs 2.0.4, LGPL-3.0) | JS/TS files are in scope, run by the `qualor/scanner` image |
| Python | **Ruff** (Qualor's rule selection: Pyflakes, pycodestyle errors, flake8-bugbear, Pylint errors, flake8-bandit's security rules) | .py files are in scope, run by the qualor/scanner image or any Ruff 0.16 on PATH |
| HTML | **HTMLHint** 1.9.2, the project's `.htmlhintrc` or Qualor's rule set | `.html` files are in scope, run by the `qualor/scanner` image |
| CSS, SCSS | **stylelint** 17.15, the project's JSON/YAML config or Qualor's default | `.css` or `.scss` files are in scope, run by the `qualor/scanner` image |
| Kotlin | **detekt** 1.23.8 (Apache-2.0), your `detekt.yml` or detekt's default rule set with the settings detekt recommends for Jetpack Compose | `.kt` or `.kts` files are in scope, run by the `qualor/scanner` image |
| Swift | **SwiftLint** 0.65.1 (MIT), your `.swiftlint.yml` or SwiftLint's default rules with a few adjustments | `.swift` files are in scope, run by the `qualor/scanner` image |
| PHP | **PHPStan** 2.2 (MIT) at level 2, with Qualor's own configuration | .php files are in scope, run by the qualor/scanner image |
| Ruby | **RuboCop** 1.91 (MIT), Qualor's selection: RuboCop's Lint and Security cops | Ruby files are in scope (.rb, .rake, .gemspec, .ru, Gemfile, Rakefile), run by the qualor/scanner image |
| Go | **staticcheck** 2026.2.1 (MIT), **go vet** (Go 1.27.1) and **gosec** 2.29.0 (Apache-2.0, security), offline | `.go` files and a `go.mod` are in scope, run by the `qualor/scanner` image |
| C | **cppcheck** (2.22.0, GPL-3.0-or-later); **clang-tidy** (yours, LLVM 14+, with a compile database) | `.c`/`.h` files exist |
| C++ | the same | `.cpp`/`.cc`/`.cxx`/`.hpp`/`.h`... files exist |
| Java | **PMD 7** (source), **SpotBugs** (bytecode) with **FindSecBugs** 1.14.0 (LGPL-3.0, security) | `.java` files exist. SpotBugs also needs compiled classes |
| C# | **Roslyn** analyzers of the .NET SDK, plus **Roslynator** and **SonarAnalyzer.CSharp** (SonarQube-compatible rules) | through `qualor dotnet begin` / `end` around your build, with `qualor/scanner-dotnet` |
| Security rules | **Qualor's own rules** on OpenGrep, for JavaScript, TypeScript, Python, Java and Go (PolyForm Shield 1.0.0, source-available) | files of those languages are in scope, run by the `qualor/scanner` image |
| Security patterns (SAST) | **OpenGrep** (or Semgrep) | you name rule files in `qualor.yml`. No rules are bundled yet |
| Secrets | **Gitleaks** | always (`enabled: true` by default) |
| Vulnerable dependencies | **Trivy** | lockfiles or manifests exist |
| Anything else | any tool that writes **SARIF 2.1.0** | you pass `--sarif file` or list it in `qualor.yml` |

Metrics (lines of code, functions, classes, cyclomatic and cognitive complexity) and duplication
detection cover TypeScript, JavaScript, Java, Kotlin, Swift, C, C++, C#, Python, PHP, Ruby, Go, HTML
and CSS; SCSS gets findings only. Other files still get findings from Gitleaks, Trivy, OpenGrep and
external SARIF.

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

Calls to HTTP-verb methods such as `client.GET()` or `api.POST()` (the request methods of
openapi-fetch style clients) are not reported by S2430, the rule for constructors called without
`new`.

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

## PHP (PHPStan)

The `qualor/scanner` image runs PHPStan 2.2 (MIT) on your `.php` files, on Debian's PHP 8.2. It
runs at **level 2**, which checks for undefined variables, calls with the wrong number of
arguments, using the result of a call that returns nothing (`void`), calls on values that are not
objects, and invalid PHPDoc. Raise the level to get stricter checks, from 0 to 10 or `max`:

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
controls, and a scan must not run it. The level and the other settings come from `qualor.yml`.
`@phpstan-ignore` comments in the code are honoured. PHPStan runs on a copy of your sources.

**Install your dependencies before the scan.** PHPStan needs to know the classes your code
extends and calls. Run `composer install --no-scripts --no-plugins` in the job first; that is
enough. Qualor reads the PHP files in `vendor/` as data, to learn their symbols, and never runs
them (not Composer's autoloader, scripts or plugins either). A project whose `composer.json`
requires packages is skipped when `vendor/` is not installed, with the reason in the scan log;
without that, every inherited class would give false findings. A project that requires no
packages runs without `vendor/`. PHPStan is also skipped when the installed dependencies are
larger than 1 GiB or hold more than 200,000 files, because reading part of them would flood the
result with false findings. A custom `config.vendor-dir` in `composer.json` is followed.

Qualor never reports "unknown class", "unknown method" or "unknown function" (and the matching
property, constant, trait and interface checks, and unknown named arguments). Whether a symbol is known depends on what your
job installed and on framework magic that PHPStan understands only with extensions such as
Larastan, which Qualor does not load. Run your own PHPStan for those checks.

A file PHPStan cannot parse is left out of the analysis with a warning in the scan log, and
PHPStan runs again on the rest, so one broken file does not hide the other findings. `.phtml` and
`.inc` files are not analysed, only files whose name ends in `.php`, and neither are files larger
than 1 MiB or reached through a symbolic link. PHPStan, its worker processes included, runs with
a `php.ini` of Qualor's own instead of yours or the system's, reads no additional `.ini` files, and
gets none of your `PHPRC`, `PHP_INI_SCAN_DIR`, `COMPOSER*`, `PHPSTAN_*` and `XDEBUG_*` variables.
`QUALOR_PHPSTAN_PHAR` names another PHPStan phar (see [Configuration](./configuration.md)); it
must be PHPStan 2.2.

An issue's rule key is `phpstan:` and PHPStan's identifier, for example
`phpstan:variable.undefined`.

Qualor runs PHPStan itself, so if you imported your own PHPStan SARIF before, remove that import
(`--sarif` or the `qualor.yml` `sarif:` entry). `phpstan` is a reserved engine id: a `sarif:`
entry with `engine: phpstan` is a configuration error. A PHPStan SARIF you still import is
reported as `ext-phpstan`, and each of its findings counts once with the built-in `phpstan`
finding of the same rule on the same line.

PHP files get the same metrics as the other languages (lines of code, functions, classes,
cyclomatic and cognitive complexity) and count in duplication detection. `*Test.php` files are
test files by default.

## Ruby (RuboCop)

The `qualor/scanner` image runs RuboCop 1.91 on your Ruby files: `.rb`, `.rake`, `.gemspec`, `.ru`,
`Gemfile` and `Rakefile`. It has its own Ruby, so no Ruby, gem or bundle is needed on the runner and
nothing is installed or built. `.erb` templates are not analysed.

Qualor chooses the cops itself. The project's `.rubocop.yml` (and `.rubocop_todo.yml`, a file in a
subdirectory or your home directory) is **never read**: RuboCop runs Ruby code that a configuration
file names (ERB, `require`, plugins), and a scan must not run code from the checkout. Choose cops in
`qualor.yml` instead. Inline comments in your code are honoured: `# rubocop:disable Lint/Foo` (and
`# rubocop:todo`) silences that cop on that line or block. A cop that is not selected is not turned
on by a `# rubocop:enable` comment.

`qualor-default` runs RuboCop's Lint and Security cops that RuboCop enables by default: the ones
that find bugs and security problems, not style. It leaves out the 12 cops below, because they
misfire in a Qualor scan:

- `Lint/CopDirectiveSyntax`, `Lint/MissingCopEnableDirective`,
  `Lint/RedundantCopDisableDirective` and `Lint/RedundantCopEnableDirective` judge your
  `rubocop:` comments against a configuration Qualor does not use.
- `Lint/AmbiguousBlockAssociation`, `Lint/AssignmentInCondition`, `Lint/ConstantDefinitionInBlock`,
  `Lint/MissingSuper`, `Lint/UnderscorePrefixedVariableName`, `Lint/UnusedBlockArgument` and
  `Lint/UnusedMethodArgument` flag idioms that are normal in Rails callbacks, RSpec and DSL blocks.
- `Lint/ScriptPermission` checks file permissions, which Qualor does not keep when it reads your
  files, so it would flag every Ruby script with a `#!` line.

Select any of them by name if you want it.

A file that RuboCop cannot parse gets no findings (a syntax error is not reported as an issue).

```yaml
analyzers:
  rubocop:
    enabled: auto              # true, false, or auto: on when Ruby files are in scope
    select: [qualor-default, Style, Naming]   # departments, cop names, or qualor-default
    ignore: [Style/Documentation]             # departments or cop names to leave out
    targetRubyVersion: '3.3'   # the Ruby syntax RuboCop parses; default 4.0
    timeoutSeconds: 600        # optional
```

`select` takes RuboCop departments (`Lint`, `Security`, `Style`, `Layout`, `Naming`, `Metrics` and
the others), cop names (`Style/StringLiterals`) and `qualor-default`. A department means the cops
RuboCop enables by default in it; a cop name turns that cop on even if RuboCop leaves it disabled
or pending. `ignore` removes departments or cops from the result. An unknown department or cop, or
a `targetRubyVersion` that RuboCop 1.91 does not parse (it accepts 2.0 to 4.1), is a configuration
error: the scan stops with exit 2.

RuboCop checks the Ruby files in scope. Files larger than 1 MiB, files reached through a symbolic
link and names with a line break are not passed. `.bundle/` directories and `db/schema.rb` are never
scanned. Qualor runs RuboCop offline, with its own configuration and a clean environment (no
`RUBYOPT`, `GEM_*` or `BUNDLE_*`). RuboCop is skipped when the image's RuboCop is missing or is a
different minor version than 1.91, with the reason in the scan log. Rule keys look like
`rubocop:Lint/UselessAssignment`.

Plugin cops (`rubocop-rails`, `rubocop-rspec`, `rubocop-performance`) do not run: the plugins are
not installed, and a configuration cannot load them.

Qualor runs RuboCop itself, so if you imported your own RuboCop SARIF before, remove that import
(`--sarif` or the `qualor.yml` `sarif:` entry). `rubocop` is a reserved engine id: a `sarif:` entry
with `engine: rubocop` is a configuration error. A RuboCop SARIF you still import is reported as
`ext-rubocop`, and each of its findings counts once with the built-in `rubocop` finding of the same
rule on the same line.

Ruby files get the same metrics as the other languages (lines of code, functions, classes,
cyclomatic and cognitive complexity) and count in duplication detection. Functions are `def` and
`def self.` methods; classes are `class` and `module` definitions; blocks and lambdas are not
counted as functions. `*_spec.rb`, `*_test.rb` and Ruby files below `spec/` and `test/` are test
files by default.

## Go (staticcheck, go vet, gosec)

The `qualor/scanner` image runs three Go analyzers on every Go module in your repository (each
`go.mod` and the `.go` files below it): **staticcheck** 2026.2.1, **go vet** of Go 1.27.1, and
**gosec** 2.29.0 for security. Your `staticcheck.conf`, `//lint:ignore` and `#nosec` comments are
honoured; `.golangci.yml` is not read. staticcheck reads `staticcheck.conf` as a settings file
only; nothing in it is run.

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
toolchain (`toolchain` and `GOTOOLCHAIN` are ignored), no C compiler, no module download.
`GOFLAGS` from the CI job and a `go.work` file in the repository are ignored too (`GOFLAGS` is
emptied and `GOWORK=off` is set), so each module is analysed on its own. A module
whose `go` line needs a newer Go than 1.27.1, whose `replace` points at a directory outside the
repository, or that contains a symbolic link out of it, is skipped with a log line.

One case is not covered. Qualor does not look for links inside the directories Go itself ignores
(names starting with `.` or `_`, `testdata`) or inside `node_modules`. If your code explicitly imports a package from one of them, `go`
could compile a file that is linked outside the repository. Findings on files outside the
repository are dropped, so only a compiler message could repeat a line of such a file in the scan
log or in the report. Don't scan repositories you do not trust in a job that can read secrets or
host files (the same rule as for ESLint above).

```yaml
analyzers:
  gosec:
    exclude: [G104, G115, G304]   # the default: unchecked errors, integer-conversion overflow, file path from a variable; [] runs every rule
```

G304 (file path provided as taint input) is excluded by default because it flags idiomatic file
reads on real projects almost every time. To turn it back on, set `exclude: []` or list only the
rules you want to skip, without `G304` (for example `exclude: [G104, G115]`).

Severity: staticcheck's correctness and concurrency checks (`SA5…`, `SA2…`) are high, its other
bug checks medium, unused code medium, simplifications and style low; go vet findings are medium;
gosec findings take gosec's own HIGH/MEDIUM/LOW. Where go vet and staticcheck report the same
mistake on one line (`printf`/`SA5009`, `bools`/`SA4000`), the server keeps one issue.
`testdata/` directories and generated `*.pb.go` files are never scanned, and `*_test.go` files are
tests. The `testdata/` exclude applies to every language, so secret and dependency scanning skip
`testdata/` directories too.

Go files get the same metrics as the other languages (lines of code, functions, types,
cyclomatic and cognitive complexity) and count in duplication detection. The three analyzers are
skipped, with the reason in the scan log, when no Go module is in scope, when no `go`,
`staticcheck` or `gosec` of the supported version is available (outside the image), or when every
module is left out for the reasons above. Qualor runs these tools itself: a SARIF file of your own
from staticcheck or gosec is counted once with the built-in finding of the same code on the same
line, and `engine: staticcheck`, `govet` or `gosec` in a `sarif:` entry is a configuration error.

## Java (PMD, SpotBugs and FindSecBugs)

- **PMD** reads the source. The default ruleset `qualor-default` is PMD's own
  `rulesets/java/quickstart.xml`. Use your own with `analyzers.pmd.rulesets: [config/pmd.xml]`, or
  PMD's built-in categories (`category/java/bestpractices.xml`).
- **SpotBugs** reads **compiled classes**. Build first (`mvn -B -DskipTests package` or
  `./gradlew classes`). It looks in `target/classes` and `build/classes/java/main` by default. When
  those are empty it is skipped, with the reason `no compiled classes … (build the project before
  qualor scan)`.
- **FindSecBugs** 1.14.0, SpotBugs' security plugin, runs inside SpotBugs in the `qualor/scanner`
  image. It follows untrusted data (request parameters, headers, files, the command line) into SQL,
  shell commands, file paths, LDAP, XPath, XML parsers and outgoing URLs, and it flags weak
  cryptography, hard-coded passwords and unsafe configuration. Its rules are SpotBugs rules
  (`spotbugs:SQL_INJECTION_JDBC`), so the Java quality profile turns each one on or off.
  - Injections and definite misuse (an XML parser open to XXE, a trust-all TLS manager, DES or ECB,
    a hard-coded password) are **issues** and count in the quality gate.
  - Findings that ask you to review a usage (a non-cryptographic random number, a cookie without
    its flags, a permissive CORS policy, a weak hash, object deserialisation, request parameters
    and endpoints) are **security hotspots**: listed, never counted.
  - Where SpotBugs' own rule and FindSecBugs report the same problem on one line (SQL built from a
    variable, a constant database password, a request parameter in a file path or a servlet
    response), Qualor shows one issue, SpotBugs' own.
  - Qualor drops `findsecbugs*` environment variables before it runs SpotBugs, so a custom
    FindSecBugs configuration named there is not read.
  - A SpotBugs installed outside the image runs without the plugin, unless you put its jar into
    SpotBugs' `plugin/` directory. The scan's SpotBugs version says whether it ran (for example
    `4.10.4 + FindSecBugs 1.14.0`).

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
  image: { name: qualor/scanner-dotnet:0.5, entrypoint: [''] }
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

## C and C++ (cppcheck, clang-tidy)

The `qualor/scanner` image runs **cppcheck** 2.22.0 on your C and C++ files, with no build and no
setup: errors plus the `warning`, `performance` and `portability` checks. Add `style` for more
(it is much noisier):

```yaml
analyzers:
  cppcheck:
    enable: [warning, style, performance, portability]
    includePaths: [include]          # used when there is no compile_commands.json
    defines: [HAVE_CONFIG_H]
```

When your repository has a `compile_commands.json` (at the root or in `build/`, or named by
`compileCommands`), Qualor gives cppcheck its include paths, defines and language standard.
Inline suppressions (`// cppcheck-suppress nullPointer`) work.

`uninitMemberVar`, `uninitMemberVarPrivate` and `uninitMemberVarNoCtor` are off by default (they
mostly flag union members); turn them on with `select: [uninitMemberVar]` under `cppcheck`.

**clang-tidy** runs when the job that scans also has `clang-tidy` (LLVM 14 or newer) on `PATH` and a
compile database, typically the job that built your project:

```sh
cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON && cmake --build build
qualor scan          # finds build/compile_commands.json
```

No Qualor image bundles clang-tidy: it needs your build's headers and flags. Use a clang-tidy of
the same LLVM major as your compiler where you can. Your `.clang-tidy` at the repository root is
used for `Checks`, `CheckOptions` and the header and implementation file extensions; without one,
Qualor runs the bug-finding groups (`bugprone-*`, `clang-analyzer-*`, `performance-*`,
`portability-*`, `concurrency-*`, minus a few noisy checks). A `.clang-tidy` that sets its own
`Checks` replaces Qualor's default checks. Settings that pass compiler arguments, load other
configurations or turn warnings into errors (`ExtraArgs`, `InheritParentConfig`,
`WarningsAsErrors`...) are ignored, and so are nested `.clang-tidy` files. Analyzer options that
name a file (`clang-analyzer-...:Config`) are dropped too. The scan log says what was left out.

Qualor never runs your build. It reads `compile_commands.json` itself and passes on only include
paths, defines, the language standard and harmless flags (`-I`, `-D`, `-U`, `-std` and a short list
of others); the compiler is never taken from the database, and plugins, `-Xclang` options and
response files (`@file`) are dropped.
Code the tools cannot compile (a missing generated header, an unknown macro) is reported as a
warning, not as an issue. A `.h` file counts as C++ when your repository has C++ files, else as C.
Any C++ file in scope, a fuzzer included, makes the `.h` files C++.
`CMakeFiles/`, `cmake-build-*/` and `_deps/` are never scanned.

Only code of your repository is reported. A finding that clang-tidy or cppcheck places in a system
header or in a directory outside the checkout is dropped, and a path outside the repository that a
message quotes is replaced by a placeholder. Headers you include from outside the repository (an
absolute `-I`) are still read for the analysis.

Both tools are skipped, with the reason in the scan log, when they are missing, when cppcheck is
not version 2.22, when clang-tidy is older than LLVM 14, or when there is no compile database for
clang-tidy; `enabled: true` fails the scan (exit 3) instead. `cppcheck` and `clang-tidy` are
reserved engine ids: a SARIF file of your own from them is reported as `ext-cppcheck` or
`ext-clang-tidy` and counted once with the built-in finding. Rule keys look like
`cppcheck:nullPointer` and `clang-tidy:bugprone-use-after-move`.

C and C++ files get the same metrics as the other languages (lines of code, functions, classes,
complexity) and duplication detection.

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
  old as the scanner release you run, so keep the scanner current (the minor tag `0.5` does that
  for its patch releases), or fetch a fresh database in the job:

```yaml
script:
  - trivy image --download-db-only --cache-dir /tmp/trivy   # add --db-repository <your mirror> if needed
  - QUALOR_TRIVY_CACHE_DIR=/tmp/trivy qualor scan
```

`QUALOR_TRIVY_CACHE_DIR` must be absolute and outside the checkout. Jobs that run repository code must
not be able to write it.

## Security rules (Qualor)

Qualor has its own security rules for JavaScript, TypeScript, Python, Java and Go: 49 rules that
run in every edition, as the `qualor` engine on OpenGrep. The `qualor/scanner` image (and
`qualor/scanner-dotnet`, which builds on it) includes them. There are three kinds:

- **Taint rules** follow data from an HTTP request (a query parameter, a form field, a header, a
  cookie, a JSON body) or the name of an archive entry to a dangerous call (an SQL query, a shell
  command, a file path, a template, an outgoing request, a redirect) and report it when nothing
  made it safe on the way.
- **Misuse rules** report unsafe settings and APIs whatever the data, such as disabled TLS
  certificate verification, an XML parser that resolves external entities or a broken cipher.
- **Hotspots** point at code to review, where only you can tell whether it is safe: a weak hash, a
  cookie without its flags, raw HTML in React.

Each rule knows the frameworks and libraries in its row. **JavaScript and TypeScript** (the `js`
rules apply to both):

| Rule | Finds | Frameworks and libraries |
|---|---|---|
| `qualor:js/sql-injection` | SQL built from request data | Express, Next.js, Fastify; `pg`, `mysql2`, Knex, Sequelize, Prisma, TypeORM |
| `qualor:js/nosql-injection` | MongoDB filters, query operators or server-side JavaScript (`$where`) from request data | Express, Next.js, Fastify; MongoDB driver, Mongoose |
| `qualor:js/command-injection` | an OS command or shell script built from request data | Express, Next.js, Fastify; `child_process` |
| `qualor:js/code-injection` | request data run as JavaScript (`eval`, `Function`, `node:vm`) | Express, Next.js, Fastify, Node.js `http` |
| `qualor:js/template-injection` | request data used as a template, or as the whole data object of an EJS render | Express, Next.js, Fastify; EJS, Pug, Handlebars, Nunjucks, lodash `template` |
| `qualor:js/path-traversal` | a file path built from request data | Express, Next.js, Fastify; `fs` |
| `qualor:js/ssrf` | a server-side request whose URL, scheme or host comes from the request | Express, Next.js, Fastify, Node.js `http`; `fetch`, axios, got, undici |
| `qualor:js/open-redirect` | a redirect whose target, scheme or host comes from the request | Express, Next.js, Fastify, Node.js `http` |
| `qualor:js/xss` | request data written into an HTML response without escaping | Express, Next.js, Fastify, Node.js `http` |
| `qualor:js/regex-injection` | a regular expression built from request data (ReDoS) | Express, Next.js, Fastify, Node.js `http` |
| `qualor:js/prototype-pollution` | nested property writes with keys from the request (`obj[a][b] = v`) | Express, Next.js, Fastify |
| `qualor:js/tls-verification-disabled` | `rejectUnauthorized: false` or `NODE_TLS_REJECT_UNAUTHORIZED` set to `0` | `https`, `tls`, `http2`, axios, undici |
| `qualor:js/react-dangerous-html` (hotspot) | raw HTML given to `dangerouslySetInnerHTML` | React, Next.js |

**Python:**

| Rule | Finds | Frameworks and libraries |
|---|---|---|
| `qualor:python/sql-injection` | SQL built from request data | Flask, Django (also `raw`, `extra`, `RawSQL`); DB-API, SQLAlchemy, psycopg |
| `qualor:python/code-injection` | request data run as Python (`eval`, `exec`, `compile`) | Flask, Django, FastAPI |
| `qualor:python/unsafe-deserialization` | request data loaded with pickle, marshal, shelve, dill, jsonpickle or an unsafe YAML loader | Flask, Django, FastAPI |
| `qualor:python/template-injection` | request data used as the source of a Jinja or Django template | Flask, Django, FastAPI; Jinja2 |
| `qualor:python/path-traversal` | a file path built from request data | Flask, Django, FastAPI, Starlette; Werkzeug, `pathlib` |
| `qualor:python/ssrf` | a server-side request whose URL, scheme or host comes from the request | Flask, Django, FastAPI; requests, httpx, aiohttp, `urllib` |
| `qualor:python/open-redirect` | a redirect whose target, scheme or host comes from the request | Flask, Django, FastAPI, Starlette |
| `qualor:python/xss` | request data written into an HTML response without escaping, or marked safe | Flask, Django, FastAPI, Starlette; MarkupSafe, bleach, nh3 |
| `qualor:python/xpath-injection` | an XPath expression built from request data | Flask, Django, FastAPI; lxml, ElementTree |
| `qualor:python/regex-injection` | a regular expression built from request data (ReDoS) | Flask, Django, FastAPI |
| `qualor:python/xxe` | an XML parser set to resolve external entities or to use the network | lxml, `xml.sax`, `xml.dom` |
| `qualor:python/tls-verification-disabled` | `verify=False`, an unverified `ssl` context or `CERT_NONE` | requests, httpx, `ssl`, urllib3 |

**Java:**

| Rule | Finds | Frameworks and libraries |
|---|---|---|
| `qualor:java/sql-injection` | SQL built from request data | Servlets, Spring MVC, JAX-RS; JDBC, Spring JDBC, JPA |
| `qualor:java/command-injection` | an OS command, its program or its environment built from request data | Servlets, Spring MVC, JAX-RS |
| `qualor:java/expression-injection` | request data evaluated as an expression | Servlets, Spring MVC, JAX-RS; Spring SpEL, Jakarta EL, OGNL, MVEL |
| `qualor:java/template-injection` | request data used as template source (or as a Thymeleaf template name) | Servlets, Spring MVC, JAX-RS; FreeMarker, Velocity, Thymeleaf |
| `qualor:java/unsafe-deserialization` | request data read with Java serialization or `XMLDecoder` | Servlets, Spring MVC, JAX-RS |
| `qualor:java/ldap-injection` | an LDAP search filter built from request data | Servlets, Spring MVC, JAX-RS; JNDI, Spring LDAP |
| `qualor:java/path-traversal` | a file path built from request data | Servlets, Spring MVC, JAX-RS |
| `qualor:java/ssrf` | a server-side request whose URL, scheme or host comes from the request | Servlets, Spring MVC, JAX-RS; `java.net.URL`, `java.net.http`, Spring `RestTemplate`, `RestClient`, `WebClient` |
| `qualor:java/open-redirect` | a redirect whose target comes from the request | Servlets, Spring MVC, JAX-RS |
| `qualor:java/xss` | request data written into an HTML response without encoding | Servlets, Spring MVC, JAX-RS |
| `qualor:java/xxe` | an XML parser used without disabling DTDs or external entities | JAXP (DOM, SAX, StAX, `TransformerFactory`, `SchemaFactory`), dom4j, JDOM |
| `qualor:java/zip-slip` | an archive entry name used as an extraction path | `java.util.zip`, `java.util.jar`, Commons Compress |

**Go:**

| Rule | Finds | Frameworks and libraries |
|---|---|---|
| `qualor:go/sql-injection` | SQL built from request data | `net/http`, Gin, Echo, chi, gorilla/mux; `database/sql`, GORM |
| `qualor:go/command-injection` | a shell script or program name built from request data | `net/http`, Gin, Echo, chi, gorilla/mux; `os/exec` |
| `qualor:go/template-injection` | request data parsed as Go template text | `net/http`, Gin, Echo, chi, gorilla/mux; `html/template`, `text/template` |
| `qualor:go/path-traversal` | a file path built from request data | `net/http`, Gin, Echo, chi, gorilla/mux; `os` |
| `qualor:go/ssrf` | a server-side request whose URL, scheme or host comes from the request | `net/http`, Gin, Echo, chi, gorilla/mux |
| `qualor:go/open-redirect` | a redirect whose target, scheme or host comes from the request | `net/http`, Gin, Echo, chi, gorilla/mux |
| `qualor:go/xss` | request data written into an HTML response without escaping (also through `text/template` or `template.HTML`) | `net/http`, Gin, Echo, chi, gorilla/mux; `html/template`, `text/template`, bluemonday |
| `qualor:go/zip-slip` | an archive entry name used as an extraction path | `archive/zip`, `archive/tar`, `os` |
| `qualor:go/tls-verification-disabled` | `InsecureSkipVerify: true` | `crypto/tls`, `net/http` |
| `qualor:go/weak-cipher` | DES, Triple DES or RC4 | `crypto/des`, `crypto/rc4` |
| `qualor:go/weak-hash` (hotspot) | MD5 or SHA-1 | `crypto/md5`, `crypto/sha1`, `crypto` |
| `qualor:go/insecure-cookie` (hotspot) | a cookie set without `Secure` or `HttpOnly` | `net/http`, Gin, Echo |

Each finding's message says why the code is unsafe and how to fix it. Each rule also has its own
page in the qualor-rules repository, under `docs/rules/<lang>/<name>.md` (for
`qualor:go/sql-injection`,
<https://github.com/qualor-dev/qualor-rules/blob/main/docs/rules/go/sql-injection.md>). The rule's
documentation link opens it: on the issue page, in the rules list, and on the rule's key in merge
request and pull request comments.

- The engine's version in a scan names the rules release, for example
  `1.30.0 + qualor-rules 2026.10.1`.
- Taint rules follow data **within one function of a file**. A value that passes through another
  function or another file is not followed yet.
- Issues (from taint and misuse rules) are Security issues and count in the quality gate.
  Hotspots are **security hotspots**: listed, never counted. Where another analyzer reports the
  same problem on the same line, Qualor's issue is the one shown and the other is its duplicate.
  That holds for rules with the same CWE and for the matching rules that carry none or another
  one: Ruff's flake8-bandit rules (`S608` with the SQL injection rule, `S307` with code injection,
  and so on), the SonarJS hotspots `S2077`, `S4721` and `S1523`, gosec's `G107`, `G708` and
  `G710`, and SpotBugs' path traversal, XSS and expression language rules. If you had marked that other issue as a false positive or won't fix, Qualor's new issue starts
  with that status when it is first created (a later reopen is kept), and its history names the
  other rule and repeats the comment on that status, if there was one.
- Turn a rule off in the language's quality profile. The `js` rules apply to JavaScript and
  TypeScript files: turn them off in both profiles.
- A `nosemgrep` comment does not hide these findings, and a `.semgrepignore` file does not apply to
  them: they scan exactly the files Qualor scans (`sources` in `qualor.yml`). Mark a finding as a
  false positive in Qualor instead.
- Configure the engine with `analyzers.qualor` (`enabled`, `timeoutSeconds`). `QUALOR_RULES_DIR`
  names another directory with the unpacked rules (see Configuration). `SEMGREP_*` and
  `OPENGREP_*` environment variables never reach OpenGrep.
- **Licence.** The rules are source-available, not open source: the PolyForm Shield License 1.0.0,
  not the MIT licence of the Qualor CLI. You may use, change and share them for any purpose, free of
  charge and in any Qualor edition, except providing a product that competes with Qualor or with the
  rules themselves. If you pass them on, pass on the licence terms too. In an image that includes
  the rules, the licence text is at `/opt/qualor/licenses/qualor-rules/LICENSE`.
- **Outside the image.** Rules releases are published at
  <https://github.com/qualor-dev/qualor-rules/releases>, each with its SHA-256. Unpack one, set
  `QUALOR_RULES_DIR` to it and put the OpenGrep version that its `manifest.json` names
  (`opengrep`) on the `PATH`; with another version the scan logs a warning. Without the rules the
  engine is skipped with the message "Qualor's security rules are not installed" (see
  Troubleshooting), and nothing else changes.

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
`detekt`, `swiftlint`, `phpstan`, `rubocop`, `staticcheck`, `govet`, `gosec`, `cppcheck`,
`clang-tidy` and the others) are reserved: `engine: ruff` is a configuration error, and a SARIF
file from a tool Qualor runs itself is reported under `ext-<tool>` (`ext-ruff`, `ext-stylelint`,
`ext-htmlhint`, `ext-detekt`, `ext-swiftlint`, `ext-phpstan`, `ext-rubocop`, `ext-staticcheck`,
`ext-gosec`, `ext-cppcheck`, `ext-clang-tidy`). Don't import Ruff, stylelint, HTMLHint, detekt,
SwiftLint, PHPStan, RuboCop, staticcheck, gosec, cppcheck or clang-tidy SARIF any more: Qualor runs
Ruff (see [Python](#python-ruff)), stylelint and HTMLHint (see
[CSS and SCSS](#css-and-scss-stylelint) and [HTML](#html-htmlhint)), detekt (see
[Kotlin](#kotlin-detekt)), SwiftLint (see [Swift](#swift-swiftlint)), PHPStan (see
[PHP](#php-phpstan)), RuboCop (see [Ruby](#ruby-rubocop)), staticcheck and gosec (see
[Go](#go-staticcheck-go-vet-gosec)) and cppcheck and clang-tidy (see
[C and C++](#c-and-c-cppcheck-clang-tidy)) itself; a SARIF file you still import for one of them
counts once with the built-in finding of the same code on the same line.

**Brakeman** (Rails security scanner) is not bundled, because its licence restricts commercial use.
If your use is covered by that licence, run it yourself and import its SARIF:

```sh
brakeman -f sarif -o brakeman.sarif
```

```yaml
sarif:
  - path: brakeman.sarif
```

RuboCop is the other direction: it is built in (see [Ruby](#ruby-rubocop)), so don't import its
SARIF.

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
    - path: coverage/coverage.xml                     # Ruby: SimpleCov + simplecov-cobertura
      format: cobertura
    - path: coverage.out                                # go test -coverprofile=coverage.out ./... (Go)
      format: gocover
  pathPrefixes: []   # prefixes to strip or try when report paths do not match repository paths
```

For Ruby, add `gem "simplecov-cobertura"` to the test group of your Gemfile and
`SimpleCov.formatter = SimpleCov::Formatter::CoberturaFormatter` to the test helper.

A Go profile names files by import path; Qualor finds them by their path suffix. Use
`-coverpkg=./...` to count code that other packages' tests run. A profile that holds more than 20
million lines is read as far as that limit, and the import warns that it was truncated. A profile
larger than 128 MiB is refused: it is ignored with a warning.

Or pass `--coverage <path>` on the command line. Test files are excluded from coverage. If a scan
imports no coverage report at all, the coverage conditions have **no value**, and they do not fail the
gate. The UI shows a warning instead.

### C and C++

Use gcovr (GCC) or llvm-cov (Clang); Qualor reads both without options:

```sh
gcovr -r . --cobertura coverage.xml          # or: --lcov coverage.info
llvm-cov export -format=lcov -instr-profile=default.profdata ./tests > coverage.info
```

The report names the files as the build saw them. When the build ran outside the checkout (another
directory or another machine), those paths do not match the repository: set `pathPrefixes` to the
directory the report names, for example `pathPrefixes: [/build/src]`.

## What is scanned

Every file in the working tree (`sources.include`, default `**/*`), minus what `.gitignore` ignores,
minus the built-in excludes (`node_modules`, `dist`, `build`, `target`, `vendor`, `*.min.js`,
`*.min.css`, .NET `obj/` and generated `*.g.cs` / `*.Designer.cs`, CMake's `CMakeFiles/`,
`cmake-build-*/` and `_deps/`, Python's `.venv`, `venv`, `.tox`, `.nox`, `__pycache__`,
`__pypackages__`, `.eggs` and `site-packages`, Bundler's `.bundle` directories, Rails' generated
`db/schema.rb`, Go's `testdata/` directories and generated `*.pb.go` files, and binary files), minus
your own `sources.exclude`. Test files are recognised by `tests.include` (by default `*.test.*`,
`*.spec.*`, `__tests__/`, `src/test/`, `*Tests/`, `test_*.py`, `*_test.py`, `conftest.py`,
`*Test.php`, `src/androidTest/`, `src/*Test/`, `*_spec.rb`, `*_test.rb`, `spec/**/*.rb`,
`test/**/*.rb` and `*_test.go`). `src/*Test/` is meant
for Kotlin Multiplatform's `commonTest` and `jvmTest`, but applies to every language: a Gradle
`src/integrationTest` or `src/functionalTest` is test code too, and leaves lines of code,
complexity, duplication and coverage.
A committed `coverage/` directory is not excluded automatically. Add it to `sources.exclude` if
yours is generated output.
