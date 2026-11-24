# Migrating from SonarQube

`qualor import sonarqube` copies a team's SonarQube setup into one Qualor organisation: quality
gates, quality profiles, project assignments and issue statuses. It works with **SonarQube Server
9.9 LTA and later** (10.x, 2025.x, Community Build) and with **SonarQube Cloud** (sonarcloud.io and
sonarqube.us).

The command runs in the CLI, on your machine or in a CI job. It only **reads** SonarQube, with `GET`
requests, and writes to Qualor through its API. The Qualor server never contacts SonarQube, and no
token is stored anywhere.

## What moves, and what doesn't

| Imported | As |
|---|---|
| Issues marked **False positive**, **Won't fix** or **Accepted** on the main branch | the same status on the matching Qualor issue, with the latest comment |
| Quality gates | Qualor gates, for conditions on metrics Qualor has |
| Projects, and which gate each one uses | project assignments. With `--create-projects`, the projects themselves |
| Quality profiles for JavaScript, TypeScript, C#, Java, Python, PHP, Ruby, Go, C and C++ | listed in the plan. Which rules are on or off, and severity overrides, move for the rules with a reviewed, equivalent mapping ([below](#how-rules-map)). A profile without any is reported as skipped, and your Qualor profiles stay as they are |

Not imported, and reported instead:

- rule parameters;
- SonarQube rules without a Qualor counterpart;
- gate conditions on metrics Qualor lacks;
- security hotspot reviews;
- branches other than main;
- users and permissions;
- history;
- new-code definitions.

SonarQube's Jira integration has its counterpart in Qualor: [Jira](./jira.md) creates a Jira issue
from a code issue, shows its Jira status, and is in every edition. For vulnerable dependencies,
[Fix merge requests](./fix-merge-requests.md) opens a merge request that bumps them.

### How rules map

Qualor does not run SonarSource's own analyzers, apart from the SonarQube-compatible rules it
bundles for C#, JavaScript and TypeScript. The import maps each SonarQube rule to a rule of the
analyzers Qualor bundles, in one of these ways:

| Mapping | Your Qualor profile | Issue statuses |
|---|---|---|
| **Equivalent**, reviewed | the rule is turned on or off, with its severity override | carried over |
| **Overlap**: the two rules flag some of the same code, but neither contains the other | unchanged | carried over |
| **Pending review** | unchanged | carried over |
| no counterpart | unchanged | not imported; the rule is reported as unmapped, never guessed |

| SonarQube rules | Qualor counterpart | Mapping |
|---|---|---|
| C# (`csharpsquid`), JavaScript (`javascript`), TypeScript (`typescript`) | the same rule key in the bundled SonarQube-compatible rules: SonarAnalyzer.CSharp 9.32 inside `roslyn`, eslint-plugin-sonarjs 2.0.4 as `sonarjs` | one to one, wherever the bundled version has the rule. A rule it lacks, mostly one SonarQube added in a later release, is unmapped |
| Python (`python:`) | the same Ruff rule (`ruff:`) | reviewed: an automated review against both rules' public documentation. **Equivalent** or **overlap** |
| Ruby (`ruby:`, `rubydre:`) | a RuboCop cop that checks the same kind of thing | reviewed against both rules' public descriptions. Two are **equivalent**: `ruby:S138` (method length) and `ruby:S1066` (collapsible `if`). The others **overlap** |
| Java security rules | SpotBugs or FindSecBugs, for 24 rules | three are **equivalent**: S2254 (the client's session id), S4433 (unauthenticated LDAP) and S4544 (Jackson default typing). The others **overlap** |
| PHP (`php:`) | PHPStan at Qualor's default level (2), for six rules | `php:S5708` (a `catch` clause naming a class that is not `Throwable`) is **equivalent** to `phpstan:catch.notThrowable`. The other five **overlap** |
| Go (`go:`) | staticcheck or gosec, for 18 rules | `go:S1656` is **equivalent** to staticcheck's `SA4018`. Three more **overlap** (reviewed). The other 14, mostly security rules matched to gosec by name, are **pending review** |
| C and C++ | cppcheck and clang-tidy, for a short list of common rules | **pending review**. MISRA rules are not mapped |
| Taint rules of SonarQube's commercial editions: `javasecurity`, `jssecurity`, `tssecurity`, `pythonsecurity`, `gosecurity`, and the C# taint rules of `roslyn.sonaranalyzer.security.cs` | [Qualor's own security rules](./languages-and-analyzers.md#security-rules-qualor), where both find the same kind of vulnerability | **pending review**. For example, `javasecurity:S3649` maps to `qualor:java/sql-injection`, and `pythonsecurity:S2076` to `qualor:python/command-injection` |
| Kotlin | none: SonarQube's own Kotlin rules have no detekt counterpart | Kotlin profiles are reported as not supported, and Kotlin issue statuses are not imported |
| Swift | none: SonarSource's Swift rules are not SwiftLint's rules | Swift profiles are read, with nothing to map |
| `phpsecurity`, SonarQube's own PHP security rules, `css`, `Web` | none | not mapped |
| Infrastructure as code (`terraform`, `cloudformation`, `kubernetes`, `docker`, `azureresourcemanager`) | none: [`trivy-iac`](./languages-and-analyzers.md#infrastructure-as-code-trivy) checks the same files with Trivy's checks | not mapped |

The taint rules map for SQL, NoSQL, OS command, LDAP, XPath, code, expression-language and template
injection, path traversal, zip slip, XSS, SSRF, open redirects, regular expressions built from
request data, unsafe deserialization and prototype pollution. A taint rule of a kind Qualor has no
rule for in that language, such as log injection, is not mapped.

**Rules the bundled configuration does not run.** Qualor runs eslint-plugin-sonarjs's `recommended`
set, the SonarAnalyzer.CSharp rules enabled by default, and its own `qualor-default` selection of
Ruff rules and RuboCop cops. A SonarQube profile can turn on a rule outside these, such as S1192.
The import still maps and records it, but no issue comes from it. The summary and the `--output`
plan count it as **mapped but not run by the bundled configuration** (`mappedNotRun`). Both
equivalent Ruby rules are such rules: they map to `Metrics` and `Style` cops. Turn a Ruff rule on
with `analyzers.ruff.select`, and a RuboCop cop with `analyzers.rubocop.select`.

### Issues SonarQube imported from other analyzers

SonarQube keeps the issues it imported from other tools under `external_*` rules.

| Imported by SonarQube from | Statuses |
|---|---|
| ESLint, PMD, SpotBugs, Roslyn, Ruff, SwiftLint (`external_swiftlint`), go vet (`external_govet`), RuboCop (`external_rubocop`) | carry over one to one |
| detekt (`external_detekt`), Bandit (`external_bandit`), golangci-lint (`external_golangci-lint`), Psalm | not imported |
| PHPStan (`external_phpstan`) | not imported: SonarQube keeps no PHPStan rule id |

SonarQube Server 9.9 does not let anyone resolve external issues, so these statuses exist only from
SonarQube Server 10.x and Community Build on.

## Step by step

### 1. Tokens

- **SonarQube:** a **user** token (`squ_…`) of a user with *Browse* on the projects. Project and
  global analysis tokens (`sqp_`, `sqa_`) cannot read the Web API.
- **Qualor:** a personal token with the **Admin** scope, of an org admin.

```sh
export SONAR_TOKEN=squ_…
export QUALOR_URL=https://qualor.example.com
export QUALOR_TOKEN=qlr_pat_…
```

Pass the SonarQube token with `SONAR_TOKEN` or `--token-file`. `--token` leaves it in the shell
history.

### 2. Dry run

```sh
# SonarQube Server
qualor import sonarqube --url https://sonar.example.com --dry-run --output import-plan.json
# SonarQube Cloud
qualor import sonarqube --url https://sonarcloud.io --organization acme --dry-run --output import-plan.json
```

With the scanner image:

```sh
docker run --rm -e SONAR_TOKEN -e QUALOR_URL -e QUALOR_TOKEN -v "$PWD":/out -w /out \
  qualor/scanner:<tag> import sonarqube --url https://sonar.example.com --dry-run --output import-plan.json
```

The import sends both tokens, and the Qualor one has the Admin scope. It therefore uses plain `http`
only to `localhost`, `127.0.0.0/8` or `[::1]`. Use `https` for any other server. From the container:

- on Linux, reach a Qualor server on your machine with `--network host` and
  `QUALOR_URL=http://127.0.0.1:8080`;
- with Docker Desktop's `QUALOR_URL=http://host.docker.internal:8080`, add `--allow-insecure-http`.

The summary lists what would be created, changed or left alone, the unmapped rules (the 20 with the
most resolved issues), the unmapped gate conditions, and the conflicts. `--output` writes the full
plan as JSON, with file mode 0600.

### 3. Import the configuration

```sh
qualor import sonarqube --url https://sonar.example.com --create-projects --set-defaults
```

- `--create-projects` creates the Qualor projects that do not exist yet, with the same keys and main
  branch names. Keep the same keys, so CI and the imported statuses line up.
- `--set-defaults` makes the imported counterparts of SonarQube's default profiles and default gate
  the organisation's defaults.

### 4. Scan, then import the issue statuses

Statuses can only be matched to issues Qualor has seen. Add the Qualor job to CI, let each project's
main branch be scanned once, then run:

```sh
qualor import sonarqube --url https://sonar.example.com --only issues
```

A status is applied only where the match is certain: the same rule mapping, the same file and line,
and the same line content. Everything else is reported as `unmatched`, `ambiguous` or
`competitors_unknown`, and nothing is applied to it. A decision someone already made in Qualor is
never overwritten.

If SonarQube analysed a subdirectory (`sonar.projectBaseDir`), pass `--path-prefix <dir>` so the
paths match.

## Options

| Option | Meaning |
|---|---|
| `--url URL` | SonarQube base URL, or `https://sonarcloud.io` |
| `--organization KEY` | the SonarQube Cloud organisation (required for Cloud) |
| `--token`, `--token-file`, `SONAR_TOKEN` | the SonarQube user token |
| `--qualor-organization KEY` | the target Qualor organisation (optional when you belong to one) |
| `--project KEY` | limit to these SonarQube projects (repeatable) |
| `--only STEPS` | a subset of `profiles,gates,projects,issues` |
| `--create-projects` | create missing Qualor projects |
| `--set-defaults` | make the imported default profiles and gate the organisation's defaults |
| `--overwrite` | replace Qualor profiles, gates and assignments of the same name that differ. Also use it to finish an interrupted run |
| `--path-prefix DIR` | prepend a directory to SonarQube file paths |
| `--dry-run`, `--output FILE` | plan only, and write the report to a file |
| `--server-url`, `--qualor-token-file`, `--ca-file` | the Qualor side |
| `--sonar-ca-file`, `--sonar-auth auto\|bearer\|basic`, `--sonar-kind auto\|server\|cloud` | the SonarQube side |
| `--timeout SECONDS`, `--max-issues N` | limits per request (default 30 seconds) and per project (default 100 000 issues) |
| `--allow-insecure-http` | allow plain `http` to a non-local host (the tokens then travel unencrypted) |

Running the import again is safe. Objects already in place are reported as `unchanged` or
`already_set`, and nothing is written.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | finished. Unmapped rules, conflicts and unmatched statuses are reported, not treated as failures |
| `2` | usage or configuration error |
| `4` | a server was unreachable or a step failed. The other steps still ran, and the report says which failed |
| `5` | a token was refused. The message says which server refused it |

## Running both side by side

A safe migration runs Qualor next to SonarQube for a few weeks:

1. Import the configuration. Add the Qualor job with `allow-failure: true` (GitLab), or as a check
   that is not required yet (GitHub, Azure DevOps).
2. Compare the verdicts on real merge requests, and tune the gate and profiles ([Quality
   gates](./quality-gates.md)).
3. Make the Qualor check required and remove the SonarQube step.
