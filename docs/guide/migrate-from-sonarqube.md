# Migrating from SonarQube

`qualor import sonarqube` copies a team's SonarQube setup into one Qualor organisation. It works with
**SonarQube Server 9.9 LTA and later** (10.x, 2025.x, Community Build) and with **SonarQube Cloud**
(sonarcloud.io and sonarqube.us).

It runs in the CLI, on your machine or in a CI job. It only **reads** SonarQube, with `GET` requests,
and writes to Qualor through its API. The Qualor server never contacts SonarQube, and no token is
stored anywhere.

## What moves, and what doesn't

| Imported | As |
|---|---|
| Issues marked **False positive**, **Won't fix** or **Accepted** on the main branch | the same status on the matching Qualor issue, with the latest comment |
| Quality gates | Qualor gates, for conditions on metrics Qualor has |
| Projects, and which gate each one uses | project assignments. With `--create-projects`, the projects themselves |
| Quality profiles for JavaScript, TypeScript, C# and Java | listed in the plan. Rule activation and severity overrides move as the SonarSource-to-analyzer rule mappings are reviewed. Until a profile has reviewed mappings it is reported as skipped, and your Qualor profiles stay as they are |

The statuses of issues that SonarQube imported from ESLint, PMD, SpotBugs or Roslyn (`external_*`
rules) map one to one. SonarQube Server 9.9 does not let anyone resolve such external issues, so they
have statuses to move from SonarQube Server 10.x and Community Build on.

C#, JavaScript and TypeScript issue statuses map one to one to SonarQube-compatible rules: Qualor
bundles the same analysers SonarQube's own `csharpsquid`, `javascript` and `typescript` rules come
from (SonarAnalyzer.CSharp 9.32 inside `roslyn`, eslint-plugin-sonarjs 2.0.4 as `sonarjs`), so a
rule key SonarQube reports is a rule key Qualor reports too, wherever the bundled version still has
it. A rule the bundled versions do not have, mostly one SonarQube added in a later release, is
reported unmapped, not guessed at.

Qualor runs these bundled rules with their default configuration: eslint-plugin-sonarjs's
`recommended` set, and the SonarAnalyzer.CSharp rules enabled by default. A profile can activate a
rule outside it (S1192 is one). The import still maps and records it, but no issue comes from it,
and the summary and the `--output` plan count such rules as **mapped but not run by the bundled
configuration** (`mappedNotRun`).

Not imported, and reported instead: rule parameters, SonarSource rules without an ESLint, PMD,
SpotBugs or SonarQube-compatible-rules counterpart, gate conditions on metrics Qualor lacks, security
hotspot reviews, branches other than main, users and permissions, history, and new-code definitions.

Qualor does not run SonarSource's own analyzers, only the bundled SonarQube-compatible rules above
for C#, JavaScript and TypeScript. Every other SonarQube rule has no counterpart, and the import says
so.

## Step by step

### 1. Tokens

- **SonarQube:** a **user** token (`squ_…`) of a user with *Browse* on the projects. Project and global
  analysis tokens (`sqp_`, `sqa_`) cannot read the Web API.
- **Qualor:** a personal token with the **Admin** scope, of an org admin.

```sh
export SONAR_TOKEN=squ_…
export QUALOR_URL=https://qualor.example.com
export QUALOR_TOKEN=qlr_pat_…
```

Prefer `SONAR_TOKEN` or `--token-file` to `--token`, which leaves the token in the shell history.

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

The import sends both tokens, and the Qualor one has the Admin scope, so it uses plain `http` only to
`localhost`, `127.0.0.0/8` or `[::1]`. From the container, a Qualor server on your machine is reachable
that way with `--network host` and `QUALOR_URL=http://127.0.0.1:8080` (Linux). With Docker Desktop's
`QUALOR_URL=http://host.docker.internal:8080`, add `--allow-insecure-http`. Use `https` for any other
server.

The summary lists what would be created, changed or left alone, the unmapped rules (the 20 with the
most resolved issues), the unmapped gate conditions, and the conflicts. `--output` writes the full plan
as JSON, with file mode 0600.

### 3. Import the configuration

```sh
qualor import sonarqube --url https://sonar.example.com --create-projects --set-defaults
```

- `--create-projects` creates the Qualor projects that do not exist yet, with the same keys and main
  branch names. Keep the same keys, so CI and the imported statuses line up.
- `--set-defaults` makes the imported counterparts of SonarQube's default profiles and default gate
  the organisation's defaults.

### 4. Scan, then import the issue statuses

Statuses can only be matched to issues Qualor has seen. So put the Qualor job into CI, let each
project's main branch be scanned once, then run:

```sh
qualor import sonarqube --url https://sonar.example.com --only issues
```

A status is applied only where the match is certain: the same rule mapping, the same file and line,
and the same line content. Everything else is reported as `unmatched`, `ambiguous` or
`competitors_unknown`, and nothing is applied to it. A decision someone has already made in Qualor is
never overwritten.

If SonarQube analysed a subdirectory (`sonar.projectBaseDir`), pass `--path-prefix <dir>` so the paths
match.

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
| `--timeout SECONDS`, `--max-issues N` | limits per request and per project |
| `--allow-insecure-http` | allow plain `http` to a non-local host (the tokens then travel unencrypted) |

Running the import again is safe. Objects that are already in place are reported as `unchanged` or
`already_set`, and nothing is written.

## Exit codes

`0` finished. Unmapped rules, conflicts and unmatched statuses are reported, not treated as failures.
`2` usage or configuration error. `4` a server was unreachable or a step failed; the others still ran,
and the report says which failed. `5` a token was refused; the message says which server refused it.

## Running both side by side

A safe migration runs Qualor next to SonarQube for a few weeks:

1. Import the configuration and add the Qualor job with `allow-failure: true` (GitLab) or as a check
   that is not required yet (GitHub).
2. Compare the verdicts on real merge requests. Tune the gate and profiles
   ([Quality gates](./quality-gates.md)).
3. Make the Qualor check required and remove the SonarQube step.
