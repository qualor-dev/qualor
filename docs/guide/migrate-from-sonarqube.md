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
| Quality profiles for JavaScript, TypeScript and Java | Qualor profiles: rule activation and severity overrides, for rules with an analyzer counterpart |
| Quality gates | Qualor gates, for conditions on metrics Qualor has |
| Which profile and gate each project uses | project assignments. With `--create-projects`, the projects themselves |
| Issues marked **False positive**, **Won't fix** or **Accepted** on the main branch | the same status on the matching Qualor issue, with the latest comment |

Not imported, and reported instead: rule parameters, SonarSource rules without an ESLint, PMD or
SpotBugs counterpart, gate conditions on metrics Qualor lacks, security hotspot reviews, branches other
than main, users and permissions, history, and new-code definitions.

Qualor does not run SonarSource's own analyzers. Many SonarQube rules therefore have no counterpart,
and the import says so. The **statuses** of issues that SonarQube imported from ESLint, PMD, SpotBugs
or Roslyn (`external_*` rules) map one to one.

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
