# CLI reference

The `qualor` CLI is the entrypoint of the `qualor/scanner` and `qualor/scanner-dotnet` images:
`docker run qualor/scanner:<tag> scan` runs `qualor scan`. In GitLab CI, set `entrypoint: ['']`
and call `qualor` in `script`. `qualor help` (or `--help`) prints the usage.

## `qualor scan`

```text
qualor scan [--config PATH] [--project-key KEY] [--sarif PATH]... [--coverage PATH]...
            [--branch NAME] [--mr ID --mr-target BRANCH] [--tag NAME] [--no-wait]
            [--token-file PATH] [--server-url URL] [--ca-file PATH]
            [--dry-run --output report.json.gz]
            [--gitlab-code-quality FILE] [--gitlab-sast FILE] [--gitlab-dependency-scanning FILE]
```

It runs the analyzers, computes metrics, duplication, coverage and the diff against the baseline,
and uploads one gzip report. Then it waits for the quality gate, prints the failed conditions and
exits. Run it from the repository root. In a tag pipeline, or with `--tag`, it records the checkout
as a [version](./releases.md) instead.

| Option | Meaning |
| --- | --- |
| `--config PATH` | config file (default `qualor.yml` at the repository root) |
| `--project-key KEY` | the Qualor project key (default: the CI project path) |
| `--sarif PATH` | an extra SARIF 2.1.0 file, added to `qualor.yml`'s list. Repeatable |
| `--coverage PATH` | an extra coverage report. Repeatable |
| `--branch NAME` | the branch name, when CI detection does not give it |
| `--mr ID --mr-target BRANCH` | analyse as a merge or pull request into `BRANCH` |
| `--tag NAME` | record the checkout as the [version](./releases.md) of tag `NAME`, so check out the tag first. Not with `--branch` or `--mr` |
| `--no-wait` | exit 0 once the server has queued the analysis, without waiting for the gate |
| `--token-file PATH` | read the token from a file (overrides `QUALOR_TOKEN`) |
| `--server-url URL` | the server (overrides `QUALOR_URL`) |
| `--ca-file PATH` | a PEM CA bundle for the server (overrides `QUALOR_CA_FILE`) |
| `--dry-run --output FILE` | build the report and write it to `FILE`. Nothing is uploaded |
| `--gitlab-code-quality FILE` | also write GitLab's Code Quality report |
| `--gitlab-sast FILE` | also write GitLab's SAST report (security findings) |
| `--gitlab-dependency-scanning FILE` | also write GitLab's Dependency Scanning report (Trivy findings) |

The GitLab report paths must be inside the working directory.

Started through the image's entrypoint, the scanner keeps `QUALOR_TOKEN` out of the environment of
the analyzers it runs.

**Versions.** The first line is the scanner's version (`qualor 0.17.0 (linux-x64)`). With a server
configured, it then logs the server's (`server https://qualor.example.com runs Qualor 0.17.0`). If
the two are different releases (`0.3` against `0.4`), it warns and names the scanner tag that
matches the server. If the server knows of a newer release (its
[update check](./telemetry.md#update-check)), the scanner logs `Qualor 0.17.0 is available …` and
the tag to move to. This check never fails a scan. A server that does not answer it is noted only in
the debug log.

**Analyzer times.** Each analyzer that ran logs one line when it finishes, such as
`sonarjs: 83.2 s, 12 findings`. The time is the one in the report. The count is what the analyzer
reported, before Qualor leaves out duplicates and files outside the scope. A skipped or failed
analyzer logs its reason instead.

**AI review.** On a merge request, when [AI review](./ai-review.md) is on for the project, the scan
also uploads a snapshot of the repository right after the report. Its log lines start with
`AI review`. A failure there is only a warning: the exit code stays the quality gate's. A scan that
exits 3 sends no snapshot.

## `qualor upload-sbom`

```text
qualor upload-sbom FILE [--version LABEL] [--project-key KEY] [--config PATH]
                   [--token-file PATH] [--server-url URL] [--ca-file PATH]
```

It uploads a CycloneDX or SPDX JSON file as a [version](./sbom-upload.md). The server, token and
project key come from the same flags, environment and `qualor.yml` as `qualor scan`. The CLI
gzips the file, prints what the server stored, and retries for up to 300 seconds while the server
is busy (503 `UPLOADS_BUSY`).

| Code | When |
|---|---|
| 0 | the server stored the version |
| 2 | the file cannot be read, a flag is wrong, or there is no server, token or project key |
| 4 | the server refused the upload (the CLI prints its code, title and detail, such as `VERSION_LABEL_TAKEN`), is unreachable, or stayed busy |
| 5 | 401 or 403: the token is wrong, or lacks the permission |

## `qualor fix`

```text
qualor fix [--project-key KEY] [--max N] [--timeout 30m] [--config PATH] [--token-file PATH]
           [--server-url URL] [--ca-file PATH]
```

It prepares the [fix merge requests](./fix-merge-requests.md) that people or the automatic mode
requested. It claims fixes from the server, runs your package managers in a scratch copy of the
checkout, and uploads the changed manifests and lockfiles. It never changes the checkout. Run it in
the main branch's checkout, in a glibc image that has your package managers
([The fix job](./fix-merge-requests.md#the-fix-job)). The server, token and project key come from
the same flags, environment and `qualor.yml` as `qualor scan`, and the token is a project analysis
token.

| Option | Meaning |
|---|---|
| `--max N` | prepare at most N fixes, from 1 to 10. Default 10 |
| `--timeout DURATION` | the job's time, such as `45m` or `2h`: from 2 minutes to 6 hours. Default 30 minutes. With less than a minute left, it claims no more |

An upload waits for the server's `Retry-After` and retries three times.

| Code | When |
|---|---|
| 0 | the run ended, also when a fix failed (its reason shows in Qualor), and when the project cannot take fixes now: the CLI logs why (fix merge requests off, no repository, monitoring off) |
| 2 | a flag is wrong, there is no server, token or project key, HEAD is not the main branch's checkout (a detached HEAD, a tag pipeline, a commit other than the job's), or the system is musl |
| 4 | the server is unreachable or answered an error |
| 5 | 401 or 403: the token is wrong, revoked, of another project, or not a project token |

## `qualor dotnet begin | end | abort`

The C# route ([Languages and analyzers](./languages-and-analyzers.md#c)):

```sh
qualor dotnet begin [--config PATH]      # before your build: install the MSBuild hook
dotnet build --no-incremental            # your own build
qualor dotnet end [qualor scan options]  # remove the hook, read the Roslyn logs, run Qualor's Roslyn taint engine (C# rules), then run qualor scan
qualor dotnet abort                      # after a failed build: clean up, scan nothing
```

## `qualor validate`

```sh
qualor validate [--config PATH]
```

It checks `qualor.yml` and prints the resolved configuration, with every default filled in and
secrets redacted.

## `qualor import sonarqube`

It imports issue statuses, quality gates, and projects with their gate assignments from SonarQube
Server or SonarQube Cloud. It imports quality profiles as their rule mappings are reviewed. See
[Migrating from SonarQube](./migrate-from-sonarqube.md).

## `qualor version`

It prints the CLI version, its platform and the bundled grammars.

## Exit codes

| Code | Meaning | What to do |
| --- | --- | --- |
| 0 | report accepted, and the gate passed (or `--no-wait`, or the project has no gate) | — |
| 1 | the **gate failed**, or ended in `error` (for example, no baseline) | fix the new issues, or read the printed conditions |
| 2 | usage or configuration error: invalid `qualor.yml`, no URL or token, not a git work tree, no project key | read the message; run `qualor validate` |
| 3 | a required analyzer (`enabled: true`) failed or is missing | install it, use the scanner image, or set `enabled: auto` |
| 4 | server unreachable, upload rejected, gate wait timed out, or an internal error | check `QUALOR_URL`, the proxy and TLS setup, and the server logs |
| 5 | authentication or authorisation failure (401/403) | check the token, its scope and its project |
| 130 / 143 / 129 | interrupted (SIGINT / SIGTERM / SIGHUP) | — |

A tag scan has exit codes of its own ([Releases and versions](./releases.md#exit-codes)).

Set `QUALOR_LOG_LEVEL=debug` to see each analyzer's command and output.
