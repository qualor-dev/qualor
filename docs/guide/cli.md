# CLI reference

The `qualor` CLI is the entrypoint of the `qualor/scanner` and `qualor/scanner-dotnet` images:
`docker run qualor/scanner:<tag> scan` runs `qualor scan`. In GitLab CI, set `entrypoint: ['']`
and call `qualor` in `script`. `qualor help` (or `--help`) prints the usage.

## `qualor scan`

```text
qualor scan [--config PATH] [--project-key KEY] [--sarif PATH]... [--coverage PATH]...
            [--branch NAME] [--mr ID --mr-target BRANCH] [--no-wait] [--token-file PATH]
            [--server-url URL] [--ca-file PATH] [--dry-run --output report.json.gz]
            [--gitlab-code-quality FILE] [--gitlab-sast FILE] [--gitlab-dependency-scanning FILE]
```

It runs the analyzers, computes metrics, duplication, coverage and the diff against the baseline,
and uploads one gzip report. Then it waits for the quality gate, prints the failed conditions and
exits. Run it from the repository root.

| Option | Meaning |
| --- | --- |
| `--config PATH` | config file (default `qualor.yml` at the repository root) |
| `--project-key KEY` | the Qualor project key (default: the CI project path) |
| `--sarif PATH` | an extra SARIF 2.1.0 file, added to `qualor.yml`'s list. Repeatable |
| `--coverage PATH` | an extra coverage report. Repeatable |
| `--branch NAME` | the branch name, when CI detection does not give it |
| `--mr ID --mr-target BRANCH` | analyse as a merge or pull request into `BRANCH` |
| `--no-wait` | exit 0 once the server has queued the analysis, without waiting for the gate |
| `--token-file PATH` | read the token from a file (overrides `QUALOR_TOKEN`) |
| `--server-url URL` | the server (overrides `QUALOR_URL`) |
| `--ca-file PATH` | a PEM CA bundle for the server (overrides `QUALOR_CA_FILE`) |
| `--dry-run --output FILE` | build the report and write it to `FILE`. Nothing is uploaded |
| `--gitlab-code-quality FILE` | also write GitLab's Code Quality report |
| `--gitlab-sast FILE` | also write GitLab's SAST report (security findings) |
| `--gitlab-dependency-scanning FILE` | also write GitLab's Dependency Scanning report (Trivy findings) |

The GitLab report paths must be inside the working directory.

**Versions.** The first line is the scanner's version (`qualor 0.12.1 (linux-x64)`). With a server
configured, it then logs the server's (`server https://qualor.example.com runs Qualor 0.12.1`). If
the two are different releases (`0.3` against `0.4`), it warns and names the scanner tag that
matches the server. If the server knows of a newer release (its
[update check](./telemetry.md#update-check)), the scanner logs `Qualor 0.12.1 is available …` and
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

Set `QUALOR_LOG_LEVEL=debug` to see each analyzer's command and output.
