# CLI reference

The `qualor` CLI is the entrypoint of the `qualor/scanner` and `qualor/scanner-dotnet` images:
`docker run qualor/scanner:<tag> scan` runs `qualor scan`. In GitLab CI, set `entrypoint: ['']` and
call `qualor` in `script`.

## `qualor scan`

```text
qualor scan [--config PATH] [--project-key KEY] [--sarif PATH]... [--coverage PATH]...
            [--branch NAME] [--mr ID --mr-target BRANCH] [--no-wait] [--token-file PATH]
            [--server-url URL] [--ca-file PATH] [--dry-run --output report.json.gz]
            [--gitlab-code-quality FILE] [--gitlab-sast FILE] [--gitlab-dependency-scanning FILE]
```

It runs the analyzers, computes metrics, duplication and coverage, and computes the diff against the
baseline. It uploads one gzip report, waits for the gate verdict, prints the failed conditions, and
exits.

Its first line is its own version (`qualor 0.5.0 (linux-x64)`). With a server configured, it then
asks the server for its version and logs `server https://qualor.example.com runs Qualor 0.5.0`. When
the two are different releases (`0.3` against `0.4`), it warns and names the scanner tag that
matches the server. The check never fails a scan: a server that does not answer it is noted only in
the debug log.

| Option | Meaning |
|---|---|
| `--config PATH` | config file (default `qualor.yml` at the repository root) |
| `--project-key KEY` | the Qualor project key (default: the CI project path) |
| `--sarif PATH` | an extra SARIF 2.1.0 file; repeatable; added to `qualor.yml`'s list |
| `--coverage PATH` | an extra coverage report; repeatable |
| `--branch NAME` | the branch name, when CI detection does not give it |
| `--mr ID --mr-target BRANCH` | analyse as a merge/pull request into `BRANCH` |
| `--no-wait` | exit 0 once the server has queued the analysis; do not wait for the gate |
| `--token-file PATH` | read the token from a file (beats `QUALOR_TOKEN`) |
| `--server-url URL` | the server (beats `QUALOR_URL`) |
| `--ca-file PATH` | a PEM CA bundle for the server (beats `QUALOR_CA_FILE`) |
| `--dry-run --output FILE` | build the report and write it to `FILE`; upload nothing |
| `--gitlab-code-quality FILE` | also write GitLab's Code Quality report |
| `--gitlab-sast FILE` | also write GitLab's SAST report (security findings) |
| `--gitlab-dependency-scanning FILE` | also write GitLab's Dependency Scanning report (Trivy findings) |

Run the CLI from the repository root. The GitLab report paths must lie inside the working directory.

## `qualor dotnet begin | end | abort`

The C# route ([Languages and analyzers](./languages-and-analyzers.md#c)):

```sh
qualor dotnet begin [--config PATH]      # before your build: install the MSBuild hook
dotnet build --no-incremental            # your own build
qualor dotnet end [qualor scan options]  # remove the hook, read the Roslyn logs, then run qualor scan
qualor dotnet abort                      # after a failed build: clean up, scan nothing
```

## `qualor validate`

```sh
qualor validate [--config PATH]
```

It checks `qualor.yml` and prints the fully resolved configuration, with every default filled in and
secrets redacted.

## `qualor import sonarqube`

It imports issue statuses, quality gates and projects with their gate assignments from SonarQube
Server or SonarQube Cloud, and quality profiles as their rule mappings are reviewed. See
[Migrating from SonarQube](./migrate-from-sonarqube.md).

## `qualor version`

It prints the CLI version and the bundled grammar and analyzer versions.

## Exit codes

| Code | Meaning | What to do |
|---|---|---|
| 0 | report accepted, and the gate passed (or `--no-wait`, or the project has no gate) | — |
| 1 | the **gate failed**, or ended in `error` (for example, no baseline) | fix the new issues, or read the printed conditions |
| 2 | usage or configuration error: invalid `qualor.yml`, no URL or token, not a git work tree, no project key | read the message; `qualor validate` |
| 3 | a required analyzer (`enabled: true`) failed or is missing | install it, use the scanner image, or set `enabled: auto` |
| 4 | server unreachable, upload rejected, gate wait timed out, or an internal error | check `QUALOR_URL`, the proxy/TLS setup and the server logs |
| 5 | authentication or authorisation failure (401/403) | check the token, its scope and its project |
| 130 / 143 / 129 | interrupted (SIGINT / SIGTERM / SIGHUP) | — |

Set `QUALOR_LOG_LEVEL=debug` to see each analyzer's command and output.
