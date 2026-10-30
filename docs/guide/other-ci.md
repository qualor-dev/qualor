# Other CI systems and local scans

Run the scanner on Jenkins, Bitbucket Pipelines, TeamCity, Azure Pipelines, Buildkite or your own
machine. The scanner reads GitLab CI and GitHub Actions variables by itself. Everywhere else it
reads the revision and the branch from git, and you pass the rest.

## What every job needs

1. The `qualor/scanner` image, or the `qualor` binary with the analyzers on `PATH`. The image is
   much simpler.
2. The repository checked out with **full history**, at the root of the working directory.
3. `QUALOR_URL` and `QUALOR_TOKEN` in the environment, with the token from the CI's secret store.
4. The project key, because no CI project path is detected: `QUALOR_PROJECT_KEY`, `--project-key`
   or `project.key` in `qualor.yml`.
5. For a pull request or merge request: `--mr <id> --mr-target <target branch>`. Without them the
   scan is a branch analysis, compared with the project's main branch.

```sh
qualor scan --project-key acme/payments-api \
  --branch "$BRANCH_NAME" \
  --mr "$PR_ID" --mr-target "$PR_TARGET_BRANCH"     # only for pull requests
```

## Jenkins (declarative pipeline)

```groovy
pipeline {
  agent { docker { image 'qualor/scanner:0.14'; args '--entrypoint=' } }
  environment {
    QUALOR_URL   = 'https://qualor.example.com'
    QUALOR_TOKEN = credentials('qualor-token')           // a "Secret text" credential
    QUALOR_PROJECT_KEY = 'acme/payments-api'
  }
  stages {
    stage('Qualor') {
      steps {
        sh 'git fetch --unshallow || true'
        sh '''
          if [ -n "$CHANGE_ID" ]; then
            qualor scan --branch "$CHANGE_BRANCH" --mr "$CHANGE_ID" --mr-target "$CHANGE_TARGET"
          else
            qualor scan --branch "$BRANCH_NAME"
          fi
        '''
      }
    }
  }
}
```

## Bitbucket Pipelines

Set `QUALOR_URL` and `QUALOR_TOKEN` as secured repository variables.

```yaml
image: qualor/scanner:0.14
clone:
  depth: full
pipelines:
  pull-requests:
    '**':
      - step:
          name: Qualor
          script:
            - qualor scan --project-key acme/payments-api --branch "$BITBUCKET_BRANCH"
              --mr "$BITBUCKET_PR_ID" --mr-target "$BITBUCKET_PR_DESTINATION_BRANCH"
  branches:
    main:
      - step:
          name: Qualor
          script:
            - qualor scan --project-key acme/payments-api --branch main
```

## C and C++

The `qualor/scanner` image runs cppcheck only. clang-tidy needs your build's compile database and
headers, so run `qualor scan` in the job that built the project, with the `qualor` binary from the
release page and your clang-tidy on `PATH`. See
[C and C++](./languages-and-analyzers.md#c-and-c-cppcheck-clang-tidy).

## A local scan

```sh
docker run --rm -v "$PWD":/src -w /src \
  -e QUALOR_URL -e QUALOR_TOKEN -e QUALOR_PROJECT_KEY \
  qualor/scanner:0.14 scan
```

Without a server, `--dry-run --output report.json.gz` writes the report to a file and uploads
nothing:

```sh
docker run --rm -v "$PWD":/src -w /src qualor/scanner:0.14 scan --dry-run --output report.json.gz --project-key local/test
```

When a scan behaves unexpectedly, run `qualor validate` first. It prints the resolved
configuration, with every default filled in and the token redacted.

## Exit codes

The job fails when the scanner exits with a non-zero code, and code `1` means the gate failed. The
full table is in the [CLI reference](./cli.md#exit-codes).

Qualor does not comment on Bitbucket, Azure DevOps or Gerrit reviews. There, the job's exit code
carries the verdict.
