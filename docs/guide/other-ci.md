# Other CI systems and local scans

The scanner reads GitLab CI and GitHub Actions variables on its own. Everywhere else (Jenkins,
Bitbucket Pipelines, TeamCity, Azure Pipelines, Buildkite, a laptop), it reads the revision and the
branch from git. You pass the rest yourself.

## What every job needs

1. The `qualor/scanner` image. Or the `qualor` binary with the analyzers on `PATH`; the image is much
   simpler.
2. The repository checked out with **full history**, at the root of the working directory.
3. `QUALOR_URL` and `QUALOR_TOKEN` in the environment, with the token from the CI's secret store.
4. The project key: `QUALOR_PROJECT_KEY`, `--project-key` or `project.key` in `qualor.yml`, because no
   CI project path is detected.
5. For a pull request or merge request: `--mr <id> --mr-target <target branch>`. Otherwise the scan is
   a branch analysis, compared with the project's main branch.

```sh
qualor scan --project-key acme/payments-api \
  --branch "$BRANCH_NAME" \
  --mr "$PR_ID" --mr-target "$PR_TARGET_BRANCH"     # only for pull requests
```

## Jenkins (declarative pipeline)

```groovy
pipeline {
  agent { docker { image 'qualor/scanner:0.2'; args '--entrypoint=' } }
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

```yaml
image: qualor/scanner:0.2
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

Set `QUALOR_URL` and `QUALOR_TOKEN` (secured) as repository variables. Qualor does not comment on
Bitbucket, Azure DevOps or Gerrit reviews. The job's exit code carries the verdict there.

## A local scan

```sh
docker run --rm -v "$PWD":/src -w /src \
  -e QUALOR_URL -e QUALOR_TOKEN -e QUALOR_PROJECT_KEY \
  qualor/scanner:0.2 scan
```

Or without a server: `--dry-run --output report.json.gz` builds the report and writes it to a file,
and uploads nothing:

```sh
docker run --rm -v "$PWD":/src -w /src qualor/scanner:0.2 scan --dry-run --output report.json.gz --project-key local/test
```

`qualor validate` prints the resolved configuration, with every default filled in and the token
redacted. Run it first when a scan behaves unexpectedly.

## Exit codes

The job fails when the scanner exits with a non-zero code. Code `1` means the gate failed. The full
table is in the [CLI reference](./cli.md#exit-codes).
