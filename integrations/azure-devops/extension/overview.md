# Qualor for Azure Pipelines

The `Qualor@0` task scans your repository and uploads the report to your Qualor server. In a pull
request build it scans the pull request's head commit, not the merge commit.

```yaml
steps:
  - checkout: self
    fetchDepth: 0
  - task: Qualor@0
```

The task reads two pipeline variables. `QUALOR_URL` is the address of your Qualor server.
`QUALOR_TOKEN` is the token, stored as a secret variable.

The task runs on Linux agents with Docker. It starts the `qualor/scanner` image with `docker run`.

The [Azure DevOps guide](https://qualor.dev/docs/azure-devops) covers pull request builds, .NET and
the other options.
