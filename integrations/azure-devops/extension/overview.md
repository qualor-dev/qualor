# Qualor for Azure Pipelines

Qualor is self-hosted code quality and security for your team. This extension adds the `Qualor@0`
task: it scans your repository in a pipeline and sends the report to your Qualor server.

## On pull requests

With your Azure DevOps connection set up in Qualor, each pull request gets:

- A status check that passes or fails with your quality gate.
- A summary comment with the result.
- Comments on the changed lines, on each new issue.
- AI review with your own model.

## Add it to your pipeline

```yaml
steps:
  - checkout: self
    fetchDepth: 0
    persistCredentials: false
  - task: Qualor@0
```

Run the pipeline as a Build validation policy to analyse every pull request.

Set two variables on the pipeline:

- `QUALOR_URL`: the address of your Qualor server.
- `QUALOR_TOKEN`: your project's analysis token, stored as a secret variable.

Set `imageTag` to your Qualor server's release line.

## Where it runs

- Azure DevOps Services and Azure DevOps Server 2022 or later.
- Linux agents with Docker.

## Learn more

The [Azure DevOps guide](https://qualor.dev/docs/azure-devops) walks through the connection,
pull request builds and .NET projects.
