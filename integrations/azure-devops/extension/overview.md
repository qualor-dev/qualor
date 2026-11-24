# Qualor for Azure Pipelines

Qualor is self-hosted code quality and security for your team. This extension adds the `Qualor@0`
task: it scans your repository in a pipeline and sends the report to your Qualor server.

## On every pull request

- A status check that passes or fails with your quality gate.
- A summary comment with the result.
- Comments on the changed lines, one for each new issue.
- AI review on your own model.

## Add it to your pipeline

```yaml
steps:
  - checkout: self
    fetchDepth: 0
    persistCredentials: false
  - task: Qualor@0
```

Set two variables on the pipeline:

- `QUALOR_URL`: the address of your Qualor server.
- `QUALOR_TOKEN`: your project's analysis token, stored as a secret variable.

## Where it runs

- Azure DevOps Services and Azure DevOps Server 2022 or later.
- Linux agents with Docker.

## Learn more

The [Azure DevOps guide](https://qualor.dev/docs/azure-devops) walks through setup, pull request
builds and .NET projects.
