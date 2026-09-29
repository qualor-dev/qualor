# qualor/scanner-dotnet

Short description: Code quality scanner for C#: qualor/scanner plus .NET 8/10, Roslynator and SonarAnalyzer.CSharp

Categories: Developer tools, Integration & delivery, Security

## Overview

The C# scanner of [Qualor](https://qualor.dev), the open-source, self-hosted SonarQube alternative
with no lines-of-code licence. This image is
[`qualor/scanner`](https://hub.docker.com/r/qualor/scanner) with the tooling for C# projects
added. Everything the scanner image does, this one does too; use it for repositories with C#
code, and the smaller `qualor/scanner` for the rest.

- Source, documentation and issues: <https://github.com/qualor-dev/qualor>
- Languages and analyzers, with the C# workflow:
  <https://qualor.dev/docs/languages-and-analyzers>

### Tags

The same tags as `qualor/scanner`: the full version, such as `0.1.0`, and the minor tag, such as
`0.1`. There is no `latest` tag.

### What it adds to qualor/scanner

- The .NET SDKs 8.0.425 and 10.0.401, in `/opt/qualor/share/dotnet` (`DOTNET_ROOT`), with the
  .NET CLI telemetry turned off (`DOTNET_CLI_TELEMETRY_OPTOUT=1`).
- The Roslynator analyzers 5.0.0, bundled in `/opt/qualor/dotnet/analyzers`
  (`QUALOR_DOTNET_ANALYZERS`).
- SonarAnalyzer.CSharp 9.32 (SonarQube-compatible rules, `roslyn:S####`), bundled next to
  Roslynator. A project's own reference to SonarAnalyzer.CSharp replaces the bundled one, so there
  is never a duplicate-analyzer error.
- Runs as the user `node` (uid 1000), like the scanner; about 4.8 GB (about 1.8 GB more than
  `qualor/scanner`). It is built from the `qualor/scanner` image of the same tag, and released
  with that tag right after it.

### How to use it

Roslyn analyzers need the compiler's semantic model, so Qualor hooks into your own build instead
of building anything itself:

```sh
qualor dotnet begin                 # installs an MSBuild hook for this checkout
dotnet build --no-incremental       # your build: its SDK, restore, feeds and arguments
qualor dotnet end                   # removes the hook, reads the Roslyn logs, runs qualor scan
```

GitLab CI, with the component from the GitLab CI/CD catalog:

```yaml
include:
  - component: gitlab.com/qualor/qualor/qualor@0.1
    inputs:
      image: qualor/scanner-dotnet
      image-tag: '0.1'
      dotnet: true
      build-command: dotnet build MySolution.sln --no-incremental
```

Or in a job of your own:

```yaml
qualor:
  image: { name: qualor/scanner-dotnet:0.1, entrypoint: [''] }
  variables: { GIT_DEPTH: 0 }
  script:
    - qualor dotnet begin
    - dotnet build MySolution.sln --no-incremental
    - qualor dotnet end
  after_script:
    - if [ -d .qualor/dotnet ]; then qualor dotnet abort; fi
```

`--no-incremental` matters: a project that is not recompiled writes no log. The environment
variables and exit codes are those of `qualor/scanner`. The full guide is at
<https://qualor.dev/docs/languages-and-analyzers>.

### Licences

The Qualor CLI is MIT-licensed. The .NET SDK is MIT-licensed, and Roslynator is Apache-2.0.
SonarAnalyzer.CSharp 9.32 is LGPL-3.0, the last release before the SONAR Source-Available
License. This image has no sources image of its own: the complete corresponding source of the
copyleft components it carries, SonarAnalyzer.CSharp included, is
[`qualor/scanner-sources`](https://hub.docker.com/r/qualor/scanner-sources) with the same tag,
the same one `qualor/scanner` uses.
The notices are in `/opt/qualor/NOTICE.md` and the licence texts in `/opt/qualor/licenses/`.

### Trademarks

SonarQube and SonarCloud are trademarks of SonarSource SA. Qualor is an independent project and is
not affiliated with, sponsored or endorsed by SonarSource. Their names are used only to describe
compatibility and to compare features.
