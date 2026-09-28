# qualor/scanner-dotnet

Short description: Qualor scanner for C#: qualor/scanner plus the .NET 8 and 10 SDKs and Roslynator

## Overview

Qualor is an open-source, self-hosted, GitLab-first code quality platform: a SonarQube
alternative without lines-of-code licensing. This image is
[`qualor/scanner`](https://hub.docker.com/r/qualor/scanner) with the tooling for C# projects
added. Everything the scanner image does, this one does too; use it for repositories with C#
code, and the smaller `qualor/scanner` for the rest.

- Source, documentation and issues: <https://github.com/qualor-dev/qualor>
- Languages and analyzers, with the C# workflow:
  <https://qualor.dev/docs/languages-and-analyzers>

### What it adds to qualor/scanner

- The .NET SDKs 8.0.425 and 10.0.401, in `/opt/qualor/share/dotnet` (`DOTNET_ROOT`), with the
  .NET CLI telemetry turned off (`DOTNET_CLI_TELEMETRY_OPTOUT=1`).
- The Roslynator analyzers 5.0.0, bundled in `/opt/qualor/dotnet/analyzers`
  (`QUALOR_DOTNET_ANALYZERS`).
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

GitLab CI:

```yaml
qualor:
  image: { name: qualor/scanner-dotnet:<tag>, entrypoint: [''] }
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

The Qualor CLI is MIT-licensed. The .NET SDK is MIT-licensed, and Roslynator is Apache-2.0. This
image adds no copyleft component, so it has no sources image of its own: the complete
corresponding source of the copyleft components it carries from `qualor/scanner` is
[`qualor/scanner-sources`](https://hub.docker.com/r/qualor/scanner-sources) with the same tag.
The notices are in `/opt/qualor/NOTICE.md` and the licence texts in `/opt/qualor/licenses/`.

### Trademarks

SonarQube and SonarCloud are trademarks of SonarSource SA. Qualor is an independent project and is
not affiliated with, sponsored or endorsed by SonarSource. Their names are used only to describe
compatibility and to compare features.
