# Migrating from Dependency-Track

Qualor takes the SBOMs you upload to Dependency-Track, tracks their packages for new
vulnerabilities, and finds where a package is used. Change the upload step of your pipelines. There
is no importer: Dependency-Track's data stays where it is.

Qualor is not a drop-in server. It has no Dependency-Track API, so `gh-upload-sbom` and similar
tools cannot point at it ([What Qualor does not do](#what-qualor-does-not-do)).

## The mapping

| Dependency-Track | Qualor |
|---|---|
| Project | a [project](./users-projects-tokens.md), created first |
| Project version | a [version](./releases.md) of that project, set by `--version` |
| One project per image | the same: a project of its own for an image ([Precedence](./sbom-upload.md#precedence)) |
| BOM upload (`PUT /api/v1/bom`) | `PUT /api/v0/projects/sbom`, or `qualor upload-sbom` ([SBOM upload](./sbom-upload.md)) |
| API key | a project analysis token, or a personal token with the `analysis:write` scope |
| Component search | the **Packages** page, and `qualor_package_usages` in the [MCP server](./mcp.md) ([Where used](./dependency-vulnerabilities.md#where-used)) |
| Components tab | the **Dependencies** tab |
| Vulnerability audit: analysis state, justification, comment | a [status with a VEX reason](./dependency-vulnerabilities.md#statuses-and-reasons) and a comment |
| Suppressing a finding | the status **Not affected (false positive)** or **Affected, won't fix** |
| VEX and SBOM export | [SBOM and VEX export](./dependency-vulnerabilities.md#export-sbom-and-vex-business-and-enterprise) (Business and Enterprise) |
| Vulnerability notifications | [Alerts](./dependency-vulnerabilities.md#alerts-business-and-enterprise) (Business and Enterprise) |

Differences that matter:

- A Qualor project holds many versions. Dependency-Track keeps one project per name and version.
- A decision covers a package and a vulnerability id for the whole project, not for one version
  ([One decision, a wide scope](./dependency-vulnerabilities.md#one-decision-a-wide-scope)).
- The server checks packages against its own copy of the Trivy database, and re-checks tracked
  versions when it changes ([The vulnerability database](./vulnerability-database.md)).
- Which versions are tracked follows a rule per project
  ([Which versions are tracked](./releases.md#which-versions-are-tracked)).

## Change a pipeline

1. Create the project in Qualor, and a [project token](./users-projects-tokens.md).
2. Replace the upload step.

Before, with Dependency-Track:

```sh
curl -fsS -X PUT "$DT_URL/api/v1/bom" -H "X-Api-Key: $DT_API_KEY" \
  -H 'Content-Type: application/json' \
  -d "{\"projectName\":\"shop\",\"projectVersion\":\"$TAG\",\"autoCreate\":true,\"bom\":\"$(base64 -w0 sbom.json)\"}"
```

After, with Qualor:

```sh
docker run --rm -v "$PWD":/work -w /work \
  -e QUALOR_URL -e QUALOR_TOKEN -e QUALOR_PROJECT_KEY=acme/shop \
  qualor/scanner:0.16 upload-sbom sbom.json --version "$TAG"
```

[An image SBOM in CI](./sbom-upload.md#an-image-sbom-in-ci) shows the whole step, with Trivy or
Syft.

## What Qualor does not do

| Dependency-Track feature | In Qualor |
|---|---|
| The upload API (`/api/v1/bom`, `X-Api-Key`, the token poll) and tools built on it, such as `gh-upload-sbom` | not offered. Use `qualor upload-sbom` or the Qualor API |
| `autoCreate`: a project made by the first upload | not offered. The project must exist, or the upload answers `PROJECT_NOT_FOUND` |
| CycloneDX XML | refused. Export CycloneDX JSON |
| SPDX 3.0 and SPDX tag-value | refused. Export SPDX 2.3 JSON |
| Components without a purl | skipped and counted |
| A version range in the component search, such as `< 2.17` | not offered. Search by package name or purl, and an exact version |
| Vulnerabilities and VEX sections of the uploaded BOM | ignored. Qualor finds the vulnerabilities itself |
| An SBOM with several distributions | refused. Split it, one file per image |

The full list of limits is in [SBOM upload](./sbom-upload.md#limits).
