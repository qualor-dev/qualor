# SBOM upload

Upload a CycloneDX or SPDX file, and Qualor tracks it as a [version](./releases.md). Use it for
container images, software you buy and builds Qualor does not scan. The server then checks the
packages for vulnerabilities like those of a scanned release. It is in every edition.

An upload is not a scan. It records no analysis, runs no gate and creates no issues.

## Formats

| Format | Read |
|---|---|
| CycloneDX JSON | 1.2 to 1.7 |
| SPDX JSON | 2.2 and 2.3 |

Plain or gzip. Qualor detects the format from the content (`bomFormat`, `spdxVersion`), not from
the content type.

| Refused | Export instead |
|---|---|
| CycloneDX XML | CycloneDX JSON |
| SPDX 3.0 (JSON-LD) | SPDX 2.3 JSON |
| SPDX tag-value | SPDX 2.3 JSON |
| An attestation (in-toto, Sigstore, DSSE) | the SBOM it carries |

## Upload a file

The project must exist. An upload does not create it.

### With the CLI

```sh
qualor upload-sbom sbom.cdx.json --version 1.4.0 --project-key acme/shop-image
```

| Option | Meaning |
|---|---|
| `--version LABEL` | the version label. Default: the SBOM's own version |
| `--project-key KEY` | the Qualor project. Without it: `QUALOR_PROJECT_KEY`, then `project.key` in `qualor.yml`, then the CI project path (GitLab `CI_PROJECT_PATH`, GitHub `GITHUB_REPOSITORY`, Azure Pipelines `<project>/<repository>`, from `SYSTEM_TEAMPROJECT` and `BUILD_REPOSITORY_NAME`). For an image, set the image's project |
| `--server-url`, `--token-file`, `--ca-file`, `--config` | as in [`qualor scan`](./cli.md#qualor-scan) |

The CLI gzips the file and prints what the server stored. It tries again while the server is busy
([`qualor upload-sbom`](./cli.md#qualor-upload-sbom): for how long, and the exit codes).

### With the API

```sh
gzip -c sbom.cdx.json | curl -fsS -X PUT \
  -H "Authorization: Bearer $QUALOR_TOKEN" \
  -H 'Content-Type: application/vnd.cyclonedx+json' -H 'Content-Encoding: gzip' \
  --data-binary @- \
  "$QUALOR_URL/api/v0/projects/sbom?projectKey=acme/shop-image&version=1.4.0"
```

- Content types: `application/vnd.cyclonedx+json`, `application/spdx+json` and
  `application/json`. Parameters such as `charset` are allowed.
- `Content-Encoding` is `gzip`, or absent for a plain file.
- `version` is optional ([The version label](#the-version-label)).
- The answer is 201 for a new version and 200 for a replaced one:

```json
{"version": {"id": "…", "label": "1.4.0", "source": "sbom"},
 "format": "CycloneDX 1.6", "subject": "ghcr.io/acme/shop 1.4.0",
 "distribution": {"family": "debian", "version": "12.15"},
 "packages": 412, "osPackages": 146,
 "skipped": {"noPurl": 3, "unsupportedType": 0, "duplicate": 7},
 "warnings": [{"code": "SBOM_OS_PACKAGES_UNCHECKED", "message": "…"}],
 "monitoring": {"enabled": true, "recheckQueued": true}}
```

### In the UI

**Upload SBOM** is on the project's **Vulnerabilities** tab and on its **Dependencies** tab. The
Vulnerabilities tab offers it also while monitoring is off or no vulnerability data exists yet.

The dialog takes a file and a version label. It fills the label from the file when it can. It
shows the answer: the counts, what was skipped, the warnings, and whether monitoring is on.

### Who may upload

| Caller | Needs |
|---|---|
| The project's analysis token | nothing more. It cannot upload to another project |
| A user | `project.analyze` on the project |
| A personal token | the same, and the `analysis:write` scope |

A project-token upload is audited with the actor `anonymous` and no token id.
With `audit-log`, an upload is recorded as `project_version.sbom_uploaded`.

## An image SBOM in CI

Make the SBOM of the image you just pushed, then upload it. Use a project of its own, such as
`acme/shop-image` ([Precedence](#precedence)).

```sh
# Trivy
docker run --rm -v "$PWD":/out aquasec/trivy:0.74.0 image \
  --format cyclonedx --output /out/sbom.cdx.json "$IMAGE"

# or Syft
docker run --rm anchore/syft:v1.57.1 "$IMAGE" -o cyclonedx-json > sbom.cdx.json

# upload
docker run --rm -v "$PWD":/work -w /work \
  -e QUALOR_URL -e QUALOR_TOKEN -e QUALOR_PROJECT_KEY=acme/shop-image \
  qualor/scanner:0.16 upload-sbom sbom.cdx.json --version "$IMAGE_TAG"
```

- `QUALOR_TOKEN` is the analysis token of the `shop-image` project.
- Syft can also write SPDX (`-o spdx-json`). Trivy can (`--format spdx-json`). For a large image,
  export CycloneDX: Syft's SPDX fits about 29 000 packages in 64 MiB.

## What is read

Packages are read from components that have a purl.

| Skipped as | Reason |
|---|---|
| `noPurl` | no purl, a purl that does not parse (the warning `SBOM_PURL_INVALID` names the first three), or a purl without a version. Also a name over 512 characters or a version over 256 |
| `unsupportedType` | a component of type `file`, `data`, `machine-learning-model`, `cryptographic-asset`, `device`, `firmware` or `platform`, or a purl type that is not 1 to 32 characters of `a-z`, `0-9` and `-` |
| `duplicate` | the same path, ecosystem, name and version again. The copies are merged |

- Nested CycloneDX components are read to depth 32. Deeper ones are counted and the warning
  `SBOM_NESTING_TOO_DEEP` gives their number.
- The ecosystem of a package is its purl type: `npm`, `pypi`, `maven`, `golang`, `deb` and so on.
- At most 16 licences are kept for a package, each of at most 256 characters.
- **Direct** is known only when the SBOM has a dependency graph. Syft's SPDX has none that Qualor
  reads, so its packages show as unknown.
- The path comes from the Trivy, Syft or CycloneDX evidence fields. SPDX gives none.

Ignored: `vulnerabilities` and VEX sections, services, files, hashes, CPEs and everything else
that is not a package. Qualor finds the vulnerabilities itself.

| Limit | Value |
|---|---|
| File as sent | 32 MiB |
| File after gunzip | 64 MiB |
| Packages after merging duplicates | 50 000 |
| JSON objects and arrays | 2 000 000 |
| JSON keys and values | 6 000 000 |
| Distinct JSON keys | 10 000 |

## OS packages

An image SBOM brings its `deb`, `rpm` and `apk` packages. The server checks them against the
advisories of the image's distribution.

- The distribution comes from the SBOM's operating-system component. Without one, it comes from
  the `distro` qualifiers and namespaces of the packages' purls.
- One SBOM holds one distribution. A file with several (an aggregated SBOM of many images) is
  refused with `SBOM_MULTIPLE_OS`. Split it, one file per image. `debian-12` and `12.15` are one
  distribution.
- Families are those Trivy 0.74.0 detects, under Trivy's names. `rhel` is `redhat`, `almalinux`
  is `alma`, `amzn` is `amazon`, `ol` is `oracle`, and `mariner` is `cbl-mariner`.
- A package is checked by its source package, as Trivy does: `libssl3` through `openssl`. The
  source comes from Trivy's properties, SPDX `sourceInfo` or the purl's `upstream` qualifier. Without
  any, the binary package is used.
- Red Hat-family packages (`rpm`) are checked with their architecture and modularity label,
  from the purl's `arch` and `modularitylabel` qualifiers. Where an rpm repeats with two
  architectures, the first is kept.

An OS package is stored but **not checked** when the SBOM names no distribution, one Trivy does
not know, or a release it cannot check ([Limits](#limits)). The answer then warns
`SBOM_OS_PACKAGES_UNCHECKED` with the count and the reason.

### Packages the re-check gives up

Trivy may not be able to check a package. The re-check then leaves it out as not checked, for that
run only, and carries on. One project's bad data never stops the re-check of other projects. The
next re-check tries again.

The counts are in `lastRecheck.givenUp`, in the answer of `GET /api/v0/system/vulnerability-db`
(instance admins):

| Field | Meaning |
|---|---|
| `invalid` | stored values that fail validation, or would make a key over 2 000 bytes. They never reach Trivy |
| `trivyFailed` | single packages that Trivy failed on |
| `overBudget` | packages of an organisation that had 16 packages fail in the run. They are not retried |
| `unsupported` | distributions, as `<family> <version>` (at most 20), whose release Trivy cannot scan |

## The version label

An upload creates a version, or replaces the one with that label.

- `?version=` is trimmed and has 1 to 100 characters. A blank one is refused.
- Without `?version=`, the label is the SBOM's own version: CycloneDX `metadata.component.version`
  or SPDX `versionInfo`. With neither, the upload is refused with `VERSION_LABEL_INVALID`.
- The version records the upload time from the server's clock, not the SBOM's.
- A second upload with the same label replaces the packages. It keeps the version's pin or
  unsupported mark.
- An upload makes a re-check when [vulnerability monitoring](./vulnerability-database.md) is on for
  the instance and the project.
- The version is tracked by the project's rule, as any version
  ([Versions from an SBOM](./releases.md#versions-from-an-sbom)).
- An upload under a mistyped label: [delete the version](./releases.md#delete-a-version).

### Precedence

A label can come from a tag scan, a branch analysis or an upload. The source that ranks highest
keeps it: **tag scan, then SBOM, then branch label**.

| Event | Result |
|---|---|
| Upload onto a tag-scan version | refused: 409 `VERSION_LABEL_TAKEN` |
| Upload onto a branch-label version | the SBOM takes the version, and its packages are replaced |
| Upload onto an SBOM version | replaced |
| Tag scan onto an SBOM version | the scan takes the version. The analysis warns `VERSION_SBOM_REPLACED` |
| Branch label onto an SBOM version | the SBOM stays |

If you tag-scan a repository and also upload its image SBOM, put the image in a project of its own,
such as `shop-image`, with the same label. Another label in the same project does not work:
`1.4.0-image` is a pre-release, and `1.4.0+image` competes with the tag version.

## Decisions

A [decision](./dependency-vulnerabilities.md#one-decision-a-wide-scope) belongs to a package name
and a vulnerability id. A project-wide decision on `openssl` covers every `openssl` of the project,
whatever its ecosystem or distribution.

## Export

[SBOM export](./dependency-vulnerabilities.md#what-an-sbom-holds) of an SBOM version is made from
the stored packages, not from the uploaded file. For OS packages it writes the distribution, the
source package and a purl with the qualifiers Trivy reads (`distro`, `upstream`, and for rpm `arch`
and `modularitylabel`). Uploading that file again gives the same packages. Paths and **Direct** are
not exported.

## Refusals

Errors are `application/problem+json` with a `code`.

| Status | Code | When |
|---|---|---|
| 401 | `UNAUTHENTICATED` | no valid token |
| 403 | `FORBIDDEN`, `INSUFFICIENT_SCOPE` | the permission or the token scope is missing |
| 404 | `PROJECT_NOT_FOUND` | no such project, or you cannot see it |
| 409 | `VERSION_LABEL_TAKEN` | the label belongs to a tag-scan version. The detail suggests a project of its own |
| 413 | `SBOM_TOO_LARGE` | the file is over a size or JSON limit of [What is read](#what-is-read). The detail says which |
| 415 | `UNSUPPORTED_MEDIA_TYPE`, `UNSUPPORTED_ENCODING` | another content type, or an encoding other than gzip |
| 422 | `VERSION_LABEL_INVALID` | no label, a blank one, or one over 100 characters |
| 422 | `VALIDATION_FAILED` | the label holds a NUL or a lone surrogate |
| 422 | `SBOM_INVALID` | not JSON (SPDX tag-value and XML other than CycloneDX included), neither CycloneDX nor SPDX, or a field has the wrong shape. The detail names the JSON path, or what to export |
| 422 | `SBOM_FORMAT_UNSUPPORTED` | CycloneDX XML, SPDX 3.0, an attestation, or a CycloneDX or SPDX version outside [Formats](#formats). The detail says what to export |
| 422 | `SBOM_TOO_MANY_PACKAGES` | over 50 000 packages |
| 422 | `SBOM_MULTIPLE_OS` | more than one distribution. The message names them |
| 503 | `UPLOADS_BUSY` | the server reads one SBOM at a time, or its upload slots are in use |

On `UPLOADS_BUSY` the CLI tries again ([`qualor upload-sbom`](./cli.md#qualor-upload-sbom)). The UI
asks you to try again.

The server refuses a declared `Content-Length` over 32 MiB before it reads the body. The CLI and
the UI always declare it. A proxy that re-chunks the body hides the length, and a body that grows
over the limit then ends in a reset connection, not a 413.

## Limits

| Limit | What happens |
|---|---|
| OS packages of RHEL 10 and CentOS 10 images are not checked: Trivy 0.74.0 needs the image's content sets, which Qualor does not keep | the upload warns `SBOM_OS_PACKAGES_UNCHECKED` |
| No vulnerability ranges or ids in [the package search](./dependency-vulnerabilities.md#where-used) | search by package |
