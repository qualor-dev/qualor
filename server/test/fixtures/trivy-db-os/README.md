# Fixture Trivy database (OS packages)

`db.tar.gz` is a small Trivy database (schema 2) with real Debian, Alpine and Red Hat advisories. The server's real re-check tests of OS packages store it as a dataset (0.16 SBOM). It covers packages of the SBOM samples in `packages/shared/test/sbom-samples/`.

| File             | Content                                                                                                                                          |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `db.tar.gz`      | `db/trivy.db` (1,331,200 bytes) and `db/metadata.json`; 99,593 bytes, SHA-256 `d44e06f9fab8b61f2e7ecf943c32d6d6530cb26d8a0594090b77a2b693d5aec3` |
| `allowlist.json` | what stays of the source database: buckets, and the keys kept in each                                                                            |

## What it holds

| Bucket          | Data source (`data-source` entry) | Kept                                                 | Why                                                                                                                                 |
| --------------- | --------------------------------- | ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `debian 12`     | `debian`, Debian Security Tracker | `openssl`, `shadow`                                  | Source packages of `libssl3`, `openssl`, `login` and `passwd` in `trivy-debian.cdx.json`. Debian keys advisories by source package. |
| `alpine 3.20`   | `alpine`, Alpine Secdb            | `openssl`                                            | Origin of `libcrypto3` and `libssl3` in `trivy-alpine.cdx.json`. Alpine keys advisories by origin.                                  |
| `Red Hat`       | `redhat-oval`, Red Hat OVAL v2    | `openssl-libs`                                       | A package of `trivy-ubi8.cdx.json`. Red Hat keys advisories by binary package.                                                      |
| `Red Hat CPE`   | none (as in the source)           | `repository`: three RHEL 8 content sets              | Trivy's Red Hat detector maps content sets to CPEs and fails without a match.                                                       |
| `data-source`   | –                                 | the entries of `debian 12`, `alpine 3.20`, `Red Hat` | Trivy names the source of each finding from them.                                                                                   |
| `vulnerability` | –                                 | 308 details                                          | The details that the kept advisories reference (a Red Hat RHSA advisory references the CVEs in its `Entries`).                      |

The content sets are `rhel-8-for-x86_64-baseos-source-rpms` (the sample's `ContentSet` property) and `rhel-8-for-x86_64-baseos-rpms` and `rhel-8-for-x86_64-appstream-rpms` (Trivy's defaults for RHEL 8 when a package has none).

Changed from the source:

- The details have no `Title` and no `Description` (ruling R12).
- `VendorSeverity` and `CVSS` keep only `debian`, `alpine`, `redhat-oval` and `nvd`.
- Every other byte of a kept key or value is as the source has it.

## What Trivy finds with it

Trivy 0.74.0 (`trivy sbom <file> --format json --list-all-pkgs --offline-scan --skip-db-update --skip-java-db-update`), with the extracted archive as `<cache-dir>/db/`:

| Sample                  | Findings | Packages                                                                       |
| ----------------------- | -------- | ------------------------------------------------------------------------------ |
| `trivy-debian.cdx.json` | 8        | `libssl3` and `openssl` 1 each (`CVE-2025-27587`); `login` and `passwd` 3 each |
| `trivy-alpine.cdx.json` | 44       | `libcrypto3` and `libssl3` 22 each                                             |
| `trivy-ubi8.cdx.json`   | 31       | `openssl-libs` 31, with or without the `ContentSet` properties                 |

These are exactly the findings of the full source database on the same packages (ID, fixed version, status and severity).

## Source and remake

| Item             | Value                                                                                                              |
| ---------------- | ------------------------------------------------------------------------------------------------------------------ |
| Source           | `ghcr.io/aquasecurity/trivy-db:2`, layer `sha256:7d0ae3ee84ece1ecae274d9ac146c7241ae483c981f68aeb3f4953f6c2fbc6b0` |
| Snapshot created | `2026-09-25T06:43:29Z` (`TRIVY_DB_CREATED`)                                                                        |
| `metadata.json`  | copied unchanged: `UpdatedAt` `2026-09-25T06:36:11.019457553Z`                                                     |
| Made             | 2026-11-16, by `tools/analyzers/make-trivy-db-fixture.sh`                                                          |

The script downloads the layer that `TRIVY_DB_DIGEST` in `tools/analyzers/install.sh` pins and checks its SHA-256. Then `trivy-db-filter -fixture allowlist.json` cuts the database down (`tools/analyzers/go-tools/trivy-db-filter`). The same layer, allowlist and filter give the same bytes. It needs install-go.sh's Go, so it runs in the analyzers toolbox:

```sh
docker run --rm -v "$PWD/tools/analyzers:/repo/tools/analyzers:ro" \
  -v "$PWD/server/test/fixtures/trivy-db-os:/repo/server/test/fixtures/trivy-db-os" \
  qualor-analyzers sh /repo/tools/analyzers/make-trivy-db-fixture.sh
```

After `pnpm trivy-db:pin` moves the pin, the script cuts the new snapshot. Update this README with it: `tools/analyzers/trivy-db-fixture.test.ts` checks that it names the archive's `UpdatedAt`.

## Attribution

The fixture is a modified extract of the advisory data below: filtered to the packages above, without titles, descriptions and other sources' severities. It keeps advisory ids, severities, fixed versions, statuses and package keys. The data comes as is, without warranty, as its licences say.

| Source                                                           | Holder             | Licence                                                       | Original                                                                                |
| ---------------------------------------------------------------- | ------------------ | ------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| Debian Security Tracker                                          | the Debian project | none stated                                                   | https://salsa.debian.org/security-tracker-team/security-tracker                         |
| Alpine secdb                                                     | Alpine Linux       | CC BY-SA 4.0, https://creativecommons.org/licenses/by-sa/4.0/ | https://secdb.alpinelinux.org/ (licence: https://secdb.alpinelinux.org/license.txt)     |
| Red Hat Security Data (OVAL v2, CPE map)                         | Red Hat, Inc.      | CC BY 4.0, https://creativecommons.org/licenses/by/4.0/       | https://access.redhat.com/security/data , https://www.redhat.com/security/data/oval/v2/ |
| NVD (the details' severity, CVSS, CWE ids, references and dates) | NIST               | public domain                                                 | https://nvd.nist.gov/                                                                   |

- The Alpine secdb data in this fixture is shared under CC BY-SA 4.0, with no other terms.
- This product uses data from the NVD API but is not endorsed or certified by the NVD.
- The database was built by Aqua Security's trivy-db (https://github.com/aquasecurity/trivy-db, Apache-2.0).
