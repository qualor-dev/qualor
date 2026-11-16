# SBOM samples

Real SBOMs (CycloneDX and SPDX) from Trivy, Syft and cdxgen, trimmed where noted, plus three hand-written files. The SBOM parser tests (`src/sbom/*.test.ts`) and later tests (the re-check against Trivy, the upload) read them.

All files were made on 2026-11-16 with Docker 29.8.2. Every image is pinned by digest. The JSON files are pretty-printed by Prettier; their content is what the tool wrote, apart from the trimming below.

## Tools

| Tool   | Version | Image                                                                                                                                                          |
| ------ | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Trivy  | 0.74.0  | `qualor/scanner:0.16-iac-dev`, local build, image ID `sha256:90cc67e07e355ccadd61b024b03211ea81f4818cad76a2ed0c6f7e41c4dec714`, binary `/opt/qualor/bin/trivy` |
| Syft   | 1.57.1  | `anchore/syft:v1.57.1@sha256:03215d0e98b661d0ecbc8575dbc14d65be1743b5de5df6410aecb7e80f95b060`                                                                 |
| cdxgen | 13.8.0  | `ghcr.io/cdxgen/cdxgen-node:13.8.0@sha256:e04df54dc1b102fe19262a8ace59d52712221fdf138e96b8361f3d48ae768dfb`                                                    |

cdxgen moved to the `cdxgen` organisation: `ghcr.io/cyclonedx/cdxgen` stops at 13.3.0. `cdxgen-node` is the project's Node.js image of the same release.

## Sources

| Name         | Reference                                                                                                                  | OS            |
| ------------ | -------------------------------------------------------------------------------------------------------------------------- | ------------- |
| Debian image | `buildpack-deps:bookworm-curl@sha256:58021c2a0204361b62a23d2e0244d144d74c29af2d678e2a1f7e6611885d6949`                     | Debian 12.15  |
| Alpine image | `alpine:3.20.3@sha256:1e42bbe2508154c9126d48c2b8a75420c3544343bf86fd041fb7527e017a4b4a`                                    | Alpine 3.20.3 |
| UBI 8 image  | `registry.access.redhat.com/ubi8/ubi-minimal:8.10@sha256:b3314c5f8d009ee6df04ead732bca6d3eaf011750185e348f55fce2678fb30d0` | Red Hat 8.10  |
| Node project | a copy of `fixtures/deps-vulnerable/web`, extended (below)                                                                 | none          |

- The Debian image is `buildpack-deps:bookworm-curl`, not `debian:12.15`. `debian:12.15` (`sha256:268fb24c39bca92d326dd83ea3abebe4a3f7751c804ffef23bb6d857dd343ff8`) holds no `libssl3` or `openssl`; `bookworm-curl` is the same Debian 12.15 base plus curl and OpenSSL.
- The Node project adds `@babel/code-frame` 7.26.2 to the fixture's `minimist` 1.2.5, for a scoped package and three transitive ones. It was locked with `npm install --package-lock-only --ignore-scripts --save-exact @babel/code-frame@7.26.2` (npm 11.19.1, registry.npmjs.org). It also holds an `index.js` that uses both, which gives cdxgen its `evidence.occurrences`:

  ```js
  const minimist = require('minimist');
  const { codeFrameColumns } = require('@babel/code-frame');

  const args = minimist(process.argv.slice(2));
  console.log(codeFrameColumns(String(args.source ?? ''), { start: { line: 1 } }));
  ```

## Files

| File                           | Tool                | Source                     | Format             | Trimmed                                                     |
| ------------------------------ | ------------------- | -------------------------- | ------------------ | ----------------------------------------------------------- |
| `trivy-debian.cdx.json`        | Trivy               | Debian image               | CycloneDX 1.7      | to the 22 Debian packages below                             |
| `syft-debian.cdx.json`         | Syft                | Debian image               | CycloneDX 1.6      | to the same 22 packages; `file` components dropped          |
| `trivy-alpine.cdx.json`        | Trivy               | Alpine image               | CycloneDX 1.7      | no (14 packages)                                            |
| `trivy-ubi8.cdx.json`          | Trivy               | UBI 8 image                | CycloneDX 1.7      | to the 21 Red Hat packages below                            |
| `trivy-ubi8-outdated.cdx.json` | derived             | `trivy-ubi8.cdx.json`      | CycloneDX 1.7      | no; `openssl-libs` made older (below)                       |
| `syft-ubi8.cdx.json`           | Syft                | UBI 8 image                | CycloneDX 1.5      | to the same 21 packages; `file` components dropped          |
| `syft-node.cdx-1.4.json`       | Syft                | Node project               | CycloneDX 1.4      | no                                                          |
| `trivy-debian.spdx.json`       | Trivy               | Debian image               | SPDX 2.3           | to the same 22 packages, the OS package and the image root  |
| `syft-debian.spdx.json`        | Syft                | Debian image               | SPDX 2.3           | to the same 22 packages and the image root; `files` dropped |
| `syft-node.spdx-2.2.json`      | Syft                | Node project               | SPDX 2.2           | no                                                          |
| `spdx-3.0.json`                | Syft                | Node project               | SPDX 3.0.1 JSON-LD | no                                                          |
| `spdx.tag-value.spdx`          | Syft                | Node project               | SPDX 2.3 tag-value | no (byte for byte)                                          |
| `cyclonedx.xml`                | Syft                | Node project               | CycloneDX 1.7 XML  | no (byte for byte)                                          |
| `cdxgen-node.cdx-1.7.json`     | cdxgen              | Node project               | CycloneDX 1.7      | no                                                          |
| `cdxgen-node.cdx-1.5.json`     | cdxgen `convert.js` | `cdxgen-node.cdx-1.7.json` | CycloneDX 1.5      | no                                                          |
| `vendor-nested.cdx.json`       | by hand             | none                       | CycloneDX 1.6      | not applicable                                              |
| `in-toto.json`                 | by hand             | none                       | DSSE envelope      | not applicable                                              |

SPDX trimming keeps the packages of the same list, the OS package (Trivy), the root package and the relationships whose two ends are kept, plus the `hasExtractedLicensingInfos` that the kept packages reference. Syft's `files` and every relationship to a file are dropped. The SPDX files were pretty-printed by Prettier like the others.

Trimming of the CycloneDX files keeps `metadata`, the `operating-system` component and the named `library` components. It keeps the `dependencies` entries of the kept `bom-ref`s and of the subject, with `dependsOn` limited to kept `bom-ref`s.

- **Debian, 22 packages** (both files): `libssl3`, `openssl`, `login`, `passwd`, `libc6`, `libc-bin`, `curl`, `libcurl4`, `zlib1g`, `bash`, `bsdutils`, `util-linux`, `libcap2`, `e2fsprogs`, `libsystemd0`, `libudev1`, `perl-base`, `tar`, `coreutils`, `libgnutls30`, `gpgv`, `ca-certificates`. The SPDX files of the same image use the same digest and list.
- **Red Hat, 21 packages** (both files): `openssl-libs`, `gmp`, `curl`, `libcurl`, `glibc`, `glibc-common`, `bash`, `systemd-libs`, `libxml2`, `sqlite-libs`, `krb5-libs`, `xz-libs`, `ncurses-libs`, `libstdc++`, `rpm`, `rpm-libs`, `sed`, `tzdata`, `ca-certificates`, `redhat-release`, `libgcc`. The two `gpg-pubkey` entries are left out: Trivy writes no source package for them.

What the samples show:

- Trivy writes the Debian epoch as an `epoch` qualifier (`pkg:deb/debian/login@4.13%2Bdfsg1-1%2Bdeb12u2?…&epoch=1`) and the source in `aquasecurity:trivy:Src*` properties. Syft writes it in the version (`login@1%3A4.13…`) and the source as `upstream`, with a version only when it differs (`upstream=bash%405.2.15-2`).
- Syft names the Red Hat OS `rhel` (`distro=rhel-8.10`, namespace `redhat`); Trivy names it `redhat`. Both write rpm epochs as `epoch=1`; Syft adds `upstream=<name>-<version>-<release>.src.rpm`.
- Trivy's SPDX root is the `SPDXRef-ContainerImage-…` package (with a `pkg:oci` purl), described by the document; the OS is a `SPDXRef-OperatingSystem-…` package that `CONTAINS` the packages, and `sourceInfo` is `built package from: <name> <version>` with the epoch in the version. Syft's root is `SPDXRef-DocumentRoot-Image-…`; it writes no OS package, every purl carries `distro=debian-12.15` and `upstream`, and it links packages with `DEPENDENCY_OF` (never `DEPENDS_ON`).
- Licences differ by format: CycloneDX lists the terms one by one, SPDX writes one expression, with `LicenseRef-…` ids that `hasExtractedLicensingInfos` names.
- `trivy-ubi8.cdx.json` keeps Trivy's `aquasecurity:trivy:ContentSet` properties, which Trivy's Red Hat detection reads.

## Commands

`$OUT` is a scratch folder mounted as `/out`; `$SRC` the Node project mounted as `/src` or `/app`.

```sh
# Trivy, one per image (Debian, Alpine, UBI 8)
docker run --rm --entrypoint /opt/qualor/bin/trivy -v "$OUT:/out" qualor/scanner:0.16-iac-dev \
  image --skip-version-check --format cyclonedx --output /out/trivy-<name>.cdx.json \
  --cache-dir /tmp/trivy-cache --platform linux/amd64 --image-src remote <image reference>

# Syft, images
docker run --rm -e SYFT_CHECK_FOR_APP_UPDATE=false -v "$OUT:/out" <syft image> \
  scan registry:<debian image reference> --platform linux/amd64 -o cyclonedx-json@1.6=/out/syft-debian.cdx.json
docker run --rm -e SYFT_CHECK_FOR_APP_UPDATE=false -v "$OUT:/out" <syft image> \
  scan registry:<ubi8 image reference> --platform linux/amd64 -o cyclonedx-json@1.5=/out/syft-ubi8.cdx.json

# Trivy and Syft, SPDX of the Debian image (then trimmed)
docker run --rm --entrypoint /opt/qualor/bin/trivy -v "$OUT:/out" qualor/scanner:0.16-iac-dev \
  image --skip-version-check --format spdx-json --output /out/trivy-debian.spdx.json \
  --cache-dir /tmp/trivy-cache --platform linux/amd64 --image-src remote <debian image reference>
docker run --rm -e SYFT_CHECK_FOR_APP_UPDATE=false -v "$OUT:/out" <syft image> \
  scan registry:<debian image reference> --platform linux/amd64 -o spdx-json@2.3=/out/syft-debian.spdx.json

# Syft, Node project (SPDX 2.2, SPDX 3.0 and tag-value, the project mounted read-only, no network)
docker run --rm --network none -e SYFT_CHECK_FOR_APP_UPDATE=false -v "$SRC:/src:ro" -v "$OUT:/out" <syft image> \
  scan dir:/src -o spdx-json@2.2=/out/syft-node.spdx-2.2.json -o spdx-json@3.0=/out/spdx-3.0.json -o spdx-tag-value=/out/spdx.tag-value.spdx

# Syft, Node project
docker run --rm --network none -e SYFT_CHECK_FOR_APP_UPDATE=false -v "$SRC:/src:ro" -v "$OUT:/out" <syft image> \
  scan dir:/src -o cyclonedx-json@1.4=/out/syft-node.cdx-1.4.json -o cyclonedx-xml=/out/cyclonedx.xml

# cdxgen, Node project; 1.5 is not a generation target of 13.8.0, so it is converted
docker run --rm --network none -v "$SRC:/app" -v "$OUT:/out" <cdxgen image> \
  -t js --evidence --no-install-deps --no-banner --json-pretty -o /out/cdxgen-node.cdx-1.7.json /app
docker run --rm --network none -v "$OUT:/out" --entrypoint node <cdxgen image> \
  /opt/cdxgen/bin/convert.js -i /out/cdxgen-node.cdx-1.7.json --to 1.5 -o /out/cdxgen-node.cdx-1.5.json --json-pretty
```

## Derived file

`trivy-ubi8-outdated.cdx.json` is `trivy-ubi8.cdx.json` with an older `openssl-libs`, so that fixed Red Hat advisories apply. Those advisories list their arches, and Trivy matches them only by the package's arch. The server's real test (`server/test/sbom-os-matching.db.test.ts`, case (f)) reads it.

Only the `openssl-libs` component and the references to it change: `1.1.1k-18.el8_6` becomes `1.1.1k-5.el8_5`, a real earlier build of RHEL 8. Eleven lines differ:

| Where                                                                       | Before                                                                               | After                                |
| --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | ------------------------------------ |
| `version`                                                                   | `1:1.1.1k-18.el8_6`                                                                  | `1:1.1.1k-5.el8_5`                   |
| `purl` and `bom-ref`                                                        | `pkg:rpm/redhat/openssl-libs@1.1.1k-18.el8_6?arch=x86_64&distro=redhat-8.10&epoch=1` | the same with `@1.1.1k-5.el8_5`      |
| property `aquasecurity:trivy:PkgID`                                         | `openssl-libs@1.1.1k-18.el8_6.x86_64`                                                | `openssl-libs@1.1.1k-5.el8_5.x86_64` |
| property `aquasecurity:trivy:SrcRelease`                                    | `18.el8_6`                                                                           | `5.el8_5`                            |
| the six `dependencies` references to the purl (one `ref`, five `dependsOn`) | old purl                                                                             | new purl                             |

The `hashes`, licences, layer properties and `SrcVersion` (`1.1.1k`) and `SrcEpoch` (`1`) are kept. The file was written with `JSON.stringify(doc, null, 2)` and then Prettier.

## Hand-written files

- `vendor-nested.cdx.json`: a vendor appliance whose packages sit in nested `components`, three levels deep (application, library, library). Seven packages: two `generic`, three `maven`, two `npm`.
- `in-toto.json`: a DSSE envelope (`payloadType: application/vnd.in-toto+json`) per the in-toto attestation framework (https://github.com/in-toto/attestation, Statement v1). The base64 `payload` is a Statement with `predicateType: https://cyclonedx.org/bom` and a one-package CycloneDX predicate. The signature is a placeholder, not a real one.
