# qualor/server: third-party notices

The `qualor/server` image runs the Qualor server and web UI (MIT, `/app/LICENSE`) on Node.js,
on the distroless base `gcr.io/distroless/cc-debian12` (pinned by digest in
`deploy/server/Dockerfile`), and carries the Qualor Enterprise plugin, which is not MIT (below).
Its parts are under their own licences:

| Component                                                                                         | Version                   | Licence                                                                                                                       | Source                                            |
| ------------------------------------------------------------------------------------------------- | ------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| Qualor server and web UI                                                                          | this release              | MIT (`/app/LICENSE`)                                                                                                          | this repository                                   |
| Qualor Enterprise (`/app/enterprise`), inert without a licence key                                | this release              | source-available, Qualor Enterprise Licence (`/app/enterprise/LICENSE`)                                                       | this repository, `enterprise/`                    |
| Noto Sans Regular and Bold (`/app/enterprise/fonts`), embedded in the compliance report PDF       | 2.015                     | SIL Open Font License 1.1 (`/app/enterprise/fonts/OFL.txt`)                                                                   | https://github.com/notofonts/latin-greek-cyrillic |
| npm packages of the server and the web UI                                                         | as `pnpm-lock.yaml` locks | MIT, MIT-0, ISC, BSD-3-Clause, Apache-2.0, 0BSD, BlueOak-1.0.0, CC-BY-4.0 (server: each licence file in `/app/node_modules/`) | https://www.npmjs.com/                            |
| SPDX License List identifiers (`spdx-ids.json`, in the Qualor packages)                           | 3.29.0                    | CC0-1.0                                                                                                                       | https://github.com/spdx/license-list-data         |
| PostgreSQL (`/opt/postgresql`), the embedded database, with its `citext` and `pg_trgm` extensions | 18.6                      | PostgreSQL Licence (`/opt/postgresql/COPYRIGHT`)                                                                              | https://ftp.postgresql.org/pub/source/v18.6/      |
| Node.js (`/usr/local/bin/node`)                                                                   | 22.23.4                   | MIT, with the bundled libraries below (`/app/NODE-LICENSE.txt`)                                                               | https://github.com/nodejs/node/tree/v22.23.4      |
| Debian packages of the base (below)                                                               | bookworm, as installed    | per package, `/usr/share/doc/<package>/copyright`                                                                             | `qualor/server-sources:<same tag>`                |

Named individually, because they read the untrusted OIDC and SAML bytes of single sign-on: `openid-client` 6.8.8 (Filip Skokan), `jose` 6.2.12, `oauth4webapi` 3.8.8, `@node-saml/node-saml`
5.1.0, `xml-crypto` 6.3.2, `@xmldom/xmldom` 0.8.15, `xml-encryption` 3.1.0, `xml2js` 0.6.2,
`xmlbuilder` 15.1.1 and 11.0.1, `xpath` 0.0.32–0.0.34, `debug` 4.4.3, `ms` 2.1.3, `escape-html` 1.0.3
and `@xmldom/is-dom-node` 1.0.1 are each MIT; `sax` 1.6.1 is BlueOak-1.0.0. Each is already covered by
the blanket npm-packages row above; this paragraph only names them.

| Component              | Version        | Licence       | Source                                             |
| ---------------------- | -------------- | ------------- | -------------------------------------------------- |
| `openid-client`        | 6.8.8          | MIT           | https://www.npmjs.com/package/openid-client        |
| `jose`                 | 6.2.12         | MIT           | https://www.npmjs.com/package/jose                 |
| `oauth4webapi`         | 3.8.8          | MIT           | https://www.npmjs.com/package/oauth4webapi         |
| `@node-saml/node-saml` | 5.1.0          | MIT           | https://www.npmjs.com/package/@node-saml/node-saml |
| `xml-crypto`           | 6.3.2          | MIT           | https://www.npmjs.com/package/xml-crypto           |
| `@xmldom/xmldom`       | 0.8.15         | MIT           | https://www.npmjs.com/package/@xmldom/xmldom       |
| `xml-encryption`       | 3.1.0          | MIT           | https://www.npmjs.com/package/xml-encryption       |
| `xml2js`               | 0.6.2          | MIT           | https://www.npmjs.com/package/xml2js               |
| `xmlbuilder`           | 15.1.1, 11.0.1 | MIT           | https://www.npmjs.com/package/xmlbuilder           |
| `xpath`                | 0.0.32–0.0.34  | MIT           | https://www.npmjs.com/package/xpath                |
| `sax`                  | 1.6.1          | BlueOak-1.0.0 | https://www.npmjs.com/package/sax                  |
| `debug`                | 4.4.3          | MIT           | https://www.npmjs.com/package/debug                |
| `ms`                   | 2.1.3          | MIT           | https://www.npmjs.com/package/ms                   |
| `escape-html`          | 1.0.3          | MIT           | https://www.npmjs.com/package/escape-html          |
| `@xmldom/is-dom-node`  | 1.0.1          | MIT           | https://www.npmjs.com/package/@xmldom/is-dom-node  |

Named individually, because the enterprise plugin writes the compliance report PDF with them:
`pdfkit` 0.20.2 and the packages it loads. They are covered by the blanket npm-packages row above.
`fontkit`, `brotli` and `dfa` ship no licence file of their own; each declares MIT in its
`package.json`, by Devon Govett, under the same MIT terms as `pdfkit`'s `LICENSE`.

| Component            | Version      | Licence    | Source                                           |
| -------------------- | ------------ | ---------- | ------------------------------------------------ |
| `pdfkit`             | 0.20.2       | MIT        | https://www.npmjs.com/package/pdfkit             |
| `fontkit`            | 2.0.4        | MIT        | https://www.npmjs.com/package/fontkit            |
| `linebreak`          | 1.1.0        | MIT        | https://www.npmjs.com/package/linebreak          |
| `png-js`             | 2.0.0        | MIT        | https://www.npmjs.com/package/png-js             |
| `fflate`             | 0.8.3        | MIT        | https://www.npmjs.com/package/fflate             |
| `@noble/hashes`      | 1.8.0        | MIT        | https://www.npmjs.com/package/@noble/hashes      |
| `@noble/ciphers`     | 1.3.0        | MIT        | https://www.npmjs.com/package/@noble/ciphers     |
| `@swc/helpers`       | 0.5.23       | Apache-2.0 | https://www.npmjs.com/package/@swc/helpers       |
| `tslib`              | 2.8.1        | 0BSD       | https://www.npmjs.com/package/tslib              |
| `brotli`             | 1.3.3        | MIT        | https://www.npmjs.com/package/brotli             |
| `clone`              | 2.1.2        | MIT        | https://www.npmjs.com/package/clone              |
| `dfa`                | 1.2.0        | MIT        | https://www.npmjs.com/package/dfa                |
| `fast-deep-equal`    | 3.1.3        | MIT        | https://www.npmjs.com/package/fast-deep-equal    |
| `restructure`        | 3.0.2        | MIT        | https://www.npmjs.com/package/restructure        |
| `tiny-inflate`       | 1.0.3        | MIT        | https://www.npmjs.com/package/tiny-inflate       |
| `unicode-properties` | 1.4.1        | MIT        | https://www.npmjs.com/package/unicode-properties |
| `unicode-trie`       | 2.0.0        | MIT        | https://www.npmjs.com/package/unicode-trie       |
| `base64-js`          | 0.0.8, 1.5.1 | MIT        | https://www.npmjs.com/package/base64-js          |
| `pako`               | 0.2.9        | MIT        | https://www.npmjs.com/package/pako               |

The compliance report PDF embeds subsets of Noto Sans Regular and Bold (Copyright 2022 The Noto
Project Authors), under the SIL Open Font License 1.1, whose text is `/app/enterprise/fonts/OFL.txt`.

The compliance reports map findings to security standards. The enterprise plugin carries, for each,
the category ids and titles and the CWE ids each category lists:

- **OWASP Top 10 2021 and 2025, and the OWASP Application Security Verification Standard 4.0.3**,
  by the OWASP Foundation (https://owasp.org/Top10/, https://github.com/OWASP/ASVS), licensed under
  Creative Commons Attribution-ShareAlike 4.0 (CC BY-SA 4.0,
  https://creativecommons.org/licenses/by-sa/4.0/). The data is extracted from the published lists
  (the ASVS requirements grouped by chapter) and is shared under the same licence.
- **CWE Top 25 2025** and the CWE ids, from MITRE's Common Weakness Enumeration
  (https://cwe.mitre.org/), used under the CWE Terms of Use
  (https://cwe.mitre.org/about/termsofuse.html). CWE™ is a trademark of The MITRE Corporation.
  Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks
  of The MITRE Corporation.

The enterprise plugin is not MIT. The server loads it only while a valid licence key is
configured, including the key's 14-day grace period after it expires; without one the server
never reads the file and runs as the community edition (docs/guide/enterprise.md). Running,
mirroring or redistributing this image with the plugin unused needs no subscription; production
use of the plugin needs a subscription or a trial, and is limited to what the key enables: its
features and its validity, grace period included. A trial key has no grace period
(`/app/enterprise/LICENSE`). Everything else of Qualor in this image is MIT.

Node.js bundles, in its binary: V8, libuv, ICU (Unicode-3.0), OpenSSL (Apache-2.0), c-ares,
llhttp, nghttp2, nghttp3, ngtcp2, zlib, brotli, zstd, simdjson, simdutf, ada, uvwasi, acorn,
undici, cjs-module-lexer, amaro/swc, SipHash, HdrHistogram and smaller parts, all under
permissive licences (MIT, BSD, Apache-2.0, ISC, Unicode-3.0, zlib); `NODE-LICENSE.txt` has each
text. None of them is copyleft. npm and Corepack are not in this image.

PostgreSQL is built from its release tarball without ICU, readline, zlib or OpenSSL, so it links
only glibc; its licence is permissive, so it has no source image entry.

The Debian packages installed in the image, by source package (`/app/SOURCES.md` lists the exact
versions and the SHA-256 of every source file):

- glibc (`libc6`): LGPL-2.1-or-later, with parts under other free licences;
- gcc-12 (`libgcc-s1`, `libgomp1`, `libstdc++6`, `gcc-12-base`): GPL-3.0-or-later with the GCC
  Runtime Library Exception;
- openssl (`libssl3`): Apache-2.0;
- base-files, ca-certificates, media-types, netbase, tzdata: GPL-2.0-or-later, MPL-2.0 (the CA
  certificates), public domain and other free licences.

## Source code

The complete corresponding source of the copyleft components of this image, the source package
of every Debian package above at its installed version (the `.dsc` and the files it lists,
checked against Debian's Sources index), is published next to it in the same registry as the
image `qualor/server-sources:<same tag>` (in its `/sources/` directory) and as files attached to
the Qualor release page of the same tag. `/app/SOURCES.md` in this image is its index.

As a courtesy, and not as the way we meet the licences: for at least three years after we last
distribute this image, we will also give any third party a copy of that source on request, for
no more than the cost of physically performing the distribution: open an issue in the Qualor
repository (https://github.com/qualor-dev/qualor) or write to the maintainers listed there.
Debian's own copies are at https://sources.debian.org/ and https://snapshot.debian.org/.
