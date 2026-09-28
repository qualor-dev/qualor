# qualor/server: third-party notices

The `qualor/server` image runs the Qualor server and web UI (MIT, `/app/LICENSE`) on Node.js,
on the distroless base `gcr.io/distroless/cc-debian12` (pinned by digest in
`deploy/server/Dockerfile`), and carries the Qualor Enterprise plugin, which is not MIT (below).
Its parts are under their own licences:

| Component                                                                                         | Version                   | Licence                                                                                                                | Source                                       |
| ------------------------------------------------------------------------------------------------- | ------------------------- | ---------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| Qualor server and web UI                                                                          | this release              | MIT (`/app/LICENSE`)                                                                                                   | this repository                              |
| Qualor Enterprise (`/app/enterprise`), inert without a licence key                                | this release              | source-available, Qualor Enterprise Licence (`/app/enterprise/LICENSE`)                                                | this repository, `enterprise/`               |
| npm packages of the server and the web UI                                                         | as `pnpm-lock.yaml` locks | MIT, ISC, BSD-3-Clause, Apache-2.0, 0BSD, BlueOak-1.0.0, CC-BY-4.0 (server: each licence file in `/app/node_modules/`) | https://www.npmjs.com/                       |
| PostgreSQL (`/opt/postgresql`), the embedded database, with its `citext` and `pg_trgm` extensions | 18.6                      | PostgreSQL Licence (`/opt/postgresql/COPYRIGHT`)                                                                       | https://ftp.postgresql.org/pub/source/v18.6/ |
| Node.js (`/usr/local/bin/node`)                                                                   | 22.23.2                   | MIT, with the bundled libraries below (`/app/NODE-LICENSE.txt`)                                                        | https://github.com/nodejs/node/tree/v22.23.2 |
| Debian packages of the base (below)                                                               | bookworm, as installed    | per package, `/usr/share/doc/<package>/copyright`                                                                      | `qualor/server-sources:<same tag>`           |

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

The enterprise plugin is not MIT. The server loads it only while a valid licence key is
configured, including the key's 14-day grace period after it expires; without one the server
never reads the file and runs as the community edition (docs/guide/enterprise.md). Running,
mirroring or redistributing this image with the plugin unused needs no subscription; production
use of the plugin does, and is limited to what the key enables: its features and its validity,
grace period included (`/app/enterprise/LICENSE`). Everything else of Qualor in this image is MIT.

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
