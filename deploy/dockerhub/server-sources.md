# qualor/server-sources

Short description: Corresponding source of the copyleft components of qualor/server, same tag.

## Overview

This image holds files only: the complete corresponding source of the copyleft components of
[`qualor/server`](https://hub.docker.com/r/qualor/server) with the **same tag**. Every release of
`qualor/server:<tag>` publishes `qualor/server-sources:<tag>` next to it, and the same files are
attached to the release of that tag at <https://github.com/qualor-dev/qualor>. It is a `scratch`
image with the files in `/sources/`, about 120 MB.

### Contents

`qualor/server` runs on the distroless `cc-debian12` base, whose Debian packages include the GNU C
library (LGPL-2.1), the GCC runtime libraries (GPL-3.0 with the GCC Runtime Library Exception) and
OpenSSL. `/sources/debian/` holds the source package of every Debian package installed in that
image, at the installed version: the `.dsc` and the files it lists. The rest of `qualor/server`
(Node.js with its bundled libraries, the Qualor server and web UI and their npm dependencies) is
under permissive licences; see `/app/NOTICE.md` in `qualor/server`.

`SOURCES.md` lists every file with its SHA-256; `debian-sources.json` is the manifest the
repository pins. Check the files with `sha256sum -c SHA256SUMS`.

### Get the files

The image has no shell and nothing to run; copy the files out:

```sh
docker create --name qualor-sources qualor/server-sources:<tag> none
docker cp qualor-sources:/sources ./qualor-server-sources
docker rm qualor-sources
```
