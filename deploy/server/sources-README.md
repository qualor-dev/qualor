# qualor/server-sources

This image holds files only: the complete corresponding source of the copyleft components of the
`qualor/server` image with the **same tag**, published next to it. The same files are attached to the Qualor release page of that tag.

`qualor/server` runs on the distroless `cc-debian12` base, whose Debian packages include the GNU
C library (LGPL-2.1), the GCC runtime libraries (GPL-3.0 with the GCC Runtime Library
Exception) and OpenSSL. `debian/` holds the source package of every Debian package installed in
the image, at the installed version: the `.dsc` and the files it lists. The image's other parts
(Node.js with its bundled libraries, the Qualor server and web UI and their npm dependencies) are
under permissive licences; see `/app/NOTICE.md` in `qualor/server`.

`SOURCES.md` lists every file with its SHA-256; `debian-sources.json` is the same list as the
Qualor repository pins it. Check the files with `sha256sum -c SHA256SUMS`.

Get them out of the image (it has no shell and nothing to run):

```sh
docker create --name qualor-sources qualor/server-sources:<tag> none
docker cp qualor-sources:/sources ./qualor-server-sources
docker rm qualor-sources
```
