# Local qualor-rules tarball (not committed)

`tools/analyzers/install-qualor-rules.sh` takes `qualor-rules-<version>.tar.gz` from this directory
when it is here, checked against `QUALOR_RULES_SHA256` in `tools/analyzers/install.sh`; otherwise
it downloads the pinned release (`QUALOR_RULES_URL` in `install.sh`). Copy a release built in the
qualor-rules repository (`npm run release`) here to build images without the download, or to try
a pack before its release is published. The pack is source-available (PolyForm Shield 1.0.0), not
MIT: `.gitignore` keeps everything in this directory but this file out of the repository.
