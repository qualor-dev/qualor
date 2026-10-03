# Local qualor-rules tarball (not committed)

`tools/analyzers/install-qualor-rules.sh` takes `qualor-rules-<version>.tar.gz` from this directory
when it is here, checked against `QUALOR_RULES_SHA256` in `tools/analyzers/install.sh`. Until the
pack is published, copy a release built in the qualor-rules repository (`npm run release`) here
to build images that carry Qualor's security rules; once the pack is published (`QUALOR_RULES_URL`
in `install.sh`), release builds require it. The pack is source-available (PolyForm Shield 1.0.0),
not MIT: `.gitignore` keeps everything in this directory but this file out of the repository.
