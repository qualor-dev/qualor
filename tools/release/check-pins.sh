#!/bin/sh
# Re-checks the pins of install-tools.sh and bun-runtimes.json independently of the toolbox
# (release.md §9). Run it when a pin changes, in a throwaway container that is removed at the end:
#   docker run --rm -v "$PWD/tools/release:/pins:ro" \
#     python:3.13-slim@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b \
#     sh /pins/check-pins.sh
# sigstore-python and its dependencies are installed from check-pins.requirements.txt, every one
# pinned by version and hash (pip-compile --generate-hashes of sigstore==4.5.0). GnuPG comes from
# the image's own Debian archive, whose signatures apt checks.
set -eu
pip install -q --root-user-action=ignore --disable-pip-version-check --no-cache-dir \
  --require-hashes --no-deps -r /pins/check-pins.requirements.txt
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends gnupg >/dev/null
python -m sigstore --version
gpg --version | head -n 1
python /pins/check-pins.py
