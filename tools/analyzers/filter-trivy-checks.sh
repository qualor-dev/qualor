#!/bin/sh
# Filters the trivy-checks bundle that tools/analyzers/install.sh unpacked into
# $QUALOR_TOOLS/share/trivy-iac/policy/content (default /opt/qualor; 0.16 IaC, Q-L180): the Kubernetes
# cluster checks (METADATA id `KCV-…`, which quote CIS Benchmark text) and the whole `specs/`
# directory (the CIS compliance specs) go. Then it checks the result. An optional argument names
# the bundle directory (the one that holds `policies/`), for tests. A missing bundle or a failed
# check fails the script: the bundle is never left unfiltered.
#   sh tools/analyzers/filter-trivy-checks.sh [bundle-dir]
set -eu

PREFIX="${QUALOR_TOOLS:-/opt/qualor}"
DIR="${1:-$PREFIX/share/trivy-iac/policy/content}"
[ -d "$DIR/policies" ] || { echo "no trivy-checks bundle at $DIR: run install.sh first" >&2; exit 1; }

# Only the `id:` line of a check's METADATA block matches: `long_id:` and the aliases do not.
KCV='^#[[:space:]]+id:[[:space:]]*KCV-'

# grep exits 1 for "no match" (fine) and 2 or more for an error (the bundle is then unknown).
status=0
found=$(grep -rlE --include='*.rego' "$KCV" "$DIR") || status=$?
[ "$status" -le 1 ] || { echo "grep failed while filtering the trivy-checks bundle: $DIR" >&2; exit 1; }
if [ -n "$found" ]; then
  printf '%s\n' "$found" | while IFS= read -r file; do rm -f -- "$file"; done
fi
rm -rf "$DIR/specs"

status=0
grep -rqE --include='*.rego' "$KCV" "$DIR" || status=$?
[ "$status" -le 1 ] || { echo "grep failed while checking the trivy-checks bundle: $DIR" >&2; exit 1; }
if [ -d "$DIR/specs" ] || [ "$status" -eq 0 ]; then
  echo "the filtered trivy-checks bundle still holds KCV checks or specs: $DIR" >&2
  exit 1
fi
