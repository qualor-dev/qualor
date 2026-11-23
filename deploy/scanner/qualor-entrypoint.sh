#!/bin/sh
# Entry point of the qualor/scanner image. The analyzers run repository-controlled code (an
# ESLint config, a PMD ruleset) as children of qualor, and a child can read the environment of
# its parent in /proc/<ppid>/environ. So QUALOR_TOKEN is not left in the environment: it goes
# to qualor on file descriptor 3 (a here-document), which qualor reads and closes at start-up.
# Nothing is written to disk by this script.
set -eu

if [ -n "${QUALOR_TOKEN:-}" ]; then
  qualor_token=$QUALOR_TOKEN
  unset QUALOR_TOKEN
  exec 3<<QUALOR_TOKEN_END
${qualor_token}
QUALOR_TOKEN_END
  QUALOR_TOKEN_FD=3
  export QUALOR_TOKEN_FD
  unset qualor_token
fi
exec /usr/local/bin/qualor "$@"
