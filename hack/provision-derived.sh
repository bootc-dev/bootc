#!/bin/bash
# Backwards-compatible wrapper: runs the fetch and configure phases in sequence.
# In CI, prefer calling just build-fetch first (which retries the fetch phase
# on transient failures) and then just build (which uses the cached fetch layer).
set -xeu

case ${1:-} in
  cloudinit|"") ;;
  *) echo "Unhandled flag: ${1:-}" 1>&2; exit 1 ;;
esac

dir="$(dirname "$0")"
"${dir}/provision-fetch.sh" "$@"
"${dir}/provision-configure.sh" "$@"
