#!/bin/sh
set -e
MODE="${1:-analyzer}"
if [ "$#" -gt 0 ]; then
  shift
fi

case "$MODE" in
  analyzer|coordinator)
    exec python -m netdiag analyzer "$@"
    ;;
  satellite)
    exec python -m netdiag satellite "$@"
    ;;
  capture)
    exec python -m netdiag capture "$@"
    ;;
  *)
    echo "Unknown mode: $MODE (use analyzer|satellite|capture)" >&2
    exit 1
    ;;
esac
