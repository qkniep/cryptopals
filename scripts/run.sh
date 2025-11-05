#!/usr/bin/env bash
# Usage: ./scripts/run.sh rust set1 ch1

set -e

lang=$1; project=$2; shift 2
case $lang in
  rust)    (cd rust/$project && cargo run -- "$@") ;;
  cpp)     (cd cpp && cmake --build build && ./build/${project}_$1) ;;
  zig)     (cd zig && zig build run-${project}-$1) ;;
  ocaml)   (cd ocaml && dune exec ${project}/$1.exe) ;;
  *) echo "Unknown language: $lang" ;;
esac
