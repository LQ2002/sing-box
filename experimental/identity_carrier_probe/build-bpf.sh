#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"

# Reuse the inspected ACK source for libbpf headers and helper declarations.
# The resulting object is BPF little-endian with arm64 tracing conventions;
# it is not linked to the build host's kernel or loaded by this script.
kernel="${1:-../sb_sockowner_probe/target/common-6.12.69}"
mkdir -p build
python3 "$kernel/scripts/bpf_doc.py" --header \
  --file "$kernel/include/uapi/linux/bpf.h" > build/bpf_helper_defs.h
"${BPF_CC:-clang}" -target bpfel -D__TARGET_ARCH_arm64 -O2 -g \
  -Wall -Werror \
  -I"${UAPI_ARCH_INCLUDE:-/usr/include/$(uname -m)-linux-gnu}" \
  -Ibuild -I"$kernel/tools/lib/bpf" \
  -c bpf/probe.bpf.c -o build/probe.bpf.o
