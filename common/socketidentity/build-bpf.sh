#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
kernel="${1:-/root/common-6.12.69}"
compiler="${BPF_CC:-/home/likayo/toolchains/clang-r536225/bin/clang}"
mkdir -p .build
python3 "$kernel/scripts/bpf_doc.py" --header \
    --file "$kernel/include/uapi/linux/bpf.h" > .build/bpf_helper_defs.h
"$compiler" -target bpfel -D__TARGET_ARCH_arm64 -O2 -g -Wall -Werror \
    -fdebug-prefix-map="$PWD"=. \
    -I"${UAPI_ARCH_INCLUDE:-/usr/include/$(uname -m)-linux-gnu}" \
    -I.build -I"$kernel/tools/lib/bpf" \
    -c bpf/creator.bpf.c -o bpf/creator.bpf.o
sha256sum bpf/creator.bpf.o
