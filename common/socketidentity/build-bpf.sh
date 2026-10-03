#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
# Any checkout of the same ACK release works: the program bytes depend only
# on the sources, and both prefix maps below keep absolute paths out of DWARF,
# so the embedded object (and its SHA-256, which the collector pins against)
# does not depend on where the trees live. Verified by rebuilding the v1
# object from /root/common-6.12.69 and from
# experimental/sb_sockowner_probe/target/common-6.12.69: identical program
# section, differing only in the recorded include directory. Line endings
# matter too: clang records the source MD5 in DWARF, and the same file with
# CRLF built 6cdcef2f... instead of d9270fe2..., hence .gitattributes eol=lf.
kernel="$(realpath "${1:-/root/common-6.12.69}")"
compiler="${BPF_CC:-/home/likayo/toolchains/clang-r536225/bin/clang}"
mkdir -p .build
python3 "$kernel/scripts/bpf_doc.py" --header \
    --file "$kernel/include/uapi/linux/bpf.h" > .build/bpf_helper_defs.h
"$compiler" -target bpfel -D__TARGET_ARCH_arm64 -O2 -g -Wall -Werror \
    -fdebug-prefix-map="$PWD"=. -fdebug-prefix-map="$kernel"=kernel \
    -I"${UAPI_ARCH_INCLUDE:-/usr/include/$(uname -m)-linux-gnu}" \
    -I.build -I"$kernel/tools/lib/bpf" \
    -c bpf/creator.bpf.c -o bpf/creator.bpf.o
sha256sum bpf/creator.bpf.o
