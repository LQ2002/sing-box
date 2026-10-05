#!/usr/bin/env bash
# Build in WSL as likayo: BPF object (Android Clang) and the arm64 binary.
set -euo pipefail
cd -- "$(dirname -- "$0")"
kernel="${1:-../sb_sockowner_probe/target/common-6.12.69}"
compiler="${BPF_CC:-$HOME/toolchains/clang-r536225/bin/clang}"
export PATH="$HOME/go-sdk/bin:$PATH"
mkdir -p build
python3 "$kernel/scripts/bpf_doc.py" --header --file "$kernel/include/uapi/linux/bpf.h" > build/bpf_helper_defs.h
"$compiler" -target bpfel -D__TARGET_ARCH_arm64 -O2 -g -Wall -Werror \
  -I"${UAPI_ARCH_INCLUDE:-/usr/include/$(uname -m)-linux-gnu}" -Ibuild -I"$kernel/tools/lib/bpf" \
  -c bpf/ct.bpf.c -o build/ct.bpf.o
gofmt -l . || true
go vet ./...
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o build/conntrack-probe .
sha256sum build/ct.bpf.o build/conntrack-probe
