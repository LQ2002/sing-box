#!/usr/bin/env bash
# Build the probe in WSL (as likayo): BPF objects with the Android Clang used
# for common/socketidentity, Go binary for linux/arm64.
set -euo pipefail
cd -- "$(dirname -- "$0")"
kernel="${1:-../sb_sockowner_probe/target/common-6.12.69}"
compiler="${BPF_CC:-$HOME/toolchains/clang-r536225/bin/clang}"
export PATH="$HOME/go-sdk/bin:$PATH"
mkdir -p build
python3 "$kernel/scripts/bpf_doc.py" --header \
  --file "$kernel/include/uapi/linux/bpf.h" > build/bpf_helper_defs.h
for name in argv netdtag; do
  "$compiler" -target bpfel -D__TARGET_ARCH_arm64 -O2 -g -Wall -Werror \
    -I"${UAPI_ARCH_INCLUDE:-/usr/include/$(uname -m)-linux-gnu}" \
    -Ibuild -I"$kernel/tools/lib/bpf" -c bpf/$name.bpf.c -o build/$name.bpf.o
done
go vet ./...
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o build/creator-v2-probe .
sha256sum build/*.o build/creator-v2-probe
