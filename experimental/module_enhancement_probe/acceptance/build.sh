#!/usr/bin/env bash
# Build in WSL as likayo: consumer BPF object (Android Clang, same flags as
# creator_v2_probe) and the linux/arm64 acceptance binary.
set -euo pipefail
cd -- "$(dirname -- "$0")"
kernel="${1:-../../sb_sockowner_probe/target/common-6.12.69}"
compiler="${BPF_CC:-$HOME/toolchains/clang-r536225/bin/clang}"
export PATH="$HOME/go-sdk/bin:$PATH"
mkdir -p build
python3 "$kernel/scripts/bpf_doc.py" --header \
  --file "$kernel/include/uapi/linux/bpf.h" > build/bpf_helper_defs.h
"$compiler" -target bpfel -D__TARGET_ARCH_arm64 -O2 -g -Wall -Werror \
  -I"${UAPI_ARCH_INCLUDE:-/usr/include/$(uname -m)-linux-gnu}" \
  -Ibuild -I"$kernel/tools/lib/bpf" -c ../bpf/consumer.bpf.c -o build/consumer.bpf.o
# Comparison consumers for timing.sh (see results/stage2-opt/README.md):
# v0 count only, v1 first 320-byte consumer, v3 prealloc HASH by cookie,
# v4 the production producer (creator.bpf.c) on this tracepoint.
for v in v0 v1 v3 v4; do
  "$compiler" -target bpfel -D__TARGET_ARCH_arm64 -O2 -g -Wall -Werror     -I"${UAPI_ARCH_INCLUDE:-/usr/include/$(uname -m)-linux-gnu}"     -Ibuild -I"$kernel/tools/lib/bpf" -c ../bpf/consumer_$v.bpf.c -o build/consumer_$v.bpf.o
done
go vet ./...
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o build/sbo-acceptance .
sha256sum build/*.bpf.o build/sbo-acceptance
