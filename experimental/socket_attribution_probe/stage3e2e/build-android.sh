#!/usr/bin/env bash
# Android arm64 build of E:\ebpf_sing-box from the repository's own settings:
# .github/workflows/android-ebpf.yml BASE_TAGS, release/LDFLAGS, CGO with NDK r29.
# Usage: build-android.sh [output-path] (path is relative to the invoking directory).
set -euo pipefail
OUT=$(realpath -m "${1:-$(dirname "$0")/../results/sing-box-android}")
export PATH="$HOME/go-sdk/bin:/usr/local/bin:/usr/bin:/bin"
export GOWORK=off GOTOOLCHAIN=local
cd /mnt/e/ebpf_sing-box
TAGS=$(grep -m1 'BASE_TAGS:' .github/workflows/android-ebpf.yml | sed -E 's/^.*BASE_TAGS:[[:space:]]*//' | tr -d '\r')
LDF=$(tr -d '\r' < release/LDFLAGS)
VERSION=$(CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go run ./cmd/internal/read_tag | tr -d '\r')
NDK="$HOME/android-ndk-r29/toolchains/llvm/prebuilt/linux-x86_64/bin"
mkdir -p "$(dirname "$OUT")"
echo "tags=$TAGS version=$VERSION commit=$(git rev-parse --short HEAD)"
CGO_ENABLED=1 GOOS=android GOARCH=arm64 CC="$NDK/aarch64-linux-android35-clang" \
  go build -trimpath -tags "$TAGS" \
  -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=$VERSION' $LDF -s -w -buildid=" \
  -o "$OUT" ./cmd/sing-box
go version -m "$OUT" | grep -E "sing-ebpf|-tags|CGO_ENABLED|vcs.revision"
go version -m "$OUT" | grep -P '\r' && echo "CARRIAGE RETURN FOUND" || echo "no CR"
"$NDK/llvm-readelf" -d "$OUT" | grep NEEDED
sha256sum "$OUT"
