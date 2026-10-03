#!/usr/bin/env bash
# Build the pre-stage-3 consumer (7c12b1de) with the same repo settings, from
# a git archive (no checkout, no worktree metadata).
set -euo pipefail
export PATH="$HOME/go-sdk/bin:/usr/local/bin:/usr/bin:/bin"
export GOWORK=off GOTOOLCHAIN=local
REV=${1:-7c12b1de}
OLD=/tmp/sb-old-$REV
rm -rf "$OLD"; mkdir -p "$OLD"
git -C /mnt/e/ebpf_sing-box archive "$REV" | tar -x -C "$OLD"
cd "$OLD"
TAGS=$(grep -m1 'BASE_TAGS:' .github/workflows/android-ebpf.yml | sed -E 's/^.*BASE_TAGS:[[:space:]]*//' | tr -d '\r')
LDF=$(tr -d '\r' < release/LDFLAGS)
NDK="$HOME/android-ndk-r29/toolchains/llvm/prebuilt/linux-x86_64/bin"
OUT=/mnt/c/Users/Admin/AppData/Local/Temp/claude/E--ebpf-sing-box/674966ce-c47c-49e4-bcdc-b11d40b683ce/scratchpad/sing-box-old
CGO_ENABLED=1 GOOS=android GOARCH=arm64 CC="$NDK/aarch64-linux-android35-clang" \
  go build -trimpath -tags "$TAGS" \
  -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=old-$REV' $LDF -s -w -buildid=" \
  -o "$OUT" ./cmd/sing-box
go version -m "$OUT" | grep -E "sing-ebpf|-tags"
sha256sum "$OUT"
