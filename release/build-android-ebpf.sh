#!/usr/bin/env bash
# Run under Linux/WSL with an installed Android NDK (r29 in Android eBPF CI).
set -euo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"

: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to the Android NDK r29 directory}"
go_binary=${GO_BINARY:-go}
output_dir=${1:-"$repo_dir/dist/android-arm64-ebpf"}
mkdir -p -- "$output_dir"
output_dir=$(cd -- "$output_dir" && pwd)
compiler="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang"
test -x "$compiler"

# The Windows checkout may use CRLF; CR must never become part of a build tag.
tags=$(sed -n 's/^[[:space:]]*BASE_TAGS:[[:space:]]*//p' .github/workflows/android-ebpf.yml | tr -d '\r')
shared_ldflags=$(tr -d '\r\n' < release/LDFLAGS)
test -n "$tags"
export GOTOOLCHAIN=local
base_version=$(CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$go_binary" run -mod=readonly ./cmd/internal/read_tag | tr -d '\r')
if [[ "$base_version" == unknown || -z "$base_version" ]]; then
  printf 'Cannot determine source version\n' >&2
  exit 1
fi
version=${VERSION:-"$base_version-strict-attribution"}

CGO_ENABLED=1 GOOS=android GOARCH=arm64 CC="$compiler" \
  "$go_binary" build -mod=readonly -trimpath -tags "$tags" \
  -ldflags "-s -w -buildid= $shared_ldflags -X github.com/sagernet/sing-box/constant.Version=$version" \
  -o "$output_dir/sing-box" ./cmd/sing-box

"$go_binary" version -m "$output_dir/sing-box" > "$output_dir/build-info.txt"
{
  printf 'version=%s\n' "$version"
  printf 'branch=%s\n' "$(git branch --show-current)"
  printf 'commit=%s\n' "$(git rev-parse HEAD)"
  printf 'tracked_source_changes=%s\n' "$(git diff --name-only HEAD | wc -l)"
  printf 'built_at_utc=%s\n' "$(date -u +%FT%TZ)"
  "$go_binary" version
  "$compiler" --version
} > "$output_dir/build-environment.txt"
cp release/ANDROID-STRICT-ATTRIBUTION.md "$output_dir/README.md"
(
  cd "$output_dir"
  sha256sum sing-box build-info.txt build-environment.txt README.md > SHA256SUMS
)
printf 'Built %s\n' "$output_dir/sing-box"
