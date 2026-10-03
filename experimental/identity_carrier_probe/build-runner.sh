#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
go_bin="${GO_BIN:-go}"
"$go_bin" test ./...
mkdir -p build
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 "$go_bin" build -trimpath -o build/identity-carrier-probe .
