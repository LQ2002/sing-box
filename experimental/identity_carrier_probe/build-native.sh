#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
cc="${NATIVE_CC:-/home/likayo/android-ndk-r29/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang}"
mkdir -p build
"$cc" -O2 -g -Wall -Wextra -Werror -pthread native/worker.c -o build/identity-native-worker
