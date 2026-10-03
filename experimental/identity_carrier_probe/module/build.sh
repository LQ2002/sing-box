#!/bin/sh
# Local build only. Never loads a module or changes the existing prepared tree.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OLD=$(CDPATH= cd -- "$HERE/../../sb_sockowner_probe" && pwd)
KDIR=${KDIR:-/root/common-6.12.69-out}
CLANG_BIN=${CLANG_BIN:-/home/likayo/toolchains/clang-r536225/bin}
BASE="$OLD/target/vmlinux.btf"
SYMVERS="$OLD/target/Module.symvers.device"
export PATH="$CLANG_BIN:$PATH"

test -f "$KDIR/Makefile"
test -s "$SYMVERS"
test -s "$BASE"
clang --version | head -1
pahole --version
mkdir -p "$HERE/.build"
# Kernel headers contain names differing only by case. Keep the private copy on
# WSL's Linux filesystem, not the Windows checkout's case-insensitive mount.
OUT=$(mktemp -d "${TMPDIR:-/tmp}/sbo-identity-bridge.XXXXXX")
cp -a "$KDIR/." "$OUT/"
printf '%s\n' "$OUT" > "$HERE/.build/kernel-out.path"
# This copy is private to the experiment; the old output tree is read only.
cp "$SYMVERS" "$OUT/Module.symvers"
python3 "$HERE/prepare_layout.py"
make -C "$OUT" M="$HERE" ARCH=arm64 LLVM=1 modules

# Kbuild has no matching ELF vmlinux here. Generate split BTF explicitly from
# the real extracted raw base; do not create a fake vmlinux or waive failures.
"$CLANG_BIN/llvm-objcopy" --remove-section=.BTF --remove-section=.BTF.base \
    "$HERE/sbo_identity_bridge.ko"
LLVM_OBJCOPY="$CLANG_BIN/llvm-objcopy" pahole -J -j1 \
    --btf_features=var,float,enum64,decl_tag,type_tag,optimized_func,consistent_func \
    --btf_base "$BASE" "$HERE/sbo_identity_bridge.ko"
"$OUT/tools/bpf/resolve_btfids/resolve_btfids" -b "$BASE" "$HERE/sbo_identity_bridge.ko"
python3 "$OLD/verify-ko.py" "$HERE/sbo_identity_bridge.ko" "$SYMVERS"
python3 "$HERE/verify_btf.py"
sha256sum "$BASE" > "$HERE/.build/base-btf.sha256"
sha256sum "$HERE/sbo_identity_bridge.ko" "$BASE" "$SYMVERS"
