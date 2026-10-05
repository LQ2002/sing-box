#!/bin/sh
# Build sbo_identity.ko in WSL (as root: the prepared kernel output tree is
# root's). Reads the device's own vmlinux BTF and symbol CRC table from
# experimental/sb_sockowner_probe/target/; performs no device operation.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DEVICE=$(CDPATH= cd -- "$HERE/../../experimental/sb_sockowner_probe" && pwd)
KDIR=${KDIR:-/root/common-6.12.69-out}
CLANG_BIN=${CLANG_BIN:-/home/likayo/toolchains/clang-r536225/bin}
BASE="$DEVICE/target/vmlinux.btf"
SYMVERS="$DEVICE/target/Module.symvers.device"
export PATH="$CLANG_BIN:$PATH"

test -f "$KDIR/Makefile"
test -s "$SYMVERS"
test -s "$BASE"
clang --version | head -1
pahole --version
mkdir -p "$HERE/.build"
python3 "$HERE/gen_layout.py"

# Kernel headers contain names differing only by case: build in a private
# copy on WSL's Linux filesystem, never in the Windows checkout's tree.
OUT=$(mktemp -d "${TMPDIR:-/tmp}/sbo-identity.XXXXXX")
cp -a "$KDIR/." "$OUT/"
cp "$SYMVERS" "$OUT/Module.symvers"
make -C "$OUT" M="$HERE" ARCH=arm64 LLVM=1 modules

# Kbuild has no matching ELF vmlinux here; generate split BTF against the
# real extracted device base instead.
"$CLANG_BIN/llvm-objcopy" --remove-section=.BTF --remove-section=.BTF.base "$HERE/sbo_identity.ko"
LLVM_OBJCOPY="$CLANG_BIN/llvm-objcopy" pahole -J -j1 \
    --btf_features=var,float,enum64,decl_tag,type_tag,optimized_func,consistent_func \
    --btf_base "$BASE" "$HERE/sbo_identity.ko"
"$OUT/tools/bpf/resolve_btfids/resolve_btfids" -b "$BASE" "$HERE/sbo_identity.ko"
python3 "$DEVICE/verify-ko.py" "$HERE/sbo_identity.ko" "$SYMVERS"
python3 "$HERE/verify_btf.py"
sha256sum "$BASE" > "$HERE/.build/base-btf.sha256"
sha256sum "$HERE/sbo_identity.ko" "$BASE" "$SYMVERS"
rm -rf "$OUT"
