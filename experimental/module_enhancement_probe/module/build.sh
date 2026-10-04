#!/bin/sh
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

OUT=$(mktemp -d "${TMPDIR:-/tmp}/sbo-enh-probe.XXXXXX")
cp -a "$KDIR/." "$OUT/"
cp "$SYMVERS" "$OUT/Module.symvers"

make -C "$OUT" M="$HERE" ARCH=arm64 LLVM=1 modules

"$CLANG_BIN/llvm-objcopy" --remove-section=.BTF --remove-section=.BTF.base \
    "$HERE/sbo_enhancement_probe.ko"
LLVM_OBJCOPY="$CLANG_BIN/llvm-objcopy" pahole -J -j1 \
    --btf_features=var,float,enum64,decl_tag,type_tag,optimized_func,consistent_func \
    --btf_base "$BASE" "$HERE/sbo_enhancement_probe.ko"
"$OUT/tools/bpf/resolve_btfids/resolve_btfids" -b "$BASE" "$HERE/sbo_enhancement_probe.ko"
python3 "$OLD/verify-ko.py" "$HERE/sbo_enhancement_probe.ko" "$SYMVERS"
sha256sum "$HERE/sbo_enhancement_probe.ko" "$BASE" "$SYMVERS"
rm -rf "$OUT"
