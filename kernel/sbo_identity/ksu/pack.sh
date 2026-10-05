#!/bin/sh
# Package a built and verified sbo_identity.ko as a KernelSU/Magisk module.
#
#   sh kernel/sbo_identity/ksu/pack.sh [out.zip]
#
# Runs in WSL after kernel/sbo_identity/build.sh. Re-checks the symbol CRCs
# and the module BTF against the device files before packing, so nothing that
# failed verification can reach the boot path. The package carries the
# kernel release string and the device BTF hash that service.sh compares at
# boot.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MOD=$(CDPATH= cd -- "$HERE/.." && pwd)
DEVICE=$(CDPATH= cd -- "$MOD/../../experimental/sb_sockowner_probe" && pwd)
KO=$MOD/sbo_identity.ko
SYMVERS=$DEVICE/target/Module.symvers.device
RELEASE_FILE=$DEVICE/target/kernel-release
BTF_HASH=$MOD/.build/base-btf.sha256
OUT=${1:-$MOD/.build/sbo_identity-ksu.zip}

for f in "$KO" "$SYMVERS" "$RELEASE_FILE" "$BTF_HASH"; do
    [ -s "$f" ] || { echo "missing $f (run build.sh first)" >&2; exit 2; }
done
command -v zip > /dev/null || { echo "zip is required" >&2; exit 2; }

python3 "$DEVICE/verify-ko.py" "$KO" "$SYMVERS"
python3 "$MOD/verify_btf.py"

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
for f in service.sh action.sh common.sh uninstall.sh module.prop; do
    tr -d '\r' < "$HERE/$f" > "$STAGE/$f"
done
chmod 755 "$STAGE/service.sh" "$STAGE/action.sh" "$STAGE/common.sh" "$STAGE/uninstall.sh"
cp "$KO" "$STAGE/"
tr -d '\r' < "$RELEASE_FILE" > "$STAGE/kernel-release"
cut -d' ' -f1 "$BTF_HASH" > "$STAGE/base-btf.sha256"

RELEASE=$(cat "$STAGE/kernel-release")
DIGEST=$(sha256sum "$KO" | cut -c1-8)
sed -i "s|^version=.*|version=${RELEASE} (${DIGEST})|; s|^versionCode=.*|versionCode=$(date +%Y%m%d%H)|" "$STAGE/module.prop"

mkdir -p "$(dirname -- "$OUT")"
rm -f "$OUT"
(cd "$STAGE" && zip -q -r "$OUT" .)
echo "packed $OUT"
echo "  kernel  $RELEASE"
echo "  btf     $(cat "$STAGE/base-btf.sha256")"
echo "  module  $(sha256sum "$KO" | cut -d' ' -f1)"
