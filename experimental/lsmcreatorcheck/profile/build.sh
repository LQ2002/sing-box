#!/usr/bin/env bash
# Builds a stage-timed copy of the LSM producer for lsmcreatorcheck -profile.
# The production source is not changed: gen_profile.py copies
# common/socketidentity/bpf/creator_lsm.bpf.c and inserts bpf_ktime_get_ns()
# checkpoints after each stage of capture_creator. Run as root in WSL (the
# kernel tree is /root/common-6.12.69, like build-bpf.sh).
set -euo pipefail
cd -- "$(dirname -- "$0")"
kernel="$(realpath "${1:-/root/common-6.12.69}")"
compiler="${BPF_CC:-/home/likayo/toolchains/clang-r536225/bin/clang}"
source_dir=../../../common/socketidentity
mkdir -p .build
python3 gen_profile.py "$source_dir/bpf/creator_lsm.bpf.c" > .build/creator_lsm_profile.bpf.c
python3 "$kernel/scripts/bpf_doc.py" --header \
    --file "$kernel/include/uapi/linux/bpf.h" > .build/bpf_helper_defs.h
"$compiler" -target bpfel -D__TARGET_ARCH_arm64 -O2 -g -Wall -Werror \
    -I"${UAPI_ARCH_INCLUDE:-/usr/include/$(uname -m)-linux-gnu}" \
    -I.build -I"$source_dir/bpf" -I"$kernel/tools/lib/bpf" \
    -c .build/creator_lsm_profile.bpf.c -o .build/creator_lsm_profile.bpf.o
sha256sum .build/creator_lsm_profile.bpf.o
