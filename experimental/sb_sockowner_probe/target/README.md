# Target build evidence

`kernel.config` is the full configuration supplied by the device owner, normalized to LF without changing options.

Runtime release: `6.12.69-android16-6-g586bfab1b9c5-abogki536749445-4k`.

Confirmed configuration:

- ARM64, 4 KiB pages, 39-bit virtual addresses, SMP, PREEMPT.
- Android Clang 19.0.1, build 14043575, based on r536225.
- `CONFIG_LTO_NONE=y`; the toolchain's descriptive `+lto` string does not mean kernel LTO is enabled.
- `CONFIG_CFI_CLANG=y`, integer-normalized indirect calls, non-permissive CFI.
- `CONFIG_MODVERSIONS=y`, `CONFIG_GENDWARFKSYMS=y`, basic and extended modversions enabled.
- `CONFIG_LOCALVERSION="-4k"`, automatic local version enabled. This configuration alone does not reproduce the entire runtime release string.
- Module BTF enabled, BTF mismatch allowed by configuration. This is not a guarantee of ABI compatibility.
- Symbol trimming uses `abi_symbollist.raw`; module protection uses `protected_module_names_list`. These named build inputs are not contained in the configuration file.

Outstanding build inputs:

1. Matching core source revision (runtime abbreviated revision has not been resolved in public ACK).
2. Matching prepared build artifacts / `Module.symvers`, generated headers and required ABI/protection lists.
3. Matching BTF input when building module BTF.
4. Linux build dependencies and compatible Android LLVM toolchain.

Existing Debian WSL was confirmed accessible with escalated read-only execution. No clang, make, git or python3 executable was found via command -v in that environment; no matching build directory was found in /opt or /usr/src. No dependencies were installed.

## Public CI reference artifact

The central Kokuban CI run `34559006526` for `mi17_sm8850` was downloaded under `ci-central/mi17_sm8850-kernel-resukisu-34559006526-1/`. It contains the release ZIP, the generated `.config`, and a 1.2 MB `vmlinux.symvers`. That symbol table includes `sock_diag_save_cookie`, `__tracepoint_android_vh_sock_create`, `__tracepoint_android_vh_sk_free`, and the tracepoint registration functions needed by the probe. Its configuration enables Android vendor hooks, CFI, MODVERSIONS, GENDWARFKSYMS, and BTF.

This is a useful toolchain and export reference, but it identifies itself as `6.12.23-android16-Kokuban-SilverWolf`, while the supplied boot image and runtime are `6.12.69-android16-6-g586bfab1b9c5-abogki536749445-4k`. Its CRCs and generated headers therefore cannot be used to certify a module for the phone. A matching 6.12.69 build artifact is still required.

The Android Common repository does publish the base tag `android16-6.12.69_r00` (commit `b18aa09ef8e78438227d33ab5e938145332e0e03`). The Xiaomi runtime suffix is downstream/vendor-specific, so this tag is a source baseline rather than proof of the complete device build.

No module has been compiled or loaded. The 6.12.23 third-party tree is reference material, not established as a matching build tree.

The supplied `boot_b.img` has now been inspected. The banner matches the running kernel, its embedded configuration matches `kernel.config`, and raw BTF has been extracted and structurally parsed. See `boot-analysis/README.md` and `boot-analysis/report.json`. This provides target type-layout evidence but does not automatically replace source, DWARF-generated symbol CRCs, or build metadata.

## OTA re-validation, 2026-09-18

The device updated from `6.12.69-android16-6-gb1493ec68d4a-abogki514973465-4k`
to `6.12.69-android16-6-g586bfab1b9c5-abogki536749445-4k`. The already-built
`sb_sockowner_probe.ko` was **not** rebuilt, because all three things it
depends on were checked and none of them moved:

1. **Imported symbol CRCs.** `verify-ko.py` was run with the existing `.ko`
   against the symbol table extracted from the new image. Both version tables
   agree: `__versions` 30 symbols, 30 matching, 0 mismatching; the extended
   table likewise 30/30/0. Across the whole table 9846 CRCs are unchanged, 19
   changed, 5 disappeared and 39 are new, but none of those touch the 30
   symbols this module imports.

2. **Struct layouts.** `layout_probe.c` and `sbo_bitfields.h` were generated
   from the old and the new BTF and diffed: identical, all 178 static
   assertions and the one bitfield self-check. In `btf-summary.json` the
   recorded struct sizes and member bit offsets are unchanged; only BTF type
   ids shifted, because the new kernel has 92 more types (168388 -> 168480).

3. **Kernel configuration.** The embedded IKCONFIG of the new image differs
   from the old one in three lines only: the Rust toolchain version string,
   two added ARM64 errata (`CONFIG_ARM64_ERRATUM_4193714`,
   `CONFIG_ARM64_ERRATUM_4118414`), and `CONFIG_BLK_WBT_MQ` turned off.
   `CONFIG_CFI_CLANG`, `CONFIG_MODVERSIONS` and `CONFIG_GENDWARFKSYMS` are
   unchanged.

What did have to change is the gate, not the module. `magisk/service.sh`
compares `uname -r` against the packaged `kernel-release` before it will
`insmod`, and refuses on any mismatch. That check exists because a module
carrying CRCs skips the version-number part of vermagic in the kernel's
`same_magic()`, so `insmod` alone will not stop a kernel generation change —
which is also why the module's own `vermagic=6.12.69-4k-gb18aa09ef8e7` never
matched the device's release string even before this OTA. So `kernel-release`
was updated and the Magisk package repacked; without that the module would
have failed to load at boot and disabled itself after three attempts.

Re-run the checks with:

    python refresh-kernel-abi.py <boot.img> target
    python verify-ko.py sb_sockowner_probe.ko target/Module.symvers.device

