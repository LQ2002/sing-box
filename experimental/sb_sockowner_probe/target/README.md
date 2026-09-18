# Target build evidence

`kernel.config` is the full configuration supplied by the device owner, normalized to LF without changing options.

Runtime release: `6.12.69-android16-6-gb1493ec68d4a-abogki514973465-4k`.

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

This is a useful toolchain and export reference, but it identifies itself as `6.12.23-android16-Kokuban-SilverWolf`, while the supplied boot image and runtime are `6.12.69-android16-6-gb1493ec68d4a-abogki514973465-4k`. Its CRCs and generated headers therefore cannot be used to certify a module for the phone. A matching 6.12.69 build artifact is still required.

The Android Common repository does publish the base tag `android16-6.12.69_r00` (commit `b18aa09ef8e78438227d33ab5e938145332e0e03`). The Xiaomi runtime suffix is downstream/vendor-specific, so this tag is a source baseline rather than proof of the complete device build.

No module has been compiled or loaded. The 6.12.23 third-party tree is reference material, not established as a matching build tree.

The supplied `E:/boot_a.img` has now been inspected. The banner matches the running kernel, its embedded configuration matches `kernel.config`, and raw BTF has been extracted and structurally parsed. See `boot-analysis/README.md` and `boot-analysis/report.json`. This provides target type-layout evidence but does not automatically replace source, DWARF-generated symbol CRCs, or build metadata.
