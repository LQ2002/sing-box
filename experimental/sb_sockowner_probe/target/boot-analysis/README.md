# boot_a.img inspection

Source: `E:/boot_a.img`, read-only; 100663296 bytes. Hashes and extraction sizes are in `report.json`.

Verified:

- Android boot header v4, 4096-byte boot image page alignment.
- Kernel payload: 41507328 bytes; uncompressed ARM64 Image (`ARM\x64` header magic).
- No ramdisk in this boot image.
- Embedded Linux banner exactly matches the supplied running kernel release, compiler string, and build timestamp. This establishes matching metadata, not cryptographic proof of the currently booted partition.
- Embedded IKCONFIG decompresses successfully and exactly matches the supplied full configuration after line-ending normalization.
- A single structurally valid BTF candidate was recovered at kernel payload offset 27084740, length 7074100 bytes.
- All 168388 BTF type records were traversed with valid record lengths and referenced names; selected layouts are in `btf-summary.json`.

Local outputs (large binaries intentionally ignored by Git):

- `kernel.bin`: original kernel payload, unmodified.
- `vmlinux.btf`: extracted raw BTF, not an ELF vmlinux.
- `embedded.config`: gzip-decoded embedded kernel configuration.

These outputs are evidence for later ABI/layout validation. No Module.symvers, symbol CRC table, ELF vmlinux, or loadable module has been recovered/generated in this step. BTF type information alone must not be treated as the target DWARF-generated CRCs. The exact corresponding core source/build inputs remain unresolved. No flashing, module loading, or changes to the source boot image were performed.
