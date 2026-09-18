# boot_b.img inspection

Source: `C:/Users/Admin/Downloads/boot_b.img`, read-only; 100663296 bytes. Hashes and extraction sizes are in `report.json`.

Verified:

- Android boot header v4, 4096-byte boot image page alignment.
- Kernel payload: 41576960 bytes; uncompressed ARM64 Image (`ARM\x64` header magic).
- No ramdisk in this boot image.
- Embedded Linux banner exactly matches the supplied running kernel release, compiler string, and build timestamp. This establishes matching metadata, not cryptographic proof of the currently booted partition.
- Embedded IKCONFIG decompresses successfully and exactly matches the supplied full configuration after line-ending normalization.
- A single structurally valid BTF candidate was recovered at kernel payload offset 27165412, length 7077741 bytes.
- All 168480 BTF type records were traversed with valid record lengths and referenced names; selected layouts are in `btf-summary.json`.

Local outputs (large binaries intentionally ignored by Git):

- `kernel.bin`: original kernel payload, unmodified.
- `vmlinux.btf`: extracted raw BTF, not an ELF vmlinux.
- `embedded.config`: gzip-decoded embedded kernel configuration.

These outputs are evidence for later ABI/layout validation. No Module.symvers, symbol CRC table, ELF vmlinux, or loadable module has been recovered/generated in this step. BTF type information alone must not be treated as the target DWARF-generated CRCs. The exact corresponding core source/build inputs remain unresolved. No flashing, module loading, or changes to the source boot image were performed.

## Replacing the boot_a.img baseline (OTA of 2026-09-18)

The device took an OTA. The previous baseline in this directory described
`E:/boot_a.img`, release `6.12.69-android16-6-gb1493ec68d4a-abogki514973465-4k`.
It has been replaced by `boot_b.img`, release
`6.12.69-android16-6-g586bfab1b9c5-abogki536749445-4k`. Same upstream base
(6.12.69-android16-6); the vendor build identifiers changed.

`report.json` and `btf-summary.json` were not hand-edited. They are produced by
a regenerator that reuses `refresh-kernel-abi.py`'s kernel extraction and BTF
parser, so the two files cannot drift from the tool that generates the symbol
table. The regenerator was validated by running it against the old
`boot_a.img` first and confirming it reproduced the previously committed
`report.json` and `btf-summary.json` byte for byte before it was pointed at the
new image.

Note when reading `btf-summary.json`: for a member of a struct whose BTF type
carries `kflag=1`, the raw member offset packs the bitfield width into the top
8 bits. The recorded `bit_offset` is masked to the low 24 bits, which is why
`sock.sk_kern_sock` reads 4497 and not 16781713.
