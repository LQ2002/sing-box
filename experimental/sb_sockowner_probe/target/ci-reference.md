# CI reference artifact

Public central CI run: `YuzakiKokuban/Kokuban_Kernel_CI_Center`, run `34559006526`, artifact `mi17_sm8850-kernel-resukisu-34559006526-1` (2026-09-11).

The artifact contained a generated `.config`, a release ZIP, and `vmlinux.symvers`. The symbol table exported `sock_diag_save_cookie`, `__tracepoint_android_vh_sock_create`, `__tracepoint_android_vh_sk_free`, `tracepoint_probe_register`, and `tracepoint_probe_unregister`. Its config enabled Android vendor hooks, CFI, MODVERSIONS, GENDWARFKSYMS, and BTF.

The artifact kernel identifies as `6.12.23-android16-Kokuban-SilverWolf`; the target phone identifies as `6.12.69-android16-6-gb1493ec68d4a-abogki514973465-4k`. Keep this artifact as a reference only. Its CRCs and generated headers must not be used to certify a module for the phone.
