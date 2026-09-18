# IPSET_LKM `6.12-Mi` check

The `v2.5` release asset `IPSET-LKM-android16-6.12-Mi.zip` was inspected. Its two kernel modules (`xt_addrtype.ko` and `xt_set.ko`) carry:

```
vermagic=6.12.76-4k SMP preempt mod_unload modversions aarch64
Android clang 19.0.1, based on r536225
```

The phone target is `6.12.69-android16-6-gb1493ec68d4a-abogki514973465-4k`. The release is therefore not an exact source match, but it can still load on the phone because Android GKI/KMI builds commonly keep the relevant exported-symbol CRCs stable across minor 6.12 updates, and the loader may treat the numeric kernel sublevel in vermagic as non-authoritative when MODVERSIONS is present. This must be verified from `dmesg`/the loader result on the actual device; changing the vermagic string alone would not repair CRC mismatches.

The target configuration has `CONFIG_MODULE_SIG_FORCE` disabled, `CONFIG_MODULE_SIG_ALL=y`, `CONFIG_MODULE_SIG_PROTECT=y`, and `CONFIG_MODULE_UNLOAD=y`. Therefore the IPSET loader is not necessarily bypassing a mandatory signature check; KernelSU/APatch integration, protected-module policy, and the loader's syscall flags must be checked separately on-device. The package's uninstall script only removes files and does not explicitly unload modules, so a probe should unregister hooks and release all state in its own exit path.
