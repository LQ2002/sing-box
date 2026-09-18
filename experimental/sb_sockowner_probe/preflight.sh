#!/system/bin/sh
# Read-only. Run in the phone's root shell; no loading or settings changes.
printf '\n== Kernel ==\n'
uname -r
cat /proc/version
printf '\n== Relevant build options ==\n'
if [ -r /proc/config.gz ]; then
    zcat /proc/config.gz | grep -E '^(# )?CONFIG_(ANDROID_VENDOR_HOOKS|TRACEPOINTS|MODULES|MODVERSIONS|MODULE_SIG|MODULE_SIG_FORCE|MODULE_SIG_PROTECT|MODULE_SIG_PROTECT_LIST|TRIM_UNUSED_KSYMS|DEBUG_INFO_BTF|DEBUG_INFO_BTF_MODULES|CFI_CLANG)(=| )'
else
    printf 'config.gz is not readable; configuration remains unknown\n'
fi
printf '\n== Candidate symbols and exports ==\n'
if [ -r /proc/kallsyms ]; then
    grep -E '(sock_diag_save_cookie|tracepoint_android_vh_(sock_create|sk_free)|tracepoint_probe_register|tracepoint_probe_unregister|tracepoint_srcu|synchronize_srcu|synchronize_rcu)' /proc/kallsyms
else
    printf 'kallsyms is not readable; export availability remains unknown\n'
fi
printf '\n== Runtime module loading switch ==\n'
cat /proc/sys/kernel/modules_disabled
printf '\n== BTF ==\n'
if [ -r /sys/kernel/btf/vmlinux ]; then
    printf 'vmlinux BTF is readable\n'
else
    printf 'vmlinux BTF is not readable\n'
fi
