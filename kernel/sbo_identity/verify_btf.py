#!/usr/bin/env python3
"""Check the built module's split BTF against the device base.

1. btf_trace_sbo_identity_socket exists with 8 parameters (void *ctx + 7 TP
   args): what tp_btf attachment needs.
2. Its socket argument is the device's struct sock, not a module-local copy
   (gen_layout.py explains why); otherwise the verifier rejects
   bpf_sk_storage_get() on it.
3. Every member the module dereferences through its own headers has the
   device offset. pahole re-emits these structs in the split BTF (the device
   uses KABI unions our tree lacks), so offsets are compared directly.
"""
from btfutil import here, elf, parse, load_base, resolve, find_structs, member

base, strings = load_base()
blob, sections = elf.read_elf(here / "sbo_identity.ko")
assert ".BTF" in sections, "Missing module BTF"
assert "__bpf_raw_tp_map" in sections, "Missing raw tracepoint map"
offset, length = sections[".BTF"]
local, _ = parse(blob[offset:offset + length], strings, len(base) + 1)
types = base | local
split = len(base) + 1

hooks = [(k, v) for k, v in local.items() if v["name"] == "btf_trace_sbo_identity_socket" and v["kind"] == 8]
assert len(hooks) == 1, "Expected exactly one typed tracepoint typedef"
pointer = types[hooks[0][1]["value"]]
assert pointer["kind"] == 2
proto = types[pointer["value"]]
assert proto["kind"] == 13 and len(proto["parameters"]) == 8, proto
sk_ptr = types[resolve(types, proto["parameters"][1])]
assert sk_ptr["kind"] == 2, sk_ptr
sk_type = resolve(types, sk_ptr["value"])
print(f"tracepoint typedef OK: 8 parameters; sk -> device type {sk_type} {types[sk_type]['name']}")
assert sk_type < split and types[sk_type]["name"] == "sock" and types[sk_type]["kind"] == 4, \
    "tracepoint sk must be the device's struct sock"
# cgroup, css_set and kernfs_node may appear (pulled in by sched.h); the module
# reads them only at device offsets, never through those definitions.
for name in ("sock", "sock_common"):
    assert not find_structs(types, name, split, 1 << 31), f"module BTF defines its own struct {name}"

used = {
    "file": [["f_inode"], ["f_path"]],
    "inode": [["i_sb"], ["i_ino"], ["i_generation"]],
    "super_block": [["s_dev"]],
    "mm_struct": [["exe_file"]],
    "task_struct": [["mm"], ["flags"], ["tgid"]],
}
bad = 0
for name, paths in used.items():
    loc = find_structs(types, name, split, 1 << 31)
    dev = find_structs(types, name, 1, split)
    if not loc:
        print(f"{name}: deduplicated against the device type")
        continue
    for bid in dev:
        line = [f"{name}: size module={types[loc[0]]['value']} device={types[bid]['value']}"]
        bad += types[loc[0]]["value"] != types[bid]["value"]
        for path in paths:
            lo, bo = member(types, loc[0], path)[0], member(types, bid, path)[0]
            line.append(f"{'.'.join(path)}@{lo // 8}/{bo // 8}")
            bad += lo != bo
        print(" ".join(line))
assert bad == 0, f"{bad} layout differences"
print("layout OK: every dereferenced member matches the device kernel")
