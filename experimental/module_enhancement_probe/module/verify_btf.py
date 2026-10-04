#!/usr/bin/env python3
"""Check the built module's split BTF against the device base.

1. btf_trace_sbo_enhancement_socket_identity exists with 8 parameters
   (void *ctx + 7 TP args) - what tp_btf attachment needs.
2. Its first TP argument is a pointer to the *device's* struct sock, not a
   module-local copy (see gen_layout.py); otherwise the verifier rejects
   bpf_sk_storage_get() on it.
3. Every member the module dereferences through its own headers sits at the
   same offset as on the device. pahole re-emits these structs in the split
   BTF (the KABI unions differ by name only), so offsets are compared
   directly rather than relying on deduplication.
"""
from btfutil import here, elf, parse, load_base, resolve, find_structs, member

base, strings = load_base()
blob, sections = elf.read_elf(here / "sbo_enhancement_probe.ko")
assert ".BTF" in sections, "Missing module BTF"
assert "__bpf_raw_tp_map" in sections, "Missing raw tracepoint map"
offset, length = sections[".BTF"]
local, _ = parse(blob[offset:offset + length], strings, len(base) + 1)
types = base | local
split = len(base) + 1

hooks = [(k, v) for k, v in local.items()
         if v["name"] == "btf_trace_sbo_enhancement_socket_identity" and v["kind"] == 8]
assert len(hooks) == 1, "Expected exactly one typed tracepoint typedef"
pointer = types[hooks[0][1]["value"]]
assert pointer["kind"] == 2
proto = types[pointer["value"]]
assert proto["kind"] == 13 and len(proto["parameters"]) == 8, proto
sk_ptr = types[resolve(types, proto["parameters"][1])]
assert sk_ptr["kind"] == 2, sk_ptr
sk_type = resolve(types, sk_ptr["value"])
print(f"tracepoint typedef OK: 8 parameters; sk -> type {sk_type} "
      f"({'device' if sk_type < split else 'MODULE-LOCAL'} {types[sk_type]['name']})")
assert sk_type < split and types[sk_type]["name"] == "sock" and types[sk_type]["kind"] == 4, \
    "tracepoint sk must be the device's struct sock"
assert not find_structs(types, "sock", split, 1 << 31), "module BTF defines its own struct sock"

used = {
    "file": [["f_inode"], ["f_path"]],
    "inode": [["i_sb"], ["i_ino"], ["i_generation"]],
    "super_block": [["s_dev"]],
    "mm_struct": [["exe_file"]],
    "task_struct": [["mm"], ["flags"]],
    "binder_transaction": [["sender_euid"], ["from_pid"]],
}
bad = 0
for name, paths in used.items():
    loc = find_structs(types, name, split, 1 << 31)
    dev = find_structs(types, name, 1, split)
    if not loc:
        print(f"{name}: deduplicated against the device type")
        continue
    lid, bid = loc[0], dev[0]
    line = [f"{name}: size module={types[lid]['value']} device={types[bid]['value']}"]
    bad += types[lid]["value"] != types[bid]["value"]
    for path in paths:
        lo, bo = member(types, lid, path)[0], member(types, bid, path)[0]
        line.append(f"{'.'.join(path)}@{lo // 8}/{bo // 8}")
        bad += lo != bo
    print(" ".join(line))
assert bad == 0, f"{bad} layout differences"
print("layout OK: every dereferenced member matches the device kernel")
