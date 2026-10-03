#!/usr/bin/env python3
"""Generate checks from the actual device BTF without altering old probe files."""
import importlib.util
from pathlib import Path
import sys

sys.dont_write_bytecode = True
here = Path(__file__).resolve().parent
old = here.parents[1] / "sb_sockowner_probe"
spec = importlib.util.spec_from_file_location("sbo_abi", old / "refresh-kernel-abi.py")
abi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(abi)
types = abi.parse_btf((old / "target/vmlinux.btf").read_bytes())
out = here / ".build/generated"
out.mkdir(parents=True, exist_ok=True)
layout = out / "sbo_layout_asserts.h"
tasks = [item for item in types if item[0] == "task_struct" and item[1] == 4]
assert tasks, "Device task_struct is missing"
signatures = set()
for task in tasks:
    offsets = []
    for field in ("tgid", "stack_canary"):
        members = [item for item in task[3] if item[0] == field]
        assert len(members) == 1 and members[0][2] % 8 == 0
        offsets.append(members[0][2] // 8)
    signatures.add((task[2], *offsets))
assert len(signatures) == 1, f"Device task layouts disagree: {signatures}"
size, tgid, stack_canary = signatures.pop()
layout.write_text(
    "/* Generated from the actual device BTF; no socket type definition. */\n"
    "#include <linux/sched.h>\n"
    f'_Static_assert(sizeof(struct task_struct) == {size}, "task_struct size");\n'
    f'_Static_assert(offsetof(struct task_struct, tgid) == {tgid}, "task tgid offset");\n'
    f'_Static_assert(offsetof(struct task_struct, stack_canary) == {stack_canary}, "compiler stack canary offset");\n'
)
print("Generated task_struct size, tgid, and stack-canary assertions from device BTF")
