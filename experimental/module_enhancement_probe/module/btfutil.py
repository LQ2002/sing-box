"""Minimal BTF reader shared by gen_layout.py and verify_btf.py.

The parser is the one in identity_carrier_probe/module/verify_btf.py, loaded
from there so both probes read BTF identically.
"""
import importlib.util
from pathlib import Path
import struct

here = Path(__file__).resolve().parent
experimental = here.parents[1]
_bridge = (experimental / "identity_carrier_probe/module/verify_btf.py").read_text()
_ns = {"struct": struct}
exec(_bridge[_bridge.index("def parse("):_bridge.index("base_path =")], _ns)
parse = _ns["parse"]

_spec = importlib.util.spec_from_file_location("sbo_elf", experimental / "sb_sockowner_probe/verify-ko.py")
elf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(elf)

BASE_PATH = experimental / "sb_sockowner_probe/target/vmlinux.btf"
MODIFIERS = {8, 9, 10, 11, 18}  # typedef, volatile, const, restrict, type_tag


def load_base():
    return parse(BASE_PATH.read_bytes())


def resolve(table, tid):
    while tid and table[tid]["kind"] in MODIFIERS:
        tid = table[tid]["value"]
    return tid


def find_structs(table, name, lo, hi):
    return [k for k, v in table.items() if lo <= k < hi and v["name"] == name and v["kind"] in (4, 5)]


def member(table, sid, path):
    """(bit offset, bitfield size or 0, type id) of a member, descending into
    named path components and anonymous struct/union members."""
    name, rest = path[0], path[1:]
    for mname, mtype, moff in table[sid]["members"]:
        bit, size = moff & 0xFFFFFF, moff >> 24
        if mname == name:
            if not rest:
                return bit, size, mtype
            off, bsize, tid = member(table, resolve(table, mtype), rest)
            return bit + off, bsize, tid
        if mname == "":
            sub = resolve(table, mtype)
            if table[sub]["kind"] in (4, 5):
                try:
                    off, bsize, tid = member(table, sub, path)
                    return bit + off, bsize, tid
                except KeyError:
                    pass
    raise KeyError(name)
