"""Minimal BTF reader for gen_layout.py and verify_btf.py.

Reads the raw device BTF (experimental/sb_sockowner_probe/target/vmlinux.btf,
extracted from the phone) and the module's split .BTF section. The ELF
reader and the device symbol tables are the ones the bridge build already
uses (experimental/sb_sockowner_probe/verify-ko.py).
"""
import importlib.util
from pathlib import Path
import struct

here = Path(__file__).resolve().parent
repo = here.parents[1]
device = repo / "experimental/sb_sockowner_probe"

_spec = importlib.util.spec_from_file_location("sbo_elf", device / "verify-ko.py")
elf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(elf)

BASE_PATH = device / "target/vmlinux.btf"
MODIFIERS = {8, 9, 10, 11, 18}  # typedef, volatile, const, restrict, type_tag


def parse(data, base_strings=b"", start_id=1):
    magic, version, flags, header, toff, tlen, soff, slen = struct.unpack_from("<HBBIIIII", data)
    assert magic == 0xEB9F and version == 1 and flags == 0
    strings = base_strings + data[header + soff:header + soff + slen]
    def string(offset):
        return strings[offset:strings.index(0, offset)].decode()
    records, pos, end = {}, header + toff, header + toff + tlen
    while pos < end:
        name, info, value = struct.unpack_from("<III", data, pos)
        kind, count = (info >> 24) & 31, info & 65535
        pos += 12
        length = ({1: 4, 3: 12, 14: 4, 17: 4}.get(kind, 0) or
                  {4: 12, 5: 12, 6: 8, 13: 8, 15: 12, 19: 12}.get(kind, 0) * count)
        record = {"name": string(name), "kind": kind, "value": value}
        if kind in (4, 5):
            record["members"] = [(string(n), t, o) for n, t, o in
                                 (struct.unpack_from("<III", data, pos + i * 12) for i in range(count))]
        if kind == 13:
            record["parameters"] = [struct.unpack_from("<II", data, pos + i * 8)[1] for i in range(count)]
        records[start_id + len(records)] = record
        pos += length
    assert pos == end, "Invalid BTF record boundary"
    return records, strings


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
