#!/usr/bin/env python3
"""Check split module BTF against the exact raw device base and report the hook."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
here = Path(__file__).resolve().parent
old = here.parents[1] / "sb_sockowner_probe"
spec = importlib.util.spec_from_file_location("sbo_elf", old / "verify-ko.py")
elf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elf)


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


base_path = old / "target/vmlinux.btf"
module_path = here / "sbo_identity_bridge.ko"
base_blob = base_path.read_bytes()
blob, sections = elf.read_elf(module_path)
assert ".BTF" in sections, "Missing module BTF"
assert "__bpf_raw_tp_map" in sections, "Missing raw tracepoint map"
base, strings = parse(base_blob)
offset, length = sections[".BTF"]
local, _ = parse(blob[offset:offset + length], strings, len(base) + 1)
types = base | local
hooks = [(key, value) for key, value in local.items()
         if value["name"] == "btf_trace_sbo_identity_socket_create" and value["kind"] == 8]
assert len(hooks) == 1, "Expected exactly one typed tracepoint typedef"
typedef_id, definition = hooks[0]
pointer = types[definition["value"]]
assert pointer["kind"] == 2
prototype = types[pointer["value"]]
assert prototype["kind"] == 13 and prototype["value"] == 0 and len(prototype["parameters"]) == 2
data_pointer = types[prototype["parameters"][0]]
assert data_pointer["kind"] == 2 and data_pointer["value"] == 0
socket_pointer = types[prototype["parameters"][1]]
assert socket_pointer["kind"] == 2
socket_id = socket_pointer["value"]
assert socket_id in base, "Tracepoint socket type was not deduplicated against real base BTF"
assert base[socket_id]["name"] == "sock" and base[socket_id]["kind"] == 4
report = {
    "module": module_path.name,
    "module_sha256": hashlib.sha256(blob).hexdigest(),
    "base_btf_sha256": hashlib.sha256(base_blob).hexdigest(),
    "base_type_count": len(base),
    "module_type_count": len(local),
    "tracepoint_typedef_id": typedef_id,
    "tracepoint_prototype": "void (*)(void *, struct sock *)",
    "socket_type_id_in_device_base": socket_id,
    "module_btf_bytes": length,
    "raw_tracepoint_map_bytes": sections["__bpf_raw_tp_map"][1],
    "device_load_verified": False,
}
print(json.dumps(report, indent=2))
(here / ".build/btf-verification.json").write_text(json.dumps(report, indent=2) + "\n")
