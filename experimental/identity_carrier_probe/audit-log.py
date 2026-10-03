#!/usr/bin/env python3
"""Independently audit the extended device JSONL, keeping 64-bit tokens exact."""
import json
import sys
from pathlib import Path

events = [json.loads(line) for line in Path(sys.argv[1]).read_text(encoding="utf-8-sig").splitlines()
          if line.startswith("{")]
expected_cases = {
    "root_matrix", "shell_matrix_a", "shell_matrix_b", "token_snapshot", "unregistered",
    "nonleader", "creator_exit", "registration_uid_mismatch", "registration_tgid_mismatch",
    "registration_deleted", "late_registration", "native_fork", "native_leader_exec",
    "native_nonleader_exec", "native_accept",
}
cases, before, first, groups, findings, tokens = {}, {}, {}, {}, {}, {}
current = None
for event in events:
    kind = event["event"]
    if kind == "case_begin":
        current = event["name"]
        assert current not in groups
        groups[current] = []
    elif kind == "case_result":
        assert event["name"] not in cases
        cases[event["name"]] = event["status"]
    elif kind == "registered":
        reg = event["registration"]
        token = reg["TokenLo"], reg["TokenHi"]
        assert token != (0, 0) and token not in tokens
        tokens[token] = reg
    elif kind == "socket_before_send":
        identity = event["identity"]
        cookie = identity["Cookie"]
        assert cookie and cookie not in before
        assert identity["ObservedNS"] >= identity["StartNS"] > 0
        if identity["Flags"] == 1:
            reg = tokens[identity["TokenLo"], identity["TokenHi"]]
            assert all(identity[key] == reg[key] for key in ("Generation", "TGID", "UID"))
        else:
            assert identity["Flags"] == 0
            assert all(identity[key] == 0 for key in ("TokenLo", "TokenHi", "Generation"))
        before[cookie] = identity
        groups[current].append(identity)
    elif kind == "first_packet":
        obs = event["observation"]
        identity = obs["Identity"]
        cookie = identity["Cookie"]
        assert cookie not in first and before[cookie] == identity
        assert obs["FirstNS"] >= identity["ObservedNS"] and obs["Ifindex"] == 1
        flags = obs["PacketFlags"]
        assert flags & 3 == (1 if identity["Family"] == 2 else 2)
        if flags & 16:
            assert obs["PacketCount"] == 1
        else:
            assert flags & 12 == 12 and not flags & 32
        if event.get("creator_exited"):
            assert event["sender_pid"] != identity["TGID"]
        first[cookie] = event
    elif kind == "lifecycle_finding":
        findings[event["case"]] = event

assert set(cases) == expected_cases and all(status == "pass" for status in cases.values())
assert len(before) == 35 and len(first) == 34
assert set(before) - set(first) == {findings["native_accept"]["listener_cookie"]}
assert findings["native_accept"]["accepted_cookie"] not in before
assert findings["native_accept"]["socket_storage_present"] is False
assert findings["native_accept"]["payload_verified"] is True
assert [item["Flags"] for item in groups["native_fork"]] == [1, 0, 1]
parent_socket = groups["native_fork"][0]
assert first[parent_socket["Cookie"]]["sender_pid"] == findings["native_fork"]["child_pid"]
assert parent_socket["TGID"] == findings["native_fork"]["parent_pid"]
assert findings["native_fork"]["task_registration_inherited"] is False
assert [item["Flags"] for item in groups["native_leader_exec"]] == [1, 1]
assert len({item["Generation"] for item in groups["native_leader_exec"]}) == 1
assert [item["Flags"] for item in groups["native_nonleader_exec"]] == [1, 0, 1]
assert len({item["TGID"] for item in groups["native_nonleader_exec"]}) == 1
assert len({item["StartNS"] for item in groups["native_nonleader_exec"]}) == 1
assert findings["native_nonleader_exec"]["task_registration_retained"] is False
for name in ("registration_uid_mismatch", "registration_tgid_mismatch", "late_registration"):
    assert [item["Flags"] for item in groups[name]] == [0, 1]
assert [item["Flags"] for item in groups["registration_deleted"]] == [1, 0]
stats, = [event for event in events if event["event"] == "capture_stats"]
assert stats["values"] == [35, 0, 28, 7, 2, 0, 1, 0, 0, 0]
filtered, = [event for event in events if event["event"] == "filtered_socket_families"]
assert filtered["counts"] == {"1": 1}
result, = [event for event in events if event["event"] == "run_result"]
assert result["status"] == "pass"
print(json.dumps({"audit": "pass", "cases": len(cases), "creation_snapshots": len(before),
                  "matching_first_packets": len(first), "accepted_sockets_without_identity": 1,
                  "distinct_registration_tokens": len(tokens), "native_findings": findings}, indent=2))
