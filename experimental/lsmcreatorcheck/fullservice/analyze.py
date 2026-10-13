"""Compare a full-service accuracy run with ActivityManager truth.

Input: the test instance's accuracy.log and the dumpsys activity processes
snapshots taken during the run (fullservice.sh accuracy). Each "found ..."
line names what sing-box attributed to a socket creator, with its PID when the
creator snapshot supplied one. Truth for a PID is the ProcessRecord that
dumpsys showed for it (process name, UID, packageList); a PID is never
matched across a different process name, so PID reuse cannot pass as truth.

Classification per attributed line:
  correct    the attributed package is in that PID's packageList
  wrong      a package was attributed that is not in the packageList
  unknown    no package (creator UID is shared/system and the name was not
             declared by exactly one package, or a native process)
  no_truth   no ProcessRecord for the PID (native daemon, or exited before
             the next snapshot) -- reported, never counted as correct
Group-level lines without a PID (UID fast path) are checked against the UID's
packages instead.
Usage: analyze.py <run-dir>
"""
import glob
import json
import os
import re
import sys
from collections import Counter

run = sys.argv[1]
record_re = re.compile(r'^\s*\*(APP|PERS)\*\s+UID\s+(\d+)\s+ProcessRecord\{[0-9a-f]+\s+(\d+):(.*)/([a-z0-9]+)\}')
packages_re = re.compile(r'^\s*packageList=\{(.*)\}')
truth = {}  # pid -> {(name, uid, packages)}
for path in sorted(glob.glob(os.path.join(run, 'dumpsys-*.txt'))):
    current = None
    for line in open(path, encoding='utf-8', errors='replace'):
        match = record_re.match(line)
        if match:
            current = [int(match.group(3)), match.group(4), int(match.group(2)), None]
            continue
        match = packages_re.match(line)
        if match and current and current[3] is None:
            current[3] = tuple(sorted(p.strip() for p in match.group(1).split(',') if p.strip()))
            truth.setdefault(current[0], set()).add((current[1], current[2], current[3]))
            current = None

found_re = re.compile(r'found (.*)$')
results = []
for line in open(os.path.join(run, 'accuracy.log'), encoding='utf-8', errors='replace'):
    match = found_re.search(line)
    if not match or 'inbound/ebpf' not in line:
        continue
    fields = {}
    for part in match.group(1).split(', '):
        key, _, value = part.partition(': ')
        fields[key] = value
    package = fields.get('package name', '')
    pid = int(fields['pid']) if 'pid' in fields else 0
    user = fields.get('user', fields.get('user id', ''))
    entry = {'package': package, 'pid': pid, 'user': user, 'path': fields.get('process path', '')}
    if pid == 0:
        entry['class'] = 'group_level' if package else 'unknown_no_pid'
    elif pid not in truth:
        entry['class'] = 'no_truth' if not package else 'no_truth_with_package'
    else:
        records = truth[pid]
        entry['truth'] = sorted([list(r[:2]) + [list(r[2])] for r in records])
        if not package:
            entry['class'] = 'unknown'
        elif all(package in r[2] for r in records):
            entry['class'] = 'correct'
        else:
            entry['class'] = 'wrong'
    results.append(entry)

counts = Counter(r['class'] for r in results)
print('ATTRIBUTED_LINES', len(results), dict(counts))
for entry in results:
    print(json.dumps(entry, ensure_ascii=False))
