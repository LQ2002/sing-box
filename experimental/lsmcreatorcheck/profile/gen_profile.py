"""Print a copy of creator_lsm.bpf.c with stage timers in capture_creator.

Stages (indexes of the per-CPU prof_ns array, summed by lsmcreatorcheck):
  0 entry -> past the kernel-thread check and own-cgroup gate
  1 -> fill_creator (cookie, pid/tid/uid, comm, birth time)
  2 -> record_process_name (argv[0] read + FNV-1a)
  3 -> record_executable (exe key, exe_paths lookup, slow path on a miss)
  4 -> store_creator (sk storage allocation)
  5 count of invocations that reached the end
bpf_ktime_get_ns itself costs a few tens of ns per checkpoint, so the sum
is above the production program's run time; the split is what matters.
"""
import sys

source = open(sys.argv[1], encoding="utf-8").read()

prelude = """
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} prof_ns SEC(".maps");

static __always_inline void prof(__u32 index, __u64 *last)
{
    __u64 now = bpf_ktime_get_ns();
    __u64 *value = bpf_map_lookup_elem(&prof_ns, &index);
    if (value)
        *value += now - *last;
    *last = now;
}

SEC("lsm/socket_post_create")"""

steps = [
    ('SEC("lsm/socket_post_create")', prelude),
    ("    struct task_struct *task = bpf_get_current_task_btf();\n    struct task_struct___lsm *t",
     "    __u64 prof_last = bpf_ktime_get_ns();\n    struct task_struct *task = bpf_get_current_task_btf();\n    struct task_struct___lsm *t"),
    ("        return 0;\n\n    struct socket_creator creator = {};",
     "        return 0;\n    prof(0, &prof_last);\n\n    struct socket_creator creator = {};"),
    ("&creator))\n        return 0;\n    if (kernel) {",
     "&creator))\n        return 0;\n    prof(1, &prof_last);\n    if (kernel) {"),
    ("        record_process_name(mm->arg_start, mm->arg_end, &creator);\n",
     "        record_process_name(mm->arg_start, mm->arg_end, &creator);\n        prof(2, &prof_last);\n"),
    ("        __u32 flags = record_executable(task, &key);\n",
     "        __u32 flags = record_executable(task, &key);\n        prof(3, &prof_last);\n"),
    ("    store_creator(sk, &creator);\n    return 0;",
     "    store_creator(sk, &creator);\n    prof(4, &prof_last);\n    __u32 count = 5;\n"
     "    __u64 *runs = bpf_map_lookup_elem(&prof_ns, &count);\n    if (runs)\n        *runs += 1;\n    return 0;"),
]
for old, new in steps:
    if source.count(old) != 1:
        sys.exit("gen_profile: anchor not found once: " + old[:60])
    source = source.replace(old, new)
sys.stdout.write(source)
