# tracepoint_producer_probe

Feasibility probe for a socket identity producer **without** the
`sbo_identity_bridge` kernel module (ANDROID_ATTRIBUTION_PLAN.md,
"免模块路线与模块增强试验"). Observation only: the TC program sits at TCX
head on every up, non-loopback interface's egress and returns `TCX_NEXT`.

- `tp_btf/inet_sock_set_state`, transition to `TCP_SYN_SENT`: TCP identity in
  the connect() caller's context, before the SYN is sent.
- `tp_btf/sock_send_length`, UDP: identity after the first `sendmsg` returned.
- TC egress observer: per TCP SYN and per UDP packet without identity, a
  ring-buffer record (interface, cookie, socket UID) so duplicates across
  interfaces (production sing-box redirects) can be told apart.
- Every identity's argv[0] is compared with `/proc/<pid>/cmdline`.

Build: `bash build.sh` in WSL as likayo. Run on the device as root:
`./tracepoint-producer-probe -object tp.bpf.o -duration 180s`.

`results/`: run1 (idle, counters only), run2 (idle, per-interface/per-socket
breakdown), run3 (controlled `toybox nc` TCP/UDP workload as UID 10136 and
root; the UDP part hung on `nc -u` and was killed after the probe had exited,
so only 4 UDP sockets were exercised).
