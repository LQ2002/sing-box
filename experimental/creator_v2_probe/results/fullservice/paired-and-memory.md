# Paired forwarding and memory runs (2026-10-04)

Transcribed verbatim from the console output of the runs. The device-side
files (`/data/local/tmp/sbe3-fix/perf-paired*.txt`) were deleted during
cleanup before being pulled, so this transcription is the only copy; the
printed lines below were filtered by `sed` at run time (dropped fields: p90,
max, byte counts, first_error, and in runs 2-3 also the constant fields).

Setup: `stage3e2e/isolated-netns.sh` private client/peer namespaces with a
veth echo peer (10.211.0.2:7000); production sing-box stopped (user approved);
a `sleep` placeholder as the protected PID. `fullservice/perf-paired.sh`
alternates the two variants per round, each with its own kernel hooks:
old = `7c12b1de` + `sb_sockowner_probe.ko` (sha `968f9164...`);
new = `b1af4410` + `sbo_identity_bridge.ko` (capture_all=1) + producer v2.
Workload: `stage3load -mode echo -uid 1000 -argv0 com.miui.securitycenter.remote
-conns 1000 -bytes 65536`; configs `perf-old.json` / `perf-new.json` route by
`package_name`, so every connection is attributed. Sanity check before the
runs: old logged `found process path: .../stage3load, user id: 1000` (no
package, shared UID); new logged `found package name: com.miui.securitycenter,
process path: .../stage3load, user id: 1000, pid: ...` (E2 by the creation
name; path shown because the exe inode matched).

## Run 1: no settle (load starts ~3 s after start), default Go madvise

```
round=1,build=old wall=696ms connect_p50=131.094µs connect_p99=272.396µs echo_mib_per_s=89.812 data_rtt_p50=515.364µs data_rtt_p99=899.323µs transaction_p50=651.875µs transaction_p99=1.099636ms singbox_cpu_ticks=68 rss_kb_before=30652 rss_kb_after=31332
round=1,build=new wall=778ms connect_p50=168.333µs connect_p99=297.031µs echo_mib_per_s=80.384 data_rtt_p50=559.635µs data_rtt_p99=972.657µs transaction_p50=732.24µs transaction_p99=1.169688ms singbox_cpu_ticks=75 rss_kb_before=47512 rss_kb_after=48040
round=2,build=new wall=771ms connect_p50=164.895µs connect_p99=294.063µs echo_mib_per_s=81.034 data_rtt_p50=555.26µs data_rtt_p99=922.5µs transaction_p50=731.667µs transaction_p99=1.121042ms singbox_cpu_ticks=74 rss_kb_before=49104 rss_kb_after=49632
round=2,build=old wall=659ms connect_p50=124.583µs connect_p99=247.239µs echo_mib_per_s=94.777 data_rtt_p50=489.792µs data_rtt_p99=895.416µs transaction_p50=613.958µs transaction_p99=1.108125ms singbox_cpu_ticks=63 rss_kb_before=32712 rss_kb_after=33324
round=3,build=old wall=648ms connect_p50=125.312µs connect_p99=235.364µs echo_mib_per_s=96.448 data_rtt_p50=483.958µs data_rtt_p99=790.365µs transaction_p50=612.396µs transaction_p99=936.302µs singbox_cpu_ticks=63 rss_kb_before=30852 rss_kb_after=31560
round=3,build=new wall=798ms connect_p50=173.073µs connect_p99=336.041µs echo_mib_per_s=78.342 data_rtt_p50=565.521µs data_rtt_p99=1.131614ms transaction_p50=745.417µs transaction_p99=1.410573ms singbox_cpu_ticks=78 rss_kb_before=50804 rss_kb_after=51372
round=4,build=new wall=779ms connect_p50=164.583µs connect_p99=289.948µs echo_mib_per_s=80.261 data_rtt_p50=568.646µs data_rtt_p99=927.135µs transaction_p50=742.292µs transaction_p99=1.127865ms singbox_cpu_ticks=75 rss_kb_before=46712 rss_kb_after=47188
round=4,build=old wall=777ms connect_p50=162.447µs connect_p99=349.583µs echo_mib_per_s=80.393 data_rtt_p50=563.229µs data_rtt_p99=1.084844ms transaction_p50=735.885µs transaction_p99=1.297917ms singbox_cpu_ticks=74 rss_kb_before=31856 rss_kb_after=32448
round=5,build=old wall=2.11s connect_p50=148.646µs connect_p99=3.772708ms echo_mib_per_s=29.617 data_rtt_p50=935.052µs data_rtt_p99=9.773177ms transaction_p50=1.410625ms transaction_p99=10.277917ms singbox_cpu_ticks=164 rss_kb_before=30392 rss_kb_after=31512
round=5,build=new wall=2.729s connect_p50=187.291µs connect_p99=491.459µs echo_mib_per_s=22.904 data_rtt_p50=2.327552ms data_rtt_p99=4.498438ms transaction_p50=2.536719ms transaction_p99=4.819948ms singbox_cpu_ticks=274 rss_kb_before=47324 rss_kb_after=47832
```

## Run 2: 20 s settle after start, default Go madvise (screen off)

```
round=1,build=old wall=1.512s connect_p50=312.031µs connect_p99=874.636µs echo_mib_per_s=41.323 data_rtt_p50=1.106407ms data_rtt_p99=2.118594ms transaction_p50=1.443333ms transaction_p99=2.708906ms singbox_cpu_ticks=148 rss_kb_before=31920 rss_kb_after=32444 settle_cpu_ticks=0 startup_cpu_ticks=19
round=1,build=new wall=1.462s connect_p50=308.646µs connect_p99=713.594µs echo_mib_per_s=42.759 data_rtt_p50=1.079844ms data_rtt_p99=1.95ms transaction_p50=1.404167ms transaction_p99=2.427396ms singbox_cpu_ticks=139 rss_kb_before=51508 rss_kb_after=52016 settle_cpu_ticks=2 startup_cpu_ticks=58
round=2,build=new wall=1.431s connect_p50=290.313µs connect_p99=1.033594ms echo_mib_per_s=43.683 data_rtt_p50=1.032605ms data_rtt_p99=2.809636ms transaction_p50=1.360521ms transaction_p99=3.306875ms singbox_cpu_ticks=134 rss_kb_before=64572 rss_kb_after=65112 settle_cpu_ticks=0 startup_cpu_ticks=56
round=2,build=old wall=1.436s connect_p50=288.229µs connect_p99=751.667µs echo_mib_per_s=43.527 data_rtt_p50=1.048698ms data_rtt_p99=1.864947ms transaction_p50=1.348073ms transaction_p99=2.364948ms singbox_cpu_ticks=145 rss_kb_before=31208 rss_kb_after=32068 settle_cpu_ticks=0 startup_cpu_ticks=20
round=3,build=old wall=1.43s connect_p50=288.229µs connect_p99=728.854µs echo_mib_per_s=43.721 data_rtt_p50=1.040781ms data_rtt_p99=1.845469ms transaction_p50=1.347864ms transaction_p99=2.337605ms singbox_cpu_ticks=145 rss_kb_before=31212 rss_kb_after=31912 settle_cpu_ticks=0 startup_cpu_ticks=27
round=3,build=new wall=1.395s connect_p50=287.136µs connect_p99=805.052µs echo_mib_per_s=44.788 data_rtt_p50=1.040885ms data_rtt_p99=1.991042ms transaction_p50=1.353125ms transaction_p99=2.409948ms singbox_cpu_ticks=138 rss_kb_before=58892 rss_kb_after=59420 settle_cpu_ticks=0 startup_cpu_ticks=53
round=4,build=new wall=1.511s connect_p50=306.094µs connect_p99=673.334µs echo_mib_per_s=41.376 data_rtt_p50=1.086354ms data_rtt_p99=1.972552ms transaction_p50=1.41073ms transaction_p99=2.458125ms singbox_cpu_ticks=150 rss_kb_before=51076 rss_kb_after=51660 settle_cpu_ticks=0 startup_cpu_ticks=47
round=4,build=old wall=1.507s connect_p50=310.156µs connect_p99=838.75µs echo_mib_per_s=41.467 data_rtt_p50=1.065209ms data_rtt_p99=2.289323ms transaction_p50=1.401667ms transaction_p99=2.824219ms singbox_cpu_ticks=148 rss_kb_before=32884 rss_kb_after=34064 settle_cpu_ticks=0 startup_cpu_ticks=20
```

## Run 3: 20 s settle, new build with `madvdontneed=1` (release/LDFLAGS)

```
round=1,build=old wall=1.366s connect_p50=277.813µs connect_p99=757.5µs echo_mib_per_s=45.765 data_rtt_p50=992.812µs data_rtt_p99=2.004167ms transaction_p50=1.285156ms transaction_p99=2.448438ms singbox_cpu_ticks=137 rss_kb_before=30948 rss_kb_after=31948 startup_cpu_ticks=19
round=1,build=new wall=762ms connect_p50=162.709µs connect_p99=297.656µs echo_mib_per_s=82.057 data_rtt_p50=553.594µs data_rtt_p99=912.5µs transaction_p50=723.907µs transaction_p99=1.171563ms singbox_cpu_ticks=73 rss_kb_before=33132 rss_kb_after=33528 startup_cpu_ticks=52
round=2,build=new wall=769ms connect_p50=165.99µs connect_p99=291.667µs echo_mib_per_s=81.321 data_rtt_p50=559.531µs data_rtt_p99=981.979µs transaction_p50=729.948µs transaction_p99=1.206302ms singbox_cpu_ticks=72 rss_kb_before=33012 rss_kb_after=33448 startup_cpu_ticks=52
round=2,build=old wall=683ms connect_p50=134.635µs connect_p99=315.417µs echo_mib_per_s=91.551 data_rtt_p50=498.177µs data_rtt_p99=859.791µs transaction_p50=637.813µs transaction_p99=1.152969ms singbox_cpu_ticks=64 rss_kb_before=31008 rss_kb_after=31804 startup_cpu_ticks=21
round=3,build=old wall=750ms connect_p50=156.928µs connect_p99=339.115µs echo_mib_per_s=83.363 data_rtt_p50=545.573µs data_rtt_p99=986.667µs transaction_p50=713.229µs transaction_p99=1.246823ms singbox_cpu_ticks=72 rss_kb_before=30848 rss_kb_after=31596 startup_cpu_ticks=24
round=3,build=new wall=665ms connect_p50=128.541µs connect_p99=252.292µs echo_mib_per_s=93.920 data_rtt_p50=494.323µs data_rtt_p99=865.156µs transaction_p50=627.292µs transaction_p99=1.040312ms singbox_cpu_ticks=63 rss_kb_before=33284 rss_kb_after=33356 startup_cpu_ticks=49
round=4,build=new wall=679ms connect_p50=131.094µs connect_p99=288.073µs echo_mib_per_s=92.066 data_rtt_p50=492.344µs data_rtt_p99=1.029792ms transaction_p50=627.24µs transaction_p99=1.202135ms singbox_cpu_ticks=64 rss_kb_before=31636 rss_kb_after=32868 startup_cpu_ticks=42
round=4,build=old wall=758ms connect_p50=164.947µs connect_p99=310.937µs echo_mib_per_s=82.492 data_rtt_p50=546.094µs data_rtt_p99=942.709µs transaction_p50=717.083µs transaction_p99=1.197343ms singbox_cpu_ticks=72 rss_kb_before=30516 rss_kb_after=31252 startup_cpu_ticks=18
```

## Memory split (same new binary, three configs; `fullservice/memsplit.sh`)

Default Go madvise (b1af4410):
```
cycle=1 config=creator rss_kb_5s=61376 rss_kb_20s=61376 rss_kb_after_load=61920 rss_kb_60s=61920 cpu_ticks=189
cycle=1 config=module  rss_kb_5s=41452 rss_kb_20s=41452 rss_kb_after_load=41988 rss_kb_60s=41988 cpu_ticks=189
cycle=1 config=noattr  rss_kb_5s=31332 rss_kb_20s=31332 rss_kb_after_load=32020 rss_kb_60s=32020 cpu_ticks=159
cycle=2 config=creator rss_kb_5s=50252 rss_kb_20s=50252 rss_kb_after_load=50764 rss_kb_60s=50764 cpu_ticks=202
cycle=2 config=module  rss_kb_5s=36868 rss_kb_20s=36868 rss_kb_after_load=37456 rss_kb_60s=37456 cpu_ticks=192
cycle=2 config=noattr  rss_kb_5s=32396 rss_kb_20s=32396 rss_kb_after_load=33056 rss_kb_60s=33056 cpu_ticks=176
```
smaps_rollup 20 s after start: creator Rss 50588 kB (Anonymous 38520), module
Rss 37596 kB (Anonymous 25660); no vmlinux BTF mapping left resident.

With `madvdontneed=1`:
```
cycle=1 config=creator rss_kb_5s=34092 rss_kb_20s=34092 rss_kb_after_load=33188 rss_kb_60s=33188 cpu_ticks=184
cycle=1 config=module  rss_kb_5s=31516 rss_kb_20s=31580 rss_kb_after_load=32252 rss_kb_60s=32252 cpu_ticks=161
cycle=1 config=noattr  rss_kb_5s=28504 rss_kb_20s=28504 rss_kb_after_load=30936 rss_kb_60s=30936 cpu_ticks=149
cycle=2 config=creator rss_kb_5s=33040 rss_kb_20s=33040 rss_kb_after_load=32948 rss_kb_60s=32948 cpu_ticks=202
cycle=2 config=module  rss_kb_5s=36512 rss_kb_20s=36512 rss_kb_after_load=32280 rss_kb_60s=32280 cpu_ticks=160
cycle=2 config=noattr  rss_kb_5s=28384 rss_kb_20s=28440 rss_kb_after_load=30988 rss_kb_60s=30988 cpu_ticks=151
```

## Collector-only memory probe (`experimental/creator_memprobe`)

Opening the collector (producer v2 load + pin validation) in an otherwise
empty process, after `runtime.GC()` + `debug.FreeOSMemory()`:
```
default:                 before rss 4796 kB  after_open heap_sys 32000 kB heap_released 30688 kB rss 32232 kB
GODEBUG=madvdontneed=1:  after_open rss 8188 kB
GODEBUG=disablethp=1:    after_open rss 25076 kB
-X runtime.godebugDefault=madvdontneed=1: before rss 4572 kB  after_open rss 7796 kB
```
Live heap after open was about 1 MB (heap_inuse); the rest was heap the Go
runtime had released with MADV_FREE, which stays in RSS until the kernel
needs the pages. Go only defaults to MADV_DONTNEED for GOOS=linux
(src/runtime/runtime1.go parseRuntimeDebugVars), not GOOS=android.

## FreeOSMemory control (madvdontneed build, creator config, 3 cycles)

```
build=with-FreeOSMemory rss_kb_5s=31948 32388 33412   rss_kb_63s=31948 30992 33412
build=without           rss_kb_5s=32856 31468 33352   rss_kb_63s=32904 31468 33352
```
No difference, so the extra call was not kept.
