//go:build linux

// creator_memprobe measures what loading the persistent socket creator
// collector (common/socketidentity) leaves live on the Go heap, and writes a
// heap profile for `go tool pprof`. It needs root and the bridge module loaded
// with capture_all=1; it uses its own pin directory and removes it afterwards.
//
//	creator-memprobe -pin /sys/fs/bpf/sing-box/memprobe -profile heap.pb.gz
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"

	"github.com/sagernet/sing-box/common/socketidentity"
)

func heap(label string) {
	runtime.GC()
	debug.FreeOSMemory()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	rss := ""
	if status, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range splitLines(string(status)) {
			if len(line) > 6 && line[:6] == "VmRSS:" {
				rss = line[6:]
			}
		}
	}
	fmt.Printf("MEM %s heap_inuse_kb=%d heap_sys_kb=%d heap_released_kb=%d stack_sys_kb=%d gc_sys_kb=%d other_sys_kb=%d sys_kb=%d rss=%s\n",
		label, stats.HeapInuse/1024, stats.HeapSys/1024, stats.HeapReleased/1024, stats.StackSys/1024, stats.GCSys/1024, stats.OtherSys/1024, stats.Sys/1024, rss)
	// Resident mappings of at least 1 MiB, to see where RSS lives.
	if smaps, err := os.ReadFile("/proc/self/smaps"); err == nil {
		header := ""
		for _, line := range splitLines(string(smaps)) {
			var kb int
			if n, _ := fmt.Sscanf(line, "Rss: %d kB", &kb); n == 1 {
				if kb >= 1024 {
					fmt.Printf("    MAP rss_kb=%d %s\n", kb, header)
				}
				continue
			}
			if len(line) > 0 && line[len(line)-1] != 'B' && !hasColonField(line) {
				header = line
			}
		}
	}
}

// hasColonField reports smaps detail lines ("Size:", "VmFlags: ...").
func hasColonField(line string) bool {
	for index := 0; index < len(line) && index < 20; index++ {
		if line[index] == ':' {
			return index > 0 && line[0] >= 'A' && line[0] <= 'Z'
		}
		if line[index] == ' ' {
			return false
		}
	}
	return false
}

func splitLines(text string) []string {
	var lines []string
	start := 0
	for index := 0; index < len(text); index++ {
		if text[index] == '\n' {
			lines = append(lines, text[start:index])
			start = index + 1
		}
	}
	return lines
}

func main() {
	pin := flag.String("pin", "/sys/fs/bpf/sing-box/memprobe", "dedicated pin directory")
	profile := flag.String("profile", "heap.pb.gz", "heap profile output")
	flag.Parse()
	heap("before")
	collector, err := socketidentity.Open(socketidentity.Config{PinPath: *pin})
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		os.Exit(1)
	}
	heap("after_open")
	file, err := os.Create(*profile)
	if err == nil {
		_ = pprof.WriteHeapProfile(file)
		_ = file.Close()
	}
	_ = collector.Close()
	heap("after_close")
	if err := socketidentity.Remove(*pin); err != nil {
		fmt.Fprintln(os.Stderr, "remove:", err)
		os.Exit(1)
	}
	heap("after_remove")
}
