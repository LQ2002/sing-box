//go:build linux

// Isolated synthetic identity-carrier verification. Run only through the
// external private-network-namespace wrapper; it does not manage kernel modules.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
func emit(event string, fields map[string]any) {
	fields["event"] = event
	if err := json.NewEncoder(os.Stdout).Encode(fields); err != nil {
		panic(err)
	}
}

func main() {
	worker := flag.Bool("worker", false, "internal worker mode")
	uid := flag.Int("worker-uid", 0, "internal worker UID (0 or 2000)")
	object := flag.String("object", "probe.bpf.o", "BPF object containing creation producer and private TCX observer")
	parameter := flag.String("module-param", "/sys/module/sbo_identity_bridge/parameters/target_tgid", "already-loaded diagnostic bridge target parameter")
	timeout := flag.Duration("timeout", 90*time.Second, "maximum parent run duration")
	flag.Parse()
	if *worker {
		if err := workerMain(*uid); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, deadline := context.WithTimeout(ctx, *timeout)
	defer deadline()
	err := run(ctx, *object, *parameter)
	emit("run_result", map[string]any{"status": func() string {
		if err != nil {
			return "fail"
		}
		return "pass"
	}(), "error": errorText(err), "unrun_extensions": []string{"pure fork inheritance", "exec/nonleader exec", "accept clone", "io_uring", "AOSP package registration", "production sing-ebpf assignment integration"}})
	if err != nil {
		os.Exit(1)
	}
}
