//go:build linux && arm64 && integration

package socketidentity

// Opt-in target-kernel acceptance. The outer harness must supply an isolated
// mount namespace, a fresh dedicated bpffs, and an already loaded bridge with
// capture_all=1. This file never mounts filesystems, loads modules, or changes
// networking. Its own sockets are never bound, connected, or sent on.
//
//   SBO_SOCKET_CREATOR_DEVICE_TEST=1
//   SBO_SOCKET_CREATOR_TEST_BPFFS=/mnt/sbo-creator-integration/bpf
//   SBO_SOCKET_CREATOR_TEST_PIN_PATH=/mnt/sbo-creator-integration/bpf/collector
//   ./collector.test -test.run '^TestDeviceCollectorPersistence$' -test.v -test.timeout 180s
//
// Optional live TC check, supplied by the same outer harness:
//   SBO_SOCKET_CREATOR_CORE_TEST_BINARY=/absolute/path/core.test
// The fixed TestTCSocketCreatorLiveProducer subprocess owns its private network
// fixture. This collector remains open throughout that subprocess and relays its
// complete output. No arbitrary command or test regex is accepted from the env.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	deviceOptInEnv = "SBO_SOCKET_CREATOR_DEVICE_TEST"
	deviceMountEnv = "SBO_SOCKET_CREATOR_TEST_BPFFS"
	devicePinEnv   = "SBO_SOCKET_CREATOR_TEST_PIN_PATH"
	deviceChildEnv = "SBO_SOCKET_CREATOR_TEST_CHILD"
)

type deviceObjectIDs struct {
	MapID     uint32 `json:"map_id"`
	LinkID    uint32 `json:"link_id"`
	ProgramID uint32 `json:"program_id"`
}

type deviceProcessReport struct {
	PID int `json:"pid"`
	deviceObjectIDs
}

type deviceCreatorTruth struct {
	PID, TID, UID uint32
	StartTicks    uint64
	ClockTicks    uint64
	Comm          [16]byte
}

type deviceHeldSocket struct {
	FD, Family, Kind int
	Phase            string
	Cookie           uint64
	Truth            deviceCreatorTruth
	Snapshot         Creator
	Captured         bool
}

func requireDeviceCollectorPath(t *testing.T) string {
	t.Helper()
	if os.Getenv(deviceOptInEnv) != "1" {
		t.Skip("set " + deviceOptInEnv + "=1 with an isolated collector bpffs to run")
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("collector acceptance requires real and effective root UID")
	}
	mountPath, pinPath := os.Getenv(deviceMountEnv), os.Getenv(devicePinEnv)
	if !filepath.IsAbs(mountPath) || filepath.Clean(mountPath) != mountPath || mountPath == "/" || mountPath == "/sys/fs/bpf" {
		t.Fatalf("%s must identify a dedicated absolute bpffs mount, not the system mount", deviceMountEnv)
	}
	if !filepath.IsAbs(pinPath) || filepath.Clean(pinPath) != pinPath || filepath.Dir(pinPath) != mountPath || pinPath == DefaultPinPath {
		t.Fatalf("%s must be an explicit direct child of the dedicated bpffs mount", devicePinEnv)
	}
	if resolved, err := filepath.EvalSymlinks(mountPath); err != nil || resolved != mountPath {
		t.Fatalf("dedicated mount must exist without symlink components: path=%s resolved=%s error=%v", mountPath, resolved, err)
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(mountPath, &stat); err != nil || uint64(stat.Type) != uint64(unix.BPF_FS_MAGIC) {
		t.Fatalf("dedicated mount is not bpffs: %v", err)
	}
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	var mountDevice string
	var devices []string
	unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		separator := -1
		for index := 6; index < len(fields); index++ {
			if fields[index] == "-" {
				separator = index
				break
			}
		}
		if separator < 0 || separator+1 >= len(fields) || fields[separator+1] != "bpf" {
			continue
		}
		devices = append(devices, fields[2])
		if unescape.Replace(fields[4]) == mountPath {
			if mountDevice != "" || unescape.Replace(fields[3]) != "/" {
				t.Fatal("ambiguous or subtree-bound collector mount")
			}
			mountDevice = fields[2]
		}
	}
	if mountDevice == "" {
		t.Fatal("explicit collector path is not a bpffs mount point in this namespace")
	}
	aliases := 0
	for _, device := range devices {
		if device == mountDevice {
			aliases++
		}
	}
	if aliases != 1 {
		t.Fatal("collector bpffs is shared with another visible mount; use a fresh dedicated filesystem")
	}
	entries, err := os.ReadDir(mountPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != filepath.Base(pinPath) || !entry.IsDir() {
			t.Fatalf("dedicated bpffs contains unrelated entry %q", entry.Name())
		}
	}
	if err := checkBridge(); err != nil {
		t.Fatal(err)
	}
	return pinPath
}

func deviceSelfTruth(t *testing.T) deviceCreatorTruth {
	t.Helper()
	truth := deviceCreatorTruth{PID: uint32(os.Getpid()), TID: uint32(unix.Gettid()), UID: uint32(os.Getuid())}
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 {
		t.Fatal("invalid /proc/self/stat")
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) <= 19 {
		t.Fatal("short /proc/self/stat")
	}
	truth.StartTicks, err = strconv.ParseUint(fields[19], 10, 64)
	if err != nil || truth.StartTicks == 0 {
		t.Fatalf("invalid process birth ticks: %v", err)
	}
	auxv, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		t.Fatal(err)
	}
	for offset := 0; offset+16 <= len(auxv); offset += 16 {
		if binary.LittleEndian.Uint64(auxv[offset:]) == 17 { // AT_CLKTCK
			truth.ClockTicks = binary.LittleEndian.Uint64(auxv[offset+8:])
			break
		}
	}
	if truth.ClockTicks == 0 || truth.ClockTicks > 1_000_000_000 {
		t.Fatal("kernel auxiliary vector did not supply a valid AT_CLKTCK")
	}
	comm, err := os.ReadFile(fmt.Sprintf("/proc/self/task/%d/comm", truth.TID))
	if err != nil {
		t.Fatal(err)
	}
	comm = bytes.TrimSuffix(comm, []byte{'\n'})
	if len(comm) == 0 || len(comm) >= len(truth.Comm) {
		t.Fatalf("unexpected current thread comm length: %d", len(comm))
	}
	copy(truth.Comm[:], comm)
	return truth
}

func deviceCreateSocket(t *testing.T, held *[]*deviceHeldSocket, phase string, family, kind int) *deviceHeldSocket {
	t.Helper()
	truth := deviceSelfTruth(t)
	fd, err := unix.Socket(family, kind|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socket phase=%s family=%d kind=%d: %v", phase, family, kind, err)
	}
	record := &deviceHeldSocket{FD: fd, Family: family, Kind: kind, Phase: phase, Truth: truth}
	*held = append(*held, record)
	record.Cookie, err = unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil || record.Cookie == 0 {
		t.Fatalf("SO_COOKIE for phase=%s family=%d kind=%d: %v", phase, family, kind, err)
	}
	if uint32(unix.Gettid()) != truth.TID {
		t.Fatal("socket creator migrated despite LockOSThread")
	}
	return record
}

func deviceCreateMatrix(t *testing.T, held *[]*deviceHeldSocket, phase string) []*deviceHeldSocket {
	t.Helper()
	var created []*deviceHeldSocket
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		for _, kind := range []int{unix.SOCK_DGRAM, unix.SOCK_STREAM} {
			created = append(created, deviceCreateSocket(t, held, phase, family, kind))
		}
	}
	return created
}

func deviceVerifySocket(t *testing.T, creators *ebpf.Map, record *deviceHeldSocket) {
	t.Helper()
	var got Creator
	key := uint32(record.FD)
	if err := creators.Lookup(&key, &got); err != nil {
		t.Fatalf("lookup phase=%s family=%d kind=%d cookie=%d: %v", record.Phase, record.Family, record.Kind, record.Cookie, err)
	}
	want := record.Truth
	if !got.Valid() || got.Cookie != record.Cookie || got.ProcessID != want.PID || got.ThreadID != want.TID || got.UserID != want.UID || got.Comm != want.Comm {
		t.Fatalf("creator mismatch phase=%s: got=%+v cookie=%d truth=%+v", record.Phase, got, record.Cookie, want)
	}
	// /proc exports USER_HZ ticks, not exact nanoseconds. Avoid overflowing the
	// product on long uptimes and allow one exported tick of conversion precision.
	gotTicks := got.StartTimeNs/1_000_000_000*want.ClockTicks + got.StartTimeNs%1_000_000_000*want.ClockTicks/1_000_000_000
	difference := gotTicks
	if gotTicks >= want.StartTicks {
		difference = gotTicks - want.StartTicks
	} else {
		difference = want.StartTicks - gotTicks
	}
	if difference > 1 {
		t.Fatalf("creator birth mismatch: kernel_ns=%d kernel_ticks=%d proc_ticks=%d clk_tck=%d", got.StartTimeNs, gotTicks, want.StartTicks, want.ClockTicks)
	}
	if record.Captured && record.Snapshot != got {
		t.Fatalf("existing creation snapshot changed: before=%+v after=%+v", record.Snapshot, got)
	}
	record.Snapshot, record.Captured = got, true
	t.Logf("CREATOR_SNAPSHOT phase=%s family=%d kind=%d cookie=%d tgid=%d tid=%d uid=%d birth_ns=%d proc_ticks=%d clk_tck=%d flags=%d comm_hex=%x", record.Phase, record.Family, record.Kind, got.Cookie, got.ProcessID, got.ThreadID, got.UserID, got.StartTimeNs, want.StartTicks, want.ClockTicks, got.Flags, got.Comm)
}

func deviceVerifyUnknown(t *testing.T, creators *ebpf.Map, record *deviceHeldSocket) {
	t.Helper()
	var got Creator
	key := uint32(record.FD)
	if err := creators.Lookup(&key, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("socket created before collector was backfilled: cookie=%d value=%+v error=%v", record.Cookie, got, err)
	}
}

func deviceReadObjectIDs(t *testing.T, collector *Collector, pinPath string) deviceObjectIDs {
	t.Helper()
	mapInfo, err := collector.Map().Info()
	if err != nil {
		t.Fatal(err)
	}
	mapID, present := mapInfo.ID()
	if !present || mapID == 0 {
		t.Fatal("creator map ID unavailable")
	}
	attached, err := link.LoadPinnedLink(filepath.Join(pinPath, linkPin), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer attached.Close()
	linkInfo, err := attached.Info()
	if err != nil || linkInfo.ID == 0 || linkInfo.Program == 0 {
		t.Fatalf("producer link identity unavailable: info=%+v error=%v", linkInfo, err)
	}
	return deviceObjectIDs{MapID: uint32(mapID), LinkID: uint32(linkInfo.ID), ProgramID: uint32(linkInfo.Program)}
}

func deviceVerifyWhileClosed(t *testing.T, pinPath string, want deviceObjectIDs, records []*deviceHeldSocket) {
	t.Helper()
	creators, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, mapPin), &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		t.Fatalf("load pinned map without an open Collector: %v", err)
	}
	defer creators.Close()
	info, err := creators.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, present := info.ID()
	if !present || uint32(id) != want.MapID {
		t.Fatal("pinned storage map changed while every Collector was closed")
	}
	for _, record := range records {
		deviceVerifySocket(t, creators, record)
	}
}

func deviceReplaceEnv(environment []string, replacements map[string]string) []string {
	result := make([]string, 0, len(environment)+len(replacements))
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		if _, replaced := replacements[key]; !replaced {
			result = append(result, entry)
		}
	}
	for key, value := range replacements {
		result = append(result, key+"="+value)
	}
	return result
}

func deviceRunProcessRestart(t *testing.T, pinPath string, want deviceObjectIDs) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestDeviceCollectorProcessHelper$", "-test.v", "-test.timeout=20s")
	cmd.Env = deviceReplaceEnv(os.Environ(), map[string]string{deviceChildEnv: "reopen-and-exit", devicePinEnv: pinPath})
	cmd.ExtraFiles = []*os.File{writer}
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	err = cmd.Wait()
	t.Logf("COLLECTOR_PROCESS_OUTPUT\n%s", output.String())
	if err != nil {
		t.Fatalf("collector restart subprocess: %v", err)
	}
	data, err := io.ReadAll(io.LimitReader(reader, 4096))
	if err != nil {
		t.Fatal(err)
	}
	var report deviceProcessReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("invalid child report %q: %v", data, err)
	}
	if report.PID == os.Getpid() || report.PID != cmd.ProcessState.Pid() || report.deviceObjectIDs != want {
		t.Fatalf("new process did not reuse the exact collector: report=%+v expected=%+v", report, want)
	}
	t.Logf("COLLECTOR_PROCESS_EXIT child_pid=%d parent_pid=%d map_id=%d link_id=%d program_id=%d exited=true", report.PID, os.Getpid(), want.MapID, want.LinkID, want.ProgramID)
}

func deviceRunLiveTC(t *testing.T, pinPath string) {
	t.Helper()
	binaryPath := os.Getenv("SBO_SOCKET_CREATOR_CORE_TEST_BINARY")
	if binaryPath == "" {
		t.Log("live TC subprocess was not requested; collector lifecycle only")
		return
	}
	if !filepath.IsAbs(binaryPath) || filepath.Clean(binaryPath) != binaryPath {
		t.Fatal("SBO_SOCKET_CREATOR_CORE_TEST_BINARY must be an absolute executable path")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binaryPath, "-test.run=^TestTCSocketCreatorLiveProducer$", "-test.v", "-test.timeout=60s")
	cmd.Env = deviceReplaceEnv(os.Environ(), map[string]string{
		"SING_EBPF_INTEGRATION":     "1",
		"SING_EBPF_CREATOR_MAP_PIN": filepath.Join(pinPath, mapPin),
	})
	output, err := cmd.CombinedOutput()
	t.Logf("LIVE_PRODUCER_CORE_OUTPUT\n%s", output)
	if err != nil {
		t.Fatalf("live producer TC integration: %v", err)
	}
	if bytes.Contains(output, []byte("--- SKIP:")) {
		t.Fatal("live producer TC subprocess did not run and pass every requested case")
	}
	for _, name := range []string{
		"TestTCSocketCreatorLiveProducer",
		"TestTCSocketCreatorLiveProducer/tcp-first-packet",
		"TestTCSocketCreatorLiveProducer/udp-first-packet",
		"TestTCSocketCreatorLiveProducer/tcp-delivery",
	} {
		if !bytes.Contains(output, []byte("--- PASS: "+name+" (")) {
			t.Fatalf("live producer TC subprocess did not execute and pass %s", name)
		}
	}
}

func TestDeviceCollectorPersistence(t *testing.T) {
	pinPath := requireDeviceCollectorPath(t)
	if os.Getenv(deviceChildEnv) != "" {
		t.Fatal("main collector test may not run as its subprocess helper")
	}
	entries, err := os.ReadDir(pinPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("exclusive collector pin directory is not empty; refusing to reuse or clean existing objects")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var held []*deviceHeldSocket
	var collectors []*Collector
	owned := false
	t.Cleanup(func() {
		for index := len(collectors) - 1; index >= 0; index-- {
			if err := collectors[index].Close(); err != nil {
				t.Errorf("close test collector: %v", err)
			}
		}
		if owned {
			if err := Remove(pinPath); err != nil {
				t.Errorf("remove owned test collector pins %s: %v", pinPath, err)
			}
		}
		for _, socket := range held {
			if err := unix.Close(socket.FD); err != nil {
				t.Errorf("close held test socket: %v", err)
			}
		}
	})
	before := deviceCreateSocket(t, &held, "before-open", unix.AF_INET, unix.SOCK_DGRAM)
	first, err := Open(Config{PinPath: pinPath})
	if err != nil {
		t.Fatalf("initial real Collector.Open: %v", err)
	}
	collectors, owned = append(collectors, first), true
	ids := deviceReadObjectIDs(t, first, pinPath)
	t.Logf("COLLECTOR_INITIAL map_id=%d link_id=%d program_id=%d", ids.MapID, ids.LinkID, ids.ProgramID)
	deviceVerifyUnknown(t, first.Map(), before)
	initial := deviceCreateMatrix(t, &held, "initial-open")
	for _, socket := range initial {
		deviceVerifySocket(t, first.Map(), socket)
	}
	deviceRunLiveTC(t, pinPath)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	duringClose := deviceCreateMatrix(t, &held, "all-collectors-closed")
	deviceVerifyWhileClosed(t, pinPath, ids, duringClose)
	deviceRunProcessRestart(t, pinPath, ids)
	afterProcessExit := deviceCreateMatrix(t, &held, "collector-process-exited")
	deviceVerifyWhileClosed(t, pinPath, ids, afterProcessExit)

	second, err := Open(Config{PinPath: pinPath})
	if err != nil {
		t.Fatalf("reopen real Collector: %v", err)
	}
	collectors = append(collectors, second)
	if got := deviceReadObjectIDs(t, second, pinPath); got != ids {
		t.Fatalf("restart replaced persistent kernel objects: before=%+v after=%+v", ids, got)
	}
	deviceVerifyUnknown(t, second.Map(), before)
	for _, socket := range held[1:] {
		deviceVerifySocket(t, second.Map(), socket)
	}
	for _, socket := range deviceCreateMatrix(t, &held, "reopened") {
		deviceVerifySocket(t, second.Map(), socket)
	}
	third, err := Open(Config{PinPath: pinPath})
	if err != nil {
		t.Fatalf("open concurrent Collector: %v", err)
	}
	collectors = append(collectors, third)
	if got := deviceReadObjectIDs(t, third, pinPath); got != ids {
		t.Fatalf("concurrent Open changed object IDs: %+v", got)
	}
	if err := Remove(pinPath); !errors.Is(err, ErrBusy) {
		t.Fatalf("Remove with two live Collectors: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Remove(pinPath); !errors.Is(err, ErrBusy) {
		t.Fatalf("Remove with one live Collector: %v", err)
	}
	deviceVerifySocket(t, third.Map(), initial[0])
	if err := third.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Remove(pinPath); err != nil {
		t.Fatalf("Remove after all Collector instances closed: %v", err)
	}
	owned = false
	entries, err = os.ReadDir(pinPath)
	if err != nil || len(entries) != 0 {
		t.Fatalf("Remove left pins or removed the stable lock directory: entries=%v error=%v", entries, err)
	}
	t.Logf("COLLECTOR_CLEANUP pins=0 retained_sockets=%d map_id=%d link_id=%d program_id=%d", len(held), ids.MapID, ids.LinkID, ids.ProgramID)
}

// The parent invokes only this test in a separate process. The report goes to
// an inherited pipe, and os.Exit deliberately bypasses Close so kernel process
// exit, rather than explicit userspace cleanup, closes the collector descriptors.
func TestDeviceCollectorProcessHelper(t *testing.T) {
	if os.Getenv(deviceChildEnv) != "reopen-and-exit" {
		t.Skip("internal collector restart subprocess")
	}
	pinPath := requireDeviceCollectorPath(t)
	entries, err := os.ReadDir(pinPath)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if empty, err := pinSetState(names); empty || err != nil {
		t.Fatalf("subprocess requires an existing complete parent-owned collector: %v", err)
	}
	sink := os.NewFile(3, "collector-restart-report")
	if sink == nil {
		t.Fatal("restart report pipe is missing")
	}
	defer sink.Close()
	if info, err := sink.Stat(); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("restart report descriptor is not a pipe: %v", err)
	}
	collector, err := Open(Config{PinPath: pinPath})
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close() // Kept for failure paths; os.Exit bypasses it on success.
	report := deviceProcessReport{PID: os.Getpid(), deviceObjectIDs: deviceReadObjectIDs(t, collector, pinPath)}
	if err := json.NewEncoder(sink).Encode(report); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}
