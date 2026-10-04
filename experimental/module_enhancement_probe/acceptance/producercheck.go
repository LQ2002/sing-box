package main

// producercheck verifies the production chain on the device: the sbo_identity
// module (kernel/sbo_identity, loaded with capture_all=1) and the producer
// (common/socketidentity/bpf/creator.bpf.c) loaded and attached exactly as
// the collector does. This process creates sockets while it sits in
//
//	1. its starting cgroup (root "/" for a KernelSU shell)  -> snapshot
//	2. a cgroup named pid_<its own tgid>                     -> no snapshot
//	3. a cgroup named pid_<another pid>                      -> snapshot
//
// and every snapshot must carry the exe key whose path-map entry equals
// /proc/self/exe.
//
// and reads each socket's snapshot back by fd. The cgroups are created under
// /sys/fs/cgroup/sbo_producercheck and removed again; the process is moved
// back to its starting cgroup first.

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func runProducerCheck(args []string) error {
	flags := flag.NewFlagSet("producercheck", flag.ExitOnError)
	object := flags.String("object", "creator.bpf.o", "production producer object")
	n := flags.Int("n", 200, "sockets per case")
	_ = flags.Parse(args)

	spec, err := ebpf.LoadCollectionSpec(*object)
	if err != nil {
		return err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var verr *ebpf.VerifierError
		if errorsAs(err, &verr) {
			fmt.Printf("VERIFIER_REJECTED\n%+v\n", verr)
		}
		return err
	}
	defer coll.Close()
	fmt.Printf("VERIFIER_ACCEPTED insns=%d\n", len(spec.Programs["capture_creator"].Instructions))
	lnk, err := link.AttachTracing(link.TracingOptions{Program: coll.Programs["capture_creator"], AttachType: ebpf.AttachTraceRawTp})
	if err != nil {
		return fmt.Errorf("attach: %w", err)
	}
	defer lnk.Close()
	creators := coll.Maps["socket_creators"]
	paths := coll.Maps["exe_paths"]
	self, _ := os.Readlink("/proc/self/exe")
	fmt.Printf("SELF_EXE %s\n", self)

	start, err := procCgroup(os.Getpid())
	if err != nil {
		return err
	}
	base := filepath.Join(cgroupRoot, "sbo_producercheck")
	tgid := os.Getpid()
	own := filepath.Join(base, "pid_"+strconv.Itoa(tgid))
	other := filepath.Join(base, "pid_"+strconv.Itoa(tgid+100000))
	moveTo := func(dir string) error {
		return os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(tgid)), 0)
	}
	cleanup := func() {
		_ = moveTo(filepath.Join(cgroupRoot, start))
		_ = unix.Rmdir(own)
		_ = unix.Rmdir(other)
		_ = unix.Rmdir(base)
	}
	defer cleanup()
	for _, dir := range []string{base, own, other} {
		if err := os.Mkdir(dir, 0o755); err != nil && !os.IsExist(err) {
			return err
		}
	}

	check := func(label string, wantSnapshot bool) int {
		fds := make([]int, 0, *n)
		for i := 0; i < *n; i++ {
			family := unix.AF_INET
			if i%2 == 1 {
				family = unix.AF_INET6
			}
			fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				continue
			}
			fds = append(fds, fd)
		}
		present, valid := 0, 0
		for _, fd := range fds {
			raw := make([]byte, 64)
			if creators.Lookup(uint32(fd), &raw) == nil {
				present++
				cookie, _ := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
				var c struct {
					Cookie, Start       uint64
					PID, TID, UID, Flag uint32
					Comm                [16]byte
					NameHash, ExeKey    uint64
				}
				_ = binary.Read(bytes.NewReader(raw), binary.LittleEndian, &c)
				var path [280]byte
				pathOK := c.Flag&(1<<4) != 0 && paths.Lookup(&c.ExeKey, &path) == nil &&
					cString(path[24:24+binary.LittleEndian.Uint32(path[16:20])]) == self
				if c.Cookie == cookie && c.PID == uint32(tgid) && c.Flag&(1<<1) != 0 && pathOK {
					valid++
				}
			}
			unix.Close(fd)
		}
		cg, _ := procCgroup(tgid)
		bad := 0
		if wantSnapshot && valid != len(fds) || !wantSnapshot && present != 0 {
			bad = 1
		}
		fmt.Printf("PRODUCERCHECK case=%s cgroup=%s sockets=%d snapshots=%d valid=%d want_snapshot=%v ok=%v\n",
			label, cg, len(fds), present, valid, wantSnapshot, bad == 0)
		return bad
	}

	failures := check("start_cgroup", !strings.HasSuffix(start, "/pid_"+strconv.Itoa(tgid)))
	if err := moveTo(own); err != nil {
		return fmt.Errorf("move to own cgroup: %w", err)
	}
	failures += check("own_pid_cgroup", false)
	if err := moveTo(other); err != nil {
		return fmt.Errorf("move to other cgroup: %w", err)
	}
	failures += check("other_pid_cgroup", true)
	if err := moveTo(filepath.Join(cgroupRoot, start)); err != nil {
		return fmt.Errorf("move back: %w", err)
	}
	failures += check("back_to_start", !strings.HasSuffix(start, "/pid_"+strconv.Itoa(tgid)))
	if failures != 0 {
		return fmt.Errorf("producercheck: %d failing cases", failures)
	}
	fmt.Println("PRODUCERCHECK_PASS")
	return nil
}
