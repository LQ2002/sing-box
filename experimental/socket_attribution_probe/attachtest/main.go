// Which socket-creation attach points does this vendor kernel allow?
// Each program is a no-op (returns 0) and is detached after one second.
package main

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

var ret0 = asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}

func try(name string, f func() (link.Link, error)) {
	l, err := f()
	if err != nil {
		fmt.Printf("%-34s FAIL %v\n", name, err)
		return
	}
	time.Sleep(time.Second)
	l.Close()
	fmt.Printf("%-34s OK\n", name)
}

func prog(spec *ebpf.ProgramSpec) (*ebpf.Program, error) {
	spec.Instructions = ret0
	spec.License = "GPL"
	return ebpf.NewProgram(spec)
}

func main() {
	try("kprobe __sock_create", func() (link.Link, error) {
		p, err := prog(&ebpf.ProgramSpec{Type: ebpf.Kprobe})
		if err != nil {
			return nil, err
		}
		return link.Kprobe("__sock_create", p, nil)
	})
	try("kprobe inet_create", func() (link.Link, error) {
		p, err := prog(&ebpf.ProgramSpec{Type: ebpf.Kprobe})
		if err != nil {
			return nil, err
		}
		return link.Kprobe("inet_create", p, nil)
	})
	try("lsm socket_post_create", func() (link.Link, error) {
		p, err := prog(&ebpf.ProgramSpec{Type: ebpf.LSM, AttachType: ebpf.AttachLSMMac, AttachTo: "socket_post_create"})
		if err != nil {
			return nil, err
		}
		return link.AttachLSM(link.LSMOptions{Program: p})
	})
	try("fentry __sock_create", func() (link.Link, error) {
		p, err := prog(&ebpf.ProgramSpec{Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFEntry, AttachTo: "__sock_create"})
		if err != nil {
			return nil, err
		}
		return link.AttachTracing(link.TracingOptions{Program: p})
	})
	try("tp_btf sched_process_fork", func() (link.Link, error) {
		p, err := prog(&ebpf.ProgramSpec{Type: ebpf.Tracing, AttachType: ebpf.AttachTraceRawTp, AttachTo: "sched_process_fork"})
		if err != nil {
			return nil, err
		}
		return link.AttachTracing(link.TracingOptions{Program: p})
	})
	try("tracepoint syscalls/sys_enter_socket", func() (link.Link, error) {
		p, err := prog(&ebpf.ProgramSpec{Type: ebpf.TracePoint})
		if err != nil {
			return nil, err
		}
		return link.Tracepoint("syscalls", "sys_enter_socket", p, nil)
	})
	try("tracepoint sock/inet_sock_set_state", func() (link.Link, error) {
		p, err := prog(&ebpf.ProgramSpec{Type: ebpf.TracePoint})
		if err != nil {
			return nil, err
		}
		return link.Tracepoint("sock", "inet_sock_set_state", p, nil)
	})
}
