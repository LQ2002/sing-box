// tracepoint_producer_probe measures whether socket identity snapshots can be
// produced without the sbo_identity_bridge kernel module (see bpf/tp.bpf.c).
// It only observes: TC programs are attached at TCX head on egress and return
// TCX_NEXT, tracepoint programs never change state outside their own map.
//
//	tracepoint-producer-probe -object tp.bpf.o -duration 120s
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type event struct {
	Cookie        uint64
	PID           uint32
	TID           uint32
	UID           uint32
	Source        uint32
	PacketsBefore uint32
	ArgvRC        int32
	NameHash      uint64
	Argv          [128]byte
}

type tcEvent struct {
	Cookie        uint64
	IfIndex       uint32
	Protocol      uint32
	SocketUID     uint32
	WithIdentity  uint32
	IdentityPID   uint32
	PacketsBefore uint32
}

var statNames = []string{
	"syn_sent_calls", "syn_sent_created", "send_udp_calls", "send_udp_created",
	"tc_tcp_syn", "tc_tcp_syn_with_identity", "tc_udp_packets", "tc_udp_with_identity",
	"tc_udp_socket_first", "udp_filled_late", "udp_later_covered", "kthread", "argv_fail",
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func main() {
	object := flag.String("object", "tp.bpf.o", "compiled probe")
	duration := flag.Duration("duration", 120*time.Second, "observation window")
	flag.Parse()
	spec, err := ebpf.LoadCollectionSpec(*object)
	if err != nil {
		fail(err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			fmt.Printf("VERIFIER_REJECTED\n%+v\n", verr)
		}
		fail(err)
	}
	defer collection.Close()
	fmt.Println("VERIFIER_ACCEPTED")
	for _, name := range []string{"on_state", "on_send"} {
		l, err := link.AttachTracing(link.TracingOptions{Program: collection.Programs[name]})
		if err != nil {
			fail(fmt.Errorf("attach %s: %w", name, err))
		}
		defer l.Close()
	}
	interfaces, _ := net.Interfaces()
	attached := []string{}
	for _, ifc := range interfaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		l, err := link.AttachTCX(link.TCXOptions{Interface: ifc.Index, Program: collection.Programs["observe"], Attach: ebpf.AttachTCXEgress, Anchor: link.Head()})
		if err != nil {
			fmt.Println("skip", ifc.Name, err)
			continue
		}
		defer l.Close()
		attached = append(attached, ifc.Name)
	}
	fmt.Println("TC_EGRESS_OBSERVERS", attached)
	reader, err := ringbuf.NewReader(collection.Maps["events"])
	if err != nil {
		fail(err)
	}
	tcReader, err := ringbuf.NewReader(collection.Maps["tc_events"])
	if err != nil {
		fail(err)
	}
	var tcEvents []tcEvent
	tcDone := make(chan struct{})
	go func() {
		defer close(tcDone)
		var rec ringbuf.Record
		for tcReader.ReadInto(&rec) == nil {
			var ev tcEvent
			if binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev) == nil {
				tcEvents = append(tcEvents, ev)
			}
		}
	}()
	go func() { time.Sleep(*duration); _ = reader.Close(); _ = tcReader.Close() }()
	fmt.Printf("OBSERVING %s\n", *duration)

	summary := map[string]int{}
	identityCookies := map[uint64]string{}
	before := map[string]int{}
	mismatches := 0
	var record ringbuf.Record
	for {
		if err := reader.ReadInto(&record); err != nil {
			break
		}
		var ev event
		if binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev) != nil {
			continue
		}
		source := map[uint32]string{1: "tcp_syn_sent", 2: "udp_send"}[ev.Source]
		argv := cString(ev.Argv[:])
		hash := fnv.New64a()
		_, _ = hash.Write([]byte(argv))
		summary[source+"_events"]++
		identityCookies[ev.Cookie] = source
		if hash.Sum64() != ev.NameHash && ev.ArgvRC > 1 {
			summary[source+"_hash_disagrees"]++
		}
		cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", ev.PID))
		switch {
		case err != nil:
			summary[source+"_proc_gone"]++
		case cString(cmdline) == argv:
			summary[source+"_argv_match"]++
		default:
			summary[source+"_argv_mismatch"]++
			if mismatches < 10 {
				fmt.Printf("MISMATCH source=%s pid=%d tid=%d uid=%d argv=%q proc=%q\n", source, ev.PID, ev.TID, ev.UID, argv, cString(cmdline))
			}
			mismatches++
		}
		if ev.Source == 2 {
			key := "udp_packets_before_identity=" + fmt.Sprint(min(ev.PacketsBefore, 3))
			before[key]++
		}
	}
	fmt.Println("BPF_COUNTERS (summed over CPUs):")
	var values []uint64
	for index, name := range statNames {
		if err := collection.Maps["stats"].Lookup(uint32(index), &values); err != nil {
			fail(err)
		}
		var total uint64
		for _, v := range values {
			total += v
		}
		fmt.Printf("  %s=%d\n", name, total)
	}
	print := func(title string, m map[string]int) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Println(title)
		for _, k := range keys {
			fmt.Printf("  %s=%d\n", k, m[k])
		}
	}
	print("IDENTITY_EVENTS:", summary)
	<-tcDone
	names := map[uint32]string{}
	for _, ifc := range interfaces {
		names[uint32(ifc.Index)] = ifc.Name
	}
	perInterface := map[string]int{}
	type socketView struct {
		protocol     uint32
		uid          uint32
		ifaces       map[string]bool
		withAtFirst  bool
		sightings    int
		laterWith    bool
	}
	sockets := map[uint64]*socketView{}
	for _, ev := range tcEvents {
		proto := map[uint32]string{6: "tcp_syn", 17: "udp_before_identity"}[ev.Protocol]
		perInterface[fmt.Sprintf("%s %s with_identity=%d", names[ev.IfIndex], proto, ev.WithIdentity)]++
		view := sockets[ev.Cookie]
		if view == nil {
			view = &socketView{protocol: ev.Protocol, uid: ev.SocketUID, ifaces: map[string]bool{}, withAtFirst: ev.WithIdentity != 0}
			sockets[ev.Cookie] = view
		}
		view.ifaces[names[ev.IfIndex]] = true
		view.sightings++
		if ev.WithIdentity != 0 {
			view.laterWith = true
		}
	}
	print("TC_SIGHTINGS_BY_INTERFACE:", perInterface)
	perSocket := map[string]int{}
	for cookie, view := range sockets {
		ifaces := make([]string, 0, len(view.ifaces))
		for name := range view.ifaces {
			ifaces = append(ifaces, name)
		}
		sort.Strings(ifaces)
		_, identityLater := identityCookies[cookie]
		key := fmt.Sprintf("proto=%d first_had_identity=%t identity_event_seen=%t ifaces=%s", view.protocol, view.withAtFirst, identityLater, strings.Join(ifaces, "+"))
		perSocket[key]++
		if view.protocol == 6 && !view.withAtFirst {
			fmt.Printf("TCP_SYN_WITHOUT_IDENTITY cookie=%d socket_uid=%d sightings=%d identity_event_seen=%t ifaces=%v\n", cookie, view.uid, view.sightings, identityLater, ifaces)
		}
	}
	print("PER_SOCKET (unique cookies):", perSocket)
	print("UDP_FIRST_SEND (packets TC saw before the identity, capped at 3):", before)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "ERROR:", err)
	os.Exit(1)
}
