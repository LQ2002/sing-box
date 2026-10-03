package socketidentity

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"reflect"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/btf"
)

func validMetadata() (metadata, [16]byte) {
	boot := [16]byte{1, 2, 3}
	return metadata{
		Magic: metadataMagic, Version: abiVersion, ValueSize: ValueSize,
		BootID: boot, ProducerSHA: producerSHA, TraceSHA: traceSHA,
		MapID: 10, LinkID: 11, ProgramID: 12, ProgramTag: [8]byte{13},
	}, boot
}

func TestCreatorABIEqualsEmbeddedObject(t *testing.T) {
	spec, err := loadSpec()
	if err != nil {
		t.Fatal(err)
	}
	value, ok := spec.Maps[MapSymbol].Value.(*btf.Struct)
	if !ok || value.Size != ValueSize || binary.Size(Creator{}) != int(ValueSize) || unsafe.Sizeof(Creator{}) != uintptr(ValueSize) {
		t.Fatalf("incompatible creator value: %T %+v", spec.Maps[MapSymbol].Value, value)
	}
	fields := []struct {
		c, goName string
		offset    uintptr
	}{{"cookie", "Cookie", 0}, {"start_time_ns", "StartTimeNs", 8}, {"process_id", "ProcessID", 16}, {"thread_id", "ThreadID", 20}, {"user_id", "UserID", 24}, {"flags", "Flags", 28}, {"comm", "Comm", 32}}
	if len(value.Members) != len(fields) {
		t.Fatalf("unexpected BTF fields: %+v", value.Members)
	}
	for index, field := range fields {
		goField, _ := reflect.TypeOf(Creator{}).FieldByName(field.goName)
		member := value.Members[index]
		size, err := btf.Sizeof(member.Type)
		if err != nil || member.Name != field.c || member.Offset != btf.Bits(field.offset*8) || goField.Offset != field.offset || size != int(goField.Type.Size()) {
			t.Errorf("C/Go ABI mismatch for %s: BTF=%+v Go=%+v size=%d error=%v", field.c, member, goField, size, err)
		}
	}
	object, err := elf.NewFile(bytes.NewReader(producerObject))
	if err != nil {
		t.Fatal(err)
	}
	defer object.Close()
	if object.ByteOrder != binary.LittleEndian || object.Machine != elf.EM_BPF || object.Section(".BTF") == nil || object.Section(".BTF.ext") == nil {
		t.Fatal("embedded producer lost BPF little-endian/BTF/CO-RE information")
	}
}

func TestCreatorRejectsIncompleteIdentityButAllowsRoot(t *testing.T) {
	creator := Creator{Cookie: 1, StartTimeNs: 2, ProcessID: 3, ThreadID: 4, Flags: CreatorValid}
	if !creator.Valid() {
		t.Fatal("root UID zero must remain valid")
	}
	for _, mutate := range []func(*Creator){
		func(c *Creator) { c.Cookie = 0 }, func(c *Creator) { c.StartTimeNs = 0 },
		func(c *Creator) { c.ProcessID = 0 }, func(c *Creator) { c.ThreadID = 0 },
		func(c *Creator) { c.Flags = 0 }, func(c *Creator) { c.Flags = CreatorValid | 2 },
	} {
		changed := creator
		mutate(&changed)
		if changed.Valid() {
			t.Fatalf("accepted incomplete or unsupported identity: %+v", changed)
		}
	}
}

func TestMetadataRejectsStaleOrForeignIdentity(t *testing.T) {
	meta, boot := validMetadata()
	if err := meta.validate(boot); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*metadata){
		"owner": func(m *metadata) { m.Magic[0]++ }, "version": func(m *metadata) { m.Version++ },
		"layout": func(m *metadata) { m.ValueSize++ }, "boot": func(m *metadata) { m.BootID[0]++ },
		"producer": func(m *metadata) { m.ProducerSHA[0]++ }, "target": func(m *metadata) { m.TraceSHA[0]++ },
		"map": func(m *metadata) { m.MapID = 0 }, "link": func(m *metadata) { m.LinkID = 0 },
		"program": func(m *metadata) { m.ProgramID = 0 }, "tag": func(m *metadata) { m.ProgramTag = [8]byte{} },
		"reserved": func(m *metadata) { m.Reserved[0] = 1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := meta
			mutate(&changed)
			if err := changed.validate(boot); err == nil {
				t.Fatal("accepted stale or foreign metadata")
			}
		})
	}
}
