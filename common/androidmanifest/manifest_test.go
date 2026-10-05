package androidmanifest

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Fixtures are real aapt2 output; testdata/build.ps1 rebuilds them from
// testdata/src.

func TestPackageProcessesPlain(t *testing.T) {
	processes, err := PackageProcesses("p.plain", filepath.Join("testdata", "plain.apk"))
	if err != nil {
		t.Fatal(err)
	}
	// application ":main" is the default for the activity; the service and
	// receiver use global names; the provider is private.
	want := []string{"global.proc", "p.plain:main", "p.plain:prov", "system"}
	if !slices.Equal(processes, want) {
		t.Fatalf("processes = %v, want %v", processes, want)
	}
}

// android:process given as @string references, including a reference to a
// reference, resolved from resources.arsc, in each table encoding aapt2 can
// produce.
func TestPackageProcessesResolvesReferences(t *testing.T) {
	for _, apk := range []string{"reference.apk", "reference-sparse.apk", "reference-compact.apk"} {
		t.Run(apk, func(t *testing.T) {
			processes, err := PackageProcesses("p.ref", filepath.Join("testdata", apk))
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"p.ref.custom", "p.ref:svc"}
			if !slices.Equal(processes, want) {
				t.Fatalf("processes = %v, want %v", processes, want)
			}
		})
	}
}

// A code directory with base and split APKs: the split's component counts,
// an APK of another package in the same directory does not, and a reference
// in a split without its own resources.arsc resolves through the base APK's
// table.
func TestPackageProcessesReadsSplits(t *testing.T) {
	processes, err := PackageProcesses("p.split", filepath.Join("testdata", "split"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"p.split", "p.split:feature", "p.split:fromBase"}
	if !slices.Equal(processes, want) {
		t.Fatalf("processes = %v, want %v", processes, want)
	}
	if _, err = PackageProcesses("p.absent", filepath.Join("testdata", "split")); err == nil {
		t.Fatal("a package with no APK in the directory was accepted")
	}
}

// Every proper prefix of a real manifest must fail cleanly: no panic, no
// partial result presented as complete.
func TestParseManifestRejectsTruncation(t *testing.T) {
	data := zipEntry(t, filepath.Join("testdata", "reference.apk"), "AndroidManifest.xml")
	tableData := zipEntry(t, filepath.Join("testdata", "reference.apk"), "resources.arsc")
	table, err := parseResourceTable(tableData)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = parseManifest(data, table.resolveString); err != nil {
		t.Fatal(err)
	}
	for cut := 0; cut < len(data); cut++ {
		if _, err := parseManifest(data[:cut], table.resolveString); err == nil {
			t.Fatalf("a manifest cut at %d of %d parsed", cut, len(data))
		}
	}
	for cut := 0; cut < len(tableData); cut++ {
		_, _ = parseResourceTable(tableData[:cut]) // must not panic
	}
}

func zipEntry(t *testing.T, apk, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(apk)
	if err != nil {
		t.Fatal(err)
	}
	// Reuse the reader the code uses.
	archive, err := zipReader(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range archive.File {
		if file.Name == name {
			content, err := readZipFile(file)
			if err != nil {
				t.Fatal(err)
			}
			return content
		}
	}
	t.Fatalf("%s has no %s", apk, name)
	return nil
}

// typeChunk builds a ResTable_type chunk with a default config, for the
// entry encodings aapt2 may or may not choose for a tiny fixture.
func typeChunk(flags uint8, entryCount uint32, offsets []byte, entries []byte) chunk {
	const configSize = 64
	headerSize := 20 + configSize
	var buffer bytes.Buffer
	write := func(value any) { _ = binary.Write(&buffer, binary.LittleEndian, value) }
	write(uint16(resTableTypeType))
	write(uint16(headerSize))
	write(uint32(headerSize + len(offsets) + len(entries)))
	write(uint8(1))
	write(flags)
	write(uint16(0))
	write(entryCount)
	write(uint32(headerSize + len(offsets)))
	write(uint32(configSize))
	buffer.Write(make([]byte, configSize-4))
	buffer.Write(offsets)
	buffer.Write(entries)
	data := buffer.Bytes()
	return chunk{kind: resTableTypeType, headerSize: headerSize, size: len(data), data: data}
}

func fullEntry(dataType uint8, data uint32) []byte {
	entry := make([]byte, 16)
	binary.LittleEndian.PutUint16(entry[0:], 8) // entry size
	entry[11] = dataType                        // Res_value at 8: size, res0, dataType
	binary.LittleEndian.PutUint16(entry[8:], 8)
	binary.LittleEndian.PutUint32(entry[12:], data)
	return entry
}

func compactEntry(dataType uint8, data uint32) []byte {
	entry := make([]byte, 8)
	binary.LittleEndian.PutUint16(entry[2:], uint16(dataType)<<8|entryFlagCompact)
	binary.LittleEndian.PutUint32(entry[4:], data)
	return entry
}

func TestEntryValueEncodings(t *testing.T) {
	le32 := func(values ...uint32) []byte {
		out := make([]byte, 4*len(values))
		for i, v := range values {
			binary.LittleEndian.PutUint32(out[i*4:], v)
		}
		return out
	}
	le16 := func(values ...uint16) []byte {
		out := make([]byte, 2*len(values))
		for i, v := range values {
			binary.LittleEndian.PutUint16(out[i*2:], v)
		}
		return out
	}
	entries := append(fullEntry(valueTypeString, 7), fullEntry(valueTypeReference, 0x7f010002)...)
	cases := []struct {
		name  string
		chunk chunk
	}{
		{"dense", typeChunk(0, 3, le32(0, noEntry, 16), entries)},
		{"offset16", typeChunk(typeFlagOffset16, 3, le16(0, 0xFFFF, 4), entries)},
		{"sparse", typeChunk(typeFlagSparse, 2, le32(0<<16|0, 4<<16|2), entries)},
		{"compact", typeChunk(0, 3, le32(0, noEntry, 8),
			append(compactEntry(valueTypeString, 7), compactEntry(valueTypeReference, 0x7f010002)...))},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			dataType, data, found, err := entryValue(testCase.chunk, 0)
			if err != nil || !found || dataType != valueTypeString || data != 7 {
				t.Fatalf("entry 0 = %#x %d %v %v", dataType, data, found, err)
			}
			if _, _, found, err = entryValue(testCase.chunk, 1); err != nil || found {
				t.Fatalf("entry 1 should be absent: %v %v", found, err)
			}
			dataType, data, found, err = entryValue(testCase.chunk, 2)
			if err != nil || !found || dataType != valueTypeReference || data != 0x7f010002 {
				t.Fatalf("entry 2 = %#x %#x %v %v", dataType, data, found, err)
			}
			if _, _, found, _ = entryValue(testCase.chunk, 9); found {
				t.Fatal("an index past the table was found")
			}
		})
	}
}
