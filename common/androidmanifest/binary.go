// Package androidmanifest reads the process names an installed APK declares,
// directly from its compiled AndroidManifest.xml and resources.arsc.
//
// The eBPF inbound uses it to name the package behind a process of a shared
// or system UID: ActivityManager keys running processes by (process name,
// UID) (ProcessList.mProcessNames.get(name, uid)), so if exactly one package
// of that UID declares the process name, that is the package.
//
// Only what that needs is parsed: the manifest's package attribute and every
// android:process attribute, with string-resource references resolved
// against the default configuration of resources.arsc, which is what
// PackageParser's getNonConfigurationString does. Binary layouts follow
// frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h; anything
// unexpected is an error, never a guess.
package androidmanifest

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
)

// Chunk types and flags from ResourceTypes.h.
const (
	resStringPoolType     = 0x0001
	resTableType          = 0x0002
	resXMLType            = 0x0003
	resXMLStartElement    = 0x0102
	resXMLResourceMapType = 0x0180
	resTablePackageType   = 0x0200
	resTableTypeType      = 0x0201

	stringPoolUTF8 = 1 << 8

	typeFlagSparse   = 0x01
	typeFlagOffset16 = 0x02
	entryFlagComplex = 0x0001
	entryFlagCompact = 0x0008
	noEntry          = 0xFFFFFFFF

	valueTypeReference = 0x01
	valueTypeString    = 0x03

	// android.R.attr.process; documented constant value 16842769.
	attrProcess = 0x01010011
)

var errTruncated = errors.New("truncated binary resource")

type chunk struct {
	kind       uint16
	headerSize int
	size       int
	data       []byte // the whole chunk, header included
}

func readChunk(data []byte, offset int) (chunk, error) {
	if offset < 0 || offset+8 > len(data) {
		return chunk{}, errTruncated
	}
	c := chunk{
		kind:       binary.LittleEndian.Uint16(data[offset:]),
		headerSize: int(binary.LittleEndian.Uint16(data[offset+2:])),
		size:       int(binary.LittleEndian.Uint32(data[offset+4:])),
	}
	if c.headerSize < 8 || c.size < c.headerSize || offset+c.size > len(data) {
		return chunk{}, errTruncated
	}
	c.data = data[offset : offset+c.size]
	return c, nil
}

func u16(data []byte, offset int) (uint16, error) {
	if offset < 0 || offset+2 > len(data) {
		return 0, errTruncated
	}
	return binary.LittleEndian.Uint16(data[offset:]), nil
}

func u32(data []byte, offset int) (uint32, error) {
	if offset < 0 || offset+4 > len(data) {
		return 0, errTruncated
	}
	return binary.LittleEndian.Uint32(data[offset:]), nil
}

// stringPool is a ResStringPool chunk; strings are decoded on demand.
type stringPool struct {
	data    []byte
	count   int
	utf8    bool
	strings int // stringsStart, relative to the chunk
}

func parseStringPool(c chunk) (*stringPool, error) {
	if c.kind != resStringPoolType || c.headerSize < 28 {
		return nil, fmt.Errorf("not a string pool: type %#x", c.kind)
	}
	count, _ := u32(c.data, 8)
	flags, _ := u32(c.data, 16)
	stringsStart, _ := u32(c.data, 20)
	if int(count) > (len(c.data)-c.headerSize)/4 {
		return nil, errTruncated
	}
	return &stringPool{data: c.data, count: int(count), utf8: flags&stringPoolUTF8 != 0, strings: int(stringsStart)}, nil
}

func (p *stringPool) get(index uint32) (string, error) {
	if p == nil || int(index) >= p.count {
		return "", fmt.Errorf("string index %d out of range", index)
	}
	headerSize := int(binary.LittleEndian.Uint16(p.data[2:]))
	offset, err := u32(p.data, headerSize+int(index)*4)
	if err != nil {
		return "", err
	}
	position := p.strings + int(offset)
	if p.utf8 {
		// UTF-16 length, then UTF-8 byte length; each 1 or 2 bytes, high bit
		// of the first byte marks the 2-byte form.
		_, position, err = utf8Length(p.data, position)
		if err != nil {
			return "", err
		}
		var length int
		length, position, err = utf8Length(p.data, position)
		if err != nil {
			return "", err
		}
		if position+length > len(p.data) {
			return "", errTruncated
		}
		return string(p.data[position : position+length]), nil
	}
	first, err := u16(p.data, position)
	if err != nil {
		return "", err
	}
	length := int(first)
	position += 2
	if first&0x8000 != 0 {
		second, err := u16(p.data, position)
		if err != nil {
			return "", err
		}
		length = int(first&0x7FFF)<<16 | int(second)
		position += 2
	}
	if position+length*2 > len(p.data) {
		return "", errTruncated
	}
	units := make([]uint16, length)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(p.data[position+i*2:])
	}
	return string(utf16.Decode(units)), nil
}

func utf8Length(data []byte, position int) (int, int, error) {
	if position >= len(data) {
		return 0, 0, errTruncated
	}
	first := data[position]
	if first&0x80 == 0 {
		return int(first), position + 1, nil
	}
	if position+1 >= len(data) {
		return 0, 0, errTruncated
	}
	return int(first&0x7F)<<8 | int(data[position+1]), position + 2, nil
}
