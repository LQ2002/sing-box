package androidmanifest

import (
	"fmt"
)

// resourceTable resolves string resources of the default configuration, the
// only ones getNonConfigurationString accepts for android:process.
type resourceTable struct {
	values *stringPool
	// types maps package id << 8 | type id to the default-configuration type
	// chunks of that type (normally one).
	types map[uint32][]chunk
}

func parseResourceTable(data []byte) (*resourceTable, error) {
	root, err := readChunk(data, 0)
	if err != nil {
		return nil, err
	}
	if root.kind != resTableType {
		return nil, fmt.Errorf("resources.arsc: unexpected root chunk %#x", root.kind)
	}
	table := &resourceTable{types: make(map[uint32][]chunk)}
	for offset := root.headerSize; offset < root.size; {
		c, err := readChunk(root.data, offset)
		if err != nil {
			return nil, err
		}
		switch c.kind {
		case resStringPoolType:
			if table.values == nil {
				table.values, err = parseStringPool(c)
				if err != nil {
					return nil, err
				}
			}
		case resTablePackageType:
			if err = table.addPackage(c); err != nil {
				return nil, err
			}
		}
		offset += c.size
	}
	return table, nil
}

func (t *resourceTable) addPackage(pkg chunk) error {
	packageID, err := u32(pkg.data, 8)
	if err != nil {
		return err
	}
	for offset := pkg.headerSize; offset < pkg.size; {
		c, err := readChunk(pkg.data, offset)
		if err != nil {
			return err
		}
		if c.kind == resTableTypeType && isDefaultConfig(c) {
			key := packageID<<8 | uint32(c.data[8])
			t.types[key] = append(t.types[key], c)
		}
		offset += c.size
	}
	return nil
}

// isDefaultConfig reports whether a ResTable_type chunk's ResTable_config is
// the default one: every field after the leading size is zero.
func isDefaultConfig(c chunk) bool {
	const configOffset = 20 // header 8, id 1, flags 1, reserved 2, entryCount 4, entriesStart 4
	size, err := u32(c.data, configOffset)
	if err != nil || configOffset+int(size) > c.headerSize {
		return false
	}
	for _, b := range c.data[configOffset+4 : configOffset+int(size)] {
		if b != 0 {
			return false
		}
	}
	return true
}

// resolveString follows a reference to a string value, through at most a
// few reference hops.
func (t *resourceTable) resolveString(id uint32) (string, error) {
	for range 4 {
		dataType, data, err := t.value(id)
		if err != nil {
			return "", err
		}
		switch dataType {
		case valueTypeString:
			return t.values.get(data)
		case valueTypeReference:
			id = data
		default:
			return "", fmt.Errorf("resource %#08x is not a string (type %#x)", id, dataType)
		}
	}
	return "", fmt.Errorf("resource %#08x: reference chain too long", id)
}

func (t *resourceTable) value(id uint32) (uint8, uint32, error) {
	entryIndex := id & 0xFFFF
	for _, c := range t.types[id>>16] {
		dataType, data, found, err := entryValue(c, entryIndex)
		if err != nil {
			return 0, 0, err
		}
		if found {
			return dataType, data, nil
		}
	}
	return 0, 0, fmt.Errorf("resource %#08x has no default-configuration value", id)
}

// entryValue reads one entry of a ResTable_type chunk, in any of its
// encodings: dense 32-bit offsets, FLAG_OFFSET16, FLAG_SPARSE, and compact
// entries (ResTable_entry::FLAG_COMPACT).
func entryValue(c chunk, index uint32) (uint8, uint32, bool, error) {
	flags := c.data[9]
	entryCount, _ := u32(c.data, 12)
	entriesStart, _ := u32(c.data, 16)
	offsets := c.headerSize
	var offset uint32
	switch {
	case flags&typeFlagSparse != 0:
		found := false
		for i := 0; i < int(entryCount); i++ {
			entry, err := u32(c.data, offsets+i*4)
			if err != nil {
				return 0, 0, false, err
			}
			if entry&0xFFFF == index {
				offset, found = (entry>>16)*4, true
				break
			}
		}
		if !found {
			return 0, 0, false, nil
		}
	case index >= entryCount:
		return 0, 0, false, nil
	case flags&typeFlagOffset16 != 0:
		value, err := u16(c.data, offsets+int(index)*2)
		if err != nil {
			return 0, 0, false, err
		}
		if value == 0xFFFF {
			return 0, 0, false, nil
		}
		offset = uint32(value) * 4
	default:
		value, err := u32(c.data, offsets+int(index)*4)
		if err != nil {
			return 0, 0, false, err
		}
		if value == noEntry {
			return 0, 0, false, nil
		}
		offset = value
	}
	entry := int(entriesStart) + int(offset)
	entryFlags, err := u16(c.data, entry+2)
	if err != nil {
		return 0, 0, false, err
	}
	if entryFlags&entryFlagCompact != 0 {
		data, err := u32(c.data, entry+4)
		return uint8(entryFlags >> 8), data, true, err
	}
	if entryFlags&entryFlagComplex != 0 {
		return 0, 0, false, fmt.Errorf("resource entry %d is complex", index)
	}
	size, err := u16(c.data, entry)
	if err != nil {
		return 0, 0, false, err
	}
	value := entry + int(size)
	if value+8 > len(c.data) {
		return 0, 0, false, errTruncated
	}
	data, _ := u32(c.data, value+4)
	return c.data[value+3], data, true, nil
}
