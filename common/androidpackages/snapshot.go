// Package androidpackages keeps an up-to-date, immutable view of Android's
// /data/system/packages.xml and serves it through tun.PackageManager.
//
// It replaces sing-tun's package manager inside sing-box rather than patching
// sing-tun: sing-tun watches packages.xml with fswatch's Direct mode, which
// only works for files that are never removed, while Android rewrites the file
// by renaming the old one away and creating a new one (observed on the device
// with inotifyd on /data/system: "m packages.xml", "n packages.xml", then about
// thirty "c packages.xml"). The direct watch therefore dies on the first
// install or uninstall and the table is never refreshed until restart.
//
// The parsing below keeps sing-tun's semantics (which elements and attributes
// populate which table) so lookups behave the same, and adds what sing-tun
// lacks: the document must be a complete <packages> tree, so a truncated or
// half-written file is rejected instead of being published as a partial table.
package androidpackages

import (
	"bytes"
	"encoding/xml"
	"io"
	"slices"
	"strconv"

	"github.com/sagernet/sing/common/abx"
	E "github.com/sagernet/sing/common/exceptions"
)

// snapshot is one complete, immutable package table. It is built once by
// parsePackages and never modified afterwards; readers may use it without
// locking, and Manager swaps whole snapshots atomically.
type snapshot struct {
	idByPackage     map[string]uint32
	sharedByPackage map[string]uint32
	packageByID     map[uint32][]string
	sharedByID      map[uint32]string
}

const rootElement = "packages"

const (
	// abxEndDocument is the ABX token byte for END_DOCUMENT: token type 1
	// (XmlPullParser.END_DOCUMENT) with no attribute type bits, as defined in
	// sing/common/abx/internal (EndDocument = 1) and AOSP BinaryXmlSerializer.
	abxEndDocument = 0x01
	// abxPadding exceeds the largest single read sing's reader can make: a
	// length-prefixed string or byte array of at most 0xFFFF bytes, plus its
	// two-byte length and a few bytes of slack.
	abxPadding = 0xFFFF + 64
)

// padABX appends END_DOCUMENT tokens to a binary XML document.
//
// sing's abx reader (common/abx/reader.go) cannot be trusted with a truncated
// document: readAttribute() returns a nil error when ReadByte hits the end of
// the input, and readAttributes() only stops on io.EOF, so a cut inside an
// element's attributes appends empty attributes forever and exhausts memory.
// Feeding every proper prefix of a 1241-byte packages.abx (made on the device
// with xml2abx) to it made 584 of 1237 cuts exceed 64 MiB of heap within
// milliseconds; with this padding none did and all returned. This matters
// because packages.xml is rewritten in place and can be read half written
// (see Manager.read).
//
// With the padding, any read that runs off the real data meets END_DOCUMENT:
// Token() turns it into io.EOF and readAttribute() treats it as "no more
// attributes". A single read can swallow at most 0xFFFF padding bytes, so
// END_DOCUMENT bytes always remain after it. The reader then reports a clean
// end, not an error, which is why parsePackages must still check that the
// <packages> root was closed: that check is what rejects the truncated input.
//
// A complete document already ends with END_DOCUMENT, so the padding is never
// reached for valid input. Fixing the reader itself would mean forking sing,
// which this project avoids.
func padABX(content []byte) []byte {
	padded := make([]byte, len(content)+abxPadding)
	copy(padded, content)
	for index := len(content); index < len(padded); index++ {
		padded[index] = abxEndDocument
	}
	return padded
}

// parsePackages decodes packages.xml in either Android binary XML (ABX, the
// format on current Android releases) or text XML. It returns an error unless
// the input is one complete <packages> document containing at least one
// package; a partial table is never returned.
func parsePackages(content []byte) (*snapshot, error) {
	var decoder *xml.Decoder
	if _, isABX := abx.NewReader(content); isABX {
		reader, _ := abx.NewReader(padABX(content))
		decoder = xml.NewTokenDecoder(reader)
	} else {
		decoder = xml.NewDecoder(bytes.NewReader(content))
	}
	result := &snapshot{
		idByPackage:     make(map[string]uint32),
		sharedByPackage: make(map[string]uint32),
		packageByID:     make(map[uint32][]string),
		sharedByID:      make(map[uint32]string),
	}
	depth := 0
	rootSeen := false
	rootClosed := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, E.Cause(err, "decode packages")
		}
		switch element := token.(type) {
		case xml.StartElement:
			if depth == 0 {
				if rootSeen {
					return nil, E.New("unexpected element after the <", rootElement, "> root: ", element.Name.Local)
				}
				if element.Name.Local != rootElement {
					return nil, E.New("unexpected root element: ", element.Name.Local)
				}
				rootSeen = true
			}
			depth++
			if err := result.addElement(element); err != nil {
				return nil, err
			}
		case xml.EndElement:
			depth--
			if depth == 0 && rootSeen {
				rootClosed = true
			}
		}
	}
	if !rootSeen {
		return nil, E.New("missing <", rootElement, "> root element")
	}
	if !rootClosed {
		return nil, E.New("truncated packages document: <", rootElement, "> is not closed")
	}
	if len(result.idByPackage) == 0 {
		return nil, E.New("packages document contains no package")
	}
	return result, nil
}

// addElement mirrors sing-tun's decodePackages for the two elements it reads,
// except that a package or shared user without a name is treated as corrupt
// input instead of being stored under the empty name.
func (s *snapshot) addElement(element xml.StartElement) error {
	switch element.Name.Local {
	case "package":
		name, userID, err := readNameAndID(element, "userId", "sharedUserId")
		if err != nil {
			return err
		}
		if userID == 0 && name == "" {
			return nil
		}
		if name == "" {
			return E.New("package without a name for uid ", userID)
		}
		s.idByPackage[name] = userID
		s.packageByID[userID] = append(s.packageByID[userID], name)
	case "shared-user":
		name, userID, err := readNameAndID(element, "userId")
		if err != nil {
			return err
		}
		if userID == 0 && name == "" {
			return nil
		}
		if name == "" {
			return E.New("shared user without a name for uid ", userID)
		}
		s.sharedByPackage[name] = userID
		s.sharedByID[userID] = name
	}
	return nil
}

func readNameAndID(element xml.StartElement, idAttributes ...string) (name string, userID uint32, err error) {
	for _, attr := range element.Attr {
		if attr.Name.Local == "name" {
			name = attr.Value
			continue
		}
		if slices.Contains(idAttributes, attr.Name.Local) {
			parsed, parseErr := strconv.ParseUint(attr.Value, 10, 32)
			if parseErr != nil {
				return "", 0, E.Cause(parseErr, "parse ", attr.Name.Local, " of ", element.Name.Local)
			}
			userID = uint32(parsed)
		}
	}
	return name, userID, nil
}

// equal reports whether two snapshots answer every lookup the same way. The
// per-UID package lists are compared as sets: their order follows the file
// and carries no meaning, so a rewrite that only reorders entries is not a
// change worth notifying.
func (s *snapshot) equal(other *snapshot) bool {
	if s == nil || other == nil {
		return s == other
	}
	if !mapsEqual(s.idByPackage, other.idByPackage) ||
		!mapsEqual(s.sharedByPackage, other.sharedByPackage) ||
		!mapsEqual(s.sharedByID, other.sharedByID) ||
		len(s.packageByID) != len(other.packageByID) {
		return false
	}
	for id, names := range s.packageByID {
		otherNames, loaded := other.packageByID[id]
		if !loaded || len(names) != len(otherNames) {
			return false
		}
		left := slices.Clone(names)
		right := slices.Clone(otherNames)
		slices.Sort(left)
		slices.Sort(right)
		if !slices.Equal(left, right) {
			return false
		}
	}
	return true
}

func mapsEqual[K comparable, V comparable](left, right map[K]V) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		otherValue, loaded := right[key]
		if !loaded || otherValue != value {
			return false
		}
	}
	return true
}
