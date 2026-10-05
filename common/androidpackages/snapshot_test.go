package androidpackages

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// testdata/packages.abx was produced on an Android 17 device by
// `xml2abx testdata/packages.xml packages.abx`, so it exercises the real
// binary format rather than a hand-made imitation.

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	return content
}

func requireFixtureTables(t *testing.T, s *snapshot) {
	t.Helper()
	require.Equal(t, map[string]uint32{
		"com.example.app":                10123,
		"com.android.settings":           1000,
		"com.android.providers.settings": 1000,
		"com.android.phone":              1001,
		"android":                        1000,
	}, s.idByPackage)
	require.Equal(t, map[string]uint32{
		"android.uid.system": 1000,
		"android.uid.phone":  1001,
	}, s.sharedByPackage)
	require.Equal(t, map[uint32]string{1000: "android.uid.system", 1001: "android.uid.phone"}, s.sharedByID)
	require.Equal(t, []string{"com.example.app"}, s.packageByID[10123])
	// File order is kept, matching sing-tun's PackageByID (first entry).
	require.Equal(t, []string{"com.android.settings", "com.android.providers.settings", "android"}, s.packageByID[1000])
}

func TestParseTextXML(t *testing.T) {
	s, err := parsePackages(loadFixture(t, "packages.xml"))
	require.NoError(t, err)
	requireFixtureTables(t, s)
}

func TestParseABX(t *testing.T) {
	content := loadFixture(t, "packages.abx")
	require.True(t, strings.HasPrefix(string(content), "ABX\x00"), "fixture must be binary XML")
	s, err := parsePackages(content)
	require.NoError(t, err)
	requireFixtureTables(t, s)
}

// guardHeap aborts the test binary if the heap runs away. Without padABX,
// sing's abx reader loops forever on many truncated inputs and grows the heap
// until the host runs out of memory (it took down the WSL VM during
// development); failing fast keeps a regression from doing that again.
func guardHeap(t *testing.T) {
	t.Helper()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		var stats runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
			runtime.ReadMemStats(&stats)
			if stats.HeapAlloc > 256<<20 {
				panic(fmt.Sprintf("heap grew to %d MiB while parsing truncated input", stats.HeapAlloc>>20))
			}
		}
	}()
}

// Cuts at which sing's abx reader ran away on testdata/packages.abx before
// padABX existed (from a standalone reproduction over all 1237 cuts).
func TestParseTruncatedABXTerminates(t *testing.T) {
	guardHeap(t)
	content := loadFixture(t, "packages.abx")
	for _, cut := range []int{22, 42, 129, 402, 601, 1005, 1215} {
		done := make(chan error, 1)
		go func() {
			_, err := parsePackages(content[:cut])
			done <- err
		}()
		select {
		case err := <-done:
			require.Error(t, err, "cut %d", cut)
		case <-time.After(5 * time.Second):
			t.Fatalf("parsing a document cut at %d did not return", cut)
		}
	}
}

// Every proper prefix of a valid document must be rejected, never returned as
// a smaller table: that is what a reader sees while Android is writing.
func TestParseRejectsEveryTruncation(t *testing.T) {
	guardHeap(t)
	for _, name := range []string{"packages.xml", "packages.abx"} {
		content := loadFixture(t, name)
		accepted := 0
		defer func() {
			t.Logf("%s: %d of %d proper prefixes accepted (all as the full table)", name, accepted, len(content))
		}()
		for cut := 0; cut < len(content); cut++ {
			s, err := parsePackages(content[:cut])
			if err == nil {
				// Accepting is only allowed once </packages> is complete, and
				// then the table must be the whole one. That happens when the
				// cut drops nothing but what follows the root: trailing
				// whitespace in text XML, or in ABX the trailing whitespace
				// token and END_DOCUMENT (0x11 in the xml2abx fixture).
				requireFixtureTables(t, s)
				accepted++
			}
		}
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"wrong root":       `<settings><package name="a" userId="10001"/></settings>`,
		"no packages":      `<packages><shared-user name="s" userId="1000"/></packages>`,
		"second root":      `<packages><package name="a" userId="10001"/></packages><packages/>`,
		"bad uid":          `<packages><package name="a" userId="ten"/></packages>`,
		"nameless package": `<packages><package userId="10001"/></packages>`,
		"unclosed child":   `<packages><package name="a" userId="10001">`,
	}
	for name, input := range cases {
		_, err := parsePackages([]byte(input))
		require.Error(t, err, name)
	}
}

func TestSnapshotEqualIgnoresOrderOnly(t *testing.T) {
	a, err := parsePackages([]byte(`<packages>
		<package name="x" sharedUserId="1000"/><package name="y" sharedUserId="1000"/>
		<shared-user name="s" userId="1000"/></packages>`))
	require.NoError(t, err)
	reordered, err := parsePackages([]byte(`<packages>
		<package name="y" sharedUserId="1000"/><package name="x" sharedUserId="1000"/>
		<shared-user name="s" userId="1000"/></packages>`))
	require.NoError(t, err)
	require.True(t, a.equal(reordered))

	grown, err := parsePackages([]byte(`<packages>
		<package name="x" sharedUserId="1000"/><package name="y" sharedUserId="1000"/>
		<package name="z" sharedUserId="1000"/><shared-user name="s" userId="1000"/></packages>`))
	require.NoError(t, err)
	require.False(t, a.equal(grown))

	moved, err := parsePackages([]byte(`<packages>
		<package name="x" sharedUserId="1000"/><package name="y" userId="10050"/>
		<shared-user name="s" userId="1000"/></packages>`))
	require.NoError(t, err)
	require.False(t, a.equal(moved))
}
