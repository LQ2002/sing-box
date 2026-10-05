package androidmanifest

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Manifest is what one APK contributes to a package's process names.
type Manifest struct {
	Package string
	// ApplicationProcess is <application android:process>, empty if absent.
	ApplicationProcess string
	// ComponentProcesses are the android:process values of activities,
	// services, receivers and providers, as written (":name" not expanded).
	ComponentProcesses []string
}

// componentElements are the components whose android:process can start a
// process (ParsedMainComponentUtils is used for all four).
var componentElements = map[string]bool{
	"activity": true, "service": true, "receiver": true, "provider": true,
}

// resolver turns a string resource reference into its value.
type resolver func(id uint32) (string, error)

// parseManifest decodes a compiled AndroidManifest.xml. resolve is called
// only for attributes given as references; it may be nil.
func parseManifest(data []byte, resolve resolver) (Manifest, error) {
	root, err := readChunk(data, 0)
	if err != nil {
		return Manifest{}, err
	}
	if root.kind != resXMLType {
		return Manifest{}, fmt.Errorf("AndroidManifest.xml: unexpected root chunk %#x", root.kind)
	}
	var (
		manifest    Manifest
		pool        *stringPool
		resourceIDs []uint32
		depth       int
	)
	for offset := root.headerSize; offset < root.size; {
		c, err := readChunk(root.data, offset)
		if err != nil {
			return Manifest{}, err
		}
		switch c.kind {
		case resStringPoolType:
			if pool, err = parseStringPool(c); err != nil {
				return Manifest{}, err
			}
		case resXMLResourceMapType:
			for i := c.headerSize; i+4 <= c.size; i += 4 {
				id, _ := u32(c.data, i)
				resourceIDs = append(resourceIDs, id)
			}
		case resXMLStartElement:
			depth++
			name, process, packageName, err := readElement(c, pool, resourceIDs, resolve)
			if err != nil {
				return Manifest{}, err
			}
			switch {
			case name == "manifest" && depth == 1:
				manifest.Package = packageName
			case name == "application":
				manifest.ApplicationProcess = process
			case componentElements[name] && process != "":
				manifest.ComponentProcesses = append(manifest.ComponentProcesses, process)
			}
		case resXMLStartElement + 1: // RES_XML_END_ELEMENT_TYPE
			depth--
		}
		offset += c.size
	}
	if manifest.Package == "" {
		return Manifest{}, fmt.Errorf("AndroidManifest.xml has no package attribute")
	}
	return manifest, nil
}

// readElement returns an element's name, its android:process value (by
// attribute resource id, so obfuscated attribute names do not matter) and,
// for <manifest>, the package attribute.
func readElement(c chunk, pool *stringPool, resourceIDs []uint32, resolve resolver) (string, string, string, error) {
	// ResXMLTree_node is 16 bytes; ResXMLTree_attrExt follows.
	extension := c.headerSize
	nameIndex, err := u32(c.data, extension+4)
	if err != nil {
		return "", "", "", err
	}
	name, err := pool.get(nameIndex)
	if err != nil {
		return "", "", "", err
	}
	attributeStart, _ := u16(c.data, extension+8)
	attributeSize, _ := u16(c.data, extension+10)
	attributeCount, err := u16(c.data, extension+12)
	if err != nil {
		return "", "", "", err
	}
	var process, packageName string
	for i := 0; i < int(attributeCount); i++ {
		attribute := extension + int(attributeStart) + i*int(attributeSize)
		attributeName, err := u32(c.data, attribute+4)
		if err != nil {
			return "", "", "", err
		}
		switch {
		case int(attributeName) < len(resourceIDs) && resourceIDs[attributeName] == attrProcess:
			process, err = attributeString(c, attribute, pool, resolve)
			if err != nil {
				return "", "", "", fmt.Errorf("<%s android:process>: %w", name, err)
			}
		case name == "manifest":
			key, err := pool.get(attributeName)
			if err == nil && key == "package" {
				packageName, err = attributeString(c, attribute, pool, resolve)
				if err != nil {
					return "", "", "", err
				}
			}
		}
	}
	return name, process, packageName, nil
}

func attributeString(c chunk, attribute int, pool *stringPool, resolve resolver) (string, error) {
	// ResXMLTree_attribute: ns 4, name 4, rawValue 4, Res_value 8.
	rawValue, _ := u32(c.data, attribute+8)
	if attribute+20 > len(c.data) {
		return "", errTruncated
	}
	dataType := c.data[attribute+15]
	data, _ := u32(c.data, attribute+16)
	switch dataType {
	case valueTypeString:
		return pool.get(data)
	case valueTypeReference:
		if resolve == nil {
			return "", fmt.Errorf("reference %#08x without resources", data)
		}
		return resolve(data)
	}
	if rawValue != noEntry {
		return pool.get(rawValue)
	}
	return "", fmt.Errorf("unsupported attribute value type %#x", dataType)
}

func readZipFile(file *zip.File) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(io.LimitReader(reader, 64<<20))
}

// PackageProcesses returns every process name a package can run in: its
// application process (the package name when unset) and each component's,
// built the way ComponentParseUtils.buildProcessName/buildCompoundName do:
// ":x" becomes "<package>:x", anything else is used as written. codePath is
// the package's directory from packages.xml (a single .apk path also works);
// all APKs in it whose manifest names packageName are read, so components
// declared in split APKs count too.
//
// resources.arsc is read only if some android:process is a reference, and
// then from every APK of the package: a split's manifest may reference a
// string defined in the base APK's table (Chrome's split_on_demand.apk does).
// Most manifests use literal names, so most packages never decompress their
// often multi-megabyte resource table.
func PackageProcesses(packageName, codePath string) ([]string, error) {
	paths := []string{codePath}
	if info, err := os.Stat(codePath); err == nil && info.IsDir() {
		paths, err = filepath.Glob(filepath.Join(codePath, "*.apk"))
		if err != nil {
			return nil, err
		}
	}
	var archives []*zip.ReadCloser
	defer func() {
		for _, archive := range archives {
			_ = archive.Close()
		}
	}()
	for _, path := range paths {
		archive, err := zip.OpenReader(path)
		if err != nil {
			return nil, err
		}
		archives = append(archives, archive)
	}
	var tables []*resourceTable
	tablesLoaded := false
	resolve := func(id uint32) (string, error) {
		if !tablesLoaded {
			tablesLoaded = true
			for _, archive := range archives {
				data, err := zipEntryData(&archive.Reader, "resources.arsc")
				if err != nil || data == nil {
					continue
				}
				if table, err := parseResourceTable(data); err == nil {
					tables = append(tables, table)
				}
			}
		}
		var firstErr error
		for _, table := range tables {
			value, err := table.resolveString(id)
			if err == nil {
				return value, nil
			}
			if firstErr == nil {
				firstErr = err
			}
		}
		if firstErr == nil {
			firstErr = fmt.Errorf("reference %#08x: no resource table", id)
		}
		return "", firstErr
	}
	applicationProcess := ""
	var components []string
	read := 0
	for index, archive := range archives {
		data, err := zipEntryData(&archive.Reader, "AndroidManifest.xml")
		if err != nil {
			return nil, err
		}
		if data == nil {
			return nil, fmt.Errorf("%s has no AndroidManifest.xml", paths[index])
		}
		manifest, err := parseManifest(data, resolve)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", paths[index], err)
		}
		if manifest.Package != packageName {
			continue // e.g. other APKs in /system/framework
		}
		read++
		if manifest.ApplicationProcess != "" {
			applicationProcess = manifest.ApplicationProcess
		}
		components = append(components, manifest.ComponentProcesses...)
	}
	if read == 0 {
		return nil, fmt.Errorf("no APK for %s in %s", packageName, codePath)
	}
	defaultProcess := packageName
	if applicationProcess != "" {
		defaultProcess = compoundName(packageName, applicationProcess)
	}
	processes := []string{defaultProcess}
	for _, process := range components {
		processes = append(processes, compoundName(packageName, process))
	}
	slices.Sort(processes)
	return slices.Compact(processes), nil
}

// zipEntryData returns one entry's content, or nil if the entry is absent.
func zipEntryData(archive *zip.Reader, name string) ([]byte, error) {
	for _, file := range archive.File {
		if file.Name == name {
			return readZipFile(file)
		}
	}
	return nil, nil
}

func compoundName(packageName, process string) string {
	if strings.HasPrefix(process, ":") {
		return packageName + process
	}
	return process
}

func zipReader(data []byte) (*zip.Reader, error) {
	return zip.NewReader(bytes.NewReader(data), int64(len(data)))
}

// ProcessRecordName maps a process's cmdline (argv[0]) to the name
// ActivityManager keys it by. They are the same for every zygote child
// (Zygote.setAppProcessName sets argv[0] to the record's name before any app
// code runs) except system_server: zygote names it "system_server"
// (ZygoteInit.forkSystemServer, --nice-name=system_server) while its
// ProcessRecord carries the "android" package's process name, "system"
// (ActivityManagerService.setSystemProcess; core/res/AndroidManifest.xml
// <application android:process="system">).
func ProcessRecordName(cmdline string) string {
	if cmdline == "system_server" {
		return "system"
	}
	return cmdline
}
