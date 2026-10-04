//go:build with_ebpf && (linux || android)

package ebpf

// Package attribution from a v2 socket creator snapshot
// (ANDROID_ATTRIBUTION_PLAN.md, "Claude 目标设计", decision 1).
//
// The producer records, at socket creation, an FNV-1a 64 hash of the
// creating process's argv[0]. For zygote children that is the
// ActivityManager process record name: zygote's setArgv0 runs before any app
// code (AndroidRuntime::setArgv0 via Zygote.setAppProcessName), so the hash
// is the record name the socket was created under, even after the creator
// exits and without reading /proc. Evidence levels:
//
//	E1  ordinary app UID with one package: the creator UID decides.
//	E2  shared/system UID: exactly one package of the app ID declares a
//	    process name with that hash (process_package_index.go).
//	E3  SDK sandbox UID: host UID = UID - 10000
//	    (Process.getAppUidForSdkSandboxUid); E1 on the host, or E2 on the
//	    host's declared names plus "_sdk_sandbox"
//	    (SdkSandboxServiceProviderImpl.toSandboxProcessName).
//
// Device evidence (experimental/creator_v2_probe): 865/865 creation-time
// argv[0] values equal /proc cmdline; 0 hash collisions among 2041 declared
// names within their app IDs; 9 names declared by several packages of one
// app ID stay unknown.
//
// argv[0] is cut to zygote's argument block (99 or 78 bytes measured), so a
// snapshot flagged as possibly truncated matches the same-length prefix of
// a declared name; more than one candidate stays unknown.

import (
	"strconv"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/common/socketidentity"
)

const (
	systemServerProcessName = "system_server"
	systemProcessRecordName = "system"
	systemAppID             = 1000
)

// sdkSandboxProcessSuffixes are appended to the host's process name:
// toSandboxProcessName and toSandboxProcessNameForInstrumentation.
var sdkSandboxProcessSuffixes = []string{"_sdk_sandbox", "_sdk_sandbox_instr"}

// snapshotName is the argv[0] evidence of one creator snapshot.
type snapshotName struct {
	hash      uint64
	length    int
	truncated bool
}

func creatorSnapshotName(creator commonEBPF.SocketCreator) (snapshotName, bool) {
	if !creator.HasProcessName() || creator.NameLength() == 0 {
		return snapshotName{}, false
	}
	return snapshotName{
		hash:      creator.ProcessNameHash,
		length:    creator.NameLength(),
		truncated: creator.Flags&commonEBPF.SocketCreatorNameTruncated != 0,
	}, true
}

// matches reports whether name is consistent with the recorded hash: the
// whole name, or for a possibly truncated record its prefix of the recorded
// length. A string that merely filled its block without being cut has the
// recorded length itself and matches either way.
func (n snapshotName) matches(name string) bool {
	if n.truncated {
		if len(name) < n.length {
			return false
		}
		name = name[:n.length]
	} else if len(name) != n.length {
		return false
	}
	return fnv1a64(name) == n.hash
}

// memoKey cannot collide with a real process name, which never contains NUL.
func (n snapshotName) memoKey(suffix string) string {
	key := "\x00" + strconv.FormatUint(n.hash, 16) + ":" + strconv.Itoa(n.length)
	if n.truncated {
		key += ":t"
	}
	return key + ":" + suffix
}

// socketOwnerFromCreator converts a TC creator snapshot for resolveSocketOwner.
func socketOwnerFromCreator(creator commonEBPF.SocketCreator) SocketOwner {
	owner := SocketOwner{
		ProcessID: creator.ProcessID, UserID: creator.UserID,
		StartTimeNs: creator.StartTimeNs, Comm: socketOwnerModuleComm(creator.Comm),
	}
	owner.name, owner.hasName = creatorSnapshotName(creator)
	if creator.HasExecutable() && creator.ExeInode != 0 {
		owner.exeInode, owner.hasExe = creator.ExeInode, true
	}
	if creator.Flags&socketidentity.CreatorExeKey != 0 && creator.ExeInode != 0 {
		owner.exeKey, owner.hasExeKey = creator.ExeInode, true
	}
	owner.exeFlags = creator.Flags & (socketidentity.CreatorPathTooLong | socketidentity.CreatorExeDeleted | socketidentity.CreatorKernel)
	return owner
}

func fnv1a64(value string) uint64 {
	hash := uint64(0xcbf29ce484222325)
	for index := 0; index < len(value); index++ {
		hash ^= uint64(value[index])
		hash *= 0x100000001b3
	}
	return hash
}

// snapshotPackage applies E1-E3 to a creator UID and name snapshot. index may
// be nil (no shared/system refinement). The outcome explains an empty result.
func snapshotPackage(uid uint32, name snapshotName, hasName bool, uniqueByUID func(uid uint32) string, index *processPackageIndex) (string, processLookupOutcome) {
	appID := uid % androidUserRange
	if appID >= 20000 && appID <= 29999 {
		hostUID := uid - 10000
		if packageName := uniqueByUID(hostUID); packageName != "" {
			return packageName, processLookupFoundByUID
		}
		if !hasName {
			return "", processLookupUndeclared
		}
		if index == nil {
			return "", processLookupPending
		}
		var outcome processLookupOutcome
		for _, suffix := range sdkSandboxProcessSuffixes {
			var packageName string
			packageName, outcome = index.lookupSnapshot(hostUID%androidUserRange, name, suffix)
			if outcome != processLookupUndeclared {
				return packageName, outcome
			}
		}
		return "", outcome
	}
	if packageName := uniqueByUID(uid); packageName != "" {
		return packageName, processLookupFoundByUID
	}
	if !hasName {
		return "", processLookupUndeclared
	}
	if index == nil {
		return "", processLookupPending
	}
	// zygote names system_server "system_server" (ZygoteInit.forkSystemServer)
	// while ActivityManager records it under the "android" package's process
	// name "system". Only UID 1000 gets this alias: an app UID on the device
	// declares a process literally named "system".
	if appID == systemAppID && !name.truncated && name.matches(systemServerProcessName) {
		return index.lookupMatching(appID, processLookupKey{appID: appID, process: systemProcessRecordName},
			func(declared string) bool { return declared == systemProcessRecordName })
	}
	return index.lookupSnapshot(appID, name, "")
}
