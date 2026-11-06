//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNetdBlockedByUIDRules(t *testing.T) {
	const (
		happyBox = 1 << 0
		// The value read from the test phone: background and standby chains on
		enabled = netdBackgroundMatch | netdStandbyMatch
	)
	require.False(t, netdBlockedByUIDRules(enabled, netdBackgroundMatch|happyBox), "on the background allowlist")
	require.True(t, netdBlockedByUIDRules(enabled, 0), "missing from the background allowlist")
	require.True(t, netdBlockedByUIDRules(enabled, netdBackgroundMatch|netdStandbyMatch), "on the standby denylist")
	require.False(t, netdBlockedByUIDRules(0, 0), "no chain enabled")
	require.True(t, netdBlockedByUIDRules(netdDozableMatch, 0), "doze allowlist")
	require.False(t, netdBlockedByUIDRules(netdDozableMatch, netdDozableMatch), "on the doze allowlist")
	require.True(t, netdBlockedByUIDRules(netdOEMDeny2Match, netdOEMDeny2Match), "oem deny")
	require.False(t, netdBlockedByUIDRules(netdOEMDeny2Match, netdOEMDeny1Match), "other oem chain")
}
