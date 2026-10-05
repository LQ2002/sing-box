//go:build with_ebpf && (linux || android)

package main

import (
	"github.com/sagernet/sing-box/common/socketidentity"
	"github.com/spf13/cobra"
)

func init() {
	var pinPath string
	command := &cobra.Command{
		Use:   "socket-creator-remove",
		Short: "Remove the persistent socket creator collector after stopping its users",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return socketidentity.Remove(pinPath)
		},
	}
	command.Flags().StringVar(&pinPath, "pin-path", socketidentity.DefaultPinPath, "Collector's dedicated bpffs directory")
	commandTools.AddCommand(command)
}
