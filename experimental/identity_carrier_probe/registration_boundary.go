//go:build linux

package main

import (
	"fmt"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func (r *runner) registrationBoundary(c *child, name string, reg registration) error {
	key := uint32(c.pidfd)
	firstRegistered := name == "registration_deleted"
	if name == "registration_uid_mismatch" || name == "registration_tgid_mismatch" {
		invalid := reg
		if name == "registration_uid_mismatch" {
			invalid.UID++
		} else {
			invalid.TGID++
		}
		if err := r.coll.Maps["task_identity"].Update(&key, &invalid, ebpf.UpdateAny); err != nil {
			return err
		}
		var readback registration
		if err := r.coll.Maps["task_identity"].Lookup(&key, &readback); err != nil || readback != invalid {
			return fmt.Errorf("invalid registration fixture was not installed: %v", err)
		}
		r.mismatched++
	}
	a, err := r.create(c, 1, unix.AF_INET, unix.SOCK_DGRAM, reg, firstRegistered, false)
	if err != nil {
		return err
	}
	secondRegistered := name != "registration_deleted"
	if secondRegistered {
		reg, err = r.register(c)
	} else {
		err = r.coll.Maps["task_identity"].Delete(&key)
	}
	if err != nil {
		return err
	}
	b, err := r.create(c, 2, unix.AF_INET, unix.SOCK_DGRAM, reg, secondRegistered, false)
	if err != nil {
		return err
	}
	if err = r.sendAndObserve(c, a, false); err != nil {
		return err
	}
	if err = r.sendAndObserve(c, b, false); err != nil {
		return err
	}
	emit("registration_boundary", map[string]any{"name": name, "existing_socket_kept_creation_snapshot": true, "first_registered": firstRegistered, "second_registered": secondRegistered})
	return c.exit()
}
