// Cost of one full package-table reload with the exact sing-tun code the
// phone's sing-box uses (reF1nd fork): NewPackageManager + Start parses
// /data/system/packages.xml (binary ABX). Measures wall time, CPU time and
// allocations per reload.
package main

import (
	"fmt"
	"runtime"
	"syscall"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
)

type cb struct{}

func (cb) OnPackagesUpdated(packages int, sharedUsers int) {}

func cpu() time.Duration {
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

func main() {
	var ms0, ms1 runtime.MemStats
	for i := 0; i < 10; i++ {
		pm, err := tun.NewPackageManager(tun.PackageManagerOptions{Callback: cb{}, Logger: logger.NOP()})
		if err != nil {
			panic(err)
		}
		runtime.GC()
		runtime.ReadMemStats(&ms0)
		c0, t0 := cpu(), time.Now()
		if err := pm.Start(); err != nil {
			panic(err)
		}
		wall, used := time.Since(t0), cpu()-c0
		runtime.ReadMemStats(&ms1)
		uid, _ := pm.IDByPackage("com.android.chrome")
		shared, _ := pm.PackagesByID(1000)
		fmt.Printf("reload#%d wall=%-10v cpu=%-10v alloc=%.1fMB mallocs=%d  chrome=%d uid1000_pkgs=%d\n",
			i, wall, used, float64(ms1.TotalAlloc-ms0.TotalAlloc)/1e6, ms1.Mallocs-ms0.Mallocs, uid, len(shared))
		pm.Close()
	}
	runtime.GC()
	runtime.ReadMemStats(&ms1)
	fmt.Printf("heap in use after GC: %.1f MB\n", float64(ms1.HeapInuse)/1e6)
}
