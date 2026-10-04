package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type ValidationReport struct {
	DeviceKernel        string             `json:"device_kernel"`
	AppProcessDevIno    DevIno             `json:"app_process64_target"`
	CgroupAppsTruth     CgroupTruthReport  `json:"cgroup_apps_truth"`
	DumpsysTruth        DumpsysTruthReport `json:"dumpsys_truth"`
	CollisionAnalysis   CollisionReport    `json:"cross_fs_collision_analysis"`
	NativeChildAnalysis NativeChildReport  `json:"native_child_analysis"`
}

type DevIno struct {
	Device uint64 `json:"st_dev"`
	Inode  uint64 `json:"i_ino"`
	Path   string `json:"path"`
}

type CgroupTruthReport struct {
	TotalCgroupAppPids int      `json:"total_cgroup_app_pids"`
	MatchingDevIno     int      `json:"matching_dev_ino"`
	MismatchingPids    []string `json:"mismatching_pids,omitempty"`
}

type DumpsysTruthReport struct {
	TotalDumpsysPids int      `json:"total_dumpsys_pids"`
	MatchingDevIno   int      `json:"matching_dev_ino"`
	MismatchingPids  []string `json:"mismatching_pids,omitempty"`
}

type CollisionReport struct {
	TotalNativeProcsScanned int      `json:"total_native_procs_scanned"`
	InodeOnlyCollisions     int      `json:"inode_only_collisions"`
	DevInoPairCollisions    int      `json:"dev_ino_pair_collisions"`
	CollidingDetails        []string `json:"colliding_details,omitempty"`
}

type NativeChildReport struct {
	AppUidNativeProcs []string `json:"app_uid_native_procs"`
}

func getDevIno(path string) (DevIno, error) {
	// os.Stat 跟随符号链接
	fi, err := os.Stat(path)
	if err != nil {
		return DevIno{}, err
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return DevIno{}, fmt.Errorf("stat sys is not *syscall.Stat_t")
	}
	realTarget, _ := filepath.EvalSymlinks(path)
	return DevIno{
		Device: uint64(stat.Dev),
		Inode:  stat.Ino,
		Path:   realTarget,
	}, nil
}

func main() {
	var uname syscall.Utsname
	syscall.Uname(&uname)
	kernelRelease := ""
	for _, b := range uname.Release {
		if b == 0 {
			break
		}
		kernelRelease += string(byte(b))
	}

	report := ValidationReport{
		DeviceKernel: kernelRelease,
	}

	// 1. 获取 /system/bin/app_process64 真实基准 (dev, ino)
	targetDevIno, err := getDevIno("/system/bin/app_process64")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get /system/bin/app_process64 dev/ino: %v\n", err)
		os.Exit(1)
	}
	report.AppProcessDevIno = targetDevIno

	// 2. 独立真值 A：扫描 /sys/fs/cgroup/apps/uid_*/pid_*
	cgroupPids := make(map[int]uint32) // pid -> uid
	cgroupRoot := "/sys/fs/cgroup/apps"
	uidEntries, err := os.ReadDir(cgroupRoot)
	if err == nil {
		for _, u := range uidEntries {
			if !u.IsDir() || !strings.HasPrefix(u.Name(), "uid_") {
				continue
			}
			uidVal, _ := strconv.ParseUint(strings.TrimPrefix(u.Name(), "uid_"), 10, 32)
			pidEntries, err := os.ReadDir(filepath.Join(cgroupRoot, u.Name()))
			if err != nil {
				continue
			}
			for _, p := range pidEntries {
				if !p.IsDir() || !strings.HasPrefix(p.Name(), "pid_") {
					continue
				}
				pidVal, err := strconv.Atoi(strings.TrimPrefix(p.Name(), "pid_"))
				if err == nil && pidVal > 0 {
					cgroupPids[pidVal] = uint32(uidVal)
				}
			}
		}
	}
	report.CgroupAppsTruth.TotalCgroupAppPids = len(cgroupPids)

	for pid, uid := range cgroupPids {
		exePath := fmt.Sprintf("/proc/%d/exe", pid)
		di, err := getDevIno(exePath)
		if err != nil {
			// 进程可能在扫描期间退出
			continue
		}
		if di.Device == targetDevIno.Device && di.Inode == targetDevIno.Inode {
			report.CgroupAppsTruth.MatchingDevIno++
		} else {
			cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
			cleanCmd := string(bytes.Split(cmdline, []byte{0})[0])
			report.CgroupAppsTruth.MismatchingPids = append(report.CgroupAppsTruth.MismatchingPids,
				fmt.Sprintf("PID %d (UID %d, cmdline=%q): target=%s (dev=%d, ino=%d, expected ino=%d)",
					pid, uid, cleanCmd, di.Path, di.Device, di.Inode, targetDevIno.Inode))
		}
	}

	// 3. 独立真值 B：解析 dumpsys activity processes
	dumpsysPids := make(map[int]string)
	cmd := exec.Command("dumpsys", "activity", "processes")
	dumpsysOut, err := cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(dumpsysOut))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			// 格式通常形如: *APP* ProcessRecord{... pid:12345:com.example.app/u0a123}
			if strings.HasPrefix(line, "*APP*") && strings.Contains(line, "pid:") {
				parts := strings.Split(line, "pid:")
				if len(parts) > 1 {
					sub := strings.Split(parts[1], ":")
					if len(sub) > 1 {
						pid, err := strconv.Atoi(sub[0])
						if err == nil {
							dumpsysPids[pid] = sub[1]
						}
					}
				}
			}
		}
	}
	report.DumpsysTruth.TotalDumpsysPids = len(dumpsysPids)
	for pid, desc := range dumpsysPids {
		exePath := fmt.Sprintf("/proc/%d/exe", pid)
		di, err := getDevIno(exePath)
		if err != nil {
			continue
		}
		if di.Device == targetDevIno.Device && di.Inode == targetDevIno.Inode {
			report.DumpsysTruth.MatchingDevIno++
		} else {
			report.DumpsysTruth.MismatchingPids = append(report.DumpsysTruth.MismatchingPids,
				fmt.Sprintf("Dumpsys PID %d (%s): target=%s (dev=%d, ino=%d)", pid, desc, di.Path, di.Device, di.Inode))
		}
	}

	// 4. 全局跨文件系统撞号与原生子进程分析（遍历整机 /proc）
	procEntries, err := os.ReadDir("/proc")
	if err == nil {
		for _, e := range procEntries {
			if !e.IsDir() {
				continue
			}
			pid, err := strconv.Atoi(e.Name())
			if err != nil {
				continue
			}
			exePath := fmt.Sprintf("/proc/%d/exe", pid)
			di, err := getDevIno(exePath)
			if err != nil {
				continue
			}

			// 如果是 app_process64 自身，跳过
			if di.Device == targetDevIno.Device && di.Inode == targetDevIno.Inode {
				continue
			}

			report.CollisionAnalysis.TotalNativeProcsScanned++

			// 检查是否发生单一 inode 撞号
			if di.Inode == targetDevIno.Inode {
				report.CollisionAnalysis.InodeOnlyCollisions++
				report.CollisionAnalysis.CollidingDetails = append(report.CollisionAnalysis.CollidingDetails,
					fmt.Sprintf("CRITICAL INODE COLLISION: PID %d exe=%s (dev=%d, ino=%d == %d)", pid, di.Path, di.Device, di.Inode, targetDevIno.Inode))
			}
			// 检查 (dev, inode) 组合是否碰撞（理论上不同文件不可能碰撞）
			if di.Device == targetDevIno.Device && di.Inode == targetDevIno.Inode {
				report.CollisionAnalysis.DevInoPairCollisions++
			}

			// 检查是否属于普通 App UID (>= 10000) 的原生子进程
			statusBytes, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
			statusStr := string(statusBytes)
			for _, line := range strings.Split(statusStr, "\n") {
				if strings.HasPrefix(line, "Uid:") {
					fields := strings.Fields(line)
					if len(fields) > 1 {
						uidVal, _ := strconv.Atoi(fields[1])
						if uidVal >= 10000 && uidVal < 20000 {
							cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
							cleanCmd := string(bytes.Split(cmdline, []byte{0})[0])
							report.NativeChildAnalysis.AppUidNativeProcs = append(report.NativeChildAnalysis.AppUidNativeProcs,
								fmt.Sprintf("PID %d (UID %d, cmdline=%q): exe=%s (dev=%d, ino=%d)", pid, uidVal, cleanCmd, di.Path, di.Device, di.Inode))
						}
					}
					break
				}
			}
		}
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}
