package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type ProbeResults struct {
	DeviceKernel       string           `json:"device_kernel"`
	MarkInheritance    MarkTestResult   `json:"mark_inheritance"`
	ExeInodeValidation InodeTestResult  `json:"exe_inode_validation"`
}

type MarkTestResult struct {
	ParentMarkSet      uint32 `json:"parent_mark_set"`
	ChildMarkReceived  uint32 `json:"child_mark_received"`
	InheritanceSuccess bool   `json:"inheritance_success"`
	SetsockoptErr      string `json:"setsockopt_err,omitempty"`
	BindErr            string `json:"bind_err,omitempty"`
	ListenErr          string `json:"listen_err,omitempty"`
	AcceptErr          string `json:"accept_err,omitempty"`
	GetsockoptErr      string `json:"getsockopt_err,omitempty"`
}

type InodeTestResult struct {
	AppProcess64Inode uint64            `json:"app_process64_inode"`
	TotalProcsScanned int               `json:"total_procs_scanned"`
	JavaAppProcs      int               `json:"java_app_procs"`
	NativeProcs       int               `json:"native_procs"`
	SampleJavaApps    []string          `json:"sample_java_apps"`
	SampleNativeProcs []string          `json:"sample_native_procs"`
}

const (
	SO_MARK_OPT = 36 // Linux SOL_SOCKET SO_MARK
	TEST_MARK   = 0x5b0c1234
)

func testMarkInheritance() MarkTestResult {
	res := MarkTestResult{
		ParentMarkSet: TEST_MARK,
	}

	// 1. 创建原生 TCP listener socket
	listenFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		res.SetsockoptErr = fmt.Sprintf("socket error: %v", err)
		return res
	}
	defer syscall.Close(listenFd)

	// 允许重用端口
	syscall.SetsockoptInt(listenFd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)

	// 2. 设置 SO_MARK
	err = syscall.SetsockoptInt(listenFd, syscall.SOL_SOCKET, SO_MARK_OPT, TEST_MARK)
	if err != nil {
		res.SetsockoptErr = fmt.Sprintf("setsockopt SO_MARK error: %v", err)
		return res
	}

	// 3. Bind 到 127.0.0.1:0 (由系统分配随机可用端口)
	sa := &syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{127, 0, 0, 1},
	}
	err = syscall.Bind(listenFd, sa)
	if err != nil {
		res.BindErr = fmt.Sprintf("bind error: %v", err)
		return res
	}

	// 4. 获取系统分配的实际端口
	boundSa, err := syscall.Getsockname(listenFd)
	if err != nil {
		res.BindErr = fmt.Sprintf("getsockname error: %v", err)
		return res
	}
	actualPort := boundSa.(*syscall.SockaddrInet4).Port

	// 5. Listen
	err = syscall.Listen(listenFd, 16)
	if err != nil {
		res.ListenErr = fmt.Sprintf("listen error: %v", err)
		return res
	}

	// 6. 在子线程中发起客户端连接
	clientDone := make(chan error, 1)
	go func() {
		clientFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
		if err != nil {
			clientDone <- err
			return
		}
		defer syscall.Close(clientFd)

		connectSa := &syscall.SockaddrInet4{
			Port: actualPort,
			Addr: [4]byte{127, 0, 0, 1},
		}
		err = syscall.Connect(clientFd, connectSa)
		clientDone <- err
	}()

	// 7. Accept 子连接
	childFd, _, err := syscall.Accept(listenFd)
	if err != nil {
		res.AcceptErr = fmt.Sprintf("accept error: %v", err)
		return res
	}
	defer syscall.Close(childFd)

	<-clientDone

	// 8. 核心校验：从 childFd 读取 SO_MARK
	childMark, err := syscall.GetsockoptInt(childFd, syscall.SOL_SOCKET, SO_MARK_OPT)
	if err != nil {
		res.GetsockoptErr = fmt.Sprintf("getsockopt child mark error: %v", err)
		return res
	}

	res.ChildMarkReceived = uint32(childMark)
	res.InheritanceSuccess = (uint32(childMark) == TEST_MARK)
	return res
}

func testExeInode() InodeTestResult {
	res := InodeTestResult{
		SampleJavaApps:    make([]string, 0),
		SampleNativeProcs: make([]string, 0),
	}

	// 1. 获取 /system/bin/app_process64 的底层文件真实 inode
	fi, err := os.Stat("/system/bin/app_process64")
	if err != nil {
		return res
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return res
	}
	res.AppProcess64Inode = stat.Ino

	// 2. 遍历 /proc 目录
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return res
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		res.TotalProcsScanned++

		exePath := filepath.Join("/proc", entry.Name(), "exe")
		// os.Stat 跟随符号链接，拿到底层二进制文件的真实 inode
		exeFi, err := os.Stat(exePath)
		if err != nil {
			// 内核线程无 exe
			continue
		}
		exeStat, ok := exeFi.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}

		cmdlineBytes, _ := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		cmdline := string(cmdlineBytes)
		if len(cmdline) > 0 {
			cmdline = strings.Split(cmdline, "\x00")[0]
		}
		if cmdline == "" {
			commBytes, _ := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
			cmdline = strings.TrimSpace(string(commBytes))
		}

		if exeStat.Ino == res.AppProcess64Inode {
			res.JavaAppProcs++
			if len(res.SampleJavaApps) < 8 {
				res.SampleJavaApps = append(res.SampleJavaApps, fmt.Sprintf("PID %d: %s", pid, cmdline))
			}
		} else {
			res.NativeProcs++
			if len(res.SampleNativeProcs) < 8 {
				target, _ := os.Readlink(exePath)
				res.SampleNativeProcs = append(res.SampleNativeProcs, fmt.Sprintf("PID %d: %s (exe=%s, ino=%d)", pid, cmdline, target, exeStat.Ino))
			}
		}
	}

	return res
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

	results := ProbeResults{
		DeviceKernel:       kernelRelease,
		MarkInheritance:    testMarkInheritance(),
		ExeInodeValidation: testExeInode(),
	}

	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "json marshal error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(data))
}
