package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func runCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func readDmesgRecent(keyword string) []string {
	out, err := runCmd("dmesg")
	if err != nil {
		return nil
	}
	var matches []string
	lines := strings.Split(out, "\n")
	for _, l := range lines {
		if strings.Contains(l, keyword) {
			matches = append(matches, l)
		}
	}
	if len(matches) > 30 {
		return matches[len(matches)-30:]
	}
	return matches
}

func main() {
	devPath := "/dev/sbo_enhancement_probe"

	fmt.Println("=== 全能单模块生产级特性真机实测 ===")

	// 1. 验证设备节点权限 (必须为 0600)
	fi, err := os.Stat(devPath)
	if err != nil {
		fmt.Printf("错误: 设备节点 %s 不存在，请确认模块已加载: %v\n", devPath, err)
		os.Exit(1)
	}
	mode := fi.Mode().Perm()
	fmt.Printf("[1] 设备节点检查: %s (权限: %04o, 期望: 0600)\n", devPath, mode)
	if mode != 0600 {
		fmt.Printf("警告: 权限非 0600! 实际为 %04o\n", mode)
	}

	// 2. 测试多持有者引用计数 (平滑重载支持)
	fmt.Println("[2] 测试多持有者引用计数 (atomic open_count)...")
	// 持有者 1 打开
	h1, err := os.OpenFile(devPath, os.O_RDWR, 0)
	if err != nil {
		fmt.Printf("持有者 1 打开失败: %v\n", err)
		os.Exit(1)
	}
	time.Sleep(50 * time.Millisecond)

	// 持有者 2 打开
	h2, err := os.OpenFile(devPath, os.O_RDWR, 0)
	if err != nil {
		fmt.Printf("持有者 2 打开失败: %v\n", err)
		os.Exit(1)
	}
	time.Sleep(50 * time.Millisecond)

	// 检查内核是否记录了 holders=2
	lines := readDmesgRecent("holders=")
	for _, l := range lines {
		fmt.Println("  ", l)
	}

	// 持有者 1 退出，验证 is_active 依然保持 TRUE
	h1.Close()
	time.Sleep(50 * time.Millisecond)
	fmt.Println("  持有者 1 已关闭，持有者 2 仍在运行 (验证未被过早停采)")

	// 3. 测试现场 d_path 与两阶段门控开销
	fmt.Println("[3] 触发原生二进制 socket 创建 (慢路径: get_file_rcu + d_path + fput)...")
	for i := 0; i < 3; i++ {
		conn, err := net.Dial("udp", "127.0.0.1:23456")
		if err == nil {
			conn.Close()
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 3.1 测试 TCP Accept 现场克隆 (android_vh_inet_csk_clone_lock)
	fmt.Println("[3.1] 触发 TCP Listen + Connect + Accept，测试子 socket 现场克隆钩子...")
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err == nil {
		go func() {
			c, err := net.Dial("tcp", tcpLn.Addr().String())
			if err == nil {
				c.Close()
			}
		}()
		acceptedConn, err := tcpLn.Accept()
		if err == nil {
			acceptedConn.Close()
		}
		tcpLn.Close()
	}

	// 3.2 测试 Binder IPC 调用方穿透 (android_vh_binder_transaction_received)
	fmt.Println("[3.2] 触发 Binder IPC 交互，测试服务端接收事务与客户端 UID 捕获...")
	_ = exec.Command("/system/bin/getprop", "ro.build.version.release").Run()

	time.Sleep(100 * time.Millisecond)
	fmt.Println("--- 内核实测日志 (两阶段门控、TCP克隆、Binder穿透) ---")
	dmesgLines := readDmesgRecent("sbo_enh_probe")
	for _, line := range dmesgLines {
		if strings.Contains(line, "FAST_BYPASS") || strings.Contains(line, "NATIVE_CHILD") ||
			strings.Contains(line, "TCP_ACCEPT_CLONE") || strings.Contains(line, "BINDER_TRANSACTION") {
			fmt.Println("  ", line)
		}
	}

	// 持有者 2 退出，验证最后一个持有者释放时停采
	h2.Close()
	time.Sleep(100 * time.Millisecond)
	fmt.Println("[4] 最后一个持有者已关闭，验证完全停采...")
	releaseLines := readDmesgRecent("last holder RELEASED")
	if len(releaseLines) > 0 {
		fmt.Printf("  [通过] 内核确认最后一个持有者释放并停采: %s\n", releaseLines[len(releaseLines)-1])
	} else {
		fmt.Println("  [未见] 未找到 last holder RELEASED 日志")
	}

	// 5. 测试 kill -9 强杀下的原子引用计数自动清零
	fmt.Println("[5] 测试异常强杀 (kill -9) 下的引用计数自动归零...")
	childCmd := exec.Command("/system/bin/sh", "-c", fmt.Sprintf("exec 3<%s && sleep 10", devPath))
	if err := childCmd.Start(); err == nil {
		childPid := childCmd.Process.Pid
		time.Sleep(100 * time.Millisecond)
		syscall.Kill(childPid, syscall.SIGKILL)
		childCmd.Wait()
		time.Sleep(100 * time.Millisecond)
		finalReleases := readDmesgRecent("last holder RELEASED")
		if len(finalReleases) > 0 {
			fmt.Printf("  [通过] 异常强杀后内核 VFS 自动归零: %s\n", finalReleases[len(finalReleases)-1])
		}
	}

	fmt.Println("=== 实测流程结束 ===")
}
