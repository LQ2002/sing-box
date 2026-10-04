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

	fmt.Println("=== 增强模块可行性真机实测 ===")

	// 1. 检查设备节点是否存在
	if _, err := os.Stat(devPath); err != nil {
		fmt.Printf("错误: 设备节点 %s 不存在，请确认模块已加载: %v\n", devPath, err)
		os.Exit(1)
	}

	// 2. 测试生命周期：打开设备 -> 激活采集
	devFile, err := os.OpenFile(devPath, os.O_RDWR, 0)
	if err != nil {
		fmt.Printf("打开设备失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[1] 成功打开 %s，持有 fd=%d\n", devPath, devFile.Fd())

	// 清理 dmesg 时间戳基线
	time.Sleep(100 * time.Millisecond)

	// 3. 测试现场 d_path 提取与纳秒级开销
	// 创建 3 个不同类型的网络 socket 触发 hook
	fmt.Println("[2] 触发 socket 创建，测试内核现场 d_path() 调用与耗时...")
	for i := 0; i < 3; i++ {
		conn, err := net.Dial("udp", "127.0.0.1:12345")
		if err == nil {
			conn.Close()
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 读取 dmesg 中的 d_path 输出
	time.Sleep(200 * time.Millisecond)
	dmesgLines := readDmesgRecent("sbo_enh_probe")
	fmt.Println("--- 内核实测采样 (d_path 路径、开销、dev、inode) ---")
	dpathFound := false
	for _, line := range dmesgLines {
		if strings.Contains(line, "d_path=") {
			fmt.Println("  ", line)
			dpathFound = true
		}
	}
	if !dpathFound {
		fmt.Println("  (未在 dmesg 中找到包含 d_path 的采样行)")
	}

	// 4. 关闭设备文件，验证主动关闭感知
	devFile.Close()
	time.Sleep(100 * time.Millisecond)
	fmt.Println("[3] 主动关闭文件描述符完成")

	// 5. 测试 kill -9 异常退出下的内核感知能力
	fmt.Println("[4] 测试子进程被 kill -9 强杀时，内核 VFS 是否自动触发 release()...")
	childDone := make(chan bool)
	childPid := 0

	// 启动一个子进程持有 fd 并进入等待
	childCmd := exec.Command("/system/bin/sh", "-c", fmt.Sprintf("exec 3<%s && sleep 10", devPath))
	if err := childCmd.Start(); err != nil {
		fmt.Printf("启动测试子进程失败: %v\n", err)
	} else {
		childPid = childCmd.Process.Pid
		fmt.Printf("  子进程 PID %d 启动并持有设备 fd\n", childPid)
		time.Sleep(200 * time.Millisecond)

		// 检查 dmesg 是否打印了 OPENED
		openLogs := readDmesgRecent("device OPENED")
		if len(openLogs) > 0 {
			fmt.Printf("  内核确认激活: %s\n", openLogs[len(openLogs)-1])
		}

		// 强杀子进程
		tKill := time.Now()
		syscall.Kill(childPid, syscall.SIGKILL)
		childCmd.Wait()
		killDuration := time.Since(tKill)
		fmt.Printf("  已对 PID %d 发送 SIGKILL (耗时 %v)\n", childPid, killDuration)

		time.Sleep(100 * time.Millisecond)
		releaseLogs := readDmesgRecent("device RELEASED")
		if len(releaseLogs) > 0 {
			fmt.Printf("  [通过] 内核 VFS 自动触发 release(): %s\n", releaseLogs[len(releaseLogs)-1])
		} else {
			fmt.Println("  [未见] dmesg 中未找到 RELEASED 记录")
		}
	}

	_ = childDone
	fmt.Println("=== 实测流程结束 ===")
}
