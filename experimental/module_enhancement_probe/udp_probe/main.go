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

func main() {
	fmt.Println("=== 干净环境下的 UDP 与 DNS 真机实测 (sing-box已停用) ===")

	// 1. 测试基础连通性
	_, err := runCmd("ping", "-c", "1", "223.5.5.5")
	if err != nil {
		fmt.Printf("警告: 外部网络 ping 失败: %v\n", err)
	} else {
		fmt.Println("[1] 网络基础连通正常")
	}

	// 2. 测试 UDP 单包流与多包流时序
	fmt.Println("[2] 测试 UDP 单包流与连接型 UDP...")
	
	// 单包 UDP (未连接，直接 sendto 发1包即关)
	t0 := time.Now()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err == nil {
		sa := &syscall.SockaddrInet4{Port: 53, Addr: [4]byte{223, 5, 5, 5}}
		_ = syscall.Sendto(fd, []byte("probe-single-packet"), 0, sa)
		syscall.Close(fd)
	}
	durSingle := time.Since(t0)
	fmt.Printf("  单包 UDP (socket -> sendto -> close): 总耗时 %v\n", durSingle)

	// 连接型 UDP (connect 后发送5包)
	t1 := time.Now()
	conn, err := net.Dial("udp", "223.5.5.5:53")
	if err == nil {
		for i := 0; i < 5; i++ {
			_, _ = conn.Write([]byte(fmt.Sprintf("probe-multi-packet-%d", i)))
			time.Sleep(2 * time.Millisecond)
		}
		conn.Close()
	}
	durMulti := time.Since(t1)
	fmt.Printf("  多包连接型 UDP (Dial -> 5次Write -> Close): 总耗时 %v\n", durMulti)

	// 3. DNS 干净复测: 以不同 UID 发起真实 DNS 解析，观察上游请求
	fmt.Println("[3] 干净环境下的 DNS UID 归属实测...")

	testUids := []int{0, 1000, 10136, 10452}
	for _, uid := range testUids {
		testDomain := fmt.Sprintf("clean-dns-%d-%d.baidu.com", uid, time.Now().Unix())
		fmt.Printf("  测试以 UID %d 解析域名 %s...\n", uid, testDomain)

		// 启动 tcpdump 抓取 53 端口 1 秒
		pcapFile := fmt.Sprintf("/data/local/tmp/dns_%d.pcap", uid)
		tcpdumpCmd := exec.Command("/system/bin/tcpdump", "-i", "any", "udp port 53", "-c", "2", "-w", pcapFile)
		_ = tcpdumpCmd.Start()
		time.Sleep(100 * time.Millisecond)

		// 触发 DNS 查询
		var queryCmd *exec.Cmd
		if uid == 0 {
			queryCmd = exec.Command("/system/bin/toybox", "ping", "-c", "1", "-W", "1", testDomain)
		} else {
			queryCmd = exec.Command("su", fmt.Sprintf("%d", uid), "-c", fmt.Sprintf("toybox ping -c 1 -W 1 %s", testDomain))
		}
		_ = queryCmd.Run()
		time.Sleep(200 * time.Millisecond)

		if tcpdumpCmd.Process != nil {
			_ = tcpdumpCmd.Process.Kill()
		}

		// 检查 dumpsys dnsresolver 中是否有此记录
		dnsInfo, _ := runCmd("dumpsys", "dnsresolver")
		foundInDumpsys := false
		for _, line := range strings.Split(dnsInfo, "\n") {
			if strings.Contains(line, testDomain) {
				fmt.Printf("    Dumpsys 命中: %s\n", strings.TrimSpace(line))
				foundInDumpsys = true
				break
			}
		}
		if !foundInDumpsys {
			// 查看最近 3 行 dumpsys 记录
			lines := strings.Split(dnsInfo, "\n")
			var lastRecs []string
			for _, l := range lines {
				if strings.Contains(l, "rec[") {
					lastRecs = append(lastRecs, strings.TrimSpace(l))
				}
			}
			if len(lastRecs) > 0 {
				fmt.Printf("    Dumpsys 最近记录: %s\n", lastRecs[len(lastRecs)-1])
			}
		}
		_ = os.Remove(pcapFile)
	}

	fmt.Println("=== 测试完成 ===")
}
