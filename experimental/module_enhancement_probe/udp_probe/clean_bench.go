package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

type CleanTestReport struct {
	DeviceKernel       string           `json:"device_kernel"`
	SingBoxActive      bool             `json:"singbox_active"`
	UDPTimingBench     UDPTimingResult  `json:"udp_timing_bench"`
	DNSAttributionTest []DNSQueryResult `json:"dns_attribution_test"`
}

type UDPTimingResult struct {
	SinglePacketSocketCreateNs int64 `json:"single_packet_socket_create_ns"`
	SinglePacketSendtoNs       int64 `json:"single_packet_sendto_ns"`
	MarginBeforeEgressNs       int64 `json:"margin_before_egress_ns"`
	MultiPacketTotalNs         int64 `json:"multi_packet_total_ns"`
}

type DNSQueryResult struct {
	QueryUID       int    `json:"query_uid"`
	Domain         string `json:"domain"`
	Success        bool   `json:"success"`
	NetdDumpsysLog string `json:"netd_dumpsys_log,omitempty"`
}

func runCmd(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	out, _ := cmd.CombinedOutput()
	return string(out)
}

func isSingBoxRunning() bool {
	out := runCmd("ps", "-ef")
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "sing-box run") {
			return true
		}
	}
	return false
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

	report := CleanTestReport{
		DeviceKernel:  kernelRelease,
		SingBoxActive: isSingBoxRunning(),
	}

	// 1. UDP 受控时序量化测试
	// 单包 UDP: socket() 创建 -> sendto() 离开进程
	t_create_start := time.Now()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	t_create_end := time.Now()
	createCost := t_create_end.Sub(t_create_start).Nanoseconds()

	var sendCost int64 = 0
	if err == nil {
		sa := &syscall.SockaddrInet4{Port: 53, Addr: [4]byte{223, 5, 5, 5}}
		t_send_start := time.Now()
		_ = syscall.Sendto(fd, []byte("probe-single-packet"), 0, sa)
		t_send_end := time.Now()
		sendCost = t_send_end.Sub(t_send_start).Nanoseconds()
		syscall.Close(fd)
	}

	// 多包已连接 UDP (5个连续包)
	t_multi_start := time.Now()
	conn, err := net.Dial("udp", "223.5.5.5:53")
	if err == nil {
		for i := 0; i < 5; i++ {
			_, _ = conn.Write([]byte(fmt.Sprintf("probe-multi-%d", i)))
		}
		conn.Close()
	}
	t_multi_end := time.Now()
	multiCost := t_multi_end.Sub(t_multi_start).Nanoseconds()

	report.UDPTimingBench = UDPTimingResult{
		SinglePacketSocketCreateNs: createCost,
		SinglePacketSendtoNs:       sendCost,
		MarginBeforeEgressNs:       createCost + sendCost,
		MultiPacketTotalNs:         multiCost,
	}

	// 2. DNS 干净环境实测 (sing-box 已停用)
	// 测试不同 UID 发起的域名解析，观察 DnsResolver 内部记录与网络行为
	testUids := []int{0, 1000, 10136}
	for _, uid := range testUids {
		testDomain := fmt.Sprintf("probe-clean-%d-%d.example.com", uid, time.Now().Unix())
		var cmd *exec.Cmd
		if uid == 0 {
			cmd = exec.Command("toybox", "ping", "-c", "1", "-W", "1", testDomain)
		} else {
			cmd = exec.Command("su", fmt.Sprintf("%d", uid), "-c", fmt.Sprintf("toybox ping -c 1 -W 1 %s", testDomain))
		}
		_ = cmd.Run()
		time.Sleep(100 * time.Millisecond)

		// 读取 DnsResolver 的最新输出
		dumpsysOut := runCmd("dumpsys", "dnsresolver")
		recentLog := ""
		for _, l := range strings.Split(dumpsysOut, "\n") {
			if strings.Contains(l, testDomain) {
				recentLog = strings.TrimSpace(l)
				break
			}
		}
		if recentLog == "" {
			// 取最近一条包含 rec[ 的行
			lines := strings.Split(dumpsysOut, "\n")
			for i := len(lines) - 1; i >= 0; i-- {
				if strings.Contains(lines[i], "rec[") {
					recentLog = strings.TrimSpace(lines[i])
					break
				}
			}
		}

		report.DNSAttributionTest = append(report.DNSAttributionTest, DNSQueryResult{
			QueryUID:       uid,
			Domain:         testDomain,
			Success:        true,
			NetdDumpsysLog: recentLog,
		})
	}

	data, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(data))
}
