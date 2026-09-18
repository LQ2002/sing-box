// sbo-stresstest 压测 sb_sockowner_probe 并验证跨进程归属。
//
// 覆盖两件 cookietest 没覆盖的事：
//
//  1. 跨进程 + 非 root UID。cookietest 里创建方和查询方都是同一个 root 进程，
//     而真实场景是应用（非 root，各自不同 UID）建 socket、sing-box（root）
//     查询。本程序以 syscall.Credential 派生不同 UID 的子进程来建 socket，
//     父进程以 root 反查并核对 tgid/uid 是否确为子进程的。
//
//  2. 容量与淘汰。模块的 owner 表有上限，满了会从最旧一端淘汰。本程序可以
//     一次性建到超过上限，观察 /proc/sb_sockowner_probe 的 evicted 是否按预期
//     增长，以及淘汰是否真的保住了最新条目——最新的那些正是查询方要问的。
//
// 需要 root。构建：
//
//	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o sbo-stresstest .
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	devPath  = "/dev/sb_sockowner_probe"
	procPath = "/proc/sb_sockowner_probe"
	soCookie = 57
	iocQuery = 0xc0305301
	commLen  = 16
)

type sboQuery struct {
	Cookie      uint64
	Tgid        int32
	Uid         uint32
	StartTimeNs uint64
	Family      uint16
	Reserved    uint16
	Comm        [commLen]byte
}

var _ [1]struct{} = [unsafe.Sizeof(sboQuery{}) - 47]struct{}{}

func socketCookie(fd int) (uint64, error) {
	var value uint64
	size := uint32(unsafe.Sizeof(value))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT,
		uintptr(fd), uintptr(syscall.SOL_SOCKET), uintptr(soCookie),
		uintptr(unsafe.Pointer(&value)), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return 0, errno
	}
	return value, nil
}

func query(devFD int, cookie uint64) (sboQuery, error) {
	request := sboQuery{Cookie: cookie}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(devFD), uintptr(iocQuery), uintptr(unsafe.Pointer(&request)))
	if errno != 0 {
		return request, errno
	}
	return request, nil
}

func commString(raw [commLen]byte) string {
	if index := bytes.IndexByte(raw[:], 0); index >= 0 {
		return string(raw[:index])
	}
	return string(raw[:])
}

// readCounters 读 /proc 里的状态快照，用于比较压测前后的变化。
func readCounters() map[string]int64 {
	out := map[string]int64{}
	raw, err := os.ReadFile(procPath)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if value, convErr := strconv.ParseInt(fields[1], 10, 64); convErr == nil {
			out[fields[0]] = value
		}
	}
	return out
}

// ---------------------------------------------------------------- 子进程模式

// runChild 由父进程以指定 UID 派生。它建 socket 并把 cookie 报回父进程，
// 然后保持它们打开直到 stdin 关闭——必须保持打开，否则 socket 提前释放会
// 进入宽限期，父进程查询时看到的就不是稳定状态了。
func runChild(count int) error {
	writer := bufio.NewWriter(os.Stdout)
	fmt.Fprintf(writer, "pid %d uid %d\n", os.Getpid(), os.Getuid())

	kept := make([]int, 0, count)
	for index := 0; index < count; index++ {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
		if err != nil {
			break
		}
		kept = append(kept, fd)
		cookie, err := socketCookie(fd)
		if err != nil {
			continue
		}
		fmt.Fprintf(writer, "cookie %d\n", cookie)
	}
	fmt.Fprintf(writer, "done %d\n", len(kept))
	if err := writer.Flush(); err != nil {
		return err
	}
	// 父进程读完后会关掉管道，这里随之退出，socket 一直活到那一刻。
	var wait [1]byte
	_, _ = os.Stdin.Read(wait[:])
	return nil
}

type childResult struct {
	uid     uint32
	pid     int
	cookies []uint64
	err     error
	// close 由父进程在查询完成后调用，放子进程退出。必须等到那时——子进程
	// 一退出，它的 socket 就被释放并进入宽限期，归属查询看到的就不是稳定状态。
	close func()
}

// spawnChild 以指定 UID 派生子进程。内核在 exec 前完成 setuid，所以这是可靠的
// 降权方式——在 Go 里直接调 setuid 只影响当前线程，不可靠。
func spawnChild(self string, uid uint32, count int) childResult {
	result := childResult{uid: uid}
	command := exec.Command(self, "-child", "-count", strconv.Itoa(count))
	command.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: uid},
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		result.err = err
		return result
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		result.err = err
		return result
	}
	if err = command.Start(); err != nil {
		result.err = err
		return result
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "pid":
			result.pid, _ = strconv.Atoi(fields[1])
		case "cookie":
			if cookie, convErr := strconv.ParseUint(fields[1], 10, 64); convErr == nil {
				result.cookies = append(result.cookies, cookie)
			}
		case "done":
			// 子进程已把全部 cookie 报完，socket 仍然打开。
			return finishChild(result, command, stdin)
		}
	}
	return finishChild(result, command, stdin)
}

func finishChild(result childResult, command *exec.Cmd, stdin interface{ Close() error }) childResult {
	// 先让父进程完成查询，再关 stdin 放子进程走——所以这里只记录，不立即关闭。
	result.close = func() {
		_ = stdin.Close()
		_ = command.Wait()
	}
	return result
}

// ------------------------------------------------------------------ 父进程

func crossProcessCheck(devFD int, self string, uids []uint32, perChild int) int {
	fmt.Printf("\n== 跨进程归属（子进程以不同 UID 建 socket，本进程以 root 查询）==\n")
	failed := 0
	children := make([]childResult, 0, len(uids))
	for _, uid := range uids {
		child := spawnChild(self, uid, perChild)
		children = append(children, child)
	}
	for _, child := range children {
		if child.err != nil {
			fmt.Printf("  SKIP uid=%-6d 无法派生子进程: %v\n", child.uid, child.err)
			continue
		}
		if len(child.cookies) == 0 {
			fmt.Printf("  FAIL uid=%-6d 子进程没有报告任何 cookie\n", child.uid)
			failed++
			continue
		}
		hit, mismatch, comm := 0, 0, ""
		for _, cookie := range child.cookies {
			answer, err := query(devFD, cookie)
			if err != nil {
				continue
			}
			hit++
			if int(answer.Tgid) != child.pid || answer.Uid != child.uid {
				mismatch++
			}
			// comm 是模块在子进程调用 socket() 那一刻抓的，应当是子进程自己的
			// 名字而非父进程的——这是归属确实来自创建者的又一个佐证。
			if comm == "" {
				comm = commString(answer.Comm)
			}
		}
		status := "PASS"
		if hit != len(child.cookies) || mismatch != 0 {
			status = "FAIL"
			failed++
		}
		fmt.Printf("  %s uid=%-6d pid=%-7d comm=%-16q 报告 %d 个，查到 %d 个，归属不符 %d 个\n",
			status, child.uid, child.pid, comm, len(child.cookies), hit, mismatch)
	}
	for _, child := range children {
		if child.close != nil {
			child.close()
		}
	}
	return failed
}

// raiseFileLimit 把本进程的 RLIMIT_NOFILE 抬到够建 want 个 socket。
//
// 要触发模块的淘汰路径必须一次持有超过 OWNER_MAX 个 socket，而 Android 默认的
// fd 上限远低于此。以 root 运行时有 CAP_SYS_RESOURCE，可以连硬上限一起抬，
// 所以在程序里做比依赖 shell 的 ulimit 可靠——后者还容易忘。
//
// 上限本身受 /proc/sys/fs/nr_open 约束，超过它 setrlimit 会直接失败。
func raiseFileLimit(want uint64) (before, after syscall.Rlimit, err error) {
	if err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &before); err != nil {
		return before, after, err
	}
	ceiling := uint64(1 << 20)
	if raw, readErr := os.ReadFile("/proc/sys/fs/nr_open"); readErr == nil {
		if parsed, convErr := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64); convErr == nil {
			ceiling = parsed
		}
	}
	if want > ceiling {
		want = ceiling
	}
	// 只抬不降。软上限本来就够用时不要去动它——把别人给的额度改小是副作用，
	// 不是这个函数该做的事。
	if before.Cur >= want {
		return before, before, nil
	}
	target := before
	if target.Max < want {
		target.Max = want
	}
	target.Cur = want
	if err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &target); err != nil {
		return before, before, err
	}
	err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &after)
	return before, after, err
}

func capacityCheck(devFD int, count int) int {
	fmt.Printf("\n== 容量与淘汰（本进程一次建 %d 个 socket）==\n", count)

	// 留出富余：除了这些 socket，还有 /dev 节点、管道、Go 运行时自己的 fd。
	wanted := uint64(count) + 1024
	limitBefore, limitAfter, limitErr := raiseFileLimit(wanted)
	switch {
	case limitErr != nil:
		fmt.Printf("  fd 上限: 当前 %d（抬升失败: %v）\n", limitBefore.Cur, limitErr)
	case limitAfter.Cur != limitBefore.Cur:
		fmt.Printf("  fd 上限: %d -> %d（硬上限 %d）\n",
			limitBefore.Cur, limitAfter.Cur, limitAfter.Max)
	default:
		fmt.Printf("  fd 上限: %d，无需抬升\n", limitBefore.Cur)
	}
	if limitAfter.Cur < wanted {
		fmt.Printf("  注意：上限 %d 低于所需 %d，建 socket 会提前停下\n",
			limitAfter.Cur, wanted)
	}

	before := readCounters()
	fmt.Printf("  压测前: entries=%d capacity=%d evicted=%d\n",
		before["entries"], before["capacity"], before["evicted"])

	kept := make([]int, 0, count)
	cookies := make([]uint64, 0, count)
	start := time.Now()
	for index := 0; index < count; index++ {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
		if err != nil {
			fmt.Printf("  在第 %d 个 socket 处停止: %v（可能受 ulimit -n 限制）\n", index, err)
			break
		}
		kept = append(kept, fd)
		if cookie, cookieErr := socketCookie(fd); cookieErr == nil {
			cookies = append(cookies, cookie)
		}
	}
	elapsed := time.Since(start)
	defer func() {
		for _, fd := range kept {
			_ = syscall.Close(fd)
		}
	}()

	fmt.Printf("  建立 %d 个 socket，耗时 %v（%.1f 个/毫秒）\n",
		len(kept), elapsed.Round(time.Millisecond),
		float64(len(kept))/float64(max(elapsed.Milliseconds(), 1)))

	after := readCounters()
	fmt.Printf("  压测后: entries=%d capacity=%d evicted=%d\n",
		after["entries"], after["capacity"], after["evicted"])

	// 淘汰必须保住最新的条目：它们才是查询方马上要问的。
	// 取最后创建的那批来验证。
	tailSize := min(len(cookies), 256)
	tail := cookies[len(cookies)-tailSize:]
	queryStart := time.Now()
	missing := 0
	for _, cookie := range tail {
		if _, err := query(devFD, cookie); err != nil {
			missing++
		}
	}
	queryElapsed := time.Since(queryStart)

	status := "PASS"
	if missing != 0 {
		status = "FAIL"
	}
	fmt.Printf("  %s 最新 %d 个 cookie 中查不到 %d 个\n", status, tailSize, missing)
	fmt.Printf("  ioctl 平均耗时 %v\n", queryElapsed/time.Duration(max(tailSize, 1)))

	evictedNow := after["evicted"] - before["evicted"]
	if evictedNow == 0 {
		fmt.Printf("  SKIP 淘汰路径未触发（建了 %d 个，上限 %d）；要覆盖它需 -stress 超过上限\n",
			len(kept), after["capacity"])
		if missing != 0 {
			return 1
		}
		return 0
	}

	// 淘汰确实发生了。除了"最新的还在"，还要正面确认"被丢掉的是最旧的"——
	// 否则无法区分淘汰方向对不对，只能说明没丢到刚建的那批而已。
	headSize := min(len(cookies), 256)
	headGone := 0
	for _, cookie := range cookies[:headSize] {
		if _, err := query(devFD, cookie); err != nil {
			headGone++
		}
	}
	headStatus := "PASS"
	if headGone == 0 {
		headStatus = "FAIL"
	}
	fmt.Printf("  发生 %d 次淘汰\n", evictedNow)
	fmt.Printf("  %s 最旧 %d 个 cookie 中已被淘汰 %d 个（应当远多于最新那批的 %d）\n",
		headStatus, headSize, headGone, missing)

	if missing != 0 || headGone == 0 {
		return 1
	}
	return 0
}

func main() {
	childMode := flag.Bool("child", false, "内部使用：以子进程模式运行")
	count := flag.Int("count", 64, "子进程模式下创建的 socket 数")
	stress := flag.Int("stress", 3000, "容量压测创建的 socket 数（0 表示跳过）")
	perChild := flag.Int("per-child", 64, "每个子进程创建的 socket 数")
	flag.Parse()

	if *childMode {
		if err := runChild(*count); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "需要 root：设备节点是 mode 0600 root:root")
		os.Exit(2)
	}
	devFD, err := syscall.Open(devPath, syscall.O_RDWR, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "打开 %s 失败: %v\n（模块没加载？）\n", devPath, err)
		os.Exit(2)
	}
	defer syscall.Close(devFD)

	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	failed := 0
	// 2000=shell、1000=system、10000+=普通应用；后者若因 /data/local/tmp 的
	// 权限无法 exec 会被跳过而不是判失败。
	failed += crossProcessCheck(devFD, self, []uint32{2000, 1000, 10001, 10002}, *perChild)
	if *stress > 0 {
		failed += capacityCheck(devFD, *stress)
	}

	fmt.Printf("\n失败项: %d\n", failed)
	if failed > 0 {
		os.Exit(1)
	}
}
