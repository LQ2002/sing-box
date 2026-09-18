//go:build with_ebpf && (linux || android)

package ebpf

import (
	"slices"
	"strconv"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestParsePackageName(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name string
		raw  string
		want string
	}{
		{
			// zygote 用 NUL 把 argv 区填满，整块读会把填充一起带进来。
			name: "应用进程带 NUL 填充",
			raw:  "com.android.settings\x00\x00\x00\x00\x00\x00\x00\x00",
			want: "com.android.settings",
		},
		{
			// 同一个应用的子进程，必须截断到包名，否则
			// package_name: [com.android.settings] 匹配不到它。
			name: "应用子进程",
			raw:  "com.android.settings:provider\x00\x00\x00",
			want: "com.android.settings",
		},
		{
			// 原生二进制不该走到这里，但真读到时不能把路径当包名。
			name: "原生二进制路径",
			raw:  "/system/bin/netd\x00",
			want: "",
		},
		{
			name: "带参数的命令行",
			raw:  "/system/bin/sh\x00-c\x00echo hi\x00",
			want: "",
		},
		{
			name: "空 cmdline",
			raw:  "",
			want: "",
		},
		{
			name: "无 NUL 结尾",
			raw:  "com.example.app",
			want: "com.example.app",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if got := parsePackageName([]byte(testCase.raw)); got != testCase.want {
				t.Errorf("parsePackageName(%q) = %q, want %q", testCase.raw, got, testCase.want)
			}
		})
	}
}

func TestRefineConnectionOwner(t *testing.T) {
	t.Parallel()

	// 模拟 MIUI 上 android.uid.system 共享 UID 的结果：
	// FindProcessInfoByPID 会按 UID 填进一整组包名。
	sharedUIDPackages := []string{"com.xiaomi.joyose", "com.xiaomi.misettings", "com.android.settings"}

	for _, testCase := range []struct {
		name         string
		info         *adapter.ConnectionOwner
		owner        SocketOwner
		lookup       func(uint32) string
		wantPaths    []string
		wantPackages []string
	}{
		{
			// 核心正确性用例：以系统 UID 运行的原生守护进程，绝不能带着一组
			// 包名出去，否则写给某个应用的 package_name 规则会把它的流量分流走。
			name: "原生守护进程清空包名",
			info: &adapter.ConnectionOwner{
				ProcessPaths: []string{"/system/bin/netd"},
				PackageNames: sharedUIDPackages,
			},
			owner:        SocketOwner{ProcessID: 2068},
			lookup:       func(uint32) string { return "" },
			wantPaths:    []string{"/system/bin/netd"},
			wantPackages: nil,
		},
		{
			name: "厂商守护进程同样清空",
			info: &adapter.ConnectionOwner{
				ProcessPaths: []string{"/vendor/bin/minetd"},
				PackageNames: sharedUIDPackages,
			},
			owner:        SocketOwner{ProcessID: 3130},
			lookup:       func(uint32) string { return "" },
			wantPaths:    []string{"/vendor/bin/minetd"},
			wantPackages: nil,
		},
		{
			// 精度用例：共享 UID 下从一组包名收敛到确切的那一个。
			name: "应用进程收敛为单个包名",
			info: &adapter.ConnectionOwner{
				ProcessPaths: []string{"/system/bin/app_process64"},
				PackageNames: sharedUIDPackages,
			},
			owner:  SocketOwner{ProcessID: 27693},
			lookup: func(uint32) string { return "com.android.settings" },
			// 应用刻意不填 ProcessPaths：app_process64 是 zygote 的路径而非
			// 这个应用的，填了会在"路径优先"的展示与日志逻辑里挤掉包名。
			wantPaths:    nil,
			wantPackages: []string{"com.android.settings"},
		},
		{
			name: "32 位应用进程",
			info: &adapter.ConnectionOwner{
				ProcessPaths: []string{"/system/bin/app_process32"},
			},
			owner:        SocketOwner{ProcessID: 100},
			lookup:       func(uint32) string { return "com.example.app" },
			wantPaths:    nil,
			wantPackages: []string{"com.example.app"},
		},
		{
			// cmdline 读不到但按 UID 已有结果时保留它：多个包名也好过没有。
			name: "cmdline 不可读则保留 UID 推断",
			info: &adapter.ConnectionOwner{
				ProcessPaths: []string{"/system/bin/app_process64"},
				PackageNames: sharedUIDPackages,
			},
			owner:        SocketOwner{ProcessID: 200, Comm: "settings"},
			lookup:       func(uint32) string { return "" },
			wantPaths:    nil,
			wantPackages: sharedUIDPackages,
		},
		{
			name: "cmdline 与 UID 都没有则退回 comm",
			info: &adapter.ConnectionOwner{
				ProcessPaths: []string{"/system/bin/app_process64"},
			},
			owner:        SocketOwner{ProcessID: 201, Comm: "com.example.ap"},
			lookup:       func(uint32) string { return "" },
			wantPaths:    nil,
			wantPackages: []string{"com.example.ap"},
		},
		{
			// 短命进程：连接建立时 procfs 已经消失，模块在 socket() 时抓的
			// comm 是唯一幸存的线索。
			name: "进程已退出时用 comm 兜底",
			info: &adapter.ConnectionOwner{
				PackageNames: sharedUIDPackages,
			},
			owner:        SocketOwner{ProcessID: 300, Comm: "curl"},
			lookup:       func(uint32) string { return "" },
			wantPaths:    []string{"curl"},
			wantPackages: nil,
		},
		{
			name:         "进程已退出且无 comm",
			info:         &adapter.ConnectionOwner{PackageNames: sharedUIDPackages},
			owner:        SocketOwner{ProcessID: 301},
			lookup:       func(uint32) string { return "" },
			wantPaths:    nil,
			wantPackages: nil,
		},
		{
			// readlink 对已删除的二进制会追加后缀，不剥掉则 process_path
			// 规则匹配不上。
			name: "剥掉已删除后缀",
			info: &adapter.ConnectionOwner{
				ProcessPaths: []string{"/data/local/tmp/probe (deleted)"},
			},
			owner:        SocketOwner{ProcessID: 400},
			lookup:       func(uint32) string { return "" },
			wantPaths:    []string{"/data/local/tmp/probe"},
			wantPackages: nil,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			refineConnectionOwner(testCase.info, testCase.owner, testCase.lookup)
			if !slices.Equal(testCase.info.ProcessPaths, testCase.wantPaths) {
				t.Errorf("ProcessPaths = %q, want %q", testCase.info.ProcessPaths, testCase.wantPaths)
			}
			if !slices.Equal(testCase.info.PackageNames, testCase.wantPackages) {
				t.Errorf("PackageNames = %q, want %q", testCase.info.PackageNames, testCase.wantPackages)
			}
		})
	}
}

// TestRefineConnectionOwnerNil 确认 FindProcessInfoByPID 返回 nil 时不 panic。
func TestRefineConnectionOwnerNil(t *testing.T) {
	t.Parallel()
	refineConnectionOwner(nil, SocketOwner{ProcessID: 1, Comm: "x"},
		func(uint32) string { return "pkg" })
}

func TestParseStartTicks(t *testing.T) {
	t.Parallel()

	// 真实 /proc/<pid>/stat 的形状：第 22 个字段是 starttime。
	// 这里把它设为 1234567，前面按真实格式补齐 21 个字段。
	const startTicks = 1234567
	build := func(comm string) []byte {
		return []byte("4242 (" + comm + ") S 1 4242 4242 0 -1 4194560 " +
			"100 0 0 0 10 20 0 0 20 0 1 0 " +
			strconv.Itoa(startTicks) + " 123456 789 18446744073709551615")
	}

	for _, testCase := range []struct {
		name string
		raw  []byte
		want uint64
		ok   bool
	}{
		{"普通进程名", build("netd"), startTicks, true},
		// 进程名里含空格：不能按空格直接切分整行。
		{"进程名含空格", build("Binder:1234 5"), startTicks, true},
		// 进程名里含右括号：必须从最后一个 ')' 之后开始切分。
		{"进程名含右括号", build("weird)name"), startTicks, true},
		{"两者兼有", build("a ) b"), startTicks, true},
		{"没有右括号", []byte("4242 no parens here"), 0, false},
		{"字段不足", []byte("4242 (x) S 1 2 3"), 0, false},
		{"空输入", []byte(""), 0, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			got, ok := parseStartTicks(testCase.raw)
			if ok != testCase.ok {
				t.Fatalf("ok = %v, want %v", ok, testCase.ok)
			}
			if got != testCase.want {
				t.Errorf("ticks = %d, want %d", got, testCase.want)
			}
		})
	}
}
