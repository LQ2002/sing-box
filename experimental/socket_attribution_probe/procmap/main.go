// Build the (uid, processName) -> packages table straight from installed APK
// manifests, i.e. the same key ActivityManager uses (mProcessNames.get(name, uid)),
// then join it with the zygote children that are running right now.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"archive/zip"
	"io"

	"github.com/shogo82148/androidbinary"
)

type comp struct {
	Process string `xml:"http://schemas.android.com/apk/res/android process,attr"`
}

type manifest struct {
	Package string `xml:"package,attr"`
	App     struct {
		Process   string `xml:"http://schemas.android.com/apk/res/android process,attr"`
		Activity  []comp `xml:"activity"`
		Alias     []comp `xml:"activity-alias"`
		Service   []comp `xml:"service"`
		Receiver  []comp `xml:"receiver"`
		Provider  []comp `xml:"provider"`
	} `xml:"application"`
}

func procName(pkg, appProc, p string) string {
	if p == "" {
		p = appProc
	}
	if p == "" {
		return pkg
	}
	if strings.HasPrefix(p, ":") {
		return pkg + p
	}
	return p
}

func main() {
	out, err := exec.Command("pm", "list", "packages", "-f", "-U").Output()
	if err != nil {
		panic(err)
	}
	table := map[string]map[string]bool{} // "uid|proc" -> pkgs
	fails := 0
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		// package:/path/base.apk=com.foo uid:10123[,10124]
		line := strings.TrimPrefix(sc.Text(), "package:")
		sp := strings.LastIndex(line, " uid:")
		if sp < 0 {
			continue
		}
		uid := strings.Split(line[sp+5:], ",")[0]
		pathPkg := line[:sp]
		eq := strings.LastIndex(pathPkg, "=")
		path, pkg := pathPkg[:eq], pathPkg[eq+1:]
		var m manifest
		if err := readManifest(path, &m); err != nil {
			fmt.Printf("FAIL\t%s\t%s\t%v\n", uid, pkg, err)
			fails++
			continue
		}
		add := func(p string) {
			k := uid + "|" + procName(pkg, m.App.Process, p)
			if table[k] == nil {
				table[k] = map[string]bool{}
			}
			table[k][pkg] = true
		}
		add("")
		for _, list := range [][]comp{m.App.Activity, m.App.Alias, m.App.Service, m.App.Receiver, m.App.Provider} {
			for _, c := range list {
				add(c.Process)
			}
		}
	}
	fmt.Printf("MANIFEST_FAILS %d\n", fails)
	for k, set := range table {
		if !strings.HasPrefix(k, "1000|") {
			continue
		}
		var ps []string
		for p := range set {
			ps = append(ps, p)
		}
		sort.Strings(ps)
		fmt.Printf("TABLE1000\t%d\t%s\t%s\n", len(ps), strings.TrimPrefix(k, "1000|"), strings.Join(ps, ","))
	}
	// running zygote children
	z := map[string]bool{}
	for _, n := range []string{"zygote64", "zygote"} {
		o, _ := exec.Command("pidof", n).Output()
		for _, p := range strings.Fields(string(o)) {
			z[p] = true
		}
	}
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		stat, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		f := strings.Fields(string(stat[bytes.LastIndexByte(stat, ')')+1:]))
		if len(f) < 2 || !z[f[1]] {
			continue
		}
		cmd, _ := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		name := string(bytes.SplitN(cmd, []byte{0}, 2)[0])
		st, _ := os.ReadFile("/proc/" + e.Name() + "/status")
		uid := ""
		for _, l := range strings.Split(string(st), "\n") {
			if strings.HasPrefix(l, "Uid:") {
				uid = strings.Fields(l)[1]
			}
		}
		appUID := uid
		var n int
		fmt.Sscan(uid, &n)
		appUID = fmt.Sprint(n % 100000)
		pk := table[appUID+"|"+name]
		var ps []string
		for p := range pk {
			ps = append(ps, p)
		}
		sort.Strings(ps)
		kind := "NONE"
		if len(ps) == 1 {
			kind = "SINGLE"
		} else if len(ps) > 1 {
			kind = "MULTI"
		}
		fmt.Printf("%s\t%s\t%s\t%s\n", kind, uid, name, strings.Join(ps, ","))
	}
}

func readManifest(path string, v interface{}) error {
	z, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer z.Close()
	for _, f := range z.File {
		if f.Name != "AndroidManifest.xml" {
			continue
		}
		r, err := f.Open()
		if err != nil {
			return err
		}
		data, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			return err
		}
		x, err := androidbinary.NewXMLFile(bytes.NewReader(data))
		if err != nil {
			return err
		}
		return x.Decode(v, nil, nil)
	}
	return fmt.Errorf("no manifest")
}
