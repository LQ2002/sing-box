// How long after ActivityManager writes am_proc_start does a live reader
// of the events buffer see it? Streams logcat and compares arrival time
// with the entry's own timestamp.
package main

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"time"
)

func main() {
	cmd := exec.Command("logcat", "-b", "events", "-v", "epoch", "-T", "1")
	out, _ := cmd.StdoutPipe()
	cmd.Start()
	re := regexp.MustCompile(`^\s*([\d.]+)\s.*am_proc_start: \[\d+,\d+,(\d+),([^,]+)`)
	done := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			arrive := float64(time.Now().UnixNano()) / 1e9
			if m := re.FindStringSubmatch(sc.Text()); m != nil {
				ts, _ := strconv.ParseFloat(m[1], 64)
				fmt.Printf("delivery latency %6.1f ms  uid=%s %s\n", (arrive-ts)*1000, m[2], m[3])
			}
		}
		close(done)
	}()
	time.Sleep(time.Second)
	for _, a := range []string{"com.android.deskclock", "com.miui.calculator", "com.android.deskclock", "com.miui.calculator"} {
		exec.Command("/system/bin/sh", "-c", "am force-stop "+a+"; monkey -p "+a+" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1").Run()
		time.Sleep(3 * time.Second)
	}
	cmd.Process.Kill()
	<-done
}
