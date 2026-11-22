package lab

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The lab's safety watchdog. An unpaced lab switch once hung macOS's
// kernel socket paths: mDNSResponder stopped answering, configd blocked on
// it, and the userspace watchdog panicked or reset the Mac about four
// minutes later (see Switch). The switch's caps are the real defence; this
// is the backstop. It asks mDNSResponder a question every couple of
// seconds, and the moment it stops answering the lab pauses its switches
// and powers off its VMs, minutes before macOS would act.
//
// It cannot help if the kernel wedges the daemon itself: that is why the
// switch is capped well below the rate that caused it.

// probeMDNS asks mDNSResponder (through dns-sd, which talks to the daemon
// itself, unlike getaddrinfo for localhost) for localhost's address.
func probeMDNS(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "dns-sd", "-G", "v4", "localhost")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) >= 6 && f[1] == "Add" && strings.HasPrefix(f[4], "localhost") {
			return nil
		}
	}
	if ctx.Err() != nil {
		return fmt.Errorf("mDNSResponder did not answer within %v", timeout)
	}
	return errors.New("dns-sd exited without an answer")
}

// watchdog calls probe every interval and trip once probe has failed
// misses times in a row. It returns when stop closes or after tripping.
func watchdog(probe func() error, interval time.Duration, misses int, trip func(reason string), stop <-chan struct{}) {
	failed := 0
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		if err := probe(); err != nil {
			failed++
			if failed >= misses {
				trip(err.Error())
				return
			}
			continue
		}
		failed = 0
	}
}

// SafetyStopPath records why the watchdog stopped the lab.
func (st State) SafetyStopPath() string { return filepath.Join(st.Dir, "safety-stop") }
