// Package sys abstracts running host commands so collectors that wrap
// vendor tools (nvidia-smi, ipmitool, nvme) can be tested with recorded output.
package sys

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// Runner runs a command and returns its standard output.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Exec runs commands on the host.
type Exec struct{}

func (Exec) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// FakeResponse is a canned result for one command line.
type FakeResponse struct {
	Out []byte
	Err error
}

// Fake returns canned output keyed by the full command line and records
// every call. Unknown commands fail.
type Fake struct {
	mu        sync.Mutex
	Responses map[string]FakeResponse
	Calls     []string
}

func (f *Fake) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, line)
	r, ok := f.Responses[line]
	if !ok {
		return nil, fmt.Errorf("fake: unexpected command %q", line)
	}
	return r.Out, r.Err
}
