package lab

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// shortDir returns a temp dir with a short path: macOS limits Unix socket
// paths to 104 bytes and t.TempDir() is often longer.
func shortDir(t *testing.T) string {
	d, err := os.MkdirTemp("/tmp", "fjlab")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// port is a fake VM NIC speaking QEMU's stream netdev protocol.
type port struct {
	t      *testing.T
	c      net.Conn
	frames chan []byte
}

func connect(t *testing.T, sw string) *port {
	c, err := net.Dial("unix", sw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	p := &port{t: t, c: c, frames: make(chan []byte, 4096)}
	go func() {
		var hdr [4]byte
		for {
			if _, err := io.ReadFull(c, hdr[:]); err != nil {
				close(p.frames)
				return
			}
			f := make([]byte, binary.BigEndian.Uint32(hdr[:]))
			if _, err := io.ReadFull(c, f); err != nil {
				close(p.frames)
				return
			}
			p.frames <- f
		}
	}()
	return p
}

func (p *port) send(frame []byte) {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(frame)))
	if _, err := p.c.Write(append(b, frame...)); err != nil {
		p.t.Fatal(err)
	}
}

// recv returns the next frame, or nil after a short timeout.
func (p *port) recv() []byte {
	select {
	case f := <-p.frames:
		return f
	case <-time.After(150 * time.Millisecond):
		return nil
	}
}

func frame(dst, src string, payload string) []byte {
	parse := func(s string) []byte {
		hw, _ := net.ParseMAC(s)
		return hw
	}
	f := append(parse(dst), parse(src)...)
	f = append(f, 0x08, 0x00)
	return append(f, payload...)
}

const (
	bcast = "ff:ff:ff:ff:ff:ff"
	macA  = "52:54:00:00:00:0a"
	macB  = "52:54:00:00:00:0b"
	macC  = "52:54:00:00:00:0c"
)

func startSwitch(t *testing.T, pcap io.Writer, configure func(*Switch)) (*Switch, string) {
	d := shortDir(t)
	path := filepath.Join(d, "sw")
	sw, err := NewSwitch(path, pcap)
	if err != nil {
		t.Fatal(err)
	}
	if configure != nil {
		configure(sw)
	}
	done := make(chan struct{})
	go func() { sw.Serve(); close(done) }()
	t.Cleanup(func() { sw.Close(); <-done })
	return sw, path
}

// connected waits until the switch has n ports.
func connected(t *testing.T, sw *Switch, n int) {
	for range 100 {
		sw.mu.Lock()
		got := len(sw.ports)
		sw.mu.Unlock()
		if got == n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("switch never had %d ports", n)
}

func TestSwitchFloodsThenLearns(t *testing.T) {
	var pcap bytes.Buffer
	var mu sync.Mutex
	sw, path := startSwitch(t, lockedWriter{&mu, &pcap}, nil)
	a, b, c := connect(t, path), connect(t, path), connect(t, path)
	connected(t, sw, 3)

	// A broadcasts (DHCPDISCOVER): B and C both receive, A does not.
	a.send(frame(bcast, macA, "discover"))
	if !bytes.Contains(b.recv(), []byte("discover")) || !bytes.Contains(c.recv(), []byte("discover")) {
		t.Fatal("broadcast not flooded")
	}
	if a.recv() != nil {
		t.Fatal("broadcast echoed to sender")
	}

	// B replies unicast to A: the switch learned A, so only A receives.
	b.send(frame(macA, macB, "offer"))
	if !bytes.Contains(a.recv(), []byte("offer")) {
		t.Fatal("unicast to learned MAC not delivered")
	}
	if c.recv() != nil {
		t.Fatal("unicast to learned MAC leaked to another port")
	}

	// Unknown unicast floods.
	a.send(frame(macC, macA, "who"))
	if !bytes.Contains(c.recv(), []byte("who")) || !bytes.Contains(b.recv(), []byte("who")) {
		t.Fatal("unknown unicast not flooded")
	}
	if sw.Frames.Load() != 3 {
		t.Fatalf("frames = %d", sw.Frames.Load())
	}
	mu.Lock()
	p := pcap.Bytes()
	if binary.LittleEndian.Uint32(p) != 0xa1b2c3d4 || binary.LittleEndian.Uint32(p[20:]) != 1 {
		t.Fatal("bad pcap header")
	}
	if first := binary.LittleEndian.Uint32(p[24+8:]); first != uint32(len(frame(bcast, macA, "discover"))) {
		t.Fatalf("first pcap record length = %d", first)
	}
	mu.Unlock()
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// A port that disconnects is forgotten, MACs and all: frames for it flood
// to whoever is left.
func TestSwitchForgetsDisconnectedPort(t *testing.T) {
	sw, path := startSwitch(t, nil, nil)
	a, b := connect(t, path), connect(t, path)
	connected(t, sw, 2)
	b.send(frame(bcast, macB, "hello"))
	a.recv()
	b.c.Close()
	connected(t, sw, 1)
	c := connect(t, path)
	connected(t, sw, 2)
	a.send(frame(macB, macA, "where are you"))
	if !bytes.Contains(c.recv(), []byte("where are you")) {
		t.Fatal("frame for a departed MAC was not flooded")
	}
}

func TestSwitchPaused(t *testing.T) {
	sw, path := startSwitch(t, nil, nil)
	a, b := connect(t, path), connect(t, path)
	connected(t, sw, 2)
	sw.Paused.Store(true)
	a.send(frame(bcast, macA, "x"))
	if b.recv() != nil {
		t.Fatal("a paused switch forwarded")
	}
	if sw.Dropped.Load() != 1 {
		t.Fatalf("dropped = %d", sw.Dropped.Load())
	}
}

func TestBucket(t *testing.T) {
	now := time.Now()
	b := bucket{rate: 1000, burst: 10}
	for i := range 10 {
		if d := b.take(1, now); d != 0 {
			t.Fatalf("token %d waited %v inside the burst", i, d)
		}
	}
	if d := b.take(1, now); d < 900*time.Microsecond || d > 1100*time.Microsecond {
		t.Errorf("11th of a 1000/s bucket waits %v, want 1ms", d)
	}
	if d := b.take(1, now.Add(time.Second)); d != 0 {
		t.Errorf("after refilling, waited %v", d)
	}
}

// The frame cap holds whatever the sizes: 200 tiny frames at 1000/s take
// at least ~180 ms (after a 1/50 s burst).
func TestSwitchFrameRate(t *testing.T) {
	sw, path := startSwitch(t, nil, func(s *Switch) { s.FrameRate = 1000; s.Rate = -1 })
	a, b := connect(t, path), connect(t, path)
	connected(t, sw, 2)
	b.send(frame(bcast, macB, "learn")) // so frames to B are unicast
	a.recv()
	start := time.Now()
	for range 200 {
		a.send(frame(macB, macA, "x"))
	}
	for got := 0; got < 200; got++ {
		if b.recv() == nil {
			t.Fatalf("only %d frames arrived (dropped %d)", got, sw.Dropped.Load())
		}
	}
	if d := time.Since(start); d < 150*time.Millisecond {
		t.Errorf("200 frames in %v: faster than 1000/s", d)
	}
	if sw.Waits.Load() == 0 {
		t.Error("no frame waited")
	}
}

// The byte cap: ~280 KiB at 1 MiB/s takes at least ~200 ms.
func TestSwitchByteRate(t *testing.T) {
	sw, path := startSwitch(t, nil, func(s *Switch) { s.Rate = 1 << 20; s.FrameRate = -1 })
	a, b := connect(t, path), connect(t, path)
	connected(t, sw, 2)
	b.send(frame(bcast, macB, "learn"))
	a.recv()
	payload := string(bytes.Repeat([]byte("x"), 1400))
	start := time.Now()
	go func() {
		for range 200 {
			a.send(frame(macB, macA, payload))
		}
	}()
	for got := 0; got < 200; got++ {
		if b.recv() == nil {
			t.Fatalf("only %d frames arrived (dropped %d)", got, sw.Dropped.Load())
		}
	}
	if d := time.Since(start); d < 180*time.Millisecond {
		t.Errorf("280 KiB in %v: faster than 1 MiB/s", d)
	}
}

// A port that stops reading loses its own frames once its queue is full;
// the others keep getting theirs.
func TestSwitchSlowPortDropsOnlyItsOwn(t *testing.T) {
	sw, path := startSwitch(t, nil, func(s *Switch) { s.Rate, s.FrameRate = -1, -1 })
	a, b := connect(t, path), connect(t, path)
	stuck, err := net.Dial("unix", path) // never reads
	if err != nil {
		t.Fatal(err)
	}
	defer stuck.Close()
	connected(t, sw, 3)
	payload := string(bytes.Repeat([]byte("y"), 1400))
	for range 2000 {
		a.send(frame(bcast, macA, payload))
	}
	got := 0
	for b.recv() != nil {
		got++
	}
	if got != 2000 {
		t.Errorf("a healthy port got %d of 2000 frames", got)
	}
	if sw.Dropped.Load() == 0 {
		t.Error("nothing was dropped for the stuck port")
	}
}

func TestWatchdogTripsAfterMisses(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	results := []error{nil, io.EOF, nil, io.EOF, io.EOF, nil}
	var calls int
	var mu sync.Mutex
	probe := func() error {
		mu.Lock()
		defer mu.Unlock()
		r := results[min(calls, len(results)-1)]
		calls++
		return r
	}
	tripped := make(chan string, 1)
	go watchdog(probe, time.Millisecond, 2, func(r string) { tripped <- r }, stop)
	select {
	case <-tripped:
		mu.Lock()
		if calls != 5 { // one miss is forgiven; two in a row trip
			t.Errorf("tripped after %d probes, want 5", calls)
		}
		mu.Unlock()
	case <-time.After(2 * time.Second):
		t.Fatal("never tripped")
	}
}

// TestProbeMDNS asks the real mDNSResponder (macOS only).
func TestProbeMDNS(t *testing.T) {
	if _, err := exec.LookPath("dns-sd"); err != nil {
		t.Skip("no dns-sd")
	}
	start := time.Now()
	if err := probeMDNS(3 * time.Second); err != nil {
		t.Fatal(err)
	}
	t.Logf("mDNSResponder answered in %v", time.Since(start))
}
