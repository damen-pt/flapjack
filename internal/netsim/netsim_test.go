package netsim

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"sync"
	"testing"
	"time"
)

// pair builds two hosts on two switches joined by a link of bps, with
// host ports twice as fast so the inter-switch link is the bottleneck.
func pair(bps float64) (*Fabric, *Host, *Host) {
	f := New()
	a, b := f.Host("a"), f.Host("b")
	a.Attach("s1", "10.0.0.1", 2*bps)
	b.Attach("s2", "10.0.0.2", 2*bps)
	f.Connect("s1", "s2", bps)
	return f, a, b
}

// sink accepts connections and discards what it reads, reporting bytes.
func sink(t *testing.T, h *Host, addr string) {
	ln, err := h.Listen(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(io.Discard, c); c.Close() }()
		}
	}()
}

func send(t *testing.T, h *Host, addr string, n int) time.Duration {
	c, err := h.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	if _, err := c.Write(make([]byte, n)); err != nil {
		t.Fatal(err)
	}
	return time.Since(start)
}

func TestReachability(t *testing.T) {
	f := New()
	a, b, c := f.Host("a"), f.Host("b"), f.Host("c")
	a.Attach("s1", "10.0.0.1", Gbps)
	b.Attach("s1", "10.0.0.2", Gbps)
	c.Attach("island", "10.9.0.1", Gbps)
	sink(t, b, "10.0.0.2:80")
	sink(t, c, "10.9.0.1:80")
	if _, err := a.DialContext(context.Background(), "tcp", "10.0.0.2:80"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DialContext(context.Background(), "tcp", "10.9.0.1:80"); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("reached an unconnected switch: %v", err)
	}
	if _, err := a.DialContext(context.Background(), "tcp", "10.0.0.2:81"); err == nil {
		t.Fatal("connected to a port nobody listens on")
	}
	if _, err := a.Listen("10.0.0.2:80"); err == nil {
		t.Fatal("listened on another host's address")
	}
	// Cabling the island in makes it reachable.
	f.Connect("s1", "island", Gbps)
	if _, err := a.DialContext(context.Background(), "tcp", "10.9.0.1:80"); err != nil {
		t.Fatal(err)
	}
}

func TestRateLimit(t *testing.T) {
	_, a, b := pair(80 * Mbps) // 10 MB/s
	sink(t, b, "10.0.0.2:80")
	took := send(t, a, "10.0.0.2:80", 2<<20) // 2 MiB: ~210ms
	want := time.Duration(float64(2<<20) / 10e6 * float64(time.Second))
	if took < want*9/10 || took > want*2 {
		t.Fatalf("2 MiB at 80 Mb/s took %s, want about %s", took, want)
	}
}

func TestFlowsShareALink(t *testing.T) {
	_, a, b := pair(80 * Mbps)
	sink(t, b, "10.0.0.2:80")
	var wg sync.WaitGroup
	start := time.Now()
	for range 2 {
		wg.Go(func() { send(t, a, "10.0.0.2:80", 1<<20) })
	}
	wg.Wait()
	took := time.Since(start)
	// Two 1 MiB flows on one 10 MB/s link take as long as one 2 MiB flow.
	want := time.Duration(float64(2<<20) / 10e6 * float64(time.Second))
	if math.Abs(float64(took-want)) > float64(want)/3 {
		t.Fatalf("two flows took %s, want about %s", took, want)
	}
}

func TestHTTPAndTap(t *testing.T) {
	f, a, b := pair(Gbps)
	ln, _ := b.Listen("10.0.0.2:80")
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello from "+r.RemoteAddr)
	})}
	go srv.Serve(ln)
	defer srv.Close()
	c := &http.Client{Transport: &http.Transport{DialContext: a.DialContext}}
	resp, err := c.Get("http://10.0.0.2/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.HasPrefix(body, []byte("hello from 10.0.0.1:")) {
		t.Fatalf("body = %q", body)
	}
	fl := f.Flows()
	if len(fl) != 1 {
		t.Fatalf("%d flows", len(fl))
	}
	fwd, rev, _, _ := fl[0].Captured()
	if !bytes.HasPrefix(fwd, []byte("GET / HTTP/1.1")) || !bytes.Contains(rev, []byte("hello from")) {
		t.Fatalf("tap saw %q / %q", fwd, rev)
	}
	if len(fl[0].Links) != 3 {
		t.Fatalf("path = %v", fl[0].Links)
	}
}
