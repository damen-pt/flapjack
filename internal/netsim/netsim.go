// Package netsim is an in-process network for testing cluster topologies:
// hosts with addressed interfaces on switches, switches joined by links,
// and a speed on every link. A connection exists only between interfaces
// whose switches are connected, so a rack node that is not cabled to the
// head really cannot reach it. Each direction of each link is a shared
// rate limiter, so concurrent flows split its bandwidth. Every byte that
// crosses the fabric passes a tap, so tests can assert what is (and is
// not) visible on the wire.
//
// Connections are reliable byte streams (net.Conn), like TCP without
// loss, so TLS and HTTP run over them unchanged.
package netsim

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Link speeds, in bits per second.
const (
	Mbps float64 = 1e6
	Gbps float64 = 1e9
)

// Fabric is the whole simulated network.
type Fabric struct {
	// CaptureLimit caps captured bytes per flow direction (default 4 MiB);
	// counters keep counting beyond it.
	CaptureLimit int

	mu        sync.Mutex
	switches  map[string]*Switch
	hosts     map[string]*Host
	ifaces    map[string]*Iface // ip → interface
	listeners map[string]*listener
	links     []*Link
	flows     []*Flow
	nextPort  int
}

// New returns an empty fabric.
func New() *Fabric {
	return &Fabric{switches: map[string]*Switch{}, hosts: map[string]*Host{}, ifaces: map[string]*Iface{},
		listeners: map[string]*listener{}, nextPort: 40000}
}

// Switch is an L2 segment. Switches joined by links form one network.
type Switch struct {
	Name  string
	links []*Link
}

// Link is a full-duplex cable with a speed in bits per second.
type Link struct {
	Name  string
	A, B  string // switch or "host/ip" endpoint names
	Bps   float64
	dir   [2]*limiter
	bytes [2]atomic.Int64
	// the far switch, for switch-to-switch links
	sa, sb *Switch
}

// Bytes is what has crossed the link from A to B and from B to A.
func (l *Link) Bytes() (ab, ba int64) { return l.bytes[0].Load(), l.bytes[1].Load() }

// Host is a machine with interfaces.
type Host struct {
	Name   string
	fabric *Fabric
	ifaces []*Iface
}

// Iface is a host's interface: an address on a switch.
type Iface struct {
	Host   *Host
	IP     string
	Switch *Switch
	Port   *Link // the cable from the interface to its switch (A = interface)
}

// Switch adds (or returns) a switch.
func (f *Fabric) Switch(name string) *Switch {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.switchLocked(name)
}

func (f *Fabric) switchLocked(name string) *Switch {
	s, ok := f.switches[name]
	if !ok {
		s = &Switch{Name: name}
		f.switches[name] = s
	}
	return s
}

func newLink(name, a, b string, bps float64) *Link {
	l := &Link{Name: name, A: a, B: b, Bps: bps}
	l.dir[0] = &limiter{bytesPerSec: bps / 8}
	l.dir[1] = &limiter{bytesPerSec: bps / 8}
	return l
}

// Connect cables two switches together.
func (f *Fabric) Connect(a, b string, bps float64) *Link {
	f.mu.Lock()
	defer f.mu.Unlock()
	sa, sb := f.switchLocked(a), f.switchLocked(b)
	l := newLink(a+"<->"+b, a, b, bps)
	l.sa, l.sb = sa, sb
	sa.links = append(sa.links, l)
	sb.links = append(sb.links, l)
	f.links = append(f.links, l)
	return l
}

// Host adds (or returns) a host.
func (f *Fabric) Host(name string) *Host {
	f.mu.Lock()
	defer f.mu.Unlock()
	h, ok := f.hosts[name]
	if !ok {
		h = &Host{Name: name, fabric: f}
		f.hosts[name] = h
	}
	return h
}

// Attach gives the host an interface with ip on switch sw, cabled at bps.
func (h *Host) Attach(sw, ip string, bps float64) *Iface {
	f := h.fabric
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, dup := f.ifaces[ip]; dup {
		panic("netsim: duplicate address " + ip)
	}
	s := f.switchLocked(sw)
	l := newLink(h.Name+"/"+ip+"<->"+sw, h.Name+"/"+ip, sw, bps)
	i := &Iface{Host: h, IP: ip, Switch: s, Port: l}
	h.ifaces = append(h.ifaces, i)
	f.ifaces[ip] = i
	f.links = append(f.links, l)
	return i
}

// Links lists every cable.
func (f *Fabric) Links() []*Link {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*Link(nil), f.links...)
}

// hop is one link crossed in one direction.
type hop struct {
	link *Link
	dir  int // 0: A→B, 1: B→A
}

// route finds the switch path between two switches (BFS), as hops.
func (f *Fabric) route(from, to *Switch) ([]hop, bool) {
	if from == to {
		return nil, true
	}
	prev := map[*Switch]hop{}
	seen := map[*Switch]bool{from: true}
	queue := []*Switch{from}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		for _, l := range s.links {
			next, dir := l.sb, 0
			if l.sb == s {
				next, dir = l.sa, 1
			}
			if seen[next] {
				continue
			}
			seen[next] = true
			prev[next] = hop{l, dir}
			if next == to {
				var path []hop
				for cur := to; cur != from; {
					h := prev[cur]
					path = append([]hop{h}, path...)
					if h.dir == 0 {
						cur = h.link.sa
					} else {
						cur = h.link.sb
					}
				}
				return path, true
			}
			queue = append(queue, next)
		}
	}
	return nil, false
}

// Addr is a simulated socket address.
type Addr struct {
	IP   string
	Port int
}

func (a Addr) Network() string { return "tcp" }
func (a Addr) String() string  { return net.JoinHostPort(a.IP, strconv.Itoa(a.Port)) }

type listener struct {
	addr   Addr
	host   *Host
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
	fabric *Fabric
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *listener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		l.fabric.mu.Lock()
		delete(l.fabric.listeners, l.addr.String())
		l.fabric.mu.Unlock()
	})
	return nil
}

func (l *listener) Addr() net.Addr { return l.addr }

// Listen listens on one of the host's addresses ("10.0.0.1:443").
func (h *Host) Listen(addr string) (net.Listener, error) {
	ip, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(ps)
	if err != nil {
		return nil, err
	}
	f := h.fabric
	f.mu.Lock()
	defer f.mu.Unlock()
	if i, ok := f.ifaces[ip]; !ok || i.Host != h {
		return nil, &net.OpError{Op: "listen", Net: "tcp", Err: fmt.Errorf("%s has no address %s", h.Name, ip)}
	}
	a := Addr{ip, port}
	if _, dup := f.listeners[a.String()]; dup {
		return nil, &net.OpError{Op: "listen", Net: "tcp", Err: errors.New("address in use")}
	}
	l := &listener{addr: a, host: h, conns: make(chan net.Conn, 64), closed: make(chan struct{}), fabric: f}
	f.listeners[a.String()] = l
	return l, nil
}

// ErrNoRoute is returned when no cabling connects the two hosts.
var ErrNoRoute = errors.New("no route to host")

// DialContext connects to addr from whichever of the host's interfaces
// can reach it. It has the signature http.Transport wants.
func (h *Host) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	ip, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	rport, err := strconv.Atoi(ps)
	if err != nil {
		return nil, err
	}
	f := h.fabric
	f.mu.Lock()
	defer f.mu.Unlock()
	dst, ok := f.ifaces[ip]
	if !ok {
		return nil, &net.OpError{Op: "dial", Net: network, Err: ErrNoRoute}
	}
	var src *Iface
	var path []hop
	for _, i := range h.ifaces {
		if p, ok := f.route(i.Switch, dst.Switch); ok {
			src, path = i, p
			break
		}
	}
	if src == nil {
		return nil, &net.OpError{Op: "dial", Net: network, Err: fmt.Errorf("%s → %s: %w", h.Name, ip, ErrNoRoute)}
	}
	l, ok := f.listeners[addr]
	if !ok {
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
	}
	// The full path: out of the source port, across switches, into the
	// destination port (traversed B→A, since A is the interface).
	full := append([]hop{{src.Port, 0}}, path...)
	full = append(full, hop{dst.Port, 1})
	back := make([]hop, len(full))
	for i, x := range full {
		back[len(full)-1-i] = hop{x.link, 1 - x.dir}
	}
	f.nextPort++
	local := Addr{src.IP, f.nextPort}
	remote := Addr{ip, rport}
	fl := &Flow{ID: len(f.flows), From: local, To: remote, limit: f.captureLimit()}
	for _, x := range full {
		fl.Links = append(fl.Links, x.link.Name)
	}
	f.flows = append(f.flows, fl)

	ab, ba := newPipe(), newPipe()
	client := &conn{local: local, remote: remote, in: ba, out: ab, path: full, flow: fl, dir: 0}
	server := &conn{local: remote, remote: local, in: ab, out: ba, path: back, flow: fl, dir: 1}
	select {
	case l.conns <- server:
	case <-l.closed:
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return client, nil
}

func (f *Fabric) captureLimit() int {
	if f.CaptureLimit > 0 {
		return f.CaptureLimit
	}
	return 4 << 20
}

// Flow is one connection as seen on the wire.
type Flow struct {
	ID    int
	From  Addr // the dialer
	To    Addr
	Links []string

	mu    sync.Mutex
	limit int
	data  [2][]byte // 0: From→To, 1: To→From
	count [2]int64
}

func (fl *Flow) record(dir int, b []byte) {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	fl.count[dir] += int64(len(b))
	if room := fl.limit - len(fl.data[dir]); room > 0 {
		fl.data[dir] = append(fl.data[dir], b[:min(room, len(b))]...)
	}
}

// Captured returns the bytes seen so far in each direction (up to the
// capture limit) and the total byte counts.
func (fl *Flow) Captured() (fwd, rev []byte, nf, nr int64) {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	return append([]byte(nil), fl.data[0]...), append([]byte(nil), fl.data[1]...), fl.count[0], fl.count[1]
}

// Flows lists every connection made so far.
func (f *Fabric) Flows() []*Flow {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*Flow(nil), f.flows...)
}

// limiter serialises transmissions on one direction of a link.
type limiter struct {
	mu          sync.Mutex
	bytesPerSec float64
	next        time.Time // when the link is free again
}

// reserve books n bytes and returns when they have been sent.
func (l *limiter) reserve(now time.Time, n int) time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.next.Before(now) {
		l.next = now
	}
	l.next = l.next.Add(time.Duration(float64(n) / l.bytesPerSec * float64(time.Second)))
	return l.next
}

// mtu is how much one write books on the links at a time, so concurrent
// flows interleave.
const mtu = 16 << 10

type conn struct {
	local, remote Addr
	in, out       *pipe
	path          []hop
	flow          *Flow
	dir           int
	closeOnce     sync.Once
}

func (c *conn) Read(b []byte) (int, error) { return c.in.read(b) }

func (c *conn) Write(b []byte) (int, error) {
	written := 0
	for len(b) > 0 {
		n := min(len(b), mtu)
		if err := c.out.writable(); err != nil {
			return written, err
		}
		now := time.Now()
		var done time.Time
		for _, h := range c.path {
			if t := h.link.dir[h.dir].reserve(now, n); t.After(done) {
				done = t
			}
			h.link.bytes[h.dir].Add(int64(n))
		}
		// Sleep only once the backlog is worth it: sub-millisecond sleeps
		// cost more than they wait, and the booking keeps the average
		// rate exact either way.
		if wait := time.Until(done); wait > time.Millisecond {
			if dl := c.out.writeDeadline(); !dl.IsZero() && time.Now().Add(wait).After(dl) {
				return written, os.ErrDeadlineExceeded
			}
			time.Sleep(wait)
		}
		c.flow.record(c.dir, b[:n])
		if err := c.out.write(b[:n]); err != nil {
			return written, err
		}
		written += n
		b = b[n:]
	}
	return written, nil
}

func (c *conn) Close() error {
	c.closeOnce.Do(func() {
		c.out.closeWrite()
		c.in.closeRead()
	})
	return nil
}

func (c *conn) LocalAddr() net.Addr  { return c.local }
func (c *conn) RemoteAddr() net.Addr { return c.remote }

func (c *conn) SetDeadline(t time.Time) error {
	c.in.setReadDeadline(t)
	c.out.setWriteDeadline(t)
	return nil
}
func (c *conn) SetReadDeadline(t time.Time) error  { c.in.setReadDeadline(t); return nil }
func (c *conn) SetWriteDeadline(t time.Time) error { c.out.setWriteDeadline(t); return nil }

// pipe is one direction of a connection: an unbounded buffer with
// deadlines.
type pipe struct {
	mu       sync.Mutex
	cond     *sync.Cond
	buf      []byte
	wclosed  bool // writer closed: reads drain then EOF
	rclosed  bool // reader closed: writes fail
	rdl, wdl time.Time
	timer    *time.Timer
}

func newPipe() *pipe {
	p := &pipe{}
	p.cond = sync.NewCond(&p.mu)
	return p
}

func (p *pipe) read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for {
		if p.rclosed {
			return 0, net.ErrClosed
		}
		if len(p.buf) > 0 {
			n := copy(b, p.buf)
			p.buf = p.buf[n:]
			return n, nil
		}
		if p.wclosed {
			return 0, io.EOF
		}
		if !p.rdl.IsZero() && !time.Now().Before(p.rdl) {
			return 0, os.ErrDeadlineExceeded
		}
		p.cond.Wait()
	}
}

func (p *pipe) writable() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.rclosed || p.wclosed {
		return net.ErrClosed
	}
	if !p.wdl.IsZero() && !time.Now().Before(p.wdl) {
		return os.ErrDeadlineExceeded
	}
	return nil
}

func (p *pipe) write(b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.rclosed || p.wclosed {
		return net.ErrClosed
	}
	p.buf = append(p.buf, b...)
	p.cond.Broadcast()
	return nil
}

func (p *pipe) writeDeadline() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.wdl
}

func (p *pipe) closeWrite() {
	p.mu.Lock()
	p.wclosed = true
	p.cond.Broadcast()
	p.mu.Unlock()
}

func (p *pipe) closeRead() {
	p.mu.Lock()
	p.rclosed = true
	p.buf = nil
	p.cond.Broadcast()
	p.mu.Unlock()
}

func (p *pipe) setReadDeadline(t time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rdl = t
	if p.timer != nil {
		p.timer.Stop()
	}
	p.cond.Broadcast()
	if !t.IsZero() {
		p.timer = time.AfterFunc(time.Until(t), func() {
			p.mu.Lock()
			p.cond.Broadcast()
			p.mu.Unlock()
		})
	}
}

func (p *pipe) setWriteDeadline(t time.Time) {
	p.mu.Lock()
	p.wdl = t
	p.mu.Unlock()
}
