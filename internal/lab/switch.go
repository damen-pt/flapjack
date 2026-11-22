// Package lab runs a Flapjack test cluster of QEMU VMs on one machine: a
// userspace Ethernet switch, a head node, node VMs with emulated TPMs, and
// a Redfish BMC per node backed by QEMU's control socket.
package lab

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Switch is a learning Ethernet switch for QEMU VMs. Each VM NIC connects
// to the switch's Unix stream socket (QEMU's "stream" netdev) and sends
// frames prefixed with their length as a 32-bit big-endian integer. The
// switch learns which connection each source MAC lives on and forwards
// unicast frames there, flooding broadcast, multicast and unknown
// destinations to every other connection. It needs no root and no kernel
// extensions, and records every frame to a pcap file.
//
// Why stream sockets, small queues and two rate caps: every frame passes
// through the Mac's kernel, which is shared with the whole machine. The
// first version used Unix datagrams addressed by path, so the kernel
// looked up a socket path for every frame, twice. At ~25,000 frames/s
// (two tentacles staging an image) mDNSResponder stopped answering, then
// configd, and macOS's watchdog panicked or reset the Mac, three times.
// Connected streams need no lookup per frame and push back on a slow
// reader instead of failing; the frame and byte caps keep the kernel's
// work bounded whatever the VMs do.
type Switch struct {
	ln   *net.UnixListener
	pcap *pcapWriter

	// Rate caps the bytes per second the switch forwards and FrameRate the
	// frames (both counting every copy of a flooded frame). Zero means the
	// default (DefaultSwitchRate, DefaultSwitchFrameRate); negative means
	// unlimited. Set them before Serve.
	Rate, FrameRate int64

	mu     sync.Mutex
	fdb    map[[6]byte]*swPort // MAC → port
	ports  map[*swPort]bool
	closed bool

	limit *limiter
	// Paused stops forwarding (frames are counted as dropped), as the
	// lab's safety watchdog does when the Mac's network daemons stall.
	Paused atomic.Bool

	Frames  atomic.Int64
	Dropped atomic.Int64
	// Waits counts frames the rate caps delayed.
	Waits atomic.Int64
}

// DefaultSwitchRate is 100 Mbit/s and DefaultSwitchFrameRate 4,000
// frames/s: a node still boots its root filesystem in under a minute,
// and the kernel does a small, fixed amount of work for the lab.
const (
	DefaultSwitchRate      = 100_000_000 / 8
	DefaultSwitchFrameRate = 4000
)

// portQueue is how many frames wait for a slow port before the switch
// drops new ones for it, as a real switch's port buffer would.
const portQueue = 256

// maxFrame is the largest frame accepted: Ethernet with a VLAN tag, and
// room for QEMU's offloads. A larger length means a broken connection.
const maxFrame = 65536

type swPort struct {
	conn *net.UnixConn
	out  chan []byte
	done chan struct{}
}

// NewSwitch listens on path. pcapOut may be nil.
func NewSwitch(path string, pcapOut io.Writer) (*Switch, error) {
	os.Remove(path)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	s := &Switch{ln: ln, fdb: map[[6]byte]*swPort{}, ports: map[*swPort]bool{}}
	if pcapOut != nil {
		if s.pcap, err = newPcap(pcapOut); err != nil {
			ln.Close()
			return nil, err
		}
	}
	return s, nil
}

// Close stops the switch and disconnects every port.
func (s *Switch) Close() error {
	s.mu.Lock()
	s.closed = true
	for p := range s.ports {
		p.conn.Close()
	}
	s.mu.Unlock()
	return s.ln.Close()
}

// Serve accepts ports and forwards frames until the switch is closed.
func (s *Switch) Serve() error {
	s.limit = newLimiter(s.Rate, s.FrameRate)
	for {
		c, err := s.ln.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		c.SetWriteBuffer(256 << 10)
		c.SetReadBuffer(256 << 10)
		p := &swPort{conn: c, out: make(chan []byte, portQueue), done: make(chan struct{})}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			c.Close()
			return nil
		}
		s.ports[p] = true
		s.mu.Unlock()
		go s.write(p)
		go s.read(p)
	}
}

// read forwards the frames one port sends until it disconnects.
func (s *Switch) read(p *swPort) {
	defer s.drop(p)
	r := bufio.NewReaderSize(p.conn, 64<<10)
	var hdr [4]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n > maxFrame {
			return
		}
		frame := make([]byte, n)
		if _, err := io.ReadFull(r, frame); err != nil {
			return
		}
		if n >= 14 {
			s.forward(frame, p)
		}
	}
}

// write sends a port's queued frames; a slow VM blocks only itself.
func (s *Switch) write(p *swPort) {
	w := bufio.NewWriterSize(p.conn, 64<<10)
	var hdr [4]byte
	for {
		var frame []byte
		select {
		case frame = <-p.out:
		case <-p.done:
			return
		}
		binary.BigEndian.PutUint32(hdr[:], uint32(len(frame)))
		w.Write(hdr[:])
		w.Write(frame)
		// Batch what is already queued into one write.
		for len(p.out) > 0 && w.Buffered() < 48<<10 {
			f := <-p.out
			binary.BigEndian.PutUint32(hdr[:], uint32(len(f)))
			w.Write(hdr[:])
			w.Write(f)
		}
		if err := w.Flush(); err != nil {
			p.conn.Close()
			return
		}
	}
}

// drop forgets a disconnected port and the MACs learned on it.
func (s *Switch) drop(p *swPort) {
	s.mu.Lock()
	delete(s.ports, p)
	for mac, q := range s.fdb {
		if q == p {
			delete(s.fdb, mac)
		}
	}
	s.mu.Unlock()
	close(p.done)
	p.conn.Close()
}

func (s *Switch) forward(frame []byte, from *swPort) {
	s.Frames.Add(1)
	if s.pcap != nil {
		s.pcap.write(frame)
	}
	if s.Paused.Load() {
		s.Dropped.Add(1)
		return
	}
	var dst, src [6]byte
	copy(dst[:], frame[0:6])
	copy(src[:], frame[6:12])

	s.mu.Lock()
	if src[0]&1 == 0 {
		s.fdb[src] = from
	}
	var out []*swPort
	if to, known := s.fdb[dst]; dst[0]&1 == 0 && known {
		if to != from {
			out = []*swPort{to}
		}
	} else {
		for p := range s.ports {
			if p != from {
				out = append(out, p)
			}
		}
	}
	s.mu.Unlock()

	for _, p := range out {
		if s.limit.wait(len(frame)) {
			s.Waits.Add(1)
		}
		select {
		case p.out <- frame:
		default:
			s.Dropped.Add(1) // the port's queue is full
		}
	}
}

// limiter paces the switch to a byte rate and a frame rate, allowing a
// burst of 1/50 s of either. Ports' readers share it.
type limiter struct {
	mu            sync.Mutex
	bytes, frames bucket
	unlimited     bool
	sleep         func(time.Duration)
}

type bucket struct {
	rate, burst, tokens float64
	last                time.Time
}

func newLimiter(rate, frameRate int64) *limiter {
	if rate == 0 {
		rate = DefaultSwitchRate
	}
	if frameRate == 0 {
		frameRate = DefaultSwitchFrameRate
	}
	l := &limiter{sleep: time.Sleep}
	if rate < 0 && frameRate < 0 {
		l.unlimited = true
		return l
	}
	if rate > 0 {
		l.bytes = bucket{rate: float64(rate), burst: max(float64(rate)/50, 64<<10)}
	}
	if frameRate > 0 {
		l.frames = bucket{rate: float64(frameRate), burst: max(float64(frameRate)/50, 16)}
	}
	return l
}

// take removes n tokens and returns how long to wait for the debt.
func (b *bucket) take(n float64, now time.Time) time.Duration {
	if b.rate == 0 {
		return 0
	}
	if b.last.IsZero() {
		b.tokens = b.burst
	} else {
		b.tokens = min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	}
	b.last = now
	b.tokens -= n
	if b.tokens >= 0 {
		return 0
	}
	return time.Duration(-b.tokens / b.rate * float64(time.Second))
}

// wait blocks until one frame of n bytes may be sent, and reports whether
// it had to.
func (l *limiter) wait(n int) bool {
	if l.unlimited || l.sleep == nil {
		return false
	}
	l.mu.Lock()
	now := time.Now()
	d := max(l.bytes.take(float64(n), now), l.frames.take(1, now))
	l.mu.Unlock()
	if d <= 0 {
		return false
	}
	// Holding no lock: other ports' frames queue up behind the debt in
	// the buckets, so the total rate stays capped.
	l.sleep(d)
	return true
}

type pcapWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func newPcap(w io.Writer) (*pcapWriter, error) {
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], 0xa1b2c3d4) // microsecond pcap
	binary.LittleEndian.PutUint16(hdr[4:], 2)
	binary.LittleEndian.PutUint16(hdr[6:], 4)
	binary.LittleEndian.PutUint32(hdr[16:], 65535) // snaplen
	binary.LittleEndian.PutUint32(hdr[20:], 1)     // LINKTYPE_ETHERNET
	if _, err := w.Write(hdr); err != nil {
		return nil, err
	}
	return &pcapWriter{w: w}, nil
}

func (p *pcapWriter) write(frame []byte) {
	now := time.Now()
	rec := make([]byte, 16, 16+len(frame))
	binary.LittleEndian.PutUint32(rec[0:], uint32(now.Unix()))
	binary.LittleEndian.PutUint32(rec[4:], uint32(now.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(rec[8:], uint32(len(frame)))
	binary.LittleEndian.PutUint32(rec[12:], uint32(len(frame)))
	rec = append(rec, frame...)
	p.mu.Lock()
	p.w.Write(rec)
	p.mu.Unlock()
}
