// Package tftp is a read-only TFTP server (RFC 1350) with the blksize,
// tsize and timeout options (RFC 2347–2349). It exists only to hand iPXE to
// PXE ROMs that cannot speak HTTP; everything after that is HTTP. Writes are
// always refused and reads are confined to one directory.
package tftp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	opRRQ   = 1
	opWRQ   = 2
	opData  = 3
	opAck   = 4
	opError = 5
	opOACK  = 6

	errNotFound     = 1
	errAccess       = 2
	errIllegalOp    = 4
	defaultBlksize  = 512
	maxBlksize      = 1468 // fits a 1500-byte MTU without fragmenting
	defaultRetries  = 5
	defaultTimeout  = time.Second
	maxRequestBytes = 512
)

// Server serves files from Root.
type Server struct {
	Root *os.Root
	// Allow, if set, is asked about every name (after cleaning); others
	// are answered as not found.
	Allow func(name string) bool
	// OnRead is called after each transfer, with err nil on success.
	OnRead func(remote net.Addr, file string, size int64, err error)
	// Timeout per packet before retransmitting (default 1s), overridable by
	// the client's timeout option.
	Timeout time.Duration
	// MaxTransfers bounds transfers in flight (default 64) and
	// MaxPerClient those for one client address (default 4). Requests past
	// either are dropped unanswered: UDP sources are trivially spoofed, and
	// every transfer sends a data block to its source before anything
	// proves the source asked, so unbounded transfers would make the head
	// a traffic reflector (and exhaust its sockets).
	MaxTransfers, MaxPerClient int

	mu       sync.Mutex
	inFlight int
	byClient map[string]int
}

// admit reserves a transfer slot for remote, or reports there is none.
func (s *Server) admit(remote net.Addr) (release func(), ok bool) {
	limit, per := s.MaxTransfers, s.MaxPerClient
	if limit <= 0 {
		limit = 64
	}
	if per <= 0 {
		per = 4
	}
	host := remote.String()
	if u, isUDP := remote.(*net.UDPAddr); isUDP {
		host = u.IP.String()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byClient == nil {
		s.byClient = map[string]int{}
	}
	if s.inFlight >= limit || s.byClient[host] >= per {
		return nil, false
	}
	s.inFlight++
	s.byClient[host]++
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.inFlight--
		if s.byClient[host]--; s.byClient[host] <= 0 {
			delete(s.byClient, host)
		}
	}, true
}

// Serve answers requests on conn until it is closed. Each transfer runs on
// its own socket bound to conn's address, as the protocol requires.
func (s *Server) Serve(conn net.PacketConn) error {
	local, _ := conn.LocalAddr().(*net.UDPAddr)
	buf := make([]byte, maxRequestBytes)
	for {
		n, remote, err := conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		release, ok := s.admit(remote)
		if !ok {
			continue
		}
		req := bytes.Clone(buf[:n])
		go func() {
			defer release()
			s.handle(local, remote, req)
		}()
	}
}

func (s *Server) handle(local *net.UDPAddr, remote net.Addr, req []byte) {
	laddr := &net.UDPAddr{}
	if local != nil {
		laddr.IP = local.IP
	}
	c, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return
	}
	defer c.Close()
	if len(req) < 4 {
		return
	}
	switch binary.BigEndian.Uint16(req) {
	case opRRQ:
	case opWRQ:
		sendError(c, remote, errAccess, "read-only server")
		return
	default:
		sendError(c, remote, errIllegalOp, "expected a read request")
		return
	}
	fields := strings.Split(string(req[2:]), "\x00")
	if len(fields) < 2 {
		sendError(c, remote, errIllegalOp, "malformed request")
		return
	}
	name, mode := fields[0], strings.ToLower(fields[1])
	opts := map[string]string{}
	for i := 2; i+1 < len(fields); i += 2 {
		opts[strings.ToLower(fields[i])] = fields[i+1]
	}
	size, err := s.send(c, remote, name, mode, opts)
	if s.OnRead != nil {
		s.OnRead(remote, name, size, err)
	}
}

func (s *Server) send(c *net.UDPConn, remote net.Addr, name, mode string, opts map[string]string) (int64, error) {
	if mode != "octet" {
		sendError(c, remote, errIllegalOp, "only octet mode is supported")
		return 0, fmt.Errorf("mode %q", mode)
	}
	clean := strings.TrimLeft(strings.ReplaceAll(name, `\`, "/"), "/")
	if s.Allow != nil && !s.Allow(clean) {
		sendError(c, remote, errNotFound, "file not found")
		return 0, errors.New("not served over TFTP")
	}
	f, err := s.Root.Open(clean)
	if err != nil {
		sendError(c, remote, errNotFound, "file not found")
		return 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		sendError(c, remote, errNotFound, "file not found")
		return 0, errors.Join(err, errors.New("not a regular file"))
	}

	blksize, timeout := defaultBlksize, s.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	var oack []string
	if v, ok := opts["blksize"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n >= 8 {
			blksize = min(n, maxBlksize)
			oack = append(oack, "blksize", strconv.Itoa(blksize))
		}
	}
	if _, ok := opts["tsize"]; ok {
		oack = append(oack, "tsize", strconv.FormatInt(st.Size(), 10))
	}
	if v, ok := opts["timeout"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 255 {
			timeout = time.Duration(n) * time.Second
			oack = append(oack, "timeout", v)
		}
	}
	if len(oack) > 0 {
		pkt := binary.BigEndian.AppendUint16(nil, opOACK)
		for _, o := range oack {
			pkt = append(append(pkt, o...), 0)
		}
		if err := exchange(c, remote, pkt, 0, timeout); err != nil {
			return 0, err
		}
	}

	buf := make([]byte, 4+blksize)
	var sent int64
	for block := uint16(1); ; block++ {
		n, err := io.ReadFull(f, buf[4:])
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			sendError(c, remote, errAccess, "read error")
			return sent, err
		}
		binary.BigEndian.PutUint16(buf, opData)
		binary.BigEndian.PutUint16(buf[2:], block)
		if err := exchange(c, remote, buf[:4+n], block, timeout); err != nil {
			return sent, err
		}
		sent += int64(n)
		if n < blksize {
			return sent, nil
		}
	}
}

// exchange sends pkt until the client acknowledges block. Duplicate ACKs
// for earlier blocks are ignored rather than answered, which avoids the
// "sorcerer's apprentice" retransmission storm.
func exchange(c *net.UDPConn, remote net.Addr, pkt []byte, block uint16, timeout time.Duration) error {
	ack := make([]byte, 512)
	for range defaultRetries {
		if _, err := c.WriteTo(pkt, remote); err != nil {
			return err
		}
		deadline := time.Now().Add(timeout)
		for {
			c.SetReadDeadline(deadline)
			n, from, err := c.ReadFrom(ack)
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			if err != nil {
				return err
			}
			if from.String() != remote.String() || n < 4 {
				continue
			}
			switch binary.BigEndian.Uint16(ack) {
			case opAck:
				if binary.BigEndian.Uint16(ack[2:]) == block {
					return nil
				}
			case opError:
				return fmt.Errorf("client aborted: %s", strings.TrimRight(string(ack[4:n]), "\x00"))
			}
		}
	}
	return errors.New("timed out waiting for ACK")
}

func sendError(c *net.UDPConn, remote net.Addr, code uint16, msg string) {
	pkt := binary.BigEndian.AppendUint16(nil, opError)
	pkt = binary.BigEndian.AppendUint16(pkt, code)
	c.WriteTo(append(append(pkt, msg...), 0), remote)
}
