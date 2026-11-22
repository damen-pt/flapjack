package tftp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func start(t *testing.T) (string, []byte) {
	dir := t.TempDir()
	data := make([]byte, 3*1468+100)
	rand.Read(data)
	os.WriteFile(filepath.Join(dir, "undionly.kpxe"), data, 0o644)
	os.WriteFile(filepath.Join(t.TempDir(), "secret"), []byte("x"), 0o644)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go (&Server{Root: root, Timeout: 200 * time.Millisecond}).Serve(conn)
	t.Cleanup(func() { conn.Close(); root.Close() })
	return conn.LocalAddr().String(), data
}

// get is a minimal client: it returns the file, or the server's error.
func get(t *testing.T, srv, name string, opts ...string) ([]byte, map[string]string, error) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	raddr, _ := net.ResolveUDPAddr("udp4", srv)
	req := binary.BigEndian.AppendUint16(nil, opRRQ)
	for _, f := range append([]string{name, "octet"}, opts...) {
		req = append(append(req, f...), 0)
	}
	c.WriteTo(req, raddr)
	var out []byte
	oack := map[string]string{}
	blksize := 512
	buf := make([]byte, 65536)
	for {
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			return nil, nil, err
		}
		switch binary.BigEndian.Uint16(buf) {
		case opError:
			return nil, nil, errors.New(strings.TrimRight(string(buf[4:n]), "\x00"))
		case opOACK:
			f := strings.Split(strings.TrimRight(string(buf[2:n]), "\x00"), "\x00")
			for i := 0; i+1 < len(f); i += 2 {
				oack[f[i]] = f[i+1]
			}
			if v, ok := oack["blksize"]; ok {
				blksize, _ = strconv.Atoi(v)
			}
			c.WriteTo([]byte{0, opAck, 0, 0}, from)
		case opData:
			out = append(out, buf[4:n]...)
			c.WriteTo([]byte{0, opAck, buf[2], buf[3]}, from)
			if n-4 < blksize {
				return out, oack, nil
			}
		}
	}
}

func TestReadWithOptions(t *testing.T) {
	srv, data := start(t)
	got, oack, err := get(t, srv, "/undionly.kpxe", "blksize", "9000", "tsize", "0")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("got %d bytes, want %d", len(got), len(data))
	}
	if oack["blksize"] != "1468" || oack["tsize"] != strconv.Itoa(len(data)) {
		t.Fatalf("oack = %v", oack)
	}
}

func TestReadPlain(t *testing.T) {
	srv, data := start(t)
	got, _, err := get(t, srv, "undionly.kpxe")
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("got %d bytes, err %v", len(got), err)
	}
}

func TestRefusals(t *testing.T) {
	srv, _ := start(t)
	for _, name := range []string{"missing.efi", "../secret", "/../../etc/passwd"} {
		if _, _, err := get(t, srv, name); err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// Replies come from a per-transfer port, so the client must not be a
	// connected socket.
	c, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer c.Close()
	raddr, _ := net.ResolveUDPAddr("udp4", srv)
	c.WriteTo(append(binary.BigEndian.AppendUint16(nil, opWRQ), "x\x00octet\x00"...), raddr)
	buf := make([]byte, 100)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := c.ReadFrom(buf)
	if err != nil || binary.BigEndian.Uint16(buf) != opError || !strings.Contains(string(buf[:n]), "read-only") {
		t.Fatalf("WRQ reply %q %v", buf[:n], err)
	}
}

// TestTransfersAreBounded: spoofed requests cannot start unbounded
// transfers, overall or from one address, and slots come back.
func TestTransfersAreBounded(t *testing.T) {
	s := &Server{MaxTransfers: 3, MaxPerClient: 2}
	a := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1000}
	a2 := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1001}
	b := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 1000}
	c := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 3), Port: 1000}
	r1, ok1 := s.admit(a)
	_, ok2 := s.admit(a2) // same host, another port: same client
	if _, ok := s.admit(a); !ok1 || !ok2 || ok {
		t.Fatalf("per-client limit: %v %v %v", ok1, ok2, ok)
	}
	if _, ok := s.admit(b); !ok {
		t.Fatal("another client refused under the total limit")
	}
	if _, ok := s.admit(c); ok {
		t.Fatal("total limit exceeded")
	}
	r1()
	if _, ok := s.admit(c); !ok {
		t.Fatal("a released slot was not reused")
	}
}
