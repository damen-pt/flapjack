package dhcp

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

var (
	known   = net.HardwareAddr{0x52, 0x54, 0, 1, 1, 1}
	unknown = net.HardwareAddr{0x52, 0x54, 0, 9, 9, 9}
	srvIP   = net.IPv4(10, 99, 0, 1)
)

func server() *Server {
	return &Server{
		ServerIP: srvIP, Mask: net.CIDRMask(16, 32), Domain: "cluster", LeaseTime: time.Hour,
		HTTPBase: "http://10.99.0.1",
		Lookup: func(mac net.HardwareAddr) (Lease, bool) {
			if mac.String() == known.String() {
				return Lease{Node: "r1n01", IP: net.IPv4(10, 99, 1, 1), Hostname: "r1n01"}, true
			}
			return Lease{}, false
		},
	}
}

func request(t byte, mac net.HardwareAddr, opts map[byte][]byte) *Packet {
	p := &Packet{Op: opBootRequest, XID: 0xabcd, CHAddr: mac, CIAddr: net.IPv4zero, YIAddr: net.IPv4zero,
		SIAddr: net.IPv4zero, GIAddr: net.IPv4zero, Options: map[byte][]byte{OptMessageType: {t}}}
	for k, v := range opts {
		p.Options[k] = v
	}
	// Round-trip through the wire format so parsing is exercised too.
	q, err := Parse(p.Marshal())
	if err != nil {
		panic(err)
	}
	return q
}

func arch(a uint16) []byte { return binary.BigEndian.AppendUint16(nil, a) }

func TestOfferAndAckForIPXE(t *testing.T) {
	s := server()
	var leased []byte
	s.OnLease = func(_ Lease, _ net.HardwareAddr, msg byte, _ string) { leased = append(leased, msg) }
	off := s.Handle(request(Discover, known, map[byte][]byte{OptUserClass: []byte("iPXE"), OptClientArch: arch(11)}))
	if off == nil || off.Type() != Offer {
		t.Fatalf("offer = %+v", off)
	}
	if !off.YIAddr.Equal(net.IPv4(10, 99, 1, 1)) || off.File != "http://10.99.0.1/boot/52-54-00-01-01-01.ipxe" {
		t.Fatalf("offer yiaddr=%s file=%q", off.YIAddr, off.File)
	}
	if string(off.Options[OptHostname]) != "r1n01" || net.IP(off.Options[OptServerID]).String() != "10.99.0.1" {
		t.Fatalf("options = %v", off.Options)
	}
	if got := binary.BigEndian.Uint32(off.Options[OptLeaseTime]); got != 3600 {
		t.Fatalf("lease = %d", got)
	}
	ack := s.Handle(request(Request, known, map[byte][]byte{OptRequestedIP: net.IPv4(10, 99, 1, 1).To4(), OptServerID: srvIP.To4(), OptUserClass: []byte("iPXE")}))
	if ack == nil || ack.Type() != Ack {
		t.Fatalf("ack = %+v", ack)
	}
	if string(leased) != string([]byte{Offer, Ack}) {
		t.Fatalf("OnLease saw %v", leased)
	}
}

func TestRequestForWrongAddressIsNaked(t *testing.T) {
	r := server().Handle(request(Request, known, map[byte][]byte{OptRequestedIP: net.IPv4(10, 99, 7, 7).To4()}))
	if r == nil || r.Type() != Nak || !r.YIAddr.Equal(net.IPv4zero) {
		t.Fatalf("reply = %+v", r)
	}
}

func TestSilentForUnknownMACsAndOtherServers(t *testing.T) {
	s := server()
	var seen int
	s.OnUnknown = func(net.HardwareAddr, *Packet) { seen++ }
	for range 3 {
		if r := s.Handle(request(Discover, unknown, nil)); r != nil {
			t.Fatal("answered an unknown MAC")
		}
	}
	if seen != 1 {
		t.Fatalf("unknown MAC reported %d times, want 1 (rate limited)", seen)
	}
	if r := s.Handle(request(Request, known, map[byte][]byte{OptServerID: net.IPv4(10, 99, 0, 2).To4()})); r != nil {
		t.Fatal("answered a REQUEST addressed to another server")
	}
	if r := s.Handle(request(Release, known, nil)); r != nil {
		t.Fatal("answered a RELEASE")
	}
}

// TestSprayedMACsStayBounded: random MACs cannot grow memory or the
// event log without limit.
func TestSprayedMACsStayBounded(t *testing.T) {
	s := server()
	var seen int
	s.OnUnknown = func(net.HardwareAddr, *Packet) { seen++ }
	for i := range 3 * maxUnknown {
		mac := net.HardwareAddr{0x02, 0, byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}
		s.Handle(request(Discover, mac, nil))
	}
	if len(s.unknown) > maxUnknown || seen > maxUnknown {
		t.Fatalf("remembered %d, reported %d unknown MACs; cap %d", len(s.unknown), seen, maxUnknown)
	}
	// Once the reports age out, new MACs are reported again.
	for m := range s.unknown {
		s.unknown[m] = time.Now().Add(-time.Hour)
	}
	seen = 0
	s.Handle(request(Discover, unknown, nil))
	if seen != 1 {
		t.Fatalf("new MAC after the cap aged out reported %d times", seen)
	}
}

func TestBootFileByClient(t *testing.T) {
	for _, tc := range []struct {
		name   string
		opts   map[byte][]byte
		file   string
		vendor string
		tftp   bool
	}{
		{"legacy BIOS PXE", map[byte][]byte{OptVendorClass: []byte("PXEClient:Arch:00000:UNDI:002001"), OptClientArch: arch(0)}, "undionly.kpxe", "PXEClient", true},
		{"x86 UEFI PXE", map[byte][]byte{OptVendorClass: []byte("PXEClient:Arch:00007:UNDI:003016"), OptClientArch: arch(7)}, "ipxe-x86_64.efi", "PXEClient", true},
		{"arm64 UEFI PXE", map[byte][]byte{OptVendorClass: []byte("PXEClient:Arch:00011:UNDI:003000"), OptClientArch: arch(11)}, "ipxe-arm64.efi", "PXEClient", true},
		{"x86 UEFI HTTP", map[byte][]byte{OptVendorClass: []byte("HTTPClient:Arch:00016:UNDI:003000"), OptClientArch: arch(16)}, "http://10.99.0.1/boot/ipxe-x86_64.efi", "HTTPClient", false},
		{"iPXE", map[byte][]byte{OptIPXEEncap: {1, 1, 1}, OptVendorClass: []byte("PXEClient"), OptClientArch: arch(0)}, "http://10.99.0.1/boot/52-54-00-01-01-01.ipxe", "", false},
		{"plain DHCP", nil, "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			off := server().Handle(request(Discover, known, tc.opts))
			if off.File != tc.file || string(off.Options[OptVendorClass]) != tc.vendor || (off.Options[OptTFTPServer] != nil) != tc.tftp {
				t.Fatalf("file=%q vendor=%q tftp=%v", off.File, off.Options[OptVendorClass], off.Options[OptTFTPServer] != nil)
			}
		})
	}
}

func TestMarshalSplitsLongOptionsAndPads(t *testing.T) {
	long := make([]byte, 300)
	for i := range long {
		long[i] = byte(i)
	}
	p := &Packet{Op: opBootReply, CHAddr: known, Options: map[byte][]byte{OptMessageType: {Ack}, OptDomainName: long}}
	b := p.Marshal()
	if len(b) < minPacketSize {
		t.Fatalf("len %d < %d", len(b), minPacketSize)
	}
	q, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(q.Options[OptDomainName]) != string(long) || q.Type() != Ack {
		t.Fatal("long option did not survive the round trip")
	}
	if _, err := Parse(b[:100]); err == nil {
		t.Fatal("short packet parsed")
	}
}
