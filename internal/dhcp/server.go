package dhcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Lease is a reservation: the address and name a known MAC always gets.
type Lease struct {
	Node     string
	IP       net.IP
	Hostname string
}

// Server answers DISCOVER and REQUEST from reserved MACs. It holds no lease
// database: every address is a fixed reservation, so a restarted server
// hands out exactly what it did before.
type Server struct {
	ServerIP  net.IP     // our address on the provisioning network (option 54)
	Mask      net.IPMask // option 1
	Router    net.IP     // option 3; nil for an isolated provisioning network
	DNS       []net.IP   // option 6
	Domain    string     // option 15
	LeaseTime time.Duration
	// HTTPBase is where boot files are served, e.g. "http://10.99.0.1".
	HTTPBase string
	// ScriptBase, if set, is where iPXE fetches its per-node script
	// instead ("https://10.99.0.1"), for iPXE built to trust the boot CA.
	ScriptBase string
	// Lookup returns the reservation for a MAC.
	Lookup func(mac net.HardwareAddr) (Lease, bool)
	// OnLease is called for each OFFER and ACK sent; OnUnknown (at most
	// once per MAC per UnknownEvery) for requests from MACs with no
	// reservation, so new hardware shows up in the event log.
	OnLease      func(l Lease, mac net.HardwareAddr, msg byte, bootFile string)
	OnUnknown    func(mac net.HardwareAddr, p *Packet)
	UnknownEvery time.Duration

	mu      sync.Mutex
	unknown map[string]time.Time
}

// Boot decides what a client should load next, from what it says it is.
//
//   - iPXE (user class "iPXE" or option 175): its per-node script over HTTP.
//   - UEFI HTTP boot (vendor class "HTTPClient"): iPXE for its arch over HTTP.
//   - PXE ROMs: iPXE over TFTP: undionly.kpxe for legacy BIOS, ipxe-<arch>.efi
//     for UEFI.
//
// vendor is the class identifier to echo back (PXE and HTTP boot clients
// ignore offers without it); tftp reports whether the file is a TFTP path.
func Boot(p *Packet, httpBase string) (file, vendor string, tftp bool) {
	vc := string(p.Options[OptVendorClass])
	if bytes.Equal(p.Options[OptUserClass], []byte("iPXE")) || p.Options[OptIPXEEncap] != nil {
		return fmt.Sprintf("%s/boot/%s.ipxe", httpBase, macKey(p.CHAddr)), "", false
	}
	arch := p.ClientArch()
	efi := map[int]string{7: "x86_64", 9: "x86_64", 16: "x86_64", 11: "arm64", 19: "arm64"}[arch]
	switch {
	case strings.HasPrefix(vc, "HTTPClient") && efi != "":
		return fmt.Sprintf("%s/boot/ipxe-%s.efi", httpBase, efi), "HTTPClient", false
	case strings.HasPrefix(vc, "PXEClient") && arch <= 0:
		return "undionly.kpxe", "PXEClient", true
	case strings.HasPrefix(vc, "PXEClient") && efi != "":
		return "ipxe-" + efi + ".efi", "PXEClient", true
	}
	return "", "", false
}

// macKey is the MAC as used in boot URLs: lower case, dash separated.
func macKey(mac net.HardwareAddr) string {
	return strings.ReplaceAll(mac.String(), ":", "-")
}

// Handle returns the reply to req, or nil when the server must stay silent.
func (s *Server) Handle(req *Packet) *Packet {
	if req.Op != opBootRequest {
		return nil
	}
	t := req.Type()
	if t != Discover && t != Request {
		return nil // RELEASE/DECLINE/INFORM: reservations make them moot
	}
	if id := req.Options[OptServerID]; id != nil && !net.IP(id).Equal(s.ServerIP.To4()) {
		return nil // the client chose another server's offer
	}
	lease, ok := s.Lookup(req.CHAddr)
	if !ok || lease.IP.To4() == nil {
		s.unknownMAC(req)
		return nil
	}
	reply := &Packet{
		Op: opBootReply, XID: req.XID, Flags: req.Flags, GIAddr: req.GIAddr, CHAddr: req.CHAddr,
		CIAddr: net.IPv4zero, YIAddr: lease.IP.To4(), SIAddr: s.ServerIP.To4(),
		Options: map[byte][]byte{OptServerID: s.ServerIP.To4()},
	}
	if t == Request {
		want := net.IP(req.Options[OptRequestedIP])
		if want == nil {
			want = req.CIAddr // renewing
		}
		if !want.Equal(lease.IP) {
			reply.YIAddr, reply.SIAddr = net.IPv4zero, net.IPv4zero
			reply.Options[OptMessageType] = []byte{Nak}
			return reply
		}
		reply.CIAddr = req.CIAddr
		reply.Options[OptMessageType] = []byte{Ack}
	} else {
		reply.Options[OptMessageType] = []byte{Offer}
	}
	lt := s.LeaseTime
	if lt <= 0 {
		lt = time.Hour
	}
	reply.Options[OptLeaseTime] = binary.BigEndian.AppendUint32(nil, uint32(lt/time.Second))
	reply.Options[OptSubnetMask] = []byte(s.Mask)
	if s.Router != nil {
		reply.Options[OptRouter] = s.Router.To4()
	}
	if len(s.DNS) > 0 {
		var dns []byte
		for _, ip := range s.DNS {
			dns = append(dns, ip.To4()...)
		}
		reply.Options[OptDNS] = dns
	}
	if lease.Hostname != "" {
		reply.Options[OptHostname] = []byte(lease.Hostname)
	}
	if s.Domain != "" {
		reply.Options[OptDomainName] = []byte(s.Domain)
	}
	file, vendor, tftp := Boot(req, s.HTTPBase)
	if s.ScriptBase != "" {
		if mac, ok := strings.CutPrefix(file, s.HTTPBase+"/boot/"); ok && strings.HasSuffix(mac, ".ipxe") {
			file = s.ScriptBase + "/boot/" + mac
		}
	}
	if file != "" {
		reply.File = file
		reply.Options[OptBootFile] = []byte(file)
		if tftp {
			reply.Options[OptTFTPServer] = []byte(s.ServerIP.String())
		}
	}
	if vendor != "" {
		reply.Options[OptVendorClass] = []byte(vendor)
	}
	if s.OnLease != nil {
		s.OnLease(lease, req.CHAddr, reply.Type(), file)
	}
	return reply
}

// maxUnknown bounds the unknown MACs remembered (and so reported) per
// UnknownEvery.
const maxUnknown = 4096

func (s *Server) unknownMAC(req *Packet) {
	if s.OnUnknown == nil {
		return
	}
	every := s.UnknownEvery
	if every == 0 {
		every = 10 * time.Minute
	}
	key := req.CHAddr.String()
	s.mu.Lock()
	if s.unknown == nil {
		s.unknown = map[string]time.Time{}
	}
	now := time.Now()
	last, seen := s.unknown[key]
	if !seen && len(s.unknown) >= maxUnknown {
		// Someone is spraying MACs: forget the ones already reported
		// long enough ago, and if that frees nothing, report no more
		// until it does. Memory and the event log stay bounded.
		for m, t := range s.unknown {
			if now.Sub(t) >= every {
				delete(s.unknown, m)
			}
		}
		if len(s.unknown) >= maxUnknown {
			s.mu.Unlock()
			return
		}
	}
	report := !seen || now.Sub(last) >= every
	if report {
		s.unknown[key] = now
	}
	s.mu.Unlock()
	if report {
		s.OnUnknown(req.CHAddr, req)
	}
}

// Serve answers requests on conn until it is closed. Replies go to the
// relay agent if there is one, to the client's address when it is renewing,
// and otherwise to the broadcast address: the client has no address yet,
// and answering it by unicast would need a raw socket to seed its ARP entry.
func (s *Server) Serve(conn net.PacketConn) error {
	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		req, err := Parse(buf[:n])
		if err != nil {
			continue
		}
		reply := s.Handle(req)
		if reply == nil {
			continue
		}
		dst := &net.UDPAddr{IP: net.IPv4bcast, Port: 68}
		switch {
		case !req.GIAddr.Equal(net.IPv4zero):
			dst = &net.UDPAddr{IP: req.GIAddr, Port: 67}
		case !req.CIAddr.Equal(net.IPv4zero) && reply.Type() == Ack:
			dst = &net.UDPAddr{IP: req.CIAddr, Port: 68}
		}
		conn.WriteTo(reply.Marshal(), dst)
	}
}
