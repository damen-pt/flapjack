// Package dhcp is a DHCPv4 server for provisioning networks. It only
// answers clients it has a reservation for: an unknown MAC gets no reply,
// so a stray laptop or rogue machine on the provisioning network is never
// handed an address or a boot file.
package dhcp

import (
	"encoding/binary"
	"errors"
	"net"
)

// Message types (option 53).
const (
	Discover byte = 1
	Offer    byte = 2
	Request  byte = 3
	Decline  byte = 4
	Ack      byte = 5
	Nak      byte = 6
	Release  byte = 7
	Inform   byte = 8
)

// Options used by the server.
const (
	OptSubnetMask    = 1
	OptRouter        = 3
	OptDNS           = 6
	OptHostname      = 12
	OptDomainName    = 15
	OptRequestedIP   = 50
	OptLeaseTime     = 51
	OptMessageType   = 53
	OptServerID      = 54
	OptParamList     = 55
	OptVendorClass   = 60
	OptClientID      = 61
	OptTFTPServer    = 66
	OptBootFile      = 67
	OptUserClass     = 77
	OptClientArch    = 93
	OptClientNDI     = 94
	OptUUID          = 97
	OptIPXEEncap     = 175
	optPad           = 0
	optEnd           = 255
	bootpHeaderSize  = 236
	minPacketSize    = 300
	magicCookie      = 0x63825363
	flagBroadcast    = 0x8000
	opBootRequest    = 1
	opBootReply      = 2
	htypeEthernet    = 1
	maxOptionPayload = 255
)

// Packet is a DHCPv4 message. Options keep only the last value of each
// code; concatenated long options (RFC 3396) are joined.
type Packet struct {
	Op      byte
	XID     uint32
	Secs    uint16
	Flags   uint16
	CIAddr  net.IP
	YIAddr  net.IP
	SIAddr  net.IP
	GIAddr  net.IP
	CHAddr  net.HardwareAddr
	SName   string
	File    string
	Options map[byte][]byte
}

var errShort = errors.New("dhcp: packet too short")

// Parse decodes a BOOTP/DHCP packet.
func Parse(b []byte) (*Packet, error) {
	if len(b) < bootpHeaderSize+4 {
		return nil, errShort
	}
	if binary.BigEndian.Uint32(b[236:]) != magicCookie {
		return nil, errors.New("dhcp: missing magic cookie")
	}
	hlen := int(b[2])
	if b[1] != htypeEthernet || hlen != 6 {
		return nil, errors.New("dhcp: not an Ethernet client")
	}
	p := &Packet{
		Op: b[0], XID: binary.BigEndian.Uint32(b[4:]), Secs: binary.BigEndian.Uint16(b[8:]),
		Flags:  binary.BigEndian.Uint16(b[10:]),
		CIAddr: net.IP(append([]byte(nil), b[12:16]...)), YIAddr: net.IP(append([]byte(nil), b[16:20]...)),
		SIAddr: net.IP(append([]byte(nil), b[20:24]...)), GIAddr: net.IP(append([]byte(nil), b[24:28]...)),
		CHAddr:  net.HardwareAddr(append([]byte(nil), b[28:28+hlen]...)),
		SName:   cstring(b[44:108]),
		File:    cstring(b[108:236]),
		Options: map[byte][]byte{},
	}
	opts := b[240:]
	for i := 0; i < len(opts); {
		code := opts[i]
		if code == optEnd {
			break
		}
		if code == optPad {
			i++
			continue
		}
		if i+1 >= len(opts) || i+2+int(opts[i+1]) > len(opts) {
			return nil, errors.New("dhcp: truncated option")
		}
		n := int(opts[i+1])
		p.Options[code] = append(p.Options[code], opts[i+2:i+2+n]...)
		i += 2 + n
	}
	return p, nil
}

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// Type returns the DHCP message type, or 0 for plain BOOTP.
func (p *Packet) Type() byte {
	if v := p.Options[OptMessageType]; len(v) == 1 {
		return v[0]
	}
	return 0
}

// Marshal encodes the packet, padded to the 300-byte BOOTP minimum that
// some PXE ROMs require. Options are written in ascending code order.
func (p *Packet) Marshal() []byte {
	b := make([]byte, 240, 576)
	b[0], b[1], b[2] = p.Op, htypeEthernet, 6
	binary.BigEndian.PutUint32(b[4:], p.XID)
	binary.BigEndian.PutUint16(b[8:], p.Secs)
	binary.BigEndian.PutUint16(b[10:], p.Flags)
	for off, ip := range map[int]net.IP{12: p.CIAddr, 16: p.YIAddr, 20: p.SIAddr, 24: p.GIAddr} {
		if v4 := ip.To4(); v4 != nil {
			copy(b[off:off+4], v4)
		}
	}
	copy(b[28:44], p.CHAddr)
	copy(b[44:107], p.SName)
	copy(b[108:235], p.File)
	binary.BigEndian.PutUint32(b[236:], magicCookie)
	// Message type first: some clients expect it.
	if t, ok := p.Options[OptMessageType]; ok {
		b = append(b, OptMessageType, byte(len(t)))
		b = append(b, t...)
	}
	for code := 1; code < optEnd; code++ {
		v, ok := p.Options[byte(code)]
		if !ok || code == OptMessageType {
			continue
		}
		for len(v) > maxOptionPayload {
			b = append(b, byte(code), maxOptionPayload)
			b = append(b, v[:maxOptionPayload]...)
			v = v[maxOptionPayload:]
		}
		b = append(b, byte(code), byte(len(v)))
		b = append(b, v...)
	}
	b = append(b, optEnd)
	for len(b) < minPacketSize {
		b = append(b, optPad)
	}
	return b
}

// ClientArch returns option 93 (RFC 4578), or -1 if absent.
func (p *Packet) ClientArch() int {
	if v := p.Options[OptClientArch]; len(v) >= 2 {
		return int(binary.BigEndian.Uint16(v))
	}
	return -1
}
