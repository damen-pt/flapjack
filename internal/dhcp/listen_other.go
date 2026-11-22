//go:build !linux

package dhcp

import (
	"context"
	"net"
	"syscall"
)

// Listen opens UDP port 67 with broadcast enabled. Only Linux can bind to
// an interface; elsewhere the server hears DHCP on every network, so this is
// for development only.
func Listen(string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
		})
		if err != nil {
			return err
		}
		return serr
	}}
	return lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:67")
}
