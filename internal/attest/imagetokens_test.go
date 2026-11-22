package attest

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestImageTokens(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	head := &ImageTokens{Key: make([]byte, 32), Now: func() time.Time { return now }}
	ip := net.ParseIP("10.99.1.1")
	tok, err := head.Mint("v1", ip)
	if err != nil {
		t.Fatal(err)
	}
	if err := head.Check(tok, "v1", ip); err != nil {
		t.Fatalf("own token: %v", err)
	}
	for name, err := range map[string]error{
		"other image":   head.Check(tok, "v2", ip),
		"other address": head.Check(tok, "v1", net.ParseIP("10.99.1.2")),
		"no address":    head.Check(tok, "v1", nil),
		"tampered":      head.Check(strings.Replace(tok, ".", "x.", 1), "v1", ip),
		"garbage":       head.Check("nope", "v1", ip),
		"rack key":      head.For("r1").Check(tok, "v1", ip),
	} {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A rack's key checks only its own tokens.
	r1, r2 := head.For("r1"), head.For("r2")
	rt, _ := r1.Mint("v1", ip)
	if err := r1.Check(rt, "v1", ip); err != nil {
		t.Fatalf("rack token: %v", err)
	}
	if r2.Check(rt, "v1", ip) == nil || head.Check(rt, "v1", ip) == nil {
		t.Error("a rack's token works elsewhere")
	}
	now = now.Add(time.Hour + time.Second)
	if head.Check(tok, "v1", ip) == nil {
		t.Error("expired token accepted")
	}
	if _, err := head.Mint("a|b", ip); err == nil {
		t.Error("minted a token for a version with a separator")
	}
}
