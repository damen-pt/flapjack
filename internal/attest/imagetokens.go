package attest

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
)

// ImageTokens mints and checks the capabilities that let a booting node
// download its image: a token names one image version and the address it
// was minted for, and expires. Tokens are only minted into a node's boot
// script during its boot window, and that script is only served over
// HTTPS to the node's reserved address, so nothing else on the network,
// and nothing outside a boot, can read an image.
//
// A rack's tentacle checks tokens for the images it serves with For(rack)'s
// key, which the head gives it; that key cannot mint tokens for other
// racks or for the head.
type ImageTokens struct {
	Key []byte
	TTL time.Duration // default 1h: long enough to pull a root filesystem
	Now func() time.Time
}

// DeriveImageKey derives the image-token key from the head's ticket key,
// so tickets and image tokens never share a key.
func DeriveImageKey(ticketKey []byte) []byte {
	return derive(ticketKey, "flapjack image tokens")
}

func derive(key []byte, label string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(label))
	return m.Sum(nil)
}

// For returns the tokens a rack's tentacle checks.
func (t *ImageTokens) For(rack string) *ImageTokens {
	return &ImageTokens{Key: derive(t.Key, "rack|"+rack), TTL: t.TTL, Now: t.Now}
}

func (t *ImageTokens) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t *ImageTokens) sign(payload string) string {
	m := hmac.New(sha256.New, t.Key)
	m.Write([]byte(payload))
	return enc.EncodeToString(m.Sum(nil))
}

// Mint returns a token for version, usable from ip until the TTL ends.
func (t *ImageTokens) Mint(version string, ip net.IP) (string, error) {
	if len(t.Key) < 32 {
		return "", errors.New("image token key must be at least 32 bytes")
	}
	if ip.To4() == nil || version == "" || strings.Contains(version, "|") {
		return "", errors.New("image tokens need an image version and an IPv4 address")
	}
	ttl := t.TTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	payload := strings.Join([]string{version, ip.To4().String(), strconv.FormatInt(t.now().Add(ttl).Unix(), 10)}, "|")
	return enc.EncodeToString([]byte(payload)) + "." + t.sign(payload), nil
}

// Check reports whether token lets ip read version now.
func (t *ImageTokens) Check(token, version string, ip net.IP) error {
	if len(t.Key) < 32 {
		return errors.New("image tokens are not configured")
	}
	p64, sig, ok := strings.Cut(token, ".")
	if !ok {
		return errors.New("malformed image token")
	}
	raw, err := enc.DecodeString(p64)
	if err != nil {
		return errors.New("malformed image token")
	}
	payload := string(raw)
	if !hmac.Equal([]byte(sig), []byte(t.sign(payload))) {
		return errors.New("invalid image token")
	}
	f := strings.Split(payload, "|")
	if len(f) != 3 {
		return errors.New("malformed image token")
	}
	exp, err := strconv.ParseInt(f[2], 10, 64)
	if err != nil {
		return errors.New("malformed image token")
	}
	if t.now().Unix() > exp {
		return errors.New("image token expired")
	}
	if f[0] != version {
		return errors.New("image token is for another image")
	}
	if ip == nil || ip.To4() == nil || f[1] != ip.To4().String() {
		return errors.New("image token was minted for another address")
	}
	return nil
}
