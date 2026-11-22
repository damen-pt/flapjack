package pki

import (
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// Sealed secrets. A node's secret files cross relays (tentacles) and
// their caches only encrypted to the node: each node generates a seal key
// when it enrolls with a boot ticket, sends the public half with its CSR,
// and the head seals every secret it serves that node to it. A relay
// holds ciphertext it cannot open; the agent opens it and checks the
// plaintext against the digest in the head's signed manifest, as for any
// file.
//
// The suite is HPKE (RFC 9180) with the hybrid ML-KEM-768 + X25519 KEM,
// so a recording of today's traffic stays sealed against a future quantum
// computer, HKDF-SHA256 and AES-256-GCM. The info string binds each blob
// to its node and content digest, so a relay cannot pass one node's (or
// file's) blob off as another's.

// SealedContentType marks a response body as sealed to the requester.
const SealedContentType = "application/x-flapjack-sealed"

var (
	sealKEM  = hpke.MLKEM768X25519()
	sealKDF  = hpke.HKDFSHA256()
	sealAEAD = hpke.AES256GCM()
)

func sealInfo(node, digest string) []byte {
	return []byte("flapjack-seal-v1\x00" + node + "\x00" + digest)
}

// NewSealKey generates a node's seal key.
func NewSealKey() (hpke.PrivateKey, error) { return sealKEM.GenerateKey() }

// ParseSealKey reads a seal key saved with its Bytes method.
func ParseSealKey(b []byte) (hpke.PrivateKey, error) { return sealKEM.NewPrivateKey(b) }

// CheckSealPublicKey reports whether b is a seal public key.
func CheckSealPublicKey(b []byte) error {
	if len(b) == 0 {
		return errors.New("no seal key")
	}
	if _, err := sealKEM.NewPublicKey(b); err != nil {
		return fmt.Errorf("seal key: %w", err)
	}
	return nil
}

// SealKeyID names a seal public key, so a relay can tell when a node's
// key changed (it enrolled again) without holding the key itself.
func SealKeyID(pub []byte) string {
	if len(pub) == 0 {
		return ""
	}
	s := sha256.Sum256(pub)
	return hex.EncodeToString(s[:16])
}

// Seal encrypts plain, the content with digest, to node's seal public key.
func Seal(pub []byte, node, digest string, plain []byte) ([]byte, error) {
	pk, err := sealKEM.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("seal key: %w", err)
	}
	return hpke.Seal(pk, sealKDF, sealAEAD, sealInfo(node, digest), plain)
}

// Unseal opens a blob Seal made for node and digest.
func Unseal(k hpke.PrivateKey, node, digest string, blob []byte) ([]byte, error) {
	plain, err := hpke.Open(k, sealKDF, sealAEAD, sealInfo(node, digest), blob)
	if err != nil {
		return nil, fmt.Errorf("sealed content %.19s: %w", digest, err)
	}
	return plain, nil
}
