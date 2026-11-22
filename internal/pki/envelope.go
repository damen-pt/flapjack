package pki

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Envelope is a head's signature over one node's generation. Relays
// (tentacles) pass it through unchanged; agents verify it, so a relay
// can delay a generation but not alter it or hand it to another node.
//
// Issued is when the head signed it. Agents refuse an envelope issued
// before the newest one they have accepted, so a relay cannot replay an
// old (genuinely signed) generation once a newer one has been seen. A
// rollback is not a replay: the head signs the older generation afresh.
type Envelope struct {
	Node       string `json:"node"`
	Generation int    `json:"generation"`
	Digest     string `json:"digest"` // overlay.ManifestDigest of the manifest
	Issued     int64  `json:"issued"` // Unix nanoseconds, head clock
	Signature  []byte `json:"signature"`
}

func (e Envelope) message() []byte {
	return []byte("flapjack-generation-v2\x00" + e.Node + "\x00" + strconv.Itoa(e.Generation) + "\x00" + e.Digest +
		"\x00" + strconv.FormatInt(e.Issued, 10))
}

// Signer signs generations with strictly increasing issue times, even if
// asked twice within the clock's resolution.
//
// With Floor set, issue times also keep increasing across restarts and
// backward clock steps: agents refuse envelopes older than the newest
// they accepted, so a head whose clock went back would otherwise be
// refused by every node until it caught up. The floor file is written
// ahead, at most about once a minute, so signing rarely touches disk.
type Signer struct {
	Key   ed25519.PrivateKey
	Now   func() time.Time
	Floor string // file holding a Unix-nanosecond lower bound

	mu     sync.Mutex
	last   int64
	floor  int64 // persisted bound; last may run up to it without a write
	loaded bool
}

// floorStep is how far ahead the persisted floor is written.
const floorStep = int64(time.Minute)

// Sign signs node's generation n with manifest digest d.
func (s *Signer) Sign(node string, n int, d string) Envelope {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	s.mu.Lock()
	if !s.loaded && s.Floor != "" {
		if b, err := os.ReadFile(s.Floor); err == nil {
			if f, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil {
				s.last, s.floor = f, f
			}
		}
	}
	s.loaded = true
	t := max(now().UnixNano(), s.last+1)
	s.last = t
	if s.Floor != "" && t >= s.floor {
		// Persist a bound ahead of t before using t. If the write fails,
		// signing still works; only a restart with a clock behind t loses.
		next := t + floorStep
		tmp := s.Floor + ".tmp"
		if err := os.WriteFile(tmp, []byte(strconv.FormatInt(next, 10)+"\n"), 0o600); err == nil && os.Rename(tmp, s.Floor) == nil {
			s.floor = next
		}
	}
	s.mu.Unlock()
	return SignGeneration(s.Key, node, n, d, t)
}

// SignGeneration signs node's generation n with manifest digest d, issued
// at Unix nanoseconds issued.
func SignGeneration(key ed25519.PrivateKey, node string, n int, d string, issued int64) Envelope {
	e := Envelope{Node: node, Generation: n, Digest: d, Issued: issued}
	e.Signature = ed25519.Sign(key, e.message())
	return e
}

// Check verifies e was signed by pub for node, generation n and digest d.
func (e Envelope) Check(pub ed25519.PublicKey, node string, n int, d string) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("no generation signing key")
	}
	if e.Node != node || e.Generation != n || e.Digest != d {
		return fmt.Errorf("envelope is for %s generation %d (%.12s), not %s generation %d (%.12s)", e.Node, e.Generation, e.Digest, node, n, d)
	}
	if !ed25519.Verify(pub, e.message(), e.Signature) {
		return errors.New("generation signature does not verify")
	}
	return nil
}

// ErrReplayed is returned for an envelope older than one already accepted.
var ErrReplayed = errors.New("generation was signed before one already applied (replayed)")

// Fresh checks e is no older than newest, the issue time of the newest
// envelope accepted so far.
func (e Envelope) Fresh(newest int64) error {
	if e.Issued < newest {
		return fmt.Errorf("%w: issued %s, newest seen %s", ErrReplayed,
			time.Unix(0, e.Issued).UTC().Format(time.RFC3339Nano), time.Unix(0, newest).UTC().Format(time.RFC3339Nano))
	}
	return nil
}
