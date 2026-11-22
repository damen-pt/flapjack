// Package attest issues the single-use boot tickets that prove a node's
// enrollment comes from a boot the head served, and the tokens that gate
// image downloads.
package attest

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Tickets issues and redeems single-use boot tickets. The control plane issues a ticket
// when it power-cycles a node through its BMC and serves it only to that
// node's MAC; the node presents it once to obtain its boot credentials.
// This proves the boot was one the control plane started, from the
// expected network position, within TTL. It cannot stop an attacker who
// controls that network position at that moment.
//
// With Armed set, a ticket is issued only inside a boot window: Arm opens
// one for a MAC (the head does so when DHCP answers that MAC's iPXE, the
// moment a network boot is under way), and issuing a ticket closes it.
// Fetching a node's script from its address outside a boot, or a second
// time within one, yields no ticket; and if an impostor does take the
// window's ticket, the real node's enrollment then fails loudly instead
// of both succeeding.
type Tickets struct {
	Key []byte
	TTL time.Duration
	Now func() time.Time
	// Armed requires a boot window from Arm before Issue; ArmFor is how
	// long a window stays open (default 2 minutes).
	Armed  bool
	ArmFor time.Duration
	// UsedFile, if set, keeps the nonces of redeemed tickets that have not
	// expired, so a restart cannot make a spent ticket (readable in a
	// node's /proc/cmdline) good again. A ticket whose use cannot be
	// recorded is refused.
	UsedFile string

	mu     sync.Mutex
	loaded bool
	used   map[string]time.Time // ticket nonce → expiry
	armed  map[string]time.Time // MAC → window close
}

// ErrNotArmed is returned by Issue for a MAC with no open boot window.
var ErrNotArmed = errors.New("no boot window open for this MAC")

// Arm opens (or reopens) a boot window for mac.
func (t *Tickets) Arm(mac string) {
	d := t.ArmFor
	if d <= 0 {
		d = 2 * time.Minute
	}
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.armed == nil {
		t.armed = map[string]time.Time{}
	}
	for m, e := range t.armed {
		if now.After(e) {
			delete(t.armed, m)
		}
	}
	t.armed[strings.ToLower(mac)] = now.Add(d)
}

// disarm closes mac's boot window, reporting whether one was open.
func (t *Tickets) disarm(mac string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := strings.ToLower(mac)
	e, ok := t.armed[k]
	delete(t.armed, k)
	return ok && !t.now().After(e)
}

var enc = base64.RawURLEncoding

func (t *Tickets) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t *Tickets) sign(payload string) string {
	m := hmac.New(sha256.New, t.Key)
	m.Write([]byte(payload))
	return enc.EncodeToString(m.Sum(nil))
}

// Issue returns a ticket bound to mac.
func (t *Tickets) Issue(mac string) (string, error) {
	if len(t.Key) < 32 {
		return "", errors.New("ticket key must be at least 32 bytes")
	}
	if t.Armed && !t.disarm(mac) {
		return "", ErrNotArmed
	}
	nonce := rand.Text()
	payload := strings.Join([]string{strings.ToLower(mac), strconv.FormatInt(t.now().Add(t.TTL).Unix(), 10), nonce}, "|")
	return enc.EncodeToString([]byte(payload)) + "." + t.sign(payload), nil
}

// Redeem validates a ticket presented by mac and consumes it.
func (t *Tickets) Redeem(ticket, mac string) error {
	p64, sig, ok := strings.Cut(ticket, ".")
	if !ok {
		return errors.New("malformed ticket")
	}
	raw, err := enc.DecodeString(p64)
	if err != nil {
		return errors.New("malformed ticket")
	}
	payload := string(raw)
	if !hmac.Equal([]byte(sig), []byte(t.sign(payload))) {
		return errors.New("invalid ticket signature")
	}
	f := strings.Split(payload, "|")
	if len(f) != 3 {
		return errors.New("malformed ticket")
	}
	exp, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil {
		return errors.New("malformed ticket")
	}
	now := t.now()
	if now.Unix() > exp {
		return errors.New("ticket expired")
	}
	if f[0] != strings.ToLower(mac) {
		return errors.New("ticket issued to a different MAC")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.loadUsed(); err != nil {
		return err
	}
	for n, e := range t.used {
		if now.After(e) {
			delete(t.used, n) // expired tickets are rejected anyway
		}
	}
	if _, dup := t.used[f[2]]; dup {
		return errors.New("ticket already used")
	}
	t.used[f[2]] = time.Unix(exp, 0)
	if err := t.saveUsed(); err != nil {
		// Still marked used here: the ticket is spent either way.
		return fmt.Errorf("recording the ticket's use: %w", err)
	}
	return nil
}

// loadUsed reads UsedFile once. A file that exists but cannot be read
// fails every redemption rather than forgetting which tickets were spent.
func (t *Tickets) loadUsed() error {
	if t.used == nil {
		t.used = map[string]time.Time{}
	}
	if t.loaded || t.UsedFile == "" {
		return nil
	}
	b, err := os.ReadFile(t.UsedFile)
	if errors.Is(err, fs.ErrNotExist) {
		t.loaded = true
		return nil
	}
	if err != nil {
		return fmt.Errorf("spent tickets: %w", err)
	}
	var used map[string]time.Time
	if err := json.Unmarshal(b, &used); err != nil {
		return fmt.Errorf("spent tickets: %s: %w", t.UsedFile, err)
	}
	maps.Copy(t.used, used)
	t.loaded = true
	return nil
}

func (t *Tickets) saveUsed() error {
	if t.UsedFile == "" {
		return nil
	}
	b, err := json.Marshal(t.used)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(t.UsedFile), "."+filepath.Base(t.UsedFile)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), t.UsedFile)
}
