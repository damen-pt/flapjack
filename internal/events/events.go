// Package events is Flapjack's append-only event timeline: every
// generation change, overlay apply, firmware flash, hardware error and
// drain, per node, queryable by time. Correlate ranks the changes that most
// plausibly explain a set of failures.
package events

import (
	"bufio"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// Category groups event types.
type Category string

const (
	Change    Category = "change"    // generation, overlay, firmware, BIOS
	Health    Category = "health"    // check results, quarantine
	Hardware  Category = "hardware"  // Xid, ECC, link down, BMC SEL
	Scheduler Category = "scheduler" // drain, resume, job failure
	Admin     Category = "admin"     // API mutations (audit)
	Power     Category = "power"
	Boot      Category = "boot" // DHCP, boot scripts, image fetches
)

// Event is one timeline entry.
type Event struct {
	Time     time.Time         `json:"time"`
	Node     string            `json:"node,omitempty"`
	Category Category          `json:"category"`
	Type     string            `json:"type"` // "firmware.flashed", "health.fail", "job.failed"
	Message  string            `json:"message,omitempty"`
	Actor    string            `json:"actor,omitempty"` // who caused it (user, controller)
	Data     map[string]string `json:"data,omitempty"`
}

// Signature identifies "the same change" across nodes: the event type plus
// the data that says what it changed to. Without it, 40 nodes flashed to
// the same NIC firmware would look like 40 unrelated changes.
func (e Event) Signature() string {
	keys := slices.Sorted(maps.Keys(e.Data))
	parts := []string{e.Type}
	for _, k := range keys {
		if k == "from" {
			continue // the old value differs per node; the new one is the change
		}
		parts = append(parts, k+"="+e.Data[k])
	}
	return strings.Join(parts, " ")
}

// Filter selects events. Zero fields match everything.
type Filter struct {
	Nodes      []string
	Categories []Category
	Types      []string // exact or prefix ending in "." ("health.")
	Since      time.Time
	Until      time.Time
}

func (f Filter) Match(e Event) bool {
	if len(f.Nodes) > 0 && !slices.Contains(f.Nodes, e.Node) {
		return false
	}
	if len(f.Categories) > 0 && !slices.Contains(f.Categories, e.Category) {
		return false
	}
	if len(f.Types) > 0 && !slices.ContainsFunc(f.Types, func(t string) bool {
		return t == e.Type || (strings.HasSuffix(t, ".") && strings.HasPrefix(e.Type, t))
	}) {
		return false
	}
	if !f.Since.IsZero() && e.Time.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && !e.Time.Before(f.Until) {
		return false
	}
	return true
}

// Log is an append-only JSON-lines event log on local disk.
type Log struct {
	mu   sync.Mutex
	path string
	f    *os.File
	Now  func() time.Time
}

// Open opens or creates the log at path.
func Open(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Log{path: path, f: f, Now: time.Now}, nil
}

// OpenReadOnly opens the log at path for queries only; Append fails. The
// file need not exist yet.
func OpenReadOnly(path string) *Log {
	return &Log{path: path, Now: time.Now}
}

// ErrReadOnly is returned by Append on a read-only log.
var ErrReadOnly = errors.New("event log is read-only")

func (l *Log) Close() error {
	if l.f == nil {
		return nil
	}
	return l.f.Close()
}

// Append records e, stamping the time if unset. Each event is one write
// so concurrent appenders never interleave lines.
func (l *Log) Append(e Event) error {
	if e.Time.IsZero() {
		e.Time = l.Now()
	}
	if e.Category == "" || e.Type == "" {
		return fmt.Errorf("event needs a category and type")
	}
	if l.f == nil {
		return ErrReadOnly
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.f.Write(append(b, '\n'))
	return err
}

// Query returns matching events in time order.
func (l *Log) Query(f Filter) ([]Event, error) {
	r, err := os.Open(l.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	defer r.Close()
	return Read(r, f)
}

// Read parses a JSON-lines event stream, returning matching events in time
// order. A torn final line (crash mid-write) is ignored.
func Read(r io.Reader, f Filter) ([]Event, error) {
	var out []Event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			continue
		}
		if f.Match(e) {
			out = append(out, e)
		}
	}
	slices.SortStableFunc(out, func(a, b Event) int { return a.Time.Compare(b.Time) })
	return out, sc.Err()
}

// Suspect is a change that may explain a set of symptoms.
type Suspect struct {
	Signature string `json:"signature"`
	// Explained are symptomatic nodes that had this change within the
	// window before their first symptom.
	Explained []string `json:"explained"`
	// Changed is every node that received the change in the period.
	Changed []string `json:"changed"`
	// Coverage is the fraction of symptomatic nodes explained; Precision is
	// the fraction of changed nodes that then showed symptoms.
	Coverage  float64 `json:"coverage"`
	Precision float64 `json:"precision"`
	Score     float64 `json:"score"`
}

// Correlate answers "what changed on these nodes before they failed?".
// symptoms are failure events (health.fail, job.failed, Xids); changes are
// candidate causes (usually Category Change). A change explains a node's
// symptom if it happened on that node within window before the node's
// first symptom. Suspects are ranked by coverage × precision, so a change
// pushed to every node (which explains everything and predicts nothing)
// ranks below one that hit exactly the failing nodes.
func Correlate(symptoms, changes []Event, window time.Duration) []Suspect {
	first := map[string]time.Time{}
	for _, s := range symptoms {
		if t, ok := first[s.Node]; !ok || s.Time.Before(t) {
			first[s.Node] = s.Time
		}
	}
	if len(first) == 0 {
		return nil
	}
	explained := map[string]map[string]bool{}
	changed := map[string]map[string]bool{}
	for _, c := range changes {
		sig := c.Signature()
		if changed[sig] == nil {
			changed[sig], explained[sig] = map[string]bool{}, map[string]bool{}
		}
		changed[sig][c.Node] = true
		if t, ok := first[c.Node]; ok && !c.Time.After(t) && t.Sub(c.Time) <= window {
			explained[sig][c.Node] = true
		}
	}
	var out []Suspect
	for sig, nodes := range explained {
		if len(nodes) == 0 {
			continue
		}
		s := Suspect{
			Signature: sig,
			Explained: slices.Sorted(maps.Keys(nodes)),
			Changed:   slices.Sorted(maps.Keys(changed[sig])),
		}
		s.Coverage = float64(len(s.Explained)) / float64(len(first))
		s.Precision = float64(len(s.Explained)) / float64(len(s.Changed))
		s.Score = s.Coverage * s.Precision
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b Suspect) int {
		return cmp.Or(cmp.Compare(b.Score, a.Score), cmp.Compare(a.Signature, b.Signature))
	})
	return out
}
