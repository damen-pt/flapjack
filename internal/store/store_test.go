package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/events"
)

func TestStorePersistsAndEnforcesLifecycle(t *testing.T) {
	dir := t.TempDir()
	log, _ := events.Open(filepath.Join(dir, "events.jsonl"))
	defer log.Close()
	s, err := Open(filepath.Join(dir, "state.json"), log)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutNode(v1.Node{Name: "n1", Rack: "r1"}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Node("n1"); n.Status.Phase != v1.PhaseDiscovered {
		t.Fatalf("new node phase = %s", n.Status.Phase)
	}
	if _, err := s.SetPhase("n1", v1.PhaseReady, "skip", "alice"); err == nil {
		t.Fatal("Discovered → Ready must be refused")
	}
	s.SetPhase("n1", v1.PhaseBurnIn, "rack accepted", "bringup")

	again, err := Open(filepath.Join(dir, "state.json"), log)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := again.Node("n1")
	if n.Status.Phase != v1.PhaseBurnIn || n.Status.Reason != "rack accepted" {
		t.Fatalf("not persisted: %+v", n.Status)
	}
	// re-putting the spec keeps status
	again.PutNode(v1.Node{Name: "n1", Rack: "r2"})
	if n, _ := again.Node("n1"); n.Status.Phase != v1.PhaseBurnIn || n.Rack != "r2" {
		t.Fatalf("PutNode clobbered status: %+v", n)
	}
	evs, _ := log.Query(events.Filter{Types: []string{"node.phase"}})
	if len(evs) != 1 || evs[0].Actor != "bringup" || evs[0].Data["to"] != "BurnIn" {
		t.Fatalf("audit events = %+v", evs)
	}
}

func TestExplain(t *testing.T) {
	dir := t.TempDir()
	log, _ := events.Open(filepath.Join(dir, "events.jsonl"))
	defer log.Close()
	s, _ := Open(filepath.Join(dir, "state.json"), log)
	s.PutNode(v1.Node{Name: "n1"})
	t0 := time.Now().Add(-time.Hour)
	for _, e := range []events.Event{
		{Time: t0, Node: "n1", Category: events.Change, Type: "overlay.applied"},
		{Time: t0.Add(time.Minute), Node: "n1", Category: events.Change, Type: "firmware.flashed"},
		{Time: t0.Add(2 * time.Minute), Node: "n1", Category: events.Hardware, Type: "xid", Data: map[string]string{"xid": "79"}},
		{Time: t0.Add(3 * time.Minute), Node: "n1", Category: events.Change, Type: "bios.configured"},
		{Time: t0.Add(time.Minute), Node: "n2", Category: events.Change, Type: "firmware.flashed"},
	} {
		log.Append(e)
	}
	ex, err := s.Explain("n1", t0.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(ex.Recent) != 4 || len(ex.PrecedingChanges) != 2 || ex.PrecedingChanges[0].Type != "firmware.flashed" {
		t.Fatalf("explanation = %+v", ex)
	}
}

func TestUpdateIsAtomicAndValidated(t *testing.T) {
	dir := t.TempDir()
	log, _ := events.Open(filepath.Join(dir, "events.jsonl"))
	defer log.Close()
	s, _ := Open(filepath.Join(dir, "state.json"), log)
	s.PutNode(v1.Node{Name: "n1"})
	if _, err := s.Update("n1", func(n *v1.Node) ([]events.Event, error) {
		n.Status.Phase = v1.PhaseReady
		return nil, nil
	}); err == nil {
		t.Fatal("Update must enforce the lifecycle")
	}
	if _, err := s.Update("n1", func(n *v1.Node) ([]events.Event, error) {
		n.Status.Reason = "leaked"
		return nil, errors.New("abort")
	}); err == nil {
		t.Fatal("fn error must propagate")
	}
	if n, _ := s.Node("n1"); n.Status.Reason != "" || n.Status.Phase != v1.PhaseDiscovered {
		t.Fatalf("aborted update leaked: %+v", n)
	}
	s.Update("n1", func(n *v1.Node) ([]events.Event, error) {
		n.Status.Phase = v1.PhaseBurnIn
		return []events.Event{{Category: events.Health, Type: "health.pass"}}, nil
	})
	evs, _ := log.Query(events.Filter{Nodes: []string{"n1"}, Types: []string{"health.pass"}})
	if len(evs) != 1 {
		t.Fatalf("event not recorded with node name: %v", evs)
	}
}

func TestReadOnlyStoreFollowsWriter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	w, _ := Open(path, nil)
	ro, err := OpenReadOnly(path, events.OpenReadOnly(filepath.Join(dir, "none.jsonl")))
	if err != nil {
		t.Fatal(err)
	}
	if len(ro.Nodes("")) != 0 {
		t.Fatal("expected empty")
	}
	w.PutNode(v1.Node{Name: "n1"})
	if len(ro.Nodes("")) != 1 {
		t.Fatal("reader did not pick up the write")
	}
	w.PutNode(v1.Node{Name: "n2"})
	if _, err := ro.Node("n2"); err != nil {
		t.Fatal(err)
	}
	if err := ro.PutNode(v1.Node{Name: "x"}); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("write on read-only store: %v", err)
	}
	if _, err := ro.SetPhase("n1", v1.PhaseBurnIn, "x", "y"); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("SetPhase on read-only store: %v", err)
	}
	if evs, err := ro.Events.Query(events.Filter{}); err != nil || len(evs) != 0 {
		t.Fatalf("missing log should read empty: %v %v", evs, err)
	}
}

func TestIndexesFollowWrites(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "state.json"), nil)
	s.PutNode(v1.Node{Name: "a", Interfaces: []v1.Interface{{MAC: "52:54:00:00:00:0A", IP: "10.0.0.10"}}})
	if n, i, ok := s.NodeByMAC("52:54:00:00:00:0a"); !ok || n.Name != "a" || i.IP != "10.0.0.10" {
		t.Fatalf("by MAC: %v %v %v", n.Name, i, ok)
	}
	// Moving a's address frees the old one and takes the new one.
	s.PutNode(v1.Node{Name: "a", Interfaces: []v1.Interface{{MAC: "52:54:00:00:00:0a", IP: "10.0.0.11"}}})
	if _, ok := s.NodeByIP("10.0.0.10"); ok {
		t.Fatal("old IP still indexed")
	}
	if n, ok := s.NodeByIP("10.0.0.11"); !ok || n.Name != "a" {
		t.Fatal("new IP not indexed")
	}
	if err := s.PutNode(v1.Node{Name: "b", Interfaces: []v1.Interface{{IP: "10.0.0.11"}}}); !errors.Is(err, ErrConflict) {
		t.Fatalf("shared IP: %v", err)
	}
	if err := s.PutNode(v1.Node{Name: "b", Interfaces: []v1.Interface{{MAC: "52:54:00:00:00:0A"}}}); !errors.Is(err, ErrConflict) {
		t.Fatalf("shared MAC (case differs): %v", err)
	}
	if err := s.PutNode(v1.Node{Name: "b", Interfaces: []v1.Interface{{IP: "10.0.0.10"}}}); err != nil {
		t.Fatalf("freed IP: %v", err)
	}
	if _, ok := s.NodeByIP(""); ok {
		t.Fatal("empty IP matched")
	}
}

func TestAgentReportsAreCoalesced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, _ := Open(path, nil)
	s.AgentFlush = time.Hour
	for i := range 50 {
		s.PutNode(v1.Node{Name: "n" + string(rune('a'+i%26)) + string(rune('a'+i/26))})
	}
	before, _ := Open(path, nil)
	for _, n := range before.Nodes("") {
		if _, err := s.ReportAgent(n.Name, v1.AgentStatus{Applied: 3}); err != nil {
			t.Fatal(err)
		}
	}
	if n, _ := s.Node("naa"); n.Status.Agent == nil || n.Status.Agent.Applied != 3 {
		t.Fatal("report not visible in memory")
	}
	if n, _ := (func() (v1.Node, error) { r, _ := Open(path, nil); return r.Node("naa") })(); n.Status.Agent != nil {
		t.Fatal("report written before the flush")
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	r, _ := Open(path, nil)
	for _, n := range r.Nodes("") {
		if n.Status.Agent == nil || n.Status.Agent.Applied != 3 {
			t.Fatalf("%s: report lost by the flush", n.Name)
		}
	}

	// The timer writes on its own too.
	s.AgentFlush = 20 * time.Millisecond
	s.ReportAgent("naa", v1.AgentStatus{Applied: 4})
	deadline := time.Now().Add(5 * time.Second)
	for {
		r, _ := Open(path, nil)
		if n, _ := r.Node("naa"); n.Status.Agent != nil && n.Status.Agent.Applied == 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("coalesced write never happened")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A spec change writes at once, carrying pending reports with it.
	s.AgentFlush = time.Hour
	s.ReportAgent("nab", v1.AgentStatus{Applied: 5})
	s.PutClass(v1.NodeClass{Name: "c"})
	r, _ = Open(path, nil)
	if n, _ := r.Node("nab"); n.Status.Agent == nil || n.Status.Agent.Applied != 5 {
		t.Fatal("pending report not written with the next change")
	}
	s.Flush()
}

// TestConcurrentWritesShareAWrite: writers that change state at the same
// time share writes of the file, and every change is on disk when its
// call returns.
func TestConcurrentWritesShareAWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, _ := Open(path, nil)
	const n = 200
	for i := range n {
		s.PutNode(v1.Node{Name: fmt.Sprintf("n%03d", i)})
	}
	before := s.finished
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			if _, err := s.SetPhase(fmt.Sprintf("n%03d", i), v1.PhaseBurnIn, "boot", "test"); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	t.Logf("%d writes for %d changes", s.finished-before, n)
	if w := s.finished - before; w >= n {
		t.Errorf("%d writes for %d concurrent changes", w, n)
	}
	r, err := OpenReadOnly(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(r.Nodes(v1.PhaseBurnIn)); got != n {
		t.Fatalf("%d of %d changes on disk", got, n)
	}
}

// TestFailedWriteIsRetried: a change whose write fails returns the error,
// and the next write that succeeds saves it.
func TestFailedWriteIsRetried(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s, _ := Open(path, nil)
	os.Chmod(dir, 0o500)
	defer os.Chmod(dir, 0o700)
	if err := s.PutClass(v1.NodeClass{Name: "compute"}); err == nil {
		t.Fatal("a failed write reported success")
	}
	os.Chmod(dir, 0o700)
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	r, _ := OpenReadOnly(path, nil)
	if _, err := r.Class("compute"); err != nil {
		t.Fatalf("change lost after the retry: %v", err)
	}
}

func TestSparePhaseLoadsAsReady(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	os.WriteFile(path, []byte(`{"classes":{},"nodes":{"n1":{"name":"n1","status":{"phase":"Spare"}}}}`), 0o600)
	s, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Node("n1"); n.Status.Phase != v1.PhaseReady {
		t.Fatalf("phase %s", n.Status.Phase)
	}
}
