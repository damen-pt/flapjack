package health

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/events"
	"github.com/damen-pt/flapjack/internal/store"
)

func admitStore(t *testing.T, phase v1.Phase) (*store.Store, *events.Log) {
	dir := t.TempDir()
	log, _ := events.Open(filepath.Join(dir, "events.jsonl"))
	t.Cleanup(func() { log.Close() })
	s, _ := store.Open(filepath.Join(dir, "state.json"), log)
	s.PutClass(v1.NodeClass{Name: "gpu", Health: v1.HealthPolicy{
		Checks: []string{"gpu", "ib"}, Critical: []string{"gpu"}, ConsecutiveFailures: 2,
	}})
	s.PutNode(v1.Node{Name: "n1", Class: "gpu", Status: v1.NodeStatus{Phase: phase}})
	return s, log
}

func rep(at time.Time, results ...Result) Report {
	r := Report{Node: "n1", Time: at, Results: results}
	for _, x := range results {
		r.Status = max(r.Status, x.Status)
	}
	return r
}

func TestAdmitDrivesLifecycle(t *testing.T) {
	s, log := admitStore(t, v1.PhaseBurnIn)
	t0 := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	d, err := Admit(s, rep(t0, Result{Check: "gpu"}, Result{Check: "ib", Status: Warn}), "agent/n1")
	if err != nil || d.Phase != v1.PhaseReady {
		t.Fatalf("burn-in pass: %+v %v", d, err)
	}
	// one non-critical failure: still Ready, counted
	Admit(s, rep(t0.Add(time.Minute), Result{Check: "gpu"}, Result{Check: "ib", Status: Fail, Message: "port down"}), "agent/n1")
	n, _ := s.Node("n1")
	if n.Status.Phase != v1.PhaseReady || n.Status.Failures != 1 || n.Status.Health != "fail" {
		t.Fatalf("after one failure: %+v", n.Status)
	}
	// a replayed old report must not reset the counter
	if _, err := Admit(s, rep(t0, Result{Check: "gpu"}, Result{Check: "ib"}), "agent/n1"); !errors.Is(err, ErrStale) {
		t.Fatalf("stale report: %v", err)
	}
	d, _ = Admit(s, rep(t0.Add(2*time.Minute), Result{Check: "gpu"}, Result{Check: "ib", Status: Fail}), "agent/n1")
	if d.Phase != v1.PhaseQuarantined {
		t.Fatalf("second failure: %+v", d)
	}
	evs, _ := log.Query(events.Filter{Nodes: []string{"n1"}})
	var types []string
	for _, e := range evs {
		types = append(types, e.Type)
	}
	want := []string{"health.warn", "node.phase", "health.fail", "health.fail", "node.phase"}
	if len(types) != len(want) {
		t.Fatalf("events = %v", types)
	}
	for i := range want {
		if types[i] != want[i] {
			t.Fatalf("events = %v", types)
		}
	}
}

func TestAdmitFailsClosed(t *testing.T) {
	s, _ := admitStore(t, v1.PhaseBurnIn)
	d, _ := Admit(s, rep(time.Now()), "agent")
	if d.Phase != v1.PhaseQuarantined {
		t.Fatalf("empty burn-in report admitted: %+v", d)
	}
	// a class with no listed checks requires every reported check
	p := EffectivePolicy(v1.HealthPolicy{}, rep(time.Now(), Result{Check: "a"}, Result{Check: "b", Status: Fail}))
	if len(p.Checks) != 2 {
		t.Fatalf("effective policy = %+v", p)
	}
}

func TestAdmitConcurrentReportsSerialize(t *testing.T) {
	s, _ := admitStore(t, v1.PhaseReady)
	t0 := time.Now()
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			Admit(s, rep(t0.Add(time.Duration(i+1)*time.Second), Result{Check: "gpu"}, Result{Check: "ib"}), "agent")
		})
	}
	wg.Wait()
	n, _ := s.Node("n1")
	if !n.Status.LastHealth.Equal(t0.Add(20 * time.Second)) {
		t.Fatalf("newest report not retained: %v", n.Status.LastHealth)
	}
}
