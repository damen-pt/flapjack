package gens

import (
	"testing"

	"github.com/damen-pt/flapjack/internal/overlay"
)

func man(paths ...string) overlay.Manifest {
	m := overlay.Manifest{Entries: map[string]overlay.Entry{}}
	for _, p := range paths {
		m.Entries[p] = overlay.Entry{Kind: overlay.KindDir}
	}
	return m
}

func TestGenerationsSwitchAndRollback(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	if _, err := s.Current("n1"); err != ErrNone {
		t.Fatalf("empty: %v", err)
	}
	g1, changed, err := s.Add("n1", man("/a"), "alice", "first", []string{"base"})
	if err != nil || !changed || g1.Number != 1 || g1.Manifest.Generation != 1 {
		t.Fatalf("g1 = %+v %v %v", g1, changed, err)
	}
	if g, changed, _ := s.Add("n1", man("/a"), "bob", "same", nil); changed || g.Number != 1 {
		t.Fatal("identical manifest created a new generation")
	}
	g2, changed, _ := s.Add("n1", man("/a", "/b"), "alice", "second", nil)
	if !changed || g2.Number != 2 {
		t.Fatalf("g2 = %+v", g2)
	}
	back, err := s.SetCurrent("n1", 0)
	if err != nil || back.Number != 1 {
		t.Fatalf("rollback = %+v %v", back, err)
	}
	if _, err := s.SetCurrent("n1", 0); err == nil {
		t.Fatal("rolled back past the oldest generation")
	}
	// Switching to new content after a rollback appends; history is kept.
	g3, changed, _ := s.Add("n1", man("/c"), "alice", "third", nil)
	if !changed || g3.Number != 3 {
		t.Fatalf("g3 = %+v", g3)
	}
	// Switching to content equal to an older generation still makes a new
	// one: generations record what happened, in order.
	if g, changed, _ := s.Add("n1", man("/a"), "alice", "again", nil); !changed || g.Number != 4 {
		t.Fatalf("g4 = %+v", g)
	}
	list, _ := s.List("n1")
	if len(list) != 4 || !list[3].Current || list[0].Paths != 1 || list[1].Paths != 2 {
		t.Fatalf("list = %+v", list)
	}
	if _, err := s.SetCurrent("n1", 9); err == nil {
		t.Fatal("switched to a missing generation")
	}
	if _, _, err := s.Add("../x", man(), "", "", nil); err == nil {
		t.Fatal("path traversal in node name accepted")
	}
}
