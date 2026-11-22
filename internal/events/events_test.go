package events

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)

func TestLogAppendQuery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			l.Append(Event{Time: t0.Add(time.Duration(i) * time.Minute), Node: fmt.Sprintf("n%d", i%5), Category: Health, Type: "health.fail"})
		})
	}
	wg.Wait()
	l.Append(Event{Time: t0, Node: "n1", Category: Change, Type: "firmware.flashed"})
	// simulate a crash mid-write
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"time":"2026-11-04T`)
	f.Close()

	all, err := l.Query(Filter{})
	if err != nil || len(all) != 51 {
		t.Fatalf("got %d events, %v", len(all), err)
	}
	for i := 1; i < len(all); i++ {
		if all[i].Time.Before(all[i-1].Time) {
			t.Fatal("events must be in time order")
		}
	}
	got, _ := l.Query(Filter{Nodes: []string{"n1"}, Types: []string{"health."}, Since: t0.Add(10 * time.Minute), Until: t0.Add(30 * time.Minute)})
	if len(got) != 4 { // minutes 11, 16, 21, 26
		t.Fatalf("filtered = %d", len(got))
	}
	if l.Append(Event{Node: "x"}) == nil {
		t.Fatal("event without type must be rejected")
	}
}

func TestCorrelateFindsTheBadRollout(t *testing.T) {
	var changes, symptoms []Event
	// Every node got a new overlay (explains everything, predicts nothing).
	for i := range 100 {
		changes = append(changes, Event{Time: t0, Node: fmt.Sprintf("n%03d", i), Category: Change, Type: "overlay.applied",
			Data: map[string]string{"generation": "42"}})
	}
	// 40 nodes got new NIC firmware; 38 of them later failed, plus 2 unrelated failures.
	for i := range 40 {
		changes = append(changes, Event{Time: t0.Add(10 * time.Minute), Node: fmt.Sprintf("n%03d", i), Category: Change,
			Type: "firmware.flashed", Data: map[string]string{"component": "ConnectX-7", "from": fmt.Sprint("28.39.", i), "to": "28.40.1000"}})
		if i < 38 {
			symptoms = append(symptoms, Event{Time: t0.Add(40 * time.Minute), Node: fmt.Sprintf("n%03d", i), Category: Health, Type: "health.fail"})
		}
	}
	symptoms = append(symptoms,
		Event{Time: t0.Add(40 * time.Minute), Node: "n090", Type: "health.fail"},
		Event{Time: t0.Add(40 * time.Minute), Node: "n091", Type: "health.fail"},
	)
	// A change after the symptom cannot explain it.
	changes = append(changes, Event{Time: t0.Add(time.Hour), Node: "n000", Category: Change, Type: "bios.configured"})

	got := Correlate(symptoms, changes, time.Hour)
	if len(got) != 2 {
		t.Fatalf("suspects = %+v", got)
	}
	top := got[0]
	if top.Signature != "firmware.flashed component=ConnectX-7 to=28.40.1000" || len(top.Explained) != 38 || len(top.Changed) != 40 {
		t.Fatalf("top suspect = %+v", top)
	}
	if top.Coverage != 0.95 || top.Precision != 0.95 {
		t.Fatalf("coverage/precision = %v/%v", top.Coverage, top.Precision)
	}
	if got[1].Signature != "overlay.applied generation=42" || got[1].Score >= top.Score {
		t.Fatalf("fleet-wide change should rank lower: %+v", got[1])
	}
}
