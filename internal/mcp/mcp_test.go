package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/events"
	"github.com/damen-pt/flapjack/internal/store"
)

func session(t *testing.T, s *Server, msgs ...string) []map[string]any {
	var out strings.Builder
	if err := s.Serve(strings.NewReader(strings.Join(msgs, "\n")+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	var resps []map[string]any
	sc := bufio.NewScanner(strings.NewReader(out.String()))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("bad response %q", sc.Text())
		}
		resps = append(resps, m)
	}
	return resps
}

func text(t *testing.T, resp map[string]any) string {
	t.Helper()
	r, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", resp)
	}
	return r["content"].([]any)[0].(map[string]any)["text"].(string)
}

func newServer(t *testing.T) *Server {
	dir := t.TempDir()
	log, _ := events.Open(filepath.Join(dir, "events.jsonl"))
	t.Cleanup(func() { log.Close() })
	st, _ := store.Open(filepath.Join(dir, "state.json"), log)
	now := time.Now()
	for i := range 4 {
		n := fmt.Sprintf("n%d", i)
		st.PutNode(v1.Node{Name: n, Status: v1.NodeStatus{Phase: v1.PhaseReady}})
		log.Append(events.Event{Time: now.Add(-2 * time.Hour), Node: n, Category: events.Change, Type: "overlay.applied", Data: map[string]string{"generation": "7"}})
		if i < 2 {
			log.Append(events.Event{Time: now.Add(-90 * time.Minute), Node: n, Category: events.Change, Type: "firmware.flashed", Data: map[string]string{"to": "28.40"}})
			log.Append(events.Event{Time: now.Add(-time.Hour), Node: n, Category: events.Health, Type: "health.fail"})
		}
	}
	return &Server{Store: st}
}

func TestProtocol(t *testing.T) {
	s := newServer(t)
	resps := session(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"correlate_failures","arguments":{"symptom":"health.fail","window":"1h"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_node","arguments":{"name":"missing"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"no/such"}`,
		`not json`,
	)
	if len(resps) != 6 {
		t.Fatalf("notifications must not be answered; got %d responses", len(resps))
	}
	if v := resps[0]["result"].(map[string]any)["protocolVersion"]; v != ProtocolVersion {
		t.Fatalf("version = %v", v)
	}
	tools := resps[1]["result"].(map[string]any)["tools"].([]any)
	for _, tl := range tools {
		m := tl.(map[string]any)
		if m["annotations"].(map[string]any)["readOnlyHint"] != true {
			t.Errorf("%s must be read-only", m["name"])
		}
	}
	if len(tools) != 6 {
		t.Fatalf("tools = %d", len(tools))
	}
	corr := text(t, resps[2])
	var suspects []events.Suspect
	json.Unmarshal([]byte(corr), &suspects)
	if len(suspects) == 0 || suspects[0].Signature != "firmware.flashed to=28.40" || suspects[0].Precision != 1 {
		t.Fatalf("correlate = %s", corr)
	}
	if r := resps[3]["result"].(map[string]any); r["isError"] != true {
		t.Fatalf("tool error must be a result with isError: %v", resps[3])
	}
	if resps[4]["error"].(map[string]any)["code"].(float64) != -32601 {
		t.Fatal("unknown method")
	}
	if resps[5]["error"].(map[string]any)["code"].(float64) != -32700 {
		t.Fatal("parse error")
	}
}

func TestVersionNegotiation(t *testing.T) {
	s := newServer(t)
	resps := session(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`,
	)
	if v := resps[0]["result"].(map[string]any)["protocolVersion"]; v != "2025-03-26" {
		t.Fatalf("supported version not echoed: %v", v)
	}
	if v := resps[1]["result"].(map[string]any)["protocolVersion"]; v != ProtocolVersion {
		t.Fatalf("unsupported version should get latest: %v", v)
	}
}

func TestLimitsAndFilters(t *testing.T) {
	s := newServer(t)
	resps := session(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_nodes","arguments":{"limit":3}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_events","arguments":{"limit":2}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_nodes","arguments":{"limit":-1}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"cluster_summary","arguments":{}}}`,
	)
	var nodes page[v1.Node]
	json.Unmarshal([]byte(text(t, resps[0])), &nodes)
	if nodes.Total != 4 || len(nodes.Items) != 3 || !nodes.Truncated {
		t.Fatalf("list_nodes = %+v", nodes)
	}
	var evs page[events.Event]
	json.Unmarshal([]byte(text(t, resps[1])), &evs)
	if evs.Total != 8 || len(evs.Items) != 2 || evs.Items[1].Type != "health.fail" {
		t.Fatalf("query_events must keep the newest: %+v", evs)
	}
	if resps[2]["result"].(map[string]any)["isError"] != true {
		t.Fatal("bad limit accepted")
	}
	var sum Summary
	json.Unmarshal([]byte(text(t, resps[3])), &sum)
	if sum.Nodes != 4 || sum.ByPhase[v1.PhaseReady] != 4 {
		t.Fatalf("summary = %+v", sum)
	}
}

func TestReadOnlyStoreSeesLiveChanges(t *testing.T) {
	dir := t.TempDir()
	w, _ := store.Open(filepath.Join(dir, "state.json"), nil)
	ro, _ := store.OpenReadOnly(filepath.Join(dir, "state.json"), events.OpenReadOnly(filepath.Join(dir, "events.jsonl")))
	s := &Server{Store: ro}
	w.PutNode(v1.Node{Name: "late"})
	resps := session(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_node","arguments":{"name":"late"}}}`)
	if !strings.Contains(text(t, resps[0]), `"late"`) {
		t.Fatalf("read-only server missed a write: %v", resps[0])
	}
}
