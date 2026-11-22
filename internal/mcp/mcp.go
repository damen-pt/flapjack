// Package mcp exposes Flapjack state to AI assistants as a Model Context
// Protocol server over stdio (JSON-RPC 2.0, one message per line). Every
// tool is read-only: an assistant can explain what happened but changes
// still go through the authenticated API or plan/apply. It works with
// local models, so airgapped sites can use it.
package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/events"
	"github.com/damen-pt/flapjack/internal/store"
)

// ProtocolVersion is the newest MCP revision this server implements.
const ProtocolVersion = "2025-06-18"

// supportedVersions are the revisions a client may negotiate. Everything
// this server uses (tools, annotations, isError results) exists in all.
var supportedVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// maxText bounds one tool result. Assistants have finite context, and a
// week of events on a large cluster would not fit; past this the tool
// returns an error asking for narrower filters.
const maxText = 512 << 10

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations,omitempty"`
	call        func(args map[string]any) (any, error)
}

func schema(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

func integer(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc, "minimum": 1}
}

// limitArg reads a positive integer argument, defaulting to def and capped
// at max.
func limitArg(a map[string]any, def, max int) (int, error) {
	v, ok := a["limit"]
	if !ok {
		return def, nil
	}
	f, ok := v.(float64)
	if !ok || f < 1 || f != float64(int(f)) {
		return 0, fmt.Errorf("limit must be a positive integer")
	}
	return min(int(f), max), nil
}

// page is a bounded list result.
type page[T any] struct {
	Total     int  `json:"total"`
	Truncated bool `json:"truncated,omitempty"`
	Items     []T  `json:"items"`
}

// head keeps the first n items; tail keeps the last n (newest events).
func head[T any](all []T, n int) page[T] {
	p := page[T]{Total: len(all), Items: all}
	if len(all) > n {
		p.Items, p.Truncated = all[:n], true
	}
	if p.Items == nil {
		p.Items = []T{}
	}
	return p
}

func tail[T any](all []T, n int) page[T] {
	p := page[T]{Total: len(all), Items: all}
	if len(all) > n {
		p.Items, p.Truncated = all[len(all)-n:], true
	}
	if p.Items == nil {
		p.Items = []T{}
	}
	return p
}

// Server answers MCP requests from a store.
type Server struct {
	Store *store.Store
	Now   func() time.Time
	Name  string
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) since(args map[string]any, def time.Duration) (time.Time, error) {
	v, _ := args["since"].(string)
	if v == "" {
		return s.now().Add(-def), nil
	}
	if d, err := time.ParseDuration(v); err == nil {
		return s.now().Add(-d), nil
	}
	return time.Parse(time.RFC3339, v)
}

// Summary is a cluster overview.
type Summary struct {
	Nodes   int                         `json:"nodes"`
	ByPhase map[v1.Phase]int            `json:"byPhase"`
	ByClass map[string]int              `json:"byClass"`
	Blocks  map[string]map[v1.Phase]int `json:"blocks"` // topology block → phase → count
	// Unhealthy are nodes whose last health report failed, or that are
	// quarantined, with the recorded reason.
	Unhealthy map[string]string `json:"unhealthy,omitempty"`
}

func summarize(nodes []v1.Node) Summary {
	s := Summary{Nodes: len(nodes), ByPhase: map[v1.Phase]int{}, ByClass: map[string]int{}, Blocks: map[string]map[v1.Phase]int{}, Unhealthy: map[string]string{}}
	for _, n := range nodes {
		s.ByPhase[n.Status.Phase]++
		s.ByClass[n.Class]++
		if s.Blocks[n.Block] == nil {
			s.Blocks[n.Block] = map[v1.Phase]int{}
		}
		s.Blocks[n.Block][n.Status.Phase]++
		if n.Status.Phase == v1.PhaseQuarantined || n.Status.Health == "fail" {
			s.Unhealthy[n.Name] = n.Status.Reason
		}
	}
	return s
}

func (s *Server) tools() []tool {
	ro := func(title string) map[string]any {
		// Every tool only reads local state: no side effects, same answer
		// for the same state, no outside world.
		return map[string]any{"title": title, "readOnlyHint": true, "idempotentHint": true, "destructiveHint": false, "openWorldHint": false}
	}
	return []tool{
		{
			Name: "cluster_summary", Description: "Overview of the cluster: node counts by phase, class and topology block, and every quarantined or failing node with its reason. Start here.",
			InputSchema: schema(map[string]any{}), Annotations: ro("Cluster summary"),
			call: func(map[string]any) (any, error) { return summarize(s.Store.Nodes("")), nil },
		},
		{
			Name: "list_nodes", Description: "List cluster nodes with spec and status (phase, generation, last health, reason). Filter by phase (Ready, Quarantined, Draining, BurnIn, ...), class, rack or block.",
			InputSchema: schema(map[string]any{
				"phase": str("only nodes in this phase"), "class": str("only this node class"), "rack": str("only this rack"),
				"block": str("only this topology block"), "limit": integer("maximum nodes returned (default 200, max 2000)"),
			}), Annotations: ro("List nodes"),
			call: func(a map[string]any) (any, error) {
				limit, err := limitArg(a, 200, 2000)
				if err != nil {
					return nil, err
				}
				p, _ := a["phase"].(string)
				nodes := s.Store.Nodes(v1.Phase(p))
				nodes = slices.DeleteFunc(nodes, func(n v1.Node) bool {
					for k, v := range map[string]string{"class": n.Class, "rack": n.Rack, "block": n.Block} {
						if want, _ := a[k].(string); want != "" && want != v {
							return true
						}
					}
					return false
				})
				return head(nodes, limit), nil
			},
		},
		{
			Name: "get_node", Description: "Get one node's full spec and status.",
			InputSchema: schema(map[string]any{"name": str("node name")}, "name"), Annotations: ro("Get node"),
			call: func(a map[string]any) (any, error) {
				n, _ := a["name"].(string)
				return s.Store.Node(n)
			},
		},
		{
			Name: "explain_node", Description: "Explain why a node is in its current state: its timeline and the configuration changes that preceded its first health or hardware event.",
			InputSchema: schema(map[string]any{"name": str("node name"), "since": str("RFC3339 time or duration such as 24h (default 24h)")}, "name"), Annotations: ro("Explain node"),
			call: func(a map[string]any) (any, error) {
				n, _ := a["name"].(string)
				since, err := s.since(a, 24*time.Hour)
				if err != nil {
					return nil, err
				}
				ex, err := s.Store.Explain(n, since)
				if len(ex.Recent) > 200 {
					ex.Recent = ex.Recent[len(ex.Recent)-200:] // newest; PrecedingChanges keeps the causes
				}
				return ex, err
			},
		},
		{
			Name: "query_events", Description: "Query the event timeline, newest last. Types match exactly or by prefix ending in '.' (e.g. 'health.'). When more events match than limit, the newest are returned.",
			InputSchema: schema(map[string]any{
				"node": str("node name"), "type": str("event type or prefix"), "since": str("RFC3339 time or duration (default 24h)"),
				"limit": integer("maximum events returned (default 200, max 2000)"),
			}), Annotations: ro("Query events"),
			call: func(a map[string]any) (any, error) {
				limit, err := limitArg(a, 200, 2000)
				if err != nil {
					return nil, err
				}
				since, err := s.since(a, 24*time.Hour)
				if err != nil {
					return nil, err
				}
				f := events.Filter{Since: since}
				if n, _ := a["node"].(string); n != "" {
					f.Nodes = []string{n}
				}
				if t, _ := a["type"].(string); t != "" {
					f.Types = []string{t}
				}
				evs, err := s.Store.Events.Query(f)
				if err != nil {
					return nil, err
				}
				return tail(evs, limit), nil
			},
		},
		{
			Name: "correlate_failures", Description: "Rank configuration changes (firmware, BIOS, overlay, generation) by how well they explain a set of failures across nodes.",
			InputSchema: schema(map[string]any{
				"symptom": str("symptom event type or prefix, e.g. 'health.fail' or 'hardware.'"),
				"window":  str("how long before a failure a change counts, e.g. 2h (default 1h)"),
				"since":   str("RFC3339 time or duration (default 7d = 168h)"),
			}, "symptom"), Annotations: ro("Correlate failures"),
			call: func(a map[string]any) (any, error) {
				since, err := s.since(a, 168*time.Hour)
				if err != nil {
					return nil, err
				}
				window := time.Hour
				if w, _ := a["window"].(string); w != "" {
					if window, err = time.ParseDuration(w); err != nil {
						return nil, err
					}
				}
				sym, _ := a["symptom"].(string)
				symptoms, err := s.Store.Events.Query(events.Filter{Since: since, Types: []string{sym}})
				if err != nil {
					return nil, err
				}
				changes, err := s.Store.Events.Query(events.Filter{Since: since, Categories: []events.Category{events.Change}})
				if err != nil {
					return nil, err
				}
				out := events.Correlate(symptoms, changes, window)
				if len(out) > 50 {
					out = out[:50]
				}
				return out, nil
			},
		},
	}
}

// call runs a tool, turning a panic into a tool error so one bad request
// cannot take down the assistant's session.
func call(t tool, args map[string]any) (out any, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("internal error in %s: %v", t.Name, p)
		}
	}()
	return t.call(args)
}

func toolError(msg string) map[string]any {
	return map[string]any{"isError": true, "content": []any{map[string]any{"type": "text", "text": msg}}}
}

// Serve handles requests from r until EOF, writing responses to w.
func (s *Server) Serve(r io.Reader, w io.Writer) error {
	tools := s.tools()
	enc := json.NewEncoder(w)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for sc.Scan() {
		var req request
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			enc.Encode(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}})
			continue
		}
		if req.ID == nil {
			continue // notification (e.g. notifications/initialized)
		}
		resp := response{JSONRPC: "2.0", ID: req.ID}
		switch req.Method {
		case "initialize":
			var p struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			json.Unmarshal(req.Params, &p)
			version := ProtocolVersion
			if slices.Contains(supportedVersions, p.ProtocolVersion) {
				version = p.ProtocolVersion
			}
			resp.Result = map[string]any{
				"protocolVersion": version,
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "flapjack", "version": "0.1.0"},
				"instructions":    "Read-only access to Flapjack cluster state. Start with cluster_summary; use explain_node for a single node and correlate_failures for fleet-wide incidents. Changes go through the authenticated API, not this server.",
			}
		case "ping":
			resp.Result = map[string]any{}
		case "tools/list":
			list := make([]tool, len(tools))
			copy(list, tools)
			resp.Result = map[string]any{"tools": list}
		case "tools/call":
			var p struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			if err := json.Unmarshal(req.Params, &p); err != nil {
				resp.Error = &rpcError{-32602, "invalid params"}
				break
			}
			i := slices.IndexFunc(tools, func(t tool) bool { return t.Name == p.Name })
			if i < 0 {
				resp.Error = &rpcError{-32602, "unknown tool " + p.Name}
				break
			}
			if p.Arguments == nil {
				p.Arguments = map[string]any{}
			}
			out, err := call(tools[i], p.Arguments)
			if err != nil {
				// Tool errors are results the model can read, not protocol errors.
				resp.Result = toolError(err.Error())
				break
			}
			b, err := json.MarshalIndent(out, "", "  ")
			if err != nil {
				resp.Error = &rpcError{-32603, err.Error()}
				break
			}
			if len(b) > maxText {
				resp.Result = toolError(fmt.Sprintf("result is %d KiB, over the %d KiB limit; narrow it with filters, a later since, or a smaller limit", len(b)>>10, maxText>>10))
				break
			}
			resp.Result = map[string]any{"content": []any{map[string]any{"type": "text", "text": string(b)}}}
		default:
			resp.Error = &rpcError{-32601, fmt.Sprintf("method %q not found", req.Method)}
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return sc.Err()
}
