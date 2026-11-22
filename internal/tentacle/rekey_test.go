package tentacle

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/damen-pt/flapjack/internal/pki"
	"github.com/damen-pt/flapjack/internal/server"
)

// TestEnrollmentDropsStaleSealedBlobs: when a node enrolls again (it
// rebooted, so it has a new seal key), the tentacle drops what it holds
// sealed to the old key as the enrollment succeeds, without waiting for the
// head's next snapshot, so the node's first secret request is fetched
// fresh rather than answered with a blob it cannot open.
func TestEnrollmentDropsStaleSealedBlobs(t *testing.T) {
	status := http.StatusOK
	head := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(`{}`))
	}))
	defer head.Close()
	tn := &Tentacle{Rack: "r1", Head: head.URL, Up: head.Client()}
	h := tn.AgentHandler()
	stale := func() bool { return tn.cachedSealed("n1", "old", "sha256:aa") != nil }
	reset := func() {
		tn.mu.Lock()
		tn.nodes["n1"] = &node{RackNode: server.RackNode{Name: "n1", SealKeyID: "old",
			Interfaces: []server.RackInterface{{MAC: "52:54:00:00:00:01", IP: "10.1.1.11"}}},
			sealed: map[string][]byte{"sha256:aa": []byte("sealed to the old key")}}
		tn.mu.Unlock()
	}
	k, err := pki.NewSealKey()
	if err != nil {
		t.Fatal(err)
	}
	enroll := func(ticket string) int {
		body, _ := json.Marshal(server.EnrollRequest{Node: "n1", MAC: "52:54:00:00:00:01", Ticket: ticket, SealKey: k.PublicKey().Bytes()})
		r := httptest.NewRequest(http.MethodPost, "/agent/v1/enroll", bytes.NewReader(body))
		r.RemoteAddr = "10.1.1.11:40000"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	reset()
	status = http.StatusForbidden
	if code := enroll("t"); code != http.StatusForbidden || !stale() {
		t.Fatalf("a refused enrollment dropped the cache (%d)", code)
	}
	status = http.StatusOK
	if code := enroll(""); code != http.StatusOK || !stale() {
		t.Fatalf("a renewal (no ticket, same key) dropped the cache (%d)", code)
	}
	if code := enroll("t"); code != http.StatusOK || stale() {
		t.Fatalf("an enrollment with a new seal key kept blobs sealed to the old one (%d)", code)
	}
	if tn.cachedSealed("n1", pki.SealKeyID(k.PublicKey().Bytes()), "sha256:aa") != nil {
		t.Fatal("the old blob is served under the new key")
	}
}
