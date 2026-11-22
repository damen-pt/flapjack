package staging

import (
	"bytes"
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func randomBytes(t *testing.T, n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

type countingServer struct {
	*httptest.Server
	hits atomic.Int64
}

func serve(t *testing.T, s Store) *countingServer {
	cs := &countingServer{}
	h := Handler(s)
	cs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.hits.Add(1)
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(cs.Close)
	return cs
}

func TestSplitFetchFromNearestSource(t *testing.T) {
	data := randomBytes(t, 10*1024+17)
	origin := Store{Dir: t.TempDir()}
	m, err := Split(bytes.NewReader(data), "weights.safetensors", 1024, origin)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Chunks) != 11 || m.Size != int64(len(data)) {
		t.Fatalf("manifest = %d chunks, %d bytes", len(m.Chunks), m.Size)
	}

	// The rack cache already holds every chunk; a peer holds the first half.
	rackStore, peerStore := Store{Dir: t.TempDir()}, Store{Dir: t.TempDir()}
	for i, d := range m.Chunks {
		f, _ := origin.Open(d)
		var b bytes.Buffer
		b.ReadFrom(f)
		f.Close()
		rackStore.Put(d, b.Bytes())
		if i < 5 {
			peerStore.Put(d, b.Bytes())
		}
	}
	originSrv, rackSrv, peerSrv := serve(t, origin), serve(t, rackStore), serve(t, peerStore)

	node := Store{Dir: t.TempDir()}
	f := Fetcher{Store: node, Parallel: 4, Sources: []Source{
		{Name: "origin", URL: originSrv.URL, Tier: TierOrigin},
		{Name: "rack", URL: rackSrv.URL, Tier: TierRack},
		{Name: "peer", URL: peerSrv.URL, Tier: TierPeer},
	}}
	dest := filepath.Join(t.TempDir(), "models", "weights.safetensors")
	st, err := f.Fetch(context.Background(), m, dest)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dest)
	if !bytes.Equal(got, data) {
		t.Fatal("assembled artifact differs")
	}
	if originSrv.hits.Load() != 0 {
		t.Fatalf("origin should not be touched when the rack has everything: %d hits", originSrv.hits.Load())
	}
	if st.Fetched["peer"] != 5*1024 || st.Fetched["rack"] != int64(len(data))-5*1024 || st.Failures["peer"] != 6 {
		t.Fatalf("stats = %+v", st)
	}

	// Second fetch is fully local.
	st, err = f.Fetch(context.Background(), m, dest)
	if err != nil || st.LocalChunks != 11 || len(st.Fetched) != 0 {
		t.Fatalf("refetch: %+v %v", st, err)
	}
}

func TestTamperedChunkIsRejectedAndNextSourceUsed(t *testing.T) {
	data := randomBytes(t, 3000)
	origin := Store{Dir: t.TempDir()}
	m, _ := Split(bytes.NewReader(data), "x", 1000, origin)
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(bytes.Repeat([]byte{0}, 1000))
	}))
	defer evil.Close()
	good := serve(t, origin)

	f := Fetcher{Store: Store{Dir: t.TempDir()}, Sources: []Source{
		{Name: "evil-peer", URL: evil.URL, Tier: TierPeer},
		{Name: "origin", URL: good.URL, Tier: TierOrigin},
	}}
	dest := filepath.Join(t.TempDir(), "x")
	st, err := f.Fetch(context.Background(), m, dest)
	if err != nil {
		t.Fatal(err)
	}
	if st.Failures["evil-peer"] != 3 || st.Fetched["origin"] != 3000 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestFetchFailsWithoutReplacingDest(t *testing.T) {
	origin := Store{Dir: t.TempDir()}
	m, _ := Split(bytes.NewReader(randomBytes(t, 2000)), "x", 1000, origin)
	dest := filepath.Join(t.TempDir(), "x")
	os.WriteFile(dest, []byte("previous version"), 0o644)
	empty := serve(t, Store{Dir: t.TempDir()})
	f := Fetcher{Attempts: 1, Store: Store{Dir: t.TempDir()}, Sources: []Source{{Name: "empty", URL: empty.URL}}}
	if _, err := f.Fetch(context.Background(), m, dest); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("err = %v", err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "previous version" {
		t.Fatal("failed fetch must not touch dest")
	}
}

func TestDigestsCannotEscapeStore(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	for _, d := range []string{"sha256:../../etc/passwd", "md5:abc", "sha256:" + strings.Repeat("G", 64), "sha256:" + strings.Repeat("A", 64)} {
		if ValidDigest(d) || s.Has(d) || s.Put(d, nil) == nil {
			t.Errorf("%q accepted", d)
		}
	}
	srv := serve(t, s)
	resp, _ := http.Get(srv.URL + "/chunks/sha256:..%2F..%2Fetc%2Fpasswd")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestEnsureFetchesOnceAndDetectsTampering(t *testing.T) {
	data := randomBytes(t, 4096)
	origin := Store{Dir: t.TempDir()}
	m, _ := Split(bytes.NewReader(data), "model.bin", 1024, origin)
	srv := serve(t, origin)
	f := Fetcher{Store: Store{Dir: t.TempDir()}, Sources: []Source{{Name: "origin", URL: srv.URL, Tier: TierOrigin}}}
	dest := filepath.Join(t.TempDir(), "models", "model.bin")
	ctx := context.Background()

	var wg sync.WaitGroup
	var fetches atomic.Int64
	for range 4 {
		wg.Go(func() {
			got, _, err := Ensure(ctx, f, m, dest)
			if err != nil {
				t.Error(err)
			}
			if got {
				fetches.Add(1)
			}
		})
	}
	wg.Wait()
	if fetches.Load() != 1 {
		t.Fatalf("%d concurrent ensures fetched", fetches.Load())
	}
	if !Fresh(m, dest) {
		t.Fatal("not fresh after ensure")
	}
	// a modified file is no longer fresh and is re-fetched
	os.WriteFile(dest, append(bytes.Clone(data[:len(data)-1]), 'x'), 0o644)
	if Fresh(m, dest) {
		t.Fatal("tampered file reported fresh")
	}
	if got, _, err := Ensure(ctx, f, m, dest); err != nil || !got {
		t.Fatalf("re-ensure: %v %v", got, err)
	}
	if b, _ := os.ReadFile(dest); !bytes.Equal(b, data) {
		t.Fatal("content not restored")
	}
}

func TestOversizedChunkRejected(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 2048))
	}))
	t.Cleanup(big.Close)
	m := Manifest{Name: "x", ChunkSize: 1024, Chunks: []string{digest([]byte("a"))}}
	f := Fetcher{Attempts: 1, Store: Store{Dir: t.TempDir()}, Sources: []Source{{Name: "big", URL: big.URL}}}
	if _, err := f.Fetch(context.Background(), m, ""); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err = %v", err)
	}
}

func TestRetryRoundsSurviveTransientOutage(t *testing.T) {
	data := randomBytes(t, 100)
	origin := Store{Dir: t.TempDir()}
	m, _ := Split(bytes.NewReader(data), "x", 1024, origin)
	h := Handler(origin)
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			http.Error(w, "restarting", http.StatusServiceUnavailable)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	f := Fetcher{Backoff: time.Millisecond, Store: Store{Dir: t.TempDir()}, Sources: []Source{{Name: "origin", URL: srv.URL}}}
	if _, err := f.Fetch(context.Background(), m, ""); err != nil {
		t.Fatal(err)
	}
}

// TestStoreHealsEmptyChunks: a chunk file left empty by a crash is not a
// chunk, and splitting the data again rewrites it.
func TestStoreHealsEmptyChunks(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	data := bytes.Repeat([]byte("flapjack"), 1000)
	m, err := Split(bytes.NewReader(data), "f", 4096, s)
	if err != nil {
		t.Fatal(err)
	}
	d := m.Chunks[0]
	if err := os.WriteFile(s.path(d), nil, 0o644); err != nil { // the crash
		t.Fatal(err)
	}
	if s.Has(d) {
		t.Fatal("an empty file counts as a chunk")
	}
	os.WriteFile(s.path(d), []byte("trunc"), 0o644) // a truncated one
	if _, err := Split(bytes.NewReader(data), "f", 4096, s); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(s.path(d))
	if digest(b) != d {
		t.Fatal("Split did not rewrite the damaged chunk")
	}
	if err := s.Put(emptyDigest, nil); err != nil || !s.Has(emptyDigest) {
		t.Fatalf("the empty chunk: %v", err)
	}
}
