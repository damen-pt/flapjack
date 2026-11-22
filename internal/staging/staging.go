// Package staging is Flapjack's content-addressed distribution layer. Boot
// images, model weights, datasets and container images are split into
// chunks named by digest; nodes fetch missing chunks from rack peers first,
// then the rack cache, then the origin, verifying every chunk. Any node
// holding a chunk can serve it, so origin load grows with racks, not nodes.
package staging

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// DefaultChunkSize balances per-request overhead against dedup granularity.
const DefaultChunkSize = 16 << 20

// Manifest describes one artifact as an ordered list of chunks.
type Manifest struct {
	Name      string   `json:"name"`
	Size      int64    `json:"size"`
	ChunkSize int      `json:"chunkSize"`
	Chunks    []string `json:"chunks"`
	Digest    string   `json:"digest"` // of the whole artifact
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// ValidDigest reports whether d is a well-formed sha256 digest. Digests
// become file paths, so anything else is rejected before touching disk.
func ValidDigest(d string) bool {
	h, ok := strings.CutPrefix(d, "sha256:")
	if !ok || len(h) != 64 {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil && strings.ToLower(h) == h
}

// Store is a chunk store on local disk (NVMe on nodes and rack caches).
type Store struct {
	Dir string
}

func (s Store) path(d string) string {
	h := strings.TrimPrefix(d, "sha256:")
	return filepath.Join(s.Dir, "sha256", h[:2], h)
}

// emptyDigest is the digest of no bytes: the only chunk that may be empty.
const emptyDigest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// Has reports whether d is stored. An empty file is not a chunk (unless d
// is the empty digest): it is what a crash between rename and writeback
// leaves behind, and treating it as present would serve it forever.
func (s Store) Has(d string) bool {
	if !ValidDigest(d) {
		return false
	}
	fi, err := os.Stat(s.path(d))
	return err == nil && (fi.Size() > 0 || d == emptyDigest)
}

// hasSize is Has for a chunk whose length is known: a truncated file is
// replaced.
func (s Store) hasSize(d string, size int) bool {
	if !ValidDigest(d) {
		return false
	}
	fi, err := os.Stat(s.path(d))
	return err == nil && fi.Size() == int64(size)
}

// Put stores data under d after checking it hashes to d.
func (s Store) Put(d string, data []byte) error {
	if !ValidDigest(d) {
		return fmt.Errorf("invalid digest %q", d)
	}
	if got := digest(data); got != d {
		return fmt.Errorf("chunk content is %s, expected %s", got, d)
	}
	p := s.path(d)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p), ".chunk-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	// Durable before it is visible: without this, a crash can leave the
	// renamed file empty (XFS, ext4 without auto_da_alloc).
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), p); err != nil {
		return err
	}
	if dir, err := os.Open(filepath.Dir(p)); err == nil {
		dir.Sync()
		dir.Close()
	}
	return nil
}

// Remove deletes d if it is stored.
func (s Store) Remove(d string) error {
	if !ValidDigest(d) {
		return fs.ErrNotExist
	}
	if err := os.Remove(s.path(d)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (s Store) Open(d string) (*os.File, error) {
	if !ValidDigest(d) {
		return nil, fs.ErrNotExist
	}
	return os.Open(s.path(d))
}

// Split chunks r into the store and returns its manifest.
func Split(r io.Reader, name string, chunkSize int, s Store) (Manifest, error) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	m := Manifest{Name: name, ChunkSize: chunkSize}
	whole := sha256.New()
	buf := make([]byte, chunkSize)
	for {
		n, err := io.ReadFull(r, buf)
		if n > 0 {
			c := buf[:n]
			whole.Write(c)
			d := digest(c)
			if !s.hasSize(d, n) {
				if err := s.Put(d, c); err != nil {
					return m, err
				}
			}
			m.Chunks = append(m.Chunks, d)
			m.Size += int64(n)
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return m, err
		}
	}
	m.Digest = "sha256:" + hex.EncodeToString(whole.Sum(nil))
	return m, nil
}

// Handler serves chunks read-only at GET /chunks/<digest>. In production it
// sits behind mTLS so only enrolled nodes can read.
func Handler(s Store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /chunks/{digest}", func(w http.ResponseWriter, r *http.Request) {
		f, err := s.Open(r.PathValue("digest"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		http.ServeContent(w, r, "", fsModTime(f), f)
	})
	return mux
}

// Tier orders sources from nearest to farthest.
type Tier int

const (
	TierPeer   Tier = iota // another node in the same rack
	TierRack               // the rack cache
	TierOrigin             // the control plane
)

// Source is somewhere chunks can be fetched from.
type Source struct {
	Name string
	URL  string // base URL; chunks are at URL + "/chunks/<digest>"
	Tier Tier
}

// Stats reports where an artifact's bytes came from.
type Stats struct {
	LocalChunks int              `json:"localChunks"`
	Fetched     map[string]int64 `json:"fetched"` // source name → bytes
	Failures    map[string]int   `json:"failures,omitempty"`
}

// Fetcher assembles artifacts from chunks.
type Fetcher struct {
	Store    Store
	Sources  []Source
	Client   *http.Client // carries the mTLS client certificate in production
	Parallel int
	// Attempts is how many rounds over all sources a chunk gets before the
	// fetch fails (default 3), with Backoff (default 1s) doubling between
	// rounds, so a rack cache restarting does not fail every job.
	Attempts int
	Backoff  time.Duration
}

// Fetch makes every chunk of m available locally and writes the assembled
// artifact to dest (atomically; dest is only replaced once the whole
// artifact verifies). If dest is "", chunks are only staged into the store,
// which is what a rack cache pre-warming does.
func (f Fetcher) Fetch(ctx context.Context, m Manifest, dest string) (Stats, error) {
	st := Stats{Fetched: map[string]int64{}, Failures: map[string]int{}}
	var mu sync.Mutex
	var missing []int
	seen := map[string]bool{}
	for i, d := range m.Chunks {
		if !ValidDigest(d) {
			return st, fmt.Errorf("manifest chunk %d: invalid digest %q", i, d)
		}
		switch {
		case seen[d]:
		case f.Store.Has(d):
			st.LocalChunks++
		default:
			missing = append(missing, i)
		}
		seen[d] = true
	}

	sources := slices.Clone(f.Sources)
	slices.SortStableFunc(sources, func(a, b Source) int { return int(a.Tier) - int(b.Tier) })
	par := max(f.Parallel, 1)
	work := make(chan int)
	errc := make(chan error, 1)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	for range par {
		wg.Go(func() {
			for i := range work {
				src, n, fails, err := f.fetchChunk(ctx, m.Chunks[i], sources, i, m.ChunkSize)
				mu.Lock()
				for name, c := range fails {
					st.Failures[name] += c
				}
				if err == nil {
					st.Fetched[src] += n
				}
				mu.Unlock()
				if err != nil {
					select {
					case errc <- err:
					default:
					}
					cancel()
				}
			}
		})
	}
send:
	for _, i := range missing {
		select {
		case work <- i:
		case <-ctx.Done():
			break send
		}
	}
	close(work)
	wg.Wait()
	select {
	case err := <-errc:
		return st, err
	default:
	}
	if err := ctx.Err(); err != nil {
		return st, err
	}
	if dest == "" {
		return st, nil
	}
	return st, f.assemble(m, dest)
}

// fetchChunk tries sources nearest first. Within a tier the starting
// source rotates with the chunk index, spreading load across peers.
func (f Fetcher) fetchChunk(ctx context.Context, d string, sources []Source, i, chunkSize int) (string, int64, map[string]int, error) {
	client := f.Client
	if client == nil {
		client = http.DefaultClient
	}
	fails := map[string]int{}
	var order []Source
	for start := 0; start < len(sources); {
		end := start
		for end < len(sources) && sources[end].Tier == sources[start].Tier {
			end++
		}
		tier := sources[start:end]
		for k := range tier {
			order = append(order, tier[(i+k)%len(tier)])
		}
		start = end
	}
	limit := int64(chunkSize)
	if limit <= 0 {
		limit = DefaultChunkSize
	}
	attempts := max(f.Attempts, 1)
	if f.Attempts == 0 {
		attempts = 3
	}
	backoff := f.Backoff
	if backoff <= 0 {
		backoff = time.Second
	}
	var lastErr error
	for round := range attempts {
		if round > 0 {
			select {
			case <-ctx.Done():
				return "", 0, fails, ctx.Err()
			case <-time.After(backoff << (round - 1)):
			}
		}
		for _, s := range order {
			data, err := get(ctx, client, s.URL+"/chunks/"+d, limit)
			if err == nil {
				err = f.Store.Put(d, data)
			}
			if err == nil {
				return s.Name, int64(len(data)), fails, nil
			}
			if ctx.Err() != nil {
				return "", 0, fails, ctx.Err()
			}
			fails[s.Name]++
			lastErr = fmt.Errorf("%s: %w", s.Name, err)
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no sources")
	}
	return "", 0, fails, fmt.Errorf("chunk %s unavailable after %d attempts: %w", d, attempts, lastErr)
}

// get downloads one chunk, refusing bodies larger than limit so a broken or
// hostile peer cannot exhaust memory.
func get(ctx context.Context, c *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(resp.Body, limit+1))
	if n > limit {
		return nil, fmt.Errorf("chunk larger than %d bytes", limit)
	}
	return buf.Bytes(), err
}

func (f Fetcher) assemble(m Manifest, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	out, err := os.CreateTemp(filepath.Dir(dest), "."+filepath.Base(dest)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(out.Name())
	h := sha256.New()
	w := io.MultiWriter(out, h)
	for _, d := range m.Chunks {
		c, err := f.Store.Open(d)
		if err != nil {
			out.Close()
			return err
		}
		_, err = io.Copy(w, c)
		c.Close()
		if err != nil {
			out.Close()
			return err
		}
	}
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != m.Digest {
		out.Close()
		return fmt.Errorf("assembled %s is %s, manifest says %s", m.Name, got, m.Digest)
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(out.Name(), dest)
}

func fsModTime(f *os.File) (t time.Time) {
	if fi, err := f.Stat(); err == nil {
		t = fi.ModTime()
	}
	return t
}
