package staging

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// stamp records that dest held a verified copy of an artifact, so later
// jobs can skip re-hashing hundreds of gigabytes of weights.
type stamp struct {
	Digest  string    `json:"digest"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"modTime"`
}

func stampPath(dest string) string {
	return filepath.Join(filepath.Dir(dest), "."+filepath.Base(dest)+".flapjack")
}

// Fresh reports whether dest still holds the verified artifact m: the
// stamp written after the last successful fetch matches m's digest and
// dest's size and modification time are unchanged since. It is a fast
// check, not a re-hash; Fetch verifies every byte.
func Fresh(m Manifest, dest string) bool {
	b, err := os.ReadFile(stampPath(dest))
	if err != nil {
		return false
	}
	var st stamp
	if json.Unmarshal(b, &st) != nil {
		return false
	}
	fi, err := os.Stat(dest)
	return err == nil && st.Digest == m.Digest && st.Size == fi.Size() && fi.Size() == m.Size && st.ModTime.Equal(fi.ModTime())
}

// Ensure makes dest hold artifact m, fetching only if it is not already
// Fresh. It is meant for a Slurm prolog: concurrent jobs on one node that
// need the same artifact serialise on a lock file next to dest, so it is
// downloaded once and the second job finds it fresh. It reports whether a
// fetch happened.
func Ensure(ctx context.Context, f Fetcher, m Manifest, dest string) (fetched bool, st Stats, err error) {
	if Fresh(m, dest) {
		return false, st, nil
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return false, st, err
	}
	unlock, err := lockFile(ctx, filepath.Join(filepath.Dir(dest), "."+filepath.Base(dest)+".lock"))
	if err != nil {
		return false, st, err
	}
	defer unlock()
	if Fresh(m, dest) { // another job fetched it while we waited
		return false, st, nil
	}
	os.Remove(stampPath(dest))
	if st, err = f.Fetch(ctx, m, dest); err != nil {
		return true, st, err
	}
	fi, err := os.Stat(dest)
	if err != nil {
		return true, st, err
	}
	b, _ := json.Marshal(stamp{Digest: m.Digest, Size: fi.Size(), ModTime: fi.ModTime()})
	return true, st, os.WriteFile(stampPath(dest), b, 0o644)
}

// lockFile takes an exclusive flock, polling so the wait honours ctx.
func lockFile(ctx context.Context, path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
		}
		if err != syscall.EWOULDBLOCK {
			f.Close()
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}
