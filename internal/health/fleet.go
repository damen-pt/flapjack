package health

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"io"
	"maps"
	"math"
	"slices"
	"time"
)

// Straggler is a node whose benchmark result is far worse than its peers.
type Straggler struct {
	Node   string  `json:"node"`
	Value  float64 `json:"value"`
	Median float64 `json:"median"`
	// Deficit is how much worse than the median the node is, as a fraction
	// (0.14 means 14% slower).
	Deficit float64 `json:"deficit"`
}

// Stragglers compares one metric across nodes that should perform
// identically (same class, same benchmark) and returns those worse than the
// fleet median by more than tolerance. It uses the median, not the mean, so
// a few broken nodes cannot drag the baseline down and hide themselves.
// At least three samples are needed to say anything.
func Stragglers(samples map[string]float64, higherIsBetter bool, tolerance float64) []Straggler {
	if len(samples) < 3 {
		return nil
	}
	med := median(slices.Collect(maps.Values(samples)))
	if med == 0 {
		return nil
	}
	var out []Straggler
	for _, node := range slices.Sorted(maps.Keys(samples)) {
		v := samples[node]
		d := (med - v) / math.Abs(med)
		if !higherIsBetter {
			d = -d
		}
		if d > tolerance {
			out = append(out, Straggler{Node: node, Value: v, Median: med, Deficit: d})
		}
	}
	slices.SortStableFunc(out, func(a, b Straggler) int {
		switch {
		case a.Deficit > b.Deficit:
			return -1
		case a.Deficit < b.Deficit:
			return 1
		}
		return 0
	})
	return out
}

// Regressed reports whether current is worse than the node's own history
// (median of past results) by more than tolerance. It catches slow decay
// that fleet comparison misses when many nodes degrade together.
func Regressed(history []float64, current float64, higherIsBetter bool, tolerance float64) bool {
	if len(history) == 0 {
		return false
	}
	base := median(history)
	if base == 0 {
		return false
	}
	d := (base - current) / math.Abs(base)
	if !higherIsBetter {
		d = -d
	}
	return d > tolerance
}

func median(v []float64) float64 {
	s := slices.Clone(v)
	slices.Sort(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// WriteEvidence writes an RMA evidence bundle (gzip-compressed tar) holding
// the report as JSON, every check's raw evidence under checks/<check>/, and
// any extra files (BMC event log, nvidia-bug-report, serial numbers).
func WriteEvidence(w io.Writer, rep Report, extra map[string][]byte) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	mtime := rep.Time
	if mtime.IsZero() {
		mtime = time.Unix(0, 0)
	}
	add := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), ModTime: mtime, Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err := add(rep.Node+"/report.json", b); err != nil {
		return err
	}
	for _, res := range rep.Results {
		for _, name := range slices.Sorted(maps.Keys(res.Evidence)) {
			if err := add(rep.Node+"/checks/"+res.Check+"/"+name, res.Evidence[name]); err != nil {
				return err
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(extra)) {
		if err := add(rep.Node+"/"+name, extra[name]); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}
