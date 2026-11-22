// Package health runs node admission and periodic checks, decides whether a
// node may be schedulable, finds stragglers across the fleet and packages
// evidence for vendor RMA tickets.
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
)

// Status is a check outcome. Higher is worse.
type Status int

const (
	Pass Status = iota
	Warn
	Fail
)

var statusNames = []string{"pass", "warn", "fail"}

func (s Status) String() string { return statusNames[s] }

func (s Status) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Status) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return err
	}
	i := slices.Index(statusNames, name)
	if i < 0 {
		return fmt.Errorf("unknown status %q", name)
	}
	*s = Status(i)
	return nil
}

// Result is the outcome of one check.
type Result struct {
	Check    string             `json:"check"`
	Status   Status             `json:"status"`
	Message  string             `json:"message,omitempty"`
	Metrics  map[string]float64 `json:"metrics,omitempty"`
	Duration time.Duration      `json:"duration"`
	// Evidence holds raw collector output (tool output, sysfs dumps) for the
	// RMA bundle. It is not part of the JSON report.
	Evidence map[string][]byte `json:"-"`
}

// Check is one health check.
type Check interface {
	Name() string
	Run(ctx context.Context) Result
}

// Report is the outcome of a full check run on one node.
type Report struct {
	Node    string    `json:"node"`
	Time    time.Time `json:"time"`
	Status  Status    `json:"status"`
	Results []Result  `json:"results"`
}

// Result returns the named check's result, if it ran.
func (r Report) Result(check string) (Result, bool) {
	i := slices.IndexFunc(r.Results, func(x Result) bool { return x.Check == check })
	if i < 0 {
		return Result{}, false
	}
	return r.Results[i], true
}

// Runner runs checks concurrently, each under its own timeout. A check that
// overruns is reported as failed rather than stalling admission.
type Runner struct {
	Checks  []Check
	Timeout time.Duration
	Now     func() time.Time
}

func (r Runner) Run(ctx context.Context, node string) Report {
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	rep := Report{Node: node, Time: now(), Results: make([]Result, len(r.Checks))}
	done := make(chan struct{}, len(r.Checks))
	for i, c := range r.Checks {
		go func() {
			defer func() { done <- struct{}{} }()
			rep.Results[i] = runOne(ctx, c, timeout)
		}()
	}
	for range r.Checks {
		<-done
	}
	for _, res := range rep.Results {
		rep.Status = max(rep.Status, res.Status)
	}
	return rep
}

func runOne(ctx context.Context, c Check, timeout time.Duration) (res Result) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	out := make(chan Result, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				out <- Result{Status: Fail, Message: fmt.Sprintf("check panicked: %v", p)}
			}
		}()
		out <- c.Run(ctx)
	}()
	select {
	case res = <-out:
	case <-ctx.Done():
		res = Result{Status: Fail, Message: "timed out after " + timeout.String()}
	}
	res.Check = c.Name()
	res.Duration = time.Since(start)
	return res
}

// Decision is the gate's verdict for one report.
type Decision struct {
	Phase    v1.Phase `json:"phase"`
	Failures int      `json:"failures"` // updated consecutive failure count
	Reason   string   `json:"reason,omitempty"`
}

// Gate decides a node's phase from a report. A node in BurnIn becomes Ready
// only if every required check passes (warnings allowed). A Ready
// node is quarantined on the first failure of a critical check, or after
// policy.ConsecutiveFailures failing runs. Quarantined nodes stay put until
// an admin releases them.
func Gate(status v1.NodeStatus, policy v1.HealthPolicy, rep Report) Decision {
	var failed, critical []string
	for _, name := range policy.Checks {
		res, ok := rep.Result(name)
		if !ok || res.Status == Fail {
			failed = append(failed, name)
			if slices.Contains(policy.Critical, name) {
				critical = append(critical, name)
			}
		}
	}
	reason := func(names []string) string {
		msgs := make([]string, 0, len(names))
		for _, n := range names {
			res, ok := rep.Result(n)
			if !ok {
				msgs = append(msgs, n+": did not run")
				continue
			}
			msgs = append(msgs, n+": "+res.Message)
		}
		return fmt.Sprint(msgs)
	}

	switch status.Phase {
	case v1.PhaseQuarantined, v1.PhaseRetired, v1.PhaseDiscovered:
		return Decision{Phase: status.Phase, Failures: status.Failures, Reason: status.Reason}
	case v1.PhaseBurnIn, v1.PhaseProvisioning:
		if len(failed) > 0 {
			return Decision{Phase: v1.PhaseQuarantined, Failures: 0, Reason: "burn-in failed " + reason(failed)}
		}
		return Decision{Phase: v1.PhaseReady}
	}

	if len(failed) == 0 {
		return Decision{Phase: status.Phase}
	}
	if len(critical) > 0 {
		return Decision{Phase: v1.PhaseQuarantined, Reason: "critical check failed " + reason(critical)}
	}
	n := status.Failures + 1
	limit := max(policy.ConsecutiveFailures, 1)
	if n >= limit {
		return Decision{Phase: v1.PhaseQuarantined, Reason: fmt.Sprintf("%d consecutive failures %s", n, reason(failed))}
	}
	return Decision{Phase: status.Phase, Failures: n, Reason: reason(failed)}
}
