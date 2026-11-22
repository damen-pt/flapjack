package health

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/events"
	"github.com/damen-pt/flapjack/internal/store"
)

// Store is the part of cluster state admission needs.
type Store interface {
	Node(name string) (v1.Node, error)
	Class(name string) (v1.NodeClass, error)
	Update(name string, fn func(n *v1.Node) ([]events.Event, error)) (v1.Node, error)
}

// ErrStale is returned for a report no newer than the last one applied.
var ErrStale = errors.New("stale health report")

// EffectivePolicy is the policy admission enforces. A class without listed
// checks requires every check the report contains, so an empty policy
// never means "nothing to verify".
func EffectivePolicy(p v1.HealthPolicy, rep Report) v1.HealthPolicy {
	if len(p.Checks) > 0 {
		return p
	}
	p.Checks = make([]string, 0, len(rep.Results))
	for _, r := range rep.Results {
		p.Checks = append(p.Checks, r.Check)
	}
	return p
}

// Admit applies a report to the node it describes: the gate's verdict
// becomes the node's phase and failure count, and the outcome is recorded
// on the timeline (health.pass, health.warn or health.fail, plus node.phase
// when the phase changes). The verdict is computed under the store lock
// from the node's current status, so concurrent reports cannot interleave.
// Reports no newer than the last applied one are refused with ErrStale. A
// node in burn-in with an empty report is quarantined: nothing ran, so
// nothing was proven.
func Admit(st Store, rep Report, actor string) (Decision, error) {
	if rep.Node == "" || rep.Time.IsZero() {
		return Decision{}, errors.New("report needs a node and a time")
	}
	n, err := st.Node(rep.Node)
	if err != nil {
		return Decision{}, err
	}
	class, err := st.Class(n.Class)
	if err != nil {
		return Decision{}, fmt.Errorf("node %s: %w", rep.Node, err)
	}
	policy := EffectivePolicy(class.Health, rep)
	var d Decision
	_, err = st.Update(rep.Node, func(n *v1.Node) ([]events.Event, error) {
		if !rep.Time.After(n.Status.LastHealth) {
			return nil, fmt.Errorf("%w: %s is not after %s", ErrStale, rep.Time, n.Status.LastHealth)
		}
		from := n.Status.Phase
		if len(rep.Results) == 0 && (from == v1.PhaseBurnIn || from == v1.PhaseProvisioning) {
			d = Decision{Phase: v1.PhaseQuarantined, Reason: "burn-in report contained no checks"}
		} else {
			d = Gate(n.Status, policy, rep)
		}
		n.Status.Phase, n.Status.Failures = d.Phase, d.Failures
		n.Status.LastHealth, n.Status.Health = rep.Time, rep.Status.String()
		if d.Phase != from || d.Reason != "" {
			n.Status.Reason = d.Reason
		}
		evs := []events.Event{reportEvent(rep, actor)}
		if d.Phase != from {
			pe := store.PhaseEvent(from, d.Phase, d.Reason, actor)
			pe.Time = rep.Time // keep the verdict next to its report on the timeline
			evs = append(evs, pe)
		}
		return evs, nil
	})
	return d, err
}

func reportEvent(rep Report, actor string) events.Event {
	var failed, warned []string
	for _, r := range rep.Results {
		switch r.Status {
		case Fail:
			failed = append(failed, r.Check)
		case Warn:
			warned = append(warned, r.Check)
		}
	}
	slices.Sort(failed)
	slices.Sort(warned)
	e := events.Event{Time: rep.Time, Category: events.Health, Type: "health." + rep.Status.String(), Actor: actor, Data: map[string]string{}}
	if len(failed) > 0 {
		e.Data["failed"] = strings.Join(failed, ",")
		e.Message = "failed: " + e.Data["failed"]
	}
	if len(warned) > 0 {
		e.Data["warned"] = strings.Join(warned, ",")
	}
	return e
}
