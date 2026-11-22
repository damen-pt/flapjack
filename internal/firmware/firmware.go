// Package firmware compares a node's firmware and BIOS settings against
// its generation and plans and applies the updates to converge them.
package firmware

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/bmc"
	"github.com/damen-pt/flapjack/internal/events"
)

// DriftKind says what drifted.
type DriftKind string

const (
	DriftComponent DriftKind = "component" // firmware version
	DriftBIOS      DriftKind = "bios"      // BIOS attribute
)

// Drift is one difference between spec and inventory.
type Drift struct {
	Kind DriftKind `json:"kind"`
	Name string    `json:"name"` // inventory component name or BIOS attribute
	Spec string    `json:"spec"` // spec key that matched (may be a glob)
	Want string    `json:"want"`
	Have string    `json:"have"` // "" if absent
}

// Diff compares spec with inv. A component key is an exact inventory name
// or a path.Match glob ("GPU* VBIOS") that must match at least one
// component, all of which must be at the wanted version.
func Diff(spec v1.FirmwareSpec, inv bmc.Inventory) []Drift {
	var out []Drift
	for _, key := range slices.Sorted(maps.Keys(spec.Components)) {
		want := spec.Components[key]
		var matched []string
		for name := range inv.Firmware {
			if ok, _ := path.Match(key, name); ok {
				matched = append(matched, name)
			}
		}
		if len(matched) == 0 {
			out = append(out, Drift{Kind: DriftComponent, Name: key, Spec: key, Want: want})
			continue
		}
		slices.Sort(matched)
		for _, name := range matched {
			if have := inv.Firmware[name]; have != want {
				out = append(out, Drift{Kind: DriftComponent, Name: name, Spec: key, Want: want, Have: have})
			}
		}
	}
	for _, key := range slices.Sorted(maps.Keys(spec.BIOS)) {
		if have := inv.BIOS[key]; have != spec.BIOS[key] {
			out = append(out, Drift{Kind: DriftBIOS, Name: key, Spec: key, Want: spec.BIOS[key], Have: have})
		}
	}
	return out
}

// StepKind is one kind of remediation.
type StepKind string

const (
	StepFlash     StepKind = "flash"
	StepConfigure StepKind = "configure"
	StepReboot    StepKind = "reboot"
)

// Step is one action in an update plan.
type Step struct {
	Kind     StepKind          `json:"kind"`
	ImageURI string            `json:"imageURI,omitempty"`
	Targets  []string          `json:"targets,omitempty"`
	BIOS     map[string]string `json:"bios,omitempty"`
	Why      string            `json:"why"`
}

// Plan orders remediation: BMC first (a new BMC is often needed to flash
// the rest), then BIOS, then every other device, then a reboot to activate,
// and only then BIOS settings, because a BIOS flash can reset them; a final
// reboot applies the settings. Drift for a component with no image in the
// spec is returned as unfixable.
func Plan(spec v1.FirmwareSpec, drift []Drift) (steps []Step, unfixable []Drift) {
	byImage := map[string][]Drift{}
	for _, d := range drift {
		if d.Kind != DriftComponent {
			continue
		}
		img, ok := spec.Images[d.Spec]
		if !ok || d.Have == "" {
			unfixable = append(unfixable, d)
			continue
		}
		byImage[img] = append(byImage[img], d)
	}
	rank := func(ds []Drift) int {
		n := strings.ToUpper(ds[0].Name)
		switch {
		case strings.Contains(n, "BMC"):
			return 0
		case strings.Contains(n, "BIOS") && !strings.Contains(n, "VBIOS"):
			return 1
		}
		return 2
	}
	images := slices.Collect(maps.Keys(byImage))
	slices.SortFunc(images, func(a, b string) int {
		return cmp.Or(cmp.Compare(rank(byImage[a]), rank(byImage[b])), cmp.Compare(a, b))
	})
	for _, img := range images {
		ds := byImage[img]
		s := Step{Kind: StepFlash, ImageURI: img}
		var why []string
		for _, d := range ds {
			s.Targets = append(s.Targets, d.Name)
			why = append(why, fmt.Sprintf("%s %s→%s", d.Name, d.Have, d.Want))
		}
		s.Why = strings.Join(why, ", ")
		steps = append(steps, s)
	}
	if len(steps) > 0 {
		steps = append(steps, Step{Kind: StepReboot, Why: "activate firmware"})
	}

	bios := map[string]string{}
	var why []string
	for _, d := range drift {
		if d.Kind == DriftBIOS {
			bios[d.Name] = d.Want
			why = append(why, fmt.Sprintf("%s %q→%q", d.Name, d.Have, d.Want))
		}
	}
	if len(bios) > 0 {
		steps = append(steps,
			Step{Kind: StepConfigure, BIOS: bios, Why: strings.Join(why, ", ")},
			Step{Kind: StepReboot, Why: "apply BIOS settings"})
	}
	return steps, unfixable
}

// Resolver maps inventory names to the driver's firmware handles
// (Inventory.FirmwareIDs), falling back to the name itself.
func Resolver(inv bmc.Inventory) func(string) string {
	return func(name string) string {
		if id, ok := inv.FirmwareIDs[name]; ok {
			return id
		}
		return name
	}
}

// Apply executes a plan through the node's BMC. Firmware targets are passed
// as inventory names; Redfish drivers accept the @odata.id of the
// FirmwareInventory member, so resolve maps names to whatever the driver
// needs (identity if nil; see Resolver). Callers must drain the node
// first. Apply does not wait for the node after a reboot; Converger does.
func Apply(ctx context.Context, d bmc.Driver, steps []Step, resolve func(string) string) error {
	for i, s := range steps {
		if err := applyStep(ctx, d, s, resolve); err != nil {
			return fmt.Errorf("step %d (%s %s): %w", i, s.Kind, s.Why, err)
		}
	}
	return nil
}

func applyStep(ctx context.Context, d bmc.Driver, s Step, resolve func(string) string) error {
	if resolve == nil {
		resolve = func(s string) string { return s }
	}
	switch s.Kind {
	case StepFlash:
		u, ok := d.(bmc.FirmwareUpdater)
		if !ok {
			return fmt.Errorf("firmware update: %w", bmc.ErrUnsupported)
		}
		targets := make([]string, len(s.Targets))
		for j, t := range s.Targets {
			targets[j] = resolve(t)
		}
		return u.UpdateFirmware(ctx, s.ImageURI, targets)
	case StepConfigure:
		c, ok := d.(bmc.BIOSConfigurer)
		if !ok {
			return fmt.Errorf("BIOS settings: %w", bmc.ErrUnsupported)
		}
		return c.SetBIOS(ctx, s.BIOS)
	case StepReboot:
		return d.SetPower(ctx, bmc.PowerCycle)
	}
	return errors.New("unknown step kind " + string(s.Kind))
}

// Converger brings one node's firmware and BIOS to its spec and proves it:
// it plans from live inventory, applies each step, waits for the BMC and
// host to come back after every reboot, then re-reads the inventory until
// nothing fixable is left. Each change that verifiably took effect is
// recorded as a change event (firmware.flashed, bios.configured), which is
// what event correlation later ranks when nodes start failing.
type Converger struct {
	Node   string
	Driver bmc.Driver
	Spec   v1.FirmwareSpec
	// Record receives change events; nil drops them.
	Record func(events.Event)
	Actor  string
	// Settle is how long to wait after a reboot before polling (POST and
	// BMC restart); Poll is the polling interval; ReadyTimeout bounds each
	// wait. Defaults: 2m, 15s, 30m.
	Settle, Poll, ReadyTimeout time.Duration
}

// Result is what a convergence did.
type Result struct {
	Before    []Drift `json:"before"`
	Steps     []Step  `json:"steps"`
	Unfixable []Drift `json:"unfixable,omitempty"`
	// Remaining is fixable drift still present after the plan ran.
	Remaining []Drift `json:"remaining,omitempty"`
}

// ErrNotConverged is returned when drift remains after applying the plan.
var ErrNotConverged = errors.New("firmware did not converge")

func (c Converger) dur(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// Run converges the node. The caller must have drained it. Unfixable drift
// (no image in the spec) is returned but does not fail the run.
func (c Converger) Run(ctx context.Context) (Result, error) {
	var res Result
	inv, err := c.Driver.Inventory(ctx)
	if err != nil {
		return res, fmt.Errorf("inventory: %w", err)
	}
	res.Before = Diff(c.Spec, inv)
	res.Steps, res.Unfixable = Plan(c.Spec, res.Before)
	resolve := Resolver(inv)
	for i, s := range res.Steps {
		err := applyStep(ctx, c.Driver, s, resolve)
		if errors.Is(err, bmc.ErrTaskGone) {
			// The BMC dropped the task, typically because it reset to
			// activate its own image. Wait until it answers again; the
			// final inventory check decides whether the flash took.
			err = c.waitReady(ctx, false)
		}
		if err == nil && s.Kind == StepReboot {
			err = c.waitReady(ctx, true)
		}
		if err != nil {
			return res, fmt.Errorf("%s step %d (%s %s): %w", c.Node, i, s.Kind, s.Why, err)
		}
	}
	after, err := c.verify(ctx, res.Unfixable)
	c.record(res.Before, slices.Concat(after, res.Unfixable))
	res.Remaining = after
	if err != nil {
		return res, err
	}
	if len(after) > 0 {
		return res, fmt.Errorf("%s: %w: %d items still differ", c.Node, ErrNotConverged, len(after))
	}
	return res, nil
}

// waitReady polls until the BMC answers inventory (and, if poweredOn, the
// host reports power on), after an initial settle delay.
func (c Converger) waitReady(ctx context.Context, poweredOn bool) error {
	ctx, cancel := context.WithTimeout(ctx, c.dur(c.ReadyTimeout, 30*time.Minute))
	defer cancel()
	wait := c.dur(c.Settle, 2*time.Minute)
	var last error
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for BMC: %w (last error: %v)", ctx.Err(), last)
		case <-time.After(wait):
		}
		wait = c.dur(c.Poll, 15*time.Second)
		if _, err := c.Driver.Inventory(ctx); err != nil {
			last = err
			continue
		}
		if !poweredOn {
			return nil
		}
		st, err := c.Driver.PowerState(ctx)
		if err == nil && st == bmc.PowerStatusOn {
			return nil
		}
		last = fmt.Errorf("power %q: %v", st, err)
	}
}

// verify re-reads inventory until only unfixable drift remains or
// ReadyTimeout passes; BMCs often publish new versions and BIOS values a
// while after the host is back.
func (c Converger) verify(ctx context.Context, unfixable []Drift) ([]Drift, error) {
	ctx, cancel := context.WithTimeout(ctx, c.dur(c.ReadyTimeout, 30*time.Minute))
	defer cancel()
	var remaining []Drift
	for {
		inv, err := c.Driver.Inventory(ctx)
		if err == nil {
			remaining = remaining[:0]
			for _, d := range Diff(c.Spec, inv) {
				if !slices.ContainsFunc(unfixable, func(u Drift) bool { return u.Kind == d.Kind && u.Name == d.Name }) {
					remaining = append(remaining, d)
				}
			}
			if len(remaining) == 0 {
				return nil, nil
			}
		}
		select {
		case <-ctx.Done():
			if err != nil {
				return remaining, fmt.Errorf("verifying %s: %w", c.Node, err)
			}
			return remaining, nil
		case <-time.After(c.dur(c.Poll, 15*time.Second)):
		}
	}
}

// record emits a change event for every drift item not still in unfixed.
func (c Converger) record(before, unfixed []Drift) {
	if c.Record == nil {
		return
	}
	for _, d := range before {
		if slices.ContainsFunc(unfixed, func(a Drift) bool { return a.Kind == d.Kind && a.Name == d.Name }) {
			continue
		}
		e := events.Event{Node: c.Node, Category: events.Change, Actor: c.Actor, Data: map[string]string{"from": d.Have, "to": d.Want}}
		switch d.Kind {
		case DriftComponent:
			e.Type, e.Message = "firmware.flashed", fmt.Sprintf("%s %s → %s", d.Name, d.Have, d.Want)
			e.Data["component"] = d.Name
		case DriftBIOS:
			e.Type, e.Message = "bios.configured", fmt.Sprintf("%s %q → %q", d.Name, d.Have, d.Want)
			e.Data["attribute"] = d.Name
		}
		c.Record(e)
	}
}
