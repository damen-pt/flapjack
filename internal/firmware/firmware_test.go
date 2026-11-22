package firmware

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/bmc"
	"github.com/damen-pt/flapjack/internal/events"
	"github.com/damen-pt/flapjack/internal/sys"
)

var spec = v1.FirmwareSpec{
	Components: map[string]string{"BMC": "1.50", "BIOS": "2.2.0", "ConnectX-7*": "28.40.1000", "GPU* VBIOS": "96.00.AF"},
	Images: map[string]string{
		"BMC": "https://fw/bmc-1.50.bin", "BIOS": "https://fw/bios-2.2.0.bin", "ConnectX-7*": "https://fw/cx7-28.40.bin",
	},
	BIOS: map[string]string{"SMTMode": "Disabled", "NumaPerSocket": "4"},
}

func inventory() bmc.Inventory {
	return bmc.Inventory{
		Firmware: map[string]string{
			"BMC": "1.40", "BIOS": "2.2.0", "ConnectX-7 NIC1": "28.39.1002", "ConnectX-7 NIC2": "28.40.1000",
			"GPU0 VBIOS": "96.00.AF", "GPU1 VBIOS": "96.00.9F",
		},
		BIOS: map[string]string{"SMTMode": "Enabled", "NumaPerSocket": "4"},
	}
}

func TestDiff(t *testing.T) {
	got := Diff(spec, inventory())
	want := []Drift{
		{DriftComponent, "BMC", "BMC", "1.50", "1.40"},
		{DriftComponent, "ConnectX-7 NIC1", "ConnectX-7*", "28.40.1000", "28.39.1002"},
		{DriftComponent, "GPU1 VBIOS", "GPU* VBIOS", "96.00.AF", "96.00.9F"},
		{DriftBIOS, "SMTMode", "SMTMode", "Disabled", "Enabled"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("drift %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestPlanOrderAndUnfixable(t *testing.T) {
	steps, unfixable := Plan(spec, Diff(spec, inventory()))
	var order []string
	for _, s := range steps {
		order = append(order, string(s.Kind)+":"+s.ImageURI)
	}
	want := []string{"flash:https://fw/bmc-1.50.bin", "flash:https://fw/cx7-28.40.bin", "reboot:", "configure:", "reboot:"}
	if len(order) != len(want) {
		t.Fatalf("plan = %v", order)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("plan = %v", order)
		}
	}
	if len(unfixable) != 1 || unfixable[0].Name != "GPU1 VBIOS" {
		t.Fatalf("GPU VBIOS has no image so must be unfixable: %+v", unfixable)
	}
}

func TestApplyConverges(t *testing.T) {
	inv := inventory()
	f := &bmc.Fake{Inv: inv, Power: bmc.PowerStatusOn, FirmwareVersions: map[string]string{
		"https://fw/bmc-1.50.bin": "1.50", "https://fw/cx7-28.40.bin": "28.40.1000", "https://fw/bios-2.2.0.bin": "2.2.0",
	}}
	s := spec
	s.Components = map[string]string{"BMC": "1.50", "BIOS": "2.2.0", "ConnectX-7*": "28.40.1000"}
	steps, _ := Plan(s, Diff(s, inv))
	if err := Apply(context.Background(), f, steps, nil); err != nil {
		t.Fatal(err)
	}
	after, _ := f.Inventory(context.Background())
	if d := Diff(s, after); len(d) != 0 {
		t.Fatalf("still drifted after apply: %+v", d)
	}
}

func TestApplyOverIPMIReportsUnsupported(t *testing.T) {
	steps := []Step{{Kind: StepConfigure, BIOS: map[string]string{"x": "y"}}}
	err := Apply(context.Background(), bmc.IPMI{Exec: &sys.Fake{}}, steps, nil)
	if !errors.Is(err, bmc.ErrUnsupported) {
		t.Fatalf("err = %v", err)
	}
}

// rebooting wraps a Fake whose BMC is unreachable for a few polls after
// every power cycle, like a real BMC during POST.
type rebooting struct {
	*bmc.Fake
	down int
	left int
}

func (r *rebooting) SetPower(ctx context.Context, a bmc.PowerAction) error {
	r.left = r.down
	return r.Fake.SetPower(ctx, a)
}

func (r *rebooting) Inventory(ctx context.Context) (bmc.Inventory, error) {
	if r.left > 0 {
		r.left--
		return bmc.Inventory{}, errors.New("connection refused")
	}
	return r.Fake.Inventory(ctx)
}

func fast(c Converger) Converger {
	c.Settle, c.Poll, c.ReadyTimeout = time.Millisecond, time.Millisecond, time.Second
	return c
}

func TestConvergerWaitsAndRecords(t *testing.T) {
	s := spec
	s.Components = map[string]string{"BMC": "1.50", "ConnectX-7*": "28.40.1000", "GPU* VBIOS": "96.00.AF"}
	f := &rebooting{down: 3, Fake: &bmc.Fake{Inv: inventory(), Power: bmc.PowerStatusOn, FirmwareVersions: map[string]string{
		"https://fw/bmc-1.50.bin": "1.50", "https://fw/cx7-28.40.bin": "28.40.1000",
	}}}
	var recorded []events.Event
	res, err := fast(Converger{Node: "n1", Driver: f, Spec: s, Actor: "firmware", Record: func(e events.Event) { recorded = append(recorded, e) }}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Unfixable) != 1 || len(res.Remaining) != 0 {
		t.Fatalf("result = %+v", res)
	}
	var sigs []string
	for _, e := range recorded {
		sigs = append(sigs, e.Signature())
	}
	want := []string{
		"firmware.flashed component=BMC to=1.50",
		"firmware.flashed component=ConnectX-7 NIC1 to=28.40.1000",
		"bios.configured attribute=SMTMode to=Disabled",
	}
	if !slices.Equal(sigs, want) {
		t.Fatalf("recorded %v", sigs)
	}
}

// lying accepts firmware updates but never changes versions.
type lying struct{ *bmc.Fake }

func (lying) UpdateFirmware(context.Context, string, []string) error { return nil }

func TestConvergerDetectsUpdatesThatDidNotTake(t *testing.T) {
	s := v1.FirmwareSpec{Components: map[string]string{"BMC": "1.50"}, Images: map[string]string{"BMC": "https://fw/bmc-1.50.bin"}}
	f := lying{&bmc.Fake{Inv: inventory(), Power: bmc.PowerStatusOn}}
	var recorded int
	res, err := fast(Converger{Node: "n1", Driver: f, Spec: s, Record: func(events.Event) { recorded++ }}).Run(context.Background())
	if !errors.Is(err, ErrNotConverged) || len(res.Remaining) != 1 || recorded != 0 {
		t.Fatalf("err=%v res=%+v recorded=%d", err, res, recorded)
	}
}

func TestResolverUsesDriverIDs(t *testing.T) {
	r := Resolver(bmc.Inventory{FirmwareIDs: map[string]string{"BMC": "/redfish/v1/UpdateService/FirmwareInventory/BMC"}})
	if r("BMC") != "/redfish/v1/UpdateService/FirmwareInventory/BMC" || r("other") != "other" {
		t.Fatal("resolver")
	}
}
