package bmc_test

import (
	"context"
	"net/http/httptest"
	"testing"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	. "github.com/damen-pt/flapjack/internal/bmc"
	"github.com/damen-pt/flapjack/internal/firmware"
)

// TestRedfishRoundTrip drives a Fake through RedfishServer with the real
// Redfish client, so client and server must agree on every endpoint.
func TestRedfishRoundTrip(t *testing.T) {
	fake := &Fake{
		Power: PowerStatusOff,
		Inv: Inventory{Manufacturer: "Flapjack", Model: "Lab VM", Serial: "LAB-0001",
			Firmware: map[string]string{"BIOS": "1.0", "ConnectX-7 NIC1": "28.39"},
			BIOS:     map[string]string{"SMTMode": "Enabled"}},
		FirmwareVersions: map[string]string{"https://fw/cx7.bin": "28.40"},
	}
	srv := httptest.NewServer(&RedfishServer{Driver: fake, User: "admin", Password: "pw"})
	defer srv.Close()
	c := &Redfish{Endpoint: srv.URL, User: "admin", Password: "pw"}
	ctx := context.Background()

	inv, err := c.Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Serial != "LAB-0001" || inv.Firmware["ConnectX-7 NIC1"] != "28.39" || inv.BIOS["SMTMode"] != "Enabled" {
		t.Fatalf("inventory = %+v", inv)
	}
	if err := c.SetBootOnce(ctx, BootPXE, true); err != nil || fake.BootOnce != BootPXE {
		t.Fatalf("boot once: %v %v", err, fake.BootOnce)
	}
	if err := c.SetPower(ctx, PowerOn); err != nil {
		t.Fatal(err)
	}
	if st, _ := c.PowerState(ctx); st != PowerStatusOn {
		t.Fatalf("power = %s", st)
	}

	// Firmware drift fixed end to end through the Redfish wire protocol.
	spec := v1.FirmwareSpec{
		Components: map[string]string{"ConnectX-7*": "28.40"},
		Images:     map[string]string{"ConnectX-7*": "https://fw/cx7.bin"},
		BIOS:       map[string]string{"SMTMode": "Disabled"},
	}
	steps, _ := firmware.Plan(spec, firmware.Diff(spec, inv))
	if err := firmware.Apply(ctx, c, steps, RedfishFirmwarePath); err != nil {
		t.Fatal(err)
	}
	after, _ := c.Inventory(ctx)
	if d := firmware.Diff(spec, after); len(d) != 0 {
		t.Fatalf("drift after apply over Redfish: %+v", d)
	}
	if err := c.SetPowerLimit(ctx, 700); err != nil || fake.PowerLimit != 700 {
		t.Fatalf("power limit: %v %d", err, fake.PowerLimit)
	}

	bad := &Redfish{Endpoint: srv.URL, User: "admin", Password: "nope"}
	if _, err := bad.PowerState(ctx); err == nil {
		t.Fatal("wrong password accepted")
	}
}

func TestRedfishServerPowerReading(t *testing.T) {
	fake := &Fake{Power: PowerStatusOn, Watts: 640}
	srv := httptest.NewServer(&RedfishServer{Driver: fake, User: "admin", Password: "secret"})
	t.Cleanup(srv.Close)
	c := &Redfish{Endpoint: srv.URL, User: "admin", Password: "secret"}
	if w, err := c.PowerReading(context.Background()); err != nil || w != 640 {
		t.Fatalf("reading = %v %v", w, err)
	}
}
