package bmc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/damen-pt/flapjack/internal/sys"
)

// redfishSim is a minimal Redfish service: enough of the schema to drive
// Redfish end to end, recording every mutating request.
type redfishSim struct {
	mu       sync.Mutex
	requests []string
	bodies   map[string]map[string]any
	attrs    map[string]any
}

func (s *redfishSim) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if u, p, _ := r.BasicAuth(); u != "admin" || p != "secret" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method != http.MethodGet {
		var body map[string]any
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &body)
		s.requests = append(s.requests, r.Method+" "+r.URL.Path)
		s.bodies[r.Method+" "+r.URL.Path] = body
		w.WriteHeader(http.StatusNoContent)
		return
	}
	resp := map[string]any{
		"/redfish/v1/Systems": map[string]any{"Members": []any{map[string]string{"@odata.id": "/redfish/v1/Systems/1"}}},
		"/redfish/v1/Chassis": map[string]any{"Members": []any{map[string]string{"@odata.id": "/redfish/v1/Chassis/1"}}},
		"/redfish/v1/Systems/1": map[string]any{
			"Manufacturer": "Acme", "Model": "G8", "SerialNumber": "SN123", "BiosVersion": "2.1.0",
			"PowerState": "On", "Bios": map[string]string{"@odata.id": "/redfish/v1/Systems/1/Bios"},
		},
		"/redfish/v1/Systems/1/Bios": map[string]any{
			"Attributes":        s.attrs,
			"@Redfish.Settings": map[string]any{"SettingsObject": map[string]string{"@odata.id": "/redfish/v1/Systems/1/Bios/SD"}},
		},
		"/redfish/v1/UpdateService/FirmwareInventory": map[string]any{"Members": []any{
			map[string]string{"@odata.id": "/redfish/v1/UpdateService/FirmwareInventory/BMC"},
			map[string]string{"@odata.id": "/redfish/v1/UpdateService/FirmwareInventory/NIC1"},
		}},
		"/redfish/v1/Chassis/1":                            map[string]any{"Power": map[string]string{"@odata.id": "/redfish/v1/Chassis/1/Power"}},
		"/redfish/v1/Chassis/1/Power":                      map[string]any{"PowerControl": []any{map[string]any{"PowerConsumedWatts": 812.5}}},
		"/redfish/v1/UpdateService/FirmwareInventory/BMC":  map[string]string{"Id": "BMC", "Name": "BMC", "Version": "1.40"},
		"/redfish/v1/UpdateService/FirmwareInventory/NIC1": map[string]string{"Id": "NIC1", "Name": "ConnectX-7 NIC1", "Version": "28.39.1002"},
	}[r.URL.Path]
	if resp == nil {
		http.NotFound(w, r)
		return
	}
	json.NewEncoder(w).Encode(resp)
}

func newSim(t *testing.T) (*redfishSim, *Redfish) {
	sim := &redfishSim{bodies: map[string]map[string]any{}, attrs: map[string]any{"SMTMode": "Enabled", "NumaPerSocket": 1.0, "SRIOV": true}}
	srv := httptest.NewTLSServer(sim)
	t.Cleanup(srv.Close)
	return sim, &Redfish{Endpoint: srv.URL, User: "admin", Password: "secret", HTTP: srv.Client()}
}

func TestRedfishInventory(t *testing.T) {
	_, r := newSim(t)
	inv, err := r.Inventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if inv.Serial != "SN123" || inv.Firmware["BIOS"] != "2.1.0" || inv.Firmware["ConnectX-7 NIC1"] != "28.39.1002" || inv.BIOS["NumaPerSocket"] != "1" {
		t.Fatalf("inventory = %+v", inv)
	}
	if st, _ := r.PowerState(context.Background()); st != "on" {
		t.Fatalf("power = %q", st)
	}
}

func TestRedfishActions(t *testing.T) {
	sim, r := newSim(t)
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(r.SetPower(ctx, PowerCycle))
	must(r.SetBootOnce(ctx, BootHTTP, true))
	must(r.SetBIOS(ctx, map[string]string{"SMTMode": "Disabled", "NumaPerSocket": "4", "SRIOV": "false"}))
	must(r.UpdateFirmware(ctx, "https://fw.local/nic.bin", []string{"/redfish/v1/UpdateService/FirmwareInventory/NIC1"}))
	must(r.SetPowerLimit(ctx, 9500))

	want := []string{
		"POST /redfish/v1/Systems/1/Actions/ComputerSystem.Reset",
		"PATCH /redfish/v1/Systems/1",
		"PATCH /redfish/v1/Systems/1/Bios/SD",
		"POST /redfish/v1/UpdateService/Actions/UpdateService.SimpleUpdate",
		"PATCH /redfish/v1/Chassis/1/Power",
	}
	if !slices.Equal(sim.requests, want) {
		t.Fatalf("requests = %v", sim.requests)
	}
	if sim.bodies[want[0]]["ResetType"] != "PowerCycle" {
		t.Error("reset type")
	}
	attrs := sim.bodies[want[2]]["Attributes"].(map[string]any)
	if attrs["NumaPerSocket"] != 4.0 || attrs["SRIOV"] != false || attrs["SMTMode"] != "Disabled" {
		t.Errorf("BIOS values must keep their JSON types: %v", attrs)
	}
	if err := r.SetBIOS(ctx, map[string]string{"NumaPerSocket": "four"}); err == nil {
		t.Error("non-numeric value for numeric attribute should fail")
	}
}

func TestRedfishAuthFailureIsRetried(t *testing.T) {
	_, r := newSim(t)
	r.Password = "wrong"
	if _, err := r.PowerState(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err = %v", err)
	}
	r.Password = "secret"
	if _, err := r.PowerState(context.Background()); err != nil {
		t.Fatalf("discovery failure must not be cached: %v", err)
	}
}

func TestIPMI(t *testing.T) {
	base := "ipmitool -I lanplus -H 10.0.0.5 -U admin -f /run/flapjack/bmc.pw "
	f := &sys.Fake{Responses: map[string]sys.FakeResponse{
		base + "chassis power status":                {Out: []byte("Chassis Power is off\n")},
		base + "chassis power cycle":                 {},
		base + "chassis bootdev pxe options=efiboot": {},
		base + "fru print 0":                         {Out: []byte(" Board Mfg             : Acme\n Board Serial          : BSN9\n Product Name          : G8\n Product Serial        : SN555\n")},
		base + "mc info":                             {Out: []byte("Device ID                 : 32\nFirmware Revision         : 3.45\n")},
	}}
	i := IPMI{Exec: f, Host: "10.0.0.5", User: "admin", PasswordFile: "/run/flapjack/bmc.pw"}
	ctx := context.Background()
	if st, err := i.PowerState(ctx); err != nil || st != PowerStatusOff {
		t.Fatalf("%q %v", st, err)
	}
	if err := i.SetPower(ctx, PowerCycle); err != nil {
		t.Fatal(err)
	}
	if err := i.SetBootOnce(ctx, BootPXE, true); err != nil {
		t.Fatal(err)
	}
	if err := i.SetBootOnce(ctx, BootHTTP, true); err == nil {
		t.Fatal("IPMI cannot select UEFI HTTP boot")
	}
	inv, err := i.Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Serial != "SN555" || inv.Manufacturer != "Acme" || inv.Firmware["BMC"] != "3.45" {
		t.Fatalf("inventory = %+v", inv)
	}
	var _ Driver = i
	if _, ok := any(i).(BIOSConfigurer); ok {
		t.Fatal("IPMI must not claim BIOS configuration")
	}
}

func TestFakeAppliesStagedChangesOnBoot(t *testing.T) {
	f := &Fake{Power: PowerStatusOn, FirmwareVersions: map[string]string{"nic.bin": "28.40"}}
	ctx := context.Background()
	f.SetBIOS(ctx, map[string]string{"SMTMode": "Disabled"})
	f.UpdateFirmware(ctx, "nic.bin", []string{"NIC1"})
	if inv, _ := f.Inventory(ctx); inv.BIOS["SMTMode"] != "" {
		t.Fatal("staged change applied before reboot")
	}
	f.SetPower(ctx, PowerOn) // already on: not a boot
	if inv, _ := f.Inventory(ctx); inv.BIOS["SMTMode"] != "" {
		t.Fatal("power on while on must not apply staged changes")
	}
	f.SetPower(ctx, PowerCycle)
	if inv, _ := f.Inventory(ctx); inv.BIOS["SMTMode"] != "Disabled" || inv.Firmware["NIC1"] != "28.40" {
		t.Fatalf("after cycle: %+v", inv)
	}
}

func TestIPMIPowerDCMI(t *testing.T) {
	base := "ipmitool -I lanplus -H h -U u -f p "
	f := &sys.Fake{Responses: map[string]sys.FakeResponse{
		base + "dcmi power reading":             {Out: []byte("\n    Instantaneous power reading:                   245 Watts\n    Minimum during sampling period:                 80 Watts\n")},
		base + "dcmi power set_limit limit 900": {},
		base + "dcmi power activate":            {},
	}}
	i := IPMI{Exec: f, Host: "h", User: "u", PasswordFile: "p"}
	if w, err := i.PowerReading(context.Background()); err != nil || w != 245 {
		t.Fatalf("%v %v", w, err)
	}
	if err := i.SetPowerLimit(context.Background(), 900); err != nil {
		t.Fatal(err)
	}
}
