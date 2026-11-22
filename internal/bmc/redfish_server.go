package bmc

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
)

// RedfishServer exposes any Driver over the subset of Redfish that the
// Redfish client uses, so lab VMs (or the in-memory Fake) can be driven
// exactly like real BMCs.
type RedfishServer struct {
	Driver   Driver
	User     string
	Password string
	UEFI     bool

	mu   sync.Mutex
	boot map[string]string
}

const (
	rfSystem  = "/redfish/v1/Systems/1"
	rfChassis = "/redfish/v1/Chassis/1"
	rfFW      = "/redfish/v1/UpdateService/FirmwareInventory"
)

var resetActions = map[string]PowerAction{
	"On": PowerOn, "ForceOn": PowerOn, "ForceOff": PowerOff, "GracefulShutdown": PowerSoft,
	"PowerCycle": PowerCycle, "ForceRestart": PowerReset, "GracefulRestart": PowerReset,
}

var bootDevices = map[string]BootDevice{"Pxe": BootPXE, "UefiHttp": BootHTTP, "Hdd": BootDisk, "BiosSetup": BootBIOSMenu}

// RedfishFirmwarePath returns the FirmwareInventory member path that
// RedfishServer uses for a component name. Pass it as the resolver to
// firmware.Apply when driving a RedfishServer.
func RedfishFirmwarePath(name string) string { return rfFW + "/" + fwID(name) }

func fwID(name string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, name)
}

func ref(p string) map[string]string { return map[string]string{"@odata.id": p} }

func (s *RedfishServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u, p, ok := r.BasicAuth()
	if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(s.User)) != 1 || subtle.ConstantTimeCompare([]byte(p), []byte(s.Password)) != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="flapjack-lab"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	out, err := s.handle(r)
	switch {
	case errors.Is(err, ErrUnsupported):
		http.Error(w, err.Error(), http.StatusNotImplemented)
	case errors.Is(err, errNotFound):
		http.NotFound(w, r)
	case err != nil:
		http.Error(w, err.Error(), http.StatusBadRequest)
	case out == nil:
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	}
}

var errNotFound = errors.New("not found")

func (s *RedfishServer) handle(r *http.Request) (any, error) {
	ctx := r.Context()
	var body map[string]any
	if r.Method != http.MethodGet {
		if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(&body); err != nil {
			return nil, fmt.Errorf("bad JSON: %w", err)
		}
	}
	route := r.Method + " " + strings.TrimSuffix(r.URL.Path, "/")
	switch route {
	case "GET /redfish/v1":
		return map[string]any{"RedfishVersion": "1.15.0", "Systems": ref("/redfish/v1/Systems"), "Chassis": ref("/redfish/v1/Chassis"), "UpdateService": ref("/redfish/v1/UpdateService")}, nil
	case "GET /redfish/v1/Systems":
		return map[string]any{"Members": []any{ref(rfSystem)}, "Members@odata.count": 1}, nil
	case "GET /redfish/v1/Chassis":
		return map[string]any{"Members": []any{ref(rfChassis)}, "Members@odata.count": 1}, nil
	case "GET " + rfSystem:
		inv, err := s.Driver.Inventory(ctx)
		if err != nil {
			return nil, err
		}
		st, err := s.Driver.PowerState(ctx)
		if err != nil {
			return nil, err
		}
		power := "Off"
		if st == PowerStatusOn {
			power = "On"
		}
		boot := map[string]any{"BootSourceOverrideEnabled": "Disabled", "BootSourceOverrideTarget": "None"}
		s.mu.Lock()
		for k, v := range s.boot {
			boot[k] = v
		}
		s.mu.Unlock()
		return map[string]any{
			"Id": "1", "Manufacturer": inv.Manufacturer, "Model": inv.Model, "SerialNumber": inv.Serial,
			"BiosVersion": inv.Firmware["BIOS"], "PowerState": power, "Bios": ref(rfSystem + "/Bios"), "Boot": boot,
			"Actions": map[string]any{"#ComputerSystem.Reset": map[string]any{"target": rfSystem + "/Actions/ComputerSystem.Reset",
				"ResetType@Redfish.AllowableValues": slices.Sorted(maps.Keys(resetActions))}},
		}, nil
	case "POST " + rfSystem + "/Actions/ComputerSystem.Reset":
		t, _ := body["ResetType"].(string)
		a, ok := resetActions[t]
		if !ok {
			return nil, fmt.Errorf("unsupported ResetType %q", t)
		}
		return nil, s.Driver.SetPower(ctx, a)
	case "PATCH " + rfSystem:
		b, _ := body["Boot"].(map[string]any)
		target, _ := b["BootSourceOverrideTarget"].(string)
		dev, ok := bootDevices[target]
		if !ok {
			return nil, fmt.Errorf("unsupported BootSourceOverrideTarget %q", target)
		}
		mode, _ := b["BootSourceOverrideMode"].(string)
		if err := s.Driver.SetBootOnce(ctx, dev, mode != "Legacy"); err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.boot = map[string]string{"BootSourceOverrideEnabled": "Once", "BootSourceOverrideTarget": target, "BootSourceOverrideMode": mode}
		s.mu.Unlock()
		return nil, nil
	case "GET " + rfSystem + "/Bios":
		inv, err := s.Driver.Inventory(ctx)
		if err != nil {
			return nil, err
		}
		return map[string]any{"Attributes": inv.BIOS, "@Redfish.Settings": map[string]any{"SettingsObject": ref(rfSystem + "/Bios/Settings")}}, nil
	case "PATCH " + rfSystem + "/Bios/Settings":
		c, ok := s.Driver.(BIOSConfigurer)
		if !ok {
			return nil, ErrUnsupported
		}
		attrs, _ := body["Attributes"].(map[string]any)
		set := map[string]string{}
		for k, v := range attrs {
			set[k] = fmt.Sprint(v)
		}
		return nil, c.SetBIOS(ctx, set)
	case "GET " + rfFW:
		inv, err := s.Driver.Inventory(ctx)
		if err != nil {
			return nil, err
		}
		var members []any
		for _, name := range slices.Sorted(maps.Keys(inv.Firmware)) {
			members = append(members, ref(rfFW+"/"+fwID(name)))
		}
		return map[string]any{"Members": members, "Members@odata.count": len(members)}, nil
	case "POST /redfish/v1/UpdateService/Actions/UpdateService.SimpleUpdate":
		u, ok := s.Driver.(FirmwareUpdater)
		if !ok {
			return nil, ErrUnsupported
		}
		inv, err := s.Driver.Inventory(ctx)
		if err != nil {
			return nil, err
		}
		byID := map[string]string{}
		for name := range inv.Firmware {
			byID[rfFW+"/"+fwID(name)] = name
		}
		img, _ := body["ImageURI"].(string)
		var targets []string
		ts, _ := body["Targets"].([]any)
		for _, t := range ts {
			ts, _ := t.(string)
			if name, ok := byID[ts]; ok {
				ts = name
			}
			targets = append(targets, ts)
		}
		return nil, u.UpdateFirmware(ctx, img, targets)
	case "GET " + rfChassis:
		return map[string]any{"Id": "1", "Name": "Chassis", "Power": ref(rfChassis + "/Power")}, nil
	case "GET " + rfChassis + "/Power":
		pc := map[string]any{}
		if pr, ok := s.Driver.(PowerReader); ok {
			w, err := pr.PowerReading(ctx)
			if err != nil {
				return nil, err
			}
			pc["PowerConsumedWatts"] = w
		}
		return map[string]any{"PowerControl": []any{pc}}, nil
	case "PATCH " + rfChassis + "/Power":
		l, ok := s.Driver.(PowerLimiter)
		if !ok {
			return nil, ErrUnsupported
		}
		pcs, _ := body["PowerControl"].([]any)
		if len(pcs) == 0 {
			return nil, errors.New("PowerControl missing")
		}
		pc, _ := pcs[0].(map[string]any)
		lim, _ := pc["PowerLimit"].(map[string]any)
		watts, ok := lim["LimitInWatts"].(float64)
		if !ok {
			return nil, errors.New("LimitInWatts missing")
		}
		return nil, l.SetPowerLimit(ctx, int(watts))
	}
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, rfFW+"/") {
		inv, err := s.Driver.Inventory(ctx)
		if err != nil {
			return nil, err
		}
		id := strings.TrimPrefix(r.URL.Path, rfFW+"/")
		for name, ver := range inv.Firmware {
			if fwID(name) == id {
				return map[string]any{"Id": id, "Name": name, "Version": ver, "Updateable": true}, nil
			}
		}
	}
	return nil, errNotFound
}
