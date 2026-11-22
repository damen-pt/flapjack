package bmc

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"sync"
)

// Fake is an in-memory BMC implementing every capability. Staged BIOS
// settings and firmware updates take effect on the next power cycle or
// reset, as on real hardware. It exists for tests and the digital twin.
type Fake struct {
	mu         sync.Mutex
	Inv        Inventory
	Power      string
	BootOnce   BootDevice
	PowerLimit int
	Watts      float64 // returned by PowerReading
	Log        []string

	pendingBIOS map[string]string
	pendingFW   map[string]string // component → version
	// FirmwareVersions maps image URI → version it installs, for
	// UpdateFirmware.
	FirmwareVersions map[string]string
}

func (f *Fake) logf(format string, args ...any) { f.Log = append(f.Log, fmt.Sprintf(format, args...)) }

func (f *Fake) PowerState(context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Power == "" {
		return PowerStatusOff, nil
	}
	return f.Power, nil
}

func (f *Fake) SetPower(_ context.Context, a PowerAction) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logf("power %s", a)
	switch a {
	case PowerOn:
		if f.Power != PowerStatusOn { // a boot; already-on is a no-op
			f.applyPending()
		}
		f.Power = PowerStatusOn
	case PowerCycle, PowerReset:
		f.applyPending()
		f.Power = PowerStatusOn
	case PowerOff, PowerSoft:
		f.Power = PowerStatusOff
	default:
		return fmt.Errorf("unknown power action %q", a)
	}
	return nil
}

func (f *Fake) applyPending() {
	if f.Inv.BIOS == nil {
		f.Inv.BIOS = map[string]string{}
	}
	if f.Inv.Firmware == nil {
		f.Inv.Firmware = map[string]string{}
	}
	maps.Copy(f.Inv.BIOS, f.pendingBIOS)
	maps.Copy(f.Inv.Firmware, f.pendingFW)
	f.pendingBIOS, f.pendingFW = nil, nil
}

func (f *Fake) SetBootOnce(_ context.Context, d BootDevice, uefi bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logf("bootonce %s uefi=%v", d, uefi)
	f.BootOnce = d
	return nil
}

func (f *Fake) Inventory(context.Context) (Inventory, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	inv := f.Inv
	inv.Firmware = maps.Clone(f.Inv.Firmware)
	inv.BIOS = maps.Clone(f.Inv.BIOS)
	return inv, nil
}

func (f *Fake) SetBIOS(_ context.Context, attrs map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logf("bios %d attributes", len(attrs))
	if f.pendingBIOS == nil {
		f.pendingBIOS = map[string]string{}
	}
	maps.Copy(f.pendingBIOS, attrs)
	return nil
}

func (f *Fake) UpdateFirmware(_ context.Context, imageURI string, targets []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.FirmwareVersions[imageURI]
	if !ok {
		return fmt.Errorf("fake: unknown firmware image %s", imageURI)
	}
	f.logf("firmware %s -> %s", strings.Join(targets, ","), v)
	if f.pendingFW == nil {
		f.pendingFW = map[string]string{}
	}
	for _, t := range targets {
		f.pendingFW[t] = v
	}
	return nil
}

func (f *Fake) SetPowerLimit(_ context.Context, watts int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logf("powerlimit %d", watts)
	f.PowerLimit = watts
	return nil
}

func (f *Fake) PowerReading(context.Context) (float64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Power != PowerStatusOn {
		return 0, nil
	}
	return f.Watts, nil
}
