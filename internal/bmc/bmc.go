// Package bmc drives baseboard management controllers over Redfish or IPMI
// behind one interface. Capabilities only some protocols have (BIOS
// settings, firmware updates, power limits) are separate interfaces; callers
// type-assert and report "unsupported" instead of failing silently.
package bmc

import (
	"context"
	"errors"
)

// PowerAction is a power control request.
type PowerAction string

const (
	PowerOn        PowerAction = "on"
	PowerOff       PowerAction = "off"   // immediate
	PowerSoft      PowerAction = "soft"  // ACPI shutdown
	PowerCycle     PowerAction = "cycle" // off then on
	PowerReset     PowerAction = "reset" // warm reset
	PowerStatusOn              = "on"
	PowerStatusOff             = "off"
)

// BootDevice is a one-time boot override target.
type BootDevice string

const (
	BootPXE      BootDevice = "pxe"
	BootHTTP     BootDevice = "http" // UEFI HTTP boot
	BootDisk     BootDevice = "disk"
	BootBIOSMenu BootDevice = "bios"
)

// Inventory is what a BMC reports about its system.
type Inventory struct {
	Manufacturer string            `json:"manufacturer,omitempty"`
	Model        string            `json:"model,omitempty"`
	Serial       string            `json:"serial,omitempty"`
	Firmware     map[string]string `json:"firmware,omitempty"` // component → version
	// FirmwareIDs maps component → the driver's handle for it (the Redfish
	// FirmwareInventory @odata.id), which firmware updates target.
	FirmwareIDs map[string]string `json:"firmwareIds,omitempty"`
	BIOS        map[string]string `json:"bios,omitempty"` // attribute → value
}

// Driver is the minimum every BMC protocol supports.
type Driver interface {
	PowerState(ctx context.Context) (string, error)
	SetPower(ctx context.Context, a PowerAction) error
	SetBootOnce(ctx context.Context, d BootDevice, uefi bool) error
	Inventory(ctx context.Context) (Inventory, error)
}

// BIOSConfigurer stages BIOS attribute changes; they apply on next reboot.
type BIOSConfigurer interface {
	SetBIOS(ctx context.Context, attrs map[string]string) error
}

// FirmwareUpdater pushes a firmware image to the named components. It
// returns only once the image is fully written (staged for activation on
// the next reset), so the caller may reboot.
type FirmwareUpdater interface {
	UpdateFirmware(ctx context.Context, imageURI string, targets []string) error
}

// PowerLimiter sets a chassis power cap in watts.
type PowerLimiter interface {
	SetPowerLimit(ctx context.Context, watts int) error
}

// PowerReader reports current chassis power draw in watts.
type PowerReader interface {
	PowerReading(ctx context.Context) (float64, error)
}

// ErrUnsupported is returned when a driver lacks a capability.
var ErrUnsupported = errors.New("not supported by this BMC driver")

// beforePower runs hook for the power actions that can boot a node.
func beforePower(ctx context.Context, hook func(context.Context, PowerAction) error, a PowerAction) error {
	if hook == nil {
		return nil
	}
	switch a {
	case PowerOn, PowerCycle, PowerReset:
		return hook(ctx, a)
	}
	return nil
}
