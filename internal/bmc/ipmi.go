package bmc

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/damen-pt/flapjack/internal/sys"
)

// IPMI drives a BMC with ipmitool over lanplus. The password is read from
// a file (ipmitool -f) so it never appears in the process list.
type IPMI struct {
	Exec         sys.Runner
	Host         string
	User         string
	PasswordFile string
	// BeforePower, if set, runs before every power action that can boot
	// the node (on, cycle, reset); its error stops the action.
	BeforePower func(ctx context.Context, a PowerAction) error
}

func (i IPMI) run(ctx context.Context, args ...string) ([]byte, error) {
	base := []string{"-I", "lanplus", "-H", i.Host, "-U", i.User, "-f", i.PasswordFile}
	return i.Exec.Run(ctx, "ipmitool", append(base, args...)...)
}

func (i IPMI) PowerState(ctx context.Context) (string, error) {
	out, err := i.run(ctx, "chassis", "power", "status")
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(out)) // "Chassis Power is on"
	switch {
	case strings.HasSuffix(s, " on"):
		return PowerStatusOn, nil
	case strings.HasSuffix(s, " off"):
		return PowerStatusOff, nil
	}
	return "", fmt.Errorf("unexpected ipmitool output %q", s)
}

func (i IPMI) SetPower(ctx context.Context, a PowerAction) error {
	switch a {
	case PowerOn, PowerOff, PowerSoft, PowerCycle, PowerReset:
	default:
		return fmt.Errorf("unknown power action %q", a)
	}
	if err := beforePower(ctx, i.BeforePower, a); err != nil {
		return err
	}
	_, err := i.run(ctx, "chassis", "power", string(a))
	return err
}

var ipmiBootDevs = map[BootDevice]string{BootPXE: "pxe", BootDisk: "disk", BootBIOSMenu: "bios"}

func (i IPMI) SetBootOnce(ctx context.Context, d BootDevice, uefi bool) error {
	dev, ok := ipmiBootDevs[d]
	if !ok {
		return fmt.Errorf("boot device %q: %w", d, ErrUnsupported)
	}
	args := []string{"chassis", "bootdev", dev}
	if uefi {
		args = append(args, "options=efiboot")
	}
	_, err := i.run(ctx, args...)
	return err
}

// Inventory reads FRU 0 and the BMC firmware revision. IPMI exposes no
// BIOS attributes or per-device firmware, so those stay empty.
func (i IPMI) Inventory(ctx context.Context) (Inventory, error) {
	fru, err := i.run(ctx, "fru", "print", "0")
	if err != nil {
		return Inventory{}, err
	}
	f := colonFields(fru)
	inv := Inventory{
		Manufacturer: first(f["Product Manufacturer"], f["Board Mfg"]),
		Model:        first(f["Product Name"], f["Board Product"]),
		Serial:       first(f["Product Serial"], f["Board Serial"]),
		Firmware:     map[string]string{},
	}
	mc, err := i.run(ctx, "mc", "info")
	if err != nil {
		return inv, err
	}
	if v := colonFields(mc)["Firmware Revision"]; v != "" {
		inv.Firmware["BMC"] = v
	}
	return inv, nil
}

// PowerReading uses DCMI ("Instantaneous power reading: 245 Watts").
func (i IPMI) PowerReading(ctx context.Context) (float64, error) {
	out, err := i.run(ctx, "dcmi", "power", "reading")
	if err != nil {
		return 0, err
	}
	v := strings.Fields(colonFields(out)["Instantaneous power reading"])
	if len(v) == 0 {
		return 0, fmt.Errorf("no DCMI power reading in %q", strings.TrimSpace(string(out)))
	}
	return strconv.ParseFloat(v[0], 64)
}

// SetPowerLimit sets and activates a DCMI power limit. BMCs without DCMI
// power management fail here rather than silently ignoring the cap.
func (i IPMI) SetPowerLimit(ctx context.Context, watts int) error {
	if _, err := i.run(ctx, "dcmi", "power", "set_limit", "limit", strconv.Itoa(watts)); err != nil {
		return err
	}
	_, err := i.run(ctx, "dcmi", "power", "activate")
	return err
}

func colonFields(b []byte) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if _, seen := m[k]; !seen {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

func first(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
