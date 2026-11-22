package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/bmc"
	"github.com/damen-pt/flapjack/internal/events"
	"github.com/damen-pt/flapjack/internal/firmware"
	"github.com/damen-pt/flapjack/internal/sys"
)

func interruptible() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// bmcFlags build a driver for a node's BMC.
type bmcFlags struct {
	user, passwordFile, ca *string
}

func addBMCFlags(fs *flag.FlagSet) bmcFlags {
	return bmcFlags{
		user:         fs.String("bmc-user", "admin", "BMC user"),
		passwordFile: fs.String("bmc-password-file", "", "file holding the BMC password"),
		ca:           fs.String("bmc-ca", "", "CA that signs (or is) the BMC certificates (Redfish; required)"),
	}
}

func (f bmcFlags) driver(c *apiClient, n v1.Node) (bmc.Driver, error) {
	if *f.passwordFile == "" {
		return nil, errors.New("--bmc-password-file is required")
	}
	// Before flapjack powers a node on or cycles it, it opens the node's
	// boot window, so the boot it starts can enroll (bootWindow armed).
	arm := func(ctx context.Context, a bmc.PowerAction) error {
		if err := c.do("POST", "/v1/nodes/"+url.PathEscape(n.Name)+"/boot", nil, nil); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s: could not open its boot window (%v); with bootWindow armed it will wait for flapjack node boot\n", n.Name, err)
		}
		return nil
	}
	switch n.BMC.Driver {
	case v1.BMCRedfish, "":
		pw, err := os.ReadFile(*f.passwordFile)
		if err != nil {
			return nil, err
		}
		r, err := bmc.NewRedfish(n.BMC.Address, *f.user, strings.TrimSpace(string(pw)), *f.ca)
		if err != nil {
			return nil, err
		}
		r.BeforePower = arm
		return r, nil
	case v1.BMCIPMI:
		if !n.BMC.AllowIPMI {
			return nil, fmt.Errorf("node %s: IPMI is insecure (its handshake leaks a crackable password hash); set bmc.allowIPMI on the node to use it anyway, or switch it to Redfish", n.Name)
		}
		fmt.Fprintf(os.Stderr, "warning: %s: using IPMI, an insecure BMC protocol (allowIPMI is set)\n", n.Name)
		return bmc.IPMI{Exec: sys.Exec{}, Host: n.BMC.Address, User: *f.user, PasswordFile: *f.passwordFile, BeforePower: arm}, nil
	}
	return nil, fmt.Errorf("node %s: unknown BMC driver %q", n.Name, n.BMC.Driver)
}

// firmwareConverge flashes a node's firmware and sets its BIOS to its
// class's spec over the BMC. It reads the node and class from the API and
// records what it changed there, so the node's timeline shows it.
func firmwareConverge(args []string) error {
	fs := flags("firmware converge", "NODE")
	api := apiFlags(fs)
	bf := addBMCFlags(fs)
	dryRun := fs.Bool("dry-run", false, "print drift and the plan without changing anything")
	settle := fs.Duration("settle", 2*time.Minute, "wait after each reboot before polling the BMC")
	readyTimeout := fs.Duration("ready-timeout", 30*time.Minute, "give up waiting for the node after a reboot")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return flagErr
	}
	c, err := api()
	if err != nil {
		return err
	}
	var n v1.Node
	if err := c.do("GET", "/v1/nodes/"+url.PathEscape(fs.Arg(0)), nil, &n); err != nil {
		return err
	}
	var class v1.NodeClass
	if err := c.do("GET", "/v1/classes/"+url.PathEscape(n.Class), nil, &class); err != nil {
		return err
	}
	d, err := bf.driver(c, n)
	if err != nil {
		return err
	}
	record := func(e events.Event) {
		if err := c.do("POST", "/v1/nodes/"+url.PathEscape(n.Name)+"/events", e, nil); err != nil {
			fmt.Fprintln(os.Stderr, "flapjack: recording event:", err)
		}
	}
	if n.BMC.Driver == v1.BMCIPMI {
		record(events.Event{Type: "bmc.insecure_protocol",
			Message: "managed over IPMI (allowIPMI): its handshake leaks a crackable password hash"})
	}
	ctx, stop := interruptible()
	defer stop()
	if *dryRun {
		inv, err := d.Inventory(ctx)
		if err != nil {
			return err
		}
		drift := firmware.Diff(class.Firmware, inv)
		steps, unfixable := firmware.Plan(class.Firmware, drift)
		return printJSON(firmware.Result{Before: drift, Steps: steps, Unfixable: unfixable})
	}
	// Flashing reboots the node: never do it under running jobs.
	if n.Status.Phase == v1.PhaseReady {
		return fmt.Errorf("node %s is %s; drain it first", n.Name, n.Status.Phase)
	}
	conv := firmware.Converger{Node: n.Name, Driver: d, Spec: class.Firmware,
		Settle: *settle, ReadyTimeout: *readyTimeout, Record: record}
	res, err := conv.Run(ctx)
	printJSON(res)
	return err
}
