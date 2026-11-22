package server

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/bmc"
)

// PowerWatch covers power loss for bootWindow "armed": it reads each
// node's power state from its BMC (over HTTPS, checked against the BMC
// CA) and opens the node's boot window when the BMC reports it powered
// on while its agent is silent. That is a node booting with nobody having
// armed it: after a power cut, a breaker trip, or a site outage that took
// the head down too. The BMC is the witness, so a spoofed MAC on the
// provisioning network cannot open a window.
type PowerWatch struct {
	Windows *Windows
	Every   time.Duration
	// Silent is how long an agent must have been quiet for a powered-on
	// node to count as booting (default 2m).
	Silent time.Duration
	// Driver returns n's BMC driver, or nil to skip the node (no BMC, or
	// one the watcher may not use).
	Driver func(n v1.Node) bmc.Driver
	Logf   func(string, ...any)
	Now    func() time.Time

	mu    sync.Mutex
	state map[string]string // node → last power state read ("" after an error)
	armed map[string]bool   // node → a window was opened for this power-on
}

// Run polls until ctx ends.
func (p *PowerWatch) Run(ctx context.Context) {
	t := time.NewTicker(p.Every)
	defer t.Stop()
	for {
		p.Poll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Poll reads every node's power state once.
func (p *PowerWatch) Poll(ctx context.Context) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)
	for _, n := range p.Windows.Store.Nodes("") {
		d := p.Driver(n)
		if d == nil {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			s, err := d.PowerState(cctx)
			if err != nil {
				s = ""
			}
			p.observe(n, s)
		}()
	}
	wg.Wait()
}

func (p *PowerWatch) observe(n v1.Node, now string) {
	silent := p.Silent
	if silent <= 0 {
		silent = 2 * time.Minute
	}
	t := time.Now()
	if p.Now != nil {
		t = p.Now()
	}
	p.mu.Lock()
	if p.state == nil {
		p.state, p.armed = map[string]string{}, map[string]bool{}
	}
	prev, seen := p.state[n.Name]
	p.state[n.Name] = now
	on := now == "on"
	if !on {
		p.armed[n.Name] = false // the next power-on is a new boot
	}
	// The BMC saw it go from off to on: a boot, whatever the agent last
	// said (it may have reported seconds before the power cut). From
	// unknown (the head's first look, or an unreadable BMC, which a site
	// outage also causes) to on, only while the agent is silent.
	arm := on && !p.armed[n.Name] && (seen && prev == "off" || (!seen || prev == "") && agentSilent(n, t, silent))
	if arm {
		p.armed[n.Name] = true
	}
	p.mu.Unlock()
	if arm {
		if err := p.Windows.Arm(n.Name, "its BMC reports it powered on", "bmc-watch"); err != nil && p.Logf != nil {
			p.Logf("bmc watch: %s: %v", n.Name, err)
		}
	}
}

// RedfishDrivers builds Redfish drivers from the head's BMC settings,
// caching one per node. IPMI BMCs are skipped: the watcher never uses an
// insecure protocol.
func RedfishDrivers(c BMCConfig, logf func(string, ...any)) (func(v1.Node) bmc.Driver, error) {
	pw, err := os.ReadFile(c.PasswordFile)
	if err != nil {
		return nil, err
	}
	var mu sync.Mutex
	cache := map[string]bmc.Driver{}
	warned := map[string]bool{}
	return func(n v1.Node) bmc.Driver {
		if n.BMC.Address == "" || n.BMC.Driver != v1.BMCRedfish && n.BMC.Driver != "" {
			return nil
		}
		mu.Lock()
		defer mu.Unlock()
		key := n.Name + "|" + n.BMC.Address
		if d, ok := cache[key]; ok {
			return d
		}
		r, err := bmc.NewRedfish(n.BMC.Address, c.User, strings.TrimSpace(string(pw)), c.CA)
		if err != nil {
			if !warned[key] && logf != nil {
				logf("bmc watch: %s: %v", n.Name, err)
			}
			warned[key] = true
			return nil
		}
		cache[key] = r
		return r
	}, nil
}
