package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/damen-pt/flapjack/internal/agent"
	"github.com/damen-pt/flapjack/internal/apiserver"
	"github.com/damen-pt/flapjack/internal/gens"
	"github.com/damen-pt/flapjack/internal/image"
	"github.com/damen-pt/flapjack/internal/overlay"
	"github.com/damen-pt/flapjack/internal/pki"
	"github.com/damen-pt/flapjack/internal/server"
)

// selection parses "NODE... [--class C] [--all]".
func selection(fs *flag.FlagSet, args []string) (apiserver.BuildRequest, error) {
	var req apiserver.BuildRequest
	class := fs.String("class", "", "comma-separated classes")
	all := fs.Bool("all", false, "every node")
	msg := fs.String("m", "", "message recorded with the new generations")
	if err := fs.Parse(reorder(fs, args)); err != nil {
		return req, err
	}
	req.Nodes, req.All, req.Message = fs.Args(), *all, *msg
	if *class != "" {
		req.Classes = strings.Split(*class, ",")
	}
	if len(req.Nodes) == 0 && len(req.Classes) == 0 && !req.All {
		fs.Usage()
		return req, flagErr
	}
	return req, nil
}

// reorder moves flags before positional arguments, so "switch r1n01 -m x"
// works like "switch -m x r1n01". It must run after every flag is defined.
func reorder(fs *flag.FlagSet, args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			pos = append(pos, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") {
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			continue // flag.Parse reports it
		}
		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); (!ok || !b.IsBoolFlag()) && i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	}
	return append(flags, pos...)
}

func overlayBuild(args []string) error  { return buildOrSwitch("build", args, false) }
func overlaySwitch(args []string) error { return buildOrSwitch("switch", args, true) }

func buildOrSwitch(name string, args []string, sw bool) error {
	fs := flags(name, "[NODE...] [--class C] [--all] [-m MESSAGE]")
	client := apiFlags(fs)
	verbose := fs.Bool("v", false, "list every changed path")
	req, err := selection(fs, args)
	if err != nil {
		return err
	}
	req.Switch = sw
	c, err := client()
	if err != nil {
		return err
	}
	var res []server.NodeResult
	if err := c.do("POST", "/v1/overlays/build", req, &res); err != nil {
		return err
	}
	failed := 0
	for _, r := range res {
		var add, upd, rm int
		for _, ch := range r.Changes {
			switch ch.Action {
			case overlay.ActionCreate:
				add++
			case overlay.ActionRemove:
				rm++
			default:
				upd++
			}
		}
		switch {
		case r.Error != "":
			failed++
			fmt.Printf("%s  FAILED: %s\n", r.Node, r.Error)
			continue
		case len(r.Changes) == 0:
			fmt.Printf("%s  generation %d, no changes\n", r.Node, r.From)
		case sw:
			fmt.Printf("%s  generation %d → %d  (+%d ~%d -%d)\n", r.Node, r.From, r.To, add, upd, rm)
		default:
			fmt.Printf("%s  generation %d would change  (+%d ~%d -%d)\n", r.Node, r.From, add, upd, rm)
		}
		for _, w := range r.Warnings {
			fmt.Printf("    warning: %s\n", w)
		}
		if *verbose || len(res) <= 4 {
			printChanges(r.Changes, "    ")
		}
	}
	if !sw && failed < len(res) {
		fmt.Println("\nDry run. Apply with: flapjack switch", strings.Join(args, " "))
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d nodes failed to render", failed, len(res))
	}
	return nil
}

func printChanges(cs []overlay.Change, indent string) {
	sym := map[overlay.Action]string{overlay.ActionCreate: "+", overlay.ActionUpdate: "~", overlay.ActionMeta: "m", overlay.ActionRemove: "-"}
	for _, ch := range cs {
		from := ""
		if ch.New != nil && ch.New.Overlay != "" {
			from = "  (" + ch.New.Overlay + ")"
		}
		fmt.Printf("%s%s %s%s\n", indent, sym[ch.Action], ch.Path, from)
	}
}

func generationsList(args []string) error {
	fs := flags("generations", "NODE")
	client := apiFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return flagErr
	}
	c, err := client()
	if err != nil {
		return err
	}
	var list []gens.Summary
	if err := c.do("GET", "/v1/nodes/"+url.PathEscape(fs.Arg(0))+"/generations", nil, &list); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "GEN\tCREATED\tBY\tPATHS\tOVERLAYS\tMESSAGE")
	for _, g := range list {
		mark := " "
		if g.Current {
			mark = "*"
		}
		fmt.Fprintf(tw, "%s%d\t%s\t%s\t%d\t%s\t%s\n", mark, g.Number, g.Created.Local().Format("2006-01-02 15:04:05"), g.Actor, g.Paths,
			strings.Join(g.Overlays, ","), g.Message)
	}
	return tw.Flush()
}

func generationDiff(args []string) error {
	fs := flags("diff", "NODE [--from N] [--to M]")
	client := apiFlags(fs)
	from := fs.Int("from", 0, "older generation (default: the one before --to)")
	to := fs.Int("to", 0, "newer generation (default: current)")
	if err := fs.Parse(reorder(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return flagErr
	}
	c, err := client()
	if err != nil {
		return err
	}
	var d struct {
		From, To int
		Changes  []overlay.Change
	}
	q := url.Values{"from": {strconv.Itoa(*from)}, "to": {strconv.Itoa(*to)}}
	if err := c.do("GET", "/v1/nodes/"+url.PathEscape(fs.Arg(0))+"/diff?"+q.Encode(), nil, &d); err != nil {
		return err
	}
	fmt.Printf("%s: generation %d → %d\n", fs.Arg(0), d.From, d.To)
	if len(d.Changes) == 0 {
		fmt.Println("    no changes")
	}
	printChanges(d.Changes, "    ")
	return nil
}

func generationRollback(args []string) error {
	fs := flags("rollback", "NODE --reason TEXT [--to N]")
	client := apiFlags(fs)
	to := fs.Int("to", 0, "generation to switch to (default: the previous one)")
	reason := fs.String("reason", "", "why (recorded on the timeline)")
	if err := fs.Parse(reorder(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 || *reason == "" {
		fs.Usage()
		return flagErr
	}
	c, err := client()
	if err != nil {
		return err
	}
	var r struct {
		Node     string
		From, To int
	}
	if err := c.do("POST", "/v1/nodes/"+url.PathEscape(fs.Arg(0))+"/rollback", map[string]any{"to": *to, "reason": *reason}, &r); err != nil {
		return err
	}
	fmt.Printf("%s: generation %d → %d (the agent applies it now)\n", r.Node, r.From, r.To)
	return nil
}

func overlayList(args []string) error {
	fs := flags("overlay list", "")
	client := apiFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := client()
	if err != nil {
		return err
	}
	var srcs []struct {
		Name, Engine, Dir string
		Classes           []string
	}
	if err := c.do("GET", "/v1/overlays", nil, &srcs); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "OVERLAY\tENGINE\tUSED BY\tSOURCE")
	for _, s := range srcs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", s.Name, s.Engine, strings.Join(s.Classes, ","), s.Dir)
	}
	return tw.Flush()
}

func overlayShow(args []string) error {
	fs := flags("overlay show", "NODE [GENERATION]")
	client := apiFlags(fs)
	asJSON := fs.Bool("json", false, "print the full manifest")
	if err := fs.Parse(reorder(fs, args)); err != nil {
		return err
	}
	if fs.NArg() < 1 || fs.NArg() > 2 {
		fs.Usage()
		return flagErr
	}
	c, err := client()
	if err != nil {
		return err
	}
	n := 0
	if fs.NArg() == 2 {
		if n, err = strconv.Atoi(fs.Arg(1)); err != nil {
			return fmt.Errorf("generation must be a number")
		}
	} else {
		var list []gens.Summary
		if err := c.do("GET", "/v1/nodes/"+url.PathEscape(fs.Arg(0))+"/generations", nil, &list); err != nil {
			return err
		}
		for _, g := range list {
			if g.Current {
				n = g.Number
			}
		}
		if n == 0 {
			return fmt.Errorf("%s has no generations; run flapjack switch %s", fs.Arg(0), fs.Arg(0))
		}
	}
	var g gens.Generation
	if err := c.do("GET", fmt.Sprintf("/v1/nodes/%s/generations/%d", url.PathEscape(fs.Arg(0)), n), nil, &g); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(g)
	}
	fmt.Printf("%s generation %d (%s by %s: %s)\n", fs.Arg(0), g.Number, g.Created.Local().Format(time.DateTime), g.Actor, g.Message)
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "PATH\tKIND\tMODE\tOWNER\tPOLICY\tOVERLAY")
	for _, p := range sortedKeys(g.Manifest.Entries) {
		e := g.Manifest.Entries[p]
		owner := e.Owner
		if owner == "" {
			owner = strconv.Itoa(e.UID)
		}
		pol := string(e.Policy)
		if pol == "" {
			pol = "enforce"
		}
		mode := e.EffectiveMode().String()
		if e.Kind == overlay.KindSymlink {
			mode = "→ " + e.Target
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", p, e.Kind, mode, owner, pol, e.Overlay)
	}
	if len(g.Manifest.Exclusive) > 0 {
		fmt.Fprintf(tw, "\nexclusive:\t%s\n", strings.Join(g.Manifest.Exclusive, " "))
	}
	return tw.Flush()
}

func sortedKeys(m map[string]overlay.Entry) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

func agentRun(args []string) error {
	fs := flags("agent", "")
	srv := fs.String("server", "", "head agent URL, https:// (default: flapjack.server= on the kernel command line)")
	tent := fs.String("tentacle", "", "rack tentacle URL; overrides --server (default: flapjack.tentacle=)")
	stateDir := fs.String("state", "/var/lib/flapjack-agent", "where the applied manifest and the node's identity are kept")
	root := fs.String("root", "/", "node root filesystem")
	pristine := fs.String("pristine", "/run/rootfsbase", "read-only image layer; restored when a path leaves the overlay")
	verify := fs.Duration("verify", time.Minute, "drift check interval")
	caFile := fs.String("ca", "/etc/flapjack/pki/ca.pem", "cluster CA: the head or tentacle must chain to it")
	trustFile := fs.String("trust-key", "/etc/flapjack/pki/generation.pub", "head's generation key; generations must be signed with it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	kargs := map[string]string{}
	if b, err := os.ReadFile("/proc/cmdline"); err == nil {
		kargs = agent.KernelArgs(string(b))
	}
	pick := func(flagVal, key string) string {
		if flagVal != "" {
			return flagVal
		}
		return kargs[key]
	}
	*srv, *tent = pick(*srv, "server"), pick(*tent, "tentacle")
	if *srv == "" && *tent == "" {
		return errors.New("no --server or --tentacle, and neither flapjack.server= nor flapjack.tentacle= on the kernel command line")
	}
	logf := func(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) }

	r, err := os.OpenRoot(*root)
	if err != nil {
		return err
	}
	defer r.Close()
	// Boot must not wait on an unreachable server, enrollment included.
	var readyOnce sync.Once
	ready := func() {
		readyOnce.Do(func() {
			if err := agent.NotifyReady(); err != nil {
				logf("sd_notify: %v", err)
			}
		})
	}
	readyTimer := time.AfterFunc(45*time.Second, ready)
	defer readyTimer.Stop()

	a := &agent.Agent{Server: strings.TrimRight(*srv, "/"), Node: kargs["node"], Root: r, State: overlay.State{Dir: *stateDir},
		Verify: *verify, Relabel: agent.Restorecon, Ready: ready, Logf: logf}
	if fi, err := os.Stat(*pristine); err == nil && fi.IsDir() {
		a.Pristine = os.DirFS(*pristine)
	}
	// Generations are always signed: an agent without the head's key
	// would apply whatever it was handed.
	if a.TrustKey, err = pki.LoadTrustKey(*trustFile); err != nil {
		return fmt.Errorf("the head's generation key: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// Through the rack's tentacle, or straight to the head: mTLS either
	// way, enrolling with the boot ticket for a certificate first.
	node := kargs["node"]
	server, want := strings.TrimRight(*srv, "/"), pki.AnyOf(pki.Head)
	via := "head " + server
	if *tent != "" {
		rack := kargs["rack"]
		if rack == "" {
			return errors.New("a tentacle needs flapjack.rack= on the kernel command line")
		}
		server, want, via = strings.TrimRight(*tent, "/"), pki.Only(pki.Identity{Role: pki.Tentacle, Name: rack}), "tentacle "+*tent+" (rack "+rack+")"
	}
	if node == "" {
		return errors.New("no flapjack.node= on the kernel command line")
	}
	if !strings.HasPrefix(server, "https://") {
		return fmt.Errorf("%s: agents only talk to the head or a tentacle over mTLS (https://)", server)
	}
	pool, err := pki.LoadPool(*caFile)
	if err != nil {
		return err
	}
	creds := &agent.Credentials{Node: node, Server: server, Dir: *stateDir, Logf: logf}
	client := &http.Client{Timeout: *verify + 30*time.Second, Transport: &http.Transport{
		TLSClientConfig: pki.ClientConfig(creds.Certificate, pool, want)}}
	creds.Client = client
	if err := creds.Ensure(ctx, kargs["mac"], kargs["ticket"]); err != nil {
		return fmt.Errorf("enrolling with %s: %w", via, err)
	}
	go creds.Run(ctx)
	a.Server, a.Client, a.Unseal = creds.Server, client, creds.Unseal
	logf("flapjack agent: %s via %s, certificate until %s", node, via, creds.Certificate().Leaf.NotAfter.Format(time.RFC3339))
	err = a.Run(ctx)
	if agent.Rebooting() {
		// Opens this node's boot window on the head, so it can boot again
		// when windows only open on authorized triggers.
		actx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if aerr := creds.AnnounceReboot(actx); aerr != nil {
			logf("flapjack agent: announcing the reboot: %v", aerr)
		} else {
			logf("flapjack agent: announced the reboot")
		}
		cancel()
	}
	return err
}

func imageDir(flagDir string) string {
	if flagDir != "" {
		return flagDir
	}
	if c, err := server.LoadConfig(server.DefaultConfig); err == nil {
		return c.ImageDir()
	}
	return filepath.Join(server.DefaultDataDir, "images")
}

// imageSpecDir holds image specs, NAME.json.
const imageSpecDir = "/etc/flapjack/images"

func imageBuild(args []string) error {
	fs := flags("image build", "NAME")
	dir := fs.String("dir", "", "images directory (default: from "+server.DefaultConfig+")")
	specPath := fs.String("spec", "", "image spec (default: /etc/flapjack/images/NAME.json if present)")
	quiet := fs.Bool("q", false, "only print errors and the result")
	if err := fs.Parse(reorder(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return flagErr
	}
	name := fs.Arg(0)
	spec := image.DefaultSpec()
	if *specPath == "" {
		if p := filepath.Join(imageSpecDir, name+".json"); fileExists(p) {
			*specPath = p
		}
	}
	if *specPath != "" {
		spec = image.Spec{}
		if err := readJSON(*specPath, &spec); err != nil {
			return err
		}
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	b := &image.Builder{Dir: imageDir(*dir), Agent: self, Log: os.Stderr, PKIDir: defaultPKIDir()}
	if !pki.Exists(b.PKIDir) {
		b.PKIDir = "" // nothing to trust yet; images built now accept unsigned generations
	}
	if *quiet {
		b.Log = nil
	}
	info, err := b.Build(name, spec)
	if err != nil {
		return err
	}
	fmt.Printf("%s is current (kernel %s, %d packages, %d MiB)\n", info.Version, info.Kernel, info.Packages, info.Size>>20)
	return nil
}

func imageList(args []string) error {
	fs := flags("image list", "")
	dir := fs.String("dir", "", "images directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	vs, err := (&image.Builder{Dir: imageDir(*dir)}).List()
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "VERSION\tCREATED\tKERNEL\tPACKAGES\tSIZE")
	for _, v := range vs {
		mark := " "
		if v.Current {
			mark = "*"
		}
		fmt.Fprintf(tw, "%s%s\t%s\t%s\t%d\t%d MiB\n", mark, v.Version, v.Created.Local().Format(time.DateTime), v.Kernel, v.Packages, v.Size>>20)
	}
	return tw.Flush()
}

func imageUse(args []string) error {
	fs := flags("image use", "NAME VERSION")
	dir := fs.String("dir", "", "images directory")
	if err := fs.Parse(reorder(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return flagErr
	}
	if err := (&image.Builder{Dir: imageDir(*dir)}).Use(fs.Arg(0), fs.Arg(1)); err != nil {
		return err
	}
	fmt.Printf("%s now boots %s (nodes pick it up on their next boot)\n", fs.Arg(0), fs.Arg(1))
	return nil
}
