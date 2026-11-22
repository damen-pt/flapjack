package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/damen-pt/flapjack/internal/events"
	"github.com/damen-pt/flapjack/internal/health"
	"github.com/damen-pt/flapjack/internal/mcp"
	"github.com/damen-pt/flapjack/internal/overlay"
	"github.com/damen-pt/flapjack/internal/staging"
	"github.com/damen-pt/flapjack/internal/store"
	"github.com/damen-pt/flapjack/internal/sys"
	"github.com/damen-pt/flapjack/internal/tlsutil"
	"github.com/damen-pt/flapjack/internal/topology"
)

func overlayPlan(args []string) error {
	fs := flags("overlay plan", "OLD.json NEW.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return flagErr
	}
	var old, new overlay.Manifest
	if err := readJSON(fs.Arg(0), &old); err != nil {
		return err
	}
	if err := readJSON(fs.Arg(1), &new); err != nil {
		return err
	}
	if err := new.Validate(); err != nil {
		return err
	}
	signs := map[overlay.Action]string{overlay.ActionCreate: "+", overlay.ActionUpdate: "~", overlay.ActionMeta: "m", overlay.ActionRemove: "-"}
	for _, c := range overlay.Diff(old, new) {
		fmt.Printf("%s %s\n", signs[c.Action], c.Path)
	}
	return nil
}

var flagErr = errors.New("invalid arguments")

func healthRun(args []string) error {
	fs := flags("health run", "")
	gpus := fs.Int("gpus", 0, "expected GPU count; enables GPU and Xid checks")
	ibRate := fs.Float64("min-ib-rate", 0, "minimum RDMA port rate in Gb/s; enables the port check")
	memGiB := fs.Float64("mem-gib", 0, "expected memory in GiB; enables the memory check")
	evidence := fs.String("evidence", "", "write an RMA evidence bundle (.tar.gz) here if any check fails")
	timeout := fs.Duration("timeout", 5*time.Minute, "per-check timeout")
	reportTo := fs.String("report-to", "", "control-plane API URL to submit the report to (https://fj:7443)")
	tokenFile := fs.String("token-file", "/etc/flapjack/agent.token", "node-scoped API token, with --report-to")
	ca := fs.String("ca", "/etc/flapjack/pki/ca.pem", "cluster CA, with --report-to")
	identity := fs.String("identity", "/var/lib/flapjack-agent/identity.pem", "the node's certificate and key (the agent's), with --report-to")
	node := fs.String("node", "", "node name to report as (default: hostname)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	sysfs := os.DirFS("/sys")
	checks := []health.Check{health.PCIeLink{Sys: sysfs}}
	if *gpus > 0 {
		checks = append(checks, health.GPUs{Exec: sys.Exec{}, Expect: *gpus, MaxTempC: 85}, health.XIDs{Exec: sys.Exec{}})
	}
	if *ibRate > 0 {
		checks = append(checks, health.IBPorts{Sys: sysfs, MinRateGbps: *ibRate, MaxLinkDowned: -1})
	}
	if *memGiB > 0 {
		checks = append(checks, health.Memory{Proc: os.DirFS("/proc"), ExpectGiB: *memGiB})
	}
	host := *node
	if host == "" {
		h, err := os.Hostname()
		if err != nil {
			return err
		}
		host, _, _ = strings.Cut(h, ".")
	}
	rep := health.Runner{Checks: checks, Timeout: *timeout}.Run(context.Background(), host)
	if err := printJSON(rep); err != nil {
		return err
	}
	if *reportTo != "" {
		if err := submitReport(*reportTo, *tokenFile, *ca, *identity, rep); err != nil {
			return fmt.Errorf("submitting report: %w", err)
		}
	}
	if rep.Status == health.Fail {
		if *evidence != "" {
			f, err := os.Create(*evidence)
			if err != nil {
				return err
			}
			defer f.Close()
			if err := health.WriteEvidence(f, rep, nil); err != nil {
				return err
			}
		}
		return errors.New("health checks failed")
	}
	return nil
}

// submitReport posts a health report to the API, which applies the
// admission gate and records the verdict.
func submitReport(base, tokenFile, ca, identity string, rep health.Report) error {
	tok, err := os.ReadFile(tokenFile)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(base, "https://") {
		return fmt.Errorf("%s: the API is only reachable over https://", base)
	}
	// The API wants the node's own certificate with its node token.
	cfg, err := tlsutil.Client(ca, identity, identity)
	if err != nil {
		return err
	}
	body, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(base, "/")+"/v1/nodes/"+url.PathEscape(rep.Node)+"/health", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(out))
	}
	fmt.Fprintf(os.Stderr, "verdict: %s\n", bytes.TrimSpace(out))
	return nil
}

func readFabric(path string) (topology.Fabric, error) {
	f, err := os.Open(path)
	if err != nil {
		return topology.Fabric{}, err
	}
	defer f.Close()
	return topology.ParseIBNetDiscover(f)
}

func topologyValidate(args []string) error {
	fs := flags("topology validate", "")
	bp := fs.String("blueprint", "", "expected cabling (JSON fabric)")
	scan := fs.String("ibnetdiscover", "", "output of ibnetdiscover -p")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bp == "" || *scan == "" {
		fs.Usage()
		return flagErr
	}
	var blueprint topology.Fabric
	if err := readJSON(*bp, &blueprint); err != nil {
		return err
	}
	if err := topology.CheckBlueprint(blueprint); err != nil {
		return err
	}
	observed, err := readFabric(*scan)
	if err != nil {
		return err
	}
	findings := topology.Validate(blueprint, observed)
	for _, f := range findings {
		fmt.Printf("%-10s %s\n", f.Kind, f.Message)
	}
	if len(findings) > 0 {
		return fmt.Errorf("%d cabling problems", len(findings))
	}
	fmt.Println("cabling matches blueprint")
	return nil
}

func topologySlurm(args []string) error {
	fs := flags("topology slurm", "")
	scan := fs.String("ibnetdiscover", "", "output of ibnetdiscover -p")
	rail := fs.String("rail", "", "use only this HCA's links (e.g. mlx5_0) on rail-optimized fabrics")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *scan == "" {
		fs.Usage()
		return flagErr
	}
	f, err := readFabric(*scan)
	if err != nil {
		return err
	}
	fmt.Print(topology.SlurmTreeRail(f, *rail))
	return nil
}

func stageSplit(args []string) error {
	fs := flags("stage split", "FILE")
	dir := fs.String("store", "", "chunk store directory")
	chunk := fs.Int("chunk", staging.DefaultChunkSize, "chunk size in bytes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || fs.NArg() != 1 {
		fs.Usage()
		return flagErr
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer f.Close()
	m, err := staging.Split(f, filepath.Base(fs.Arg(0)), *chunk, staging.Store{Dir: *dir})
	if err != nil {
		return err
	}
	return printJSON(m)
}

func stageServe(args []string) error {
	fs := flags("stage serve", "")
	dir := fs.String("store", "", "chunk store directory")
	addr := fs.String("listen", "127.0.0.1:7480", "listen address (anything but loopback needs --tls-cert, --tls-key and --client-ca)")
	cert := fs.String("tls-cert", "", "TLS certificate")
	key := fs.String("tls-key", "", "TLS key")
	clientCA := fs.String("client-ca", "", "require client certificates signed by this CA (mTLS)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		fs.Usage()
		return flagErr
	}
	fmt.Fprintf(os.Stderr, "serving %s on %s\n", *dir, *addr)
	if *cert != "" && *clientCA == "" {
		return errors.New("--client-ca is required with --tls-cert: chunks are only served to clients with a certificate")
	}
	return listen(*addr, staging.Handler(staging.Store{Dir: *dir}), *cert, *key, *clientCA)
}

// sourceFlag parses repeated --source name=URL[@peer|rack|origin].
type sourceFlag []staging.Source

func (s *sourceFlag) String() string { return fmt.Sprint(*s) }

func (s *sourceFlag) Set(v string) error {
	name, rest, ok := strings.Cut(v, "=")
	if !ok {
		return errors.New("want name=URL[@peer|rack|origin]")
	}
	url, tier, _ := strings.Cut(rest, "@")
	t := map[string]staging.Tier{"": staging.TierOrigin, "peer": staging.TierPeer, "rack": staging.TierRack, "origin": staging.TierOrigin}
	tt, ok := t[tier]
	if !ok {
		return fmt.Errorf("unknown tier %q", tier)
	}
	*s = append(*s, staging.Source{Name: name, URL: strings.TrimSuffix(url, "/"), Tier: tt})
	return nil
}

// fetcherFlags are shared by stage fetch and stage ensure.
type fetcherFlags struct {
	dir, ca, cert, key *string
	par, attempts      *int
	sources            sourceFlag
}

func addFetcherFlags(fs *flag.FlagSet) *fetcherFlags {
	f := &fetcherFlags{
		dir:      fs.String("store", "", "local chunk store directory"),
		par:      fs.Int("parallel", 8, "concurrent chunk downloads"),
		attempts: fs.Int("attempts", 3, "rounds over all sources before a chunk fails"),
		ca:       fs.String("ca", "", "CA that signs chunk servers (https sources)"),
		cert:     fs.String("cert", "", "client certificate for mTLS"),
		key:      fs.String("key", "", "client key for mTLS"),
	}
	fs.Var(&f.sources, "source", "chunk source name=URL[@peer|rack|origin] (repeatable)")
	return f
}

func (f *fetcherFlags) fetcher() (staging.Fetcher, error) {
	fe := staging.Fetcher{Store: staging.Store{Dir: *f.dir}, Sources: f.sources, Parallel: *f.par, Attempts: *f.attempts}
	if *f.ca != "" || *f.cert != "" {
		cfg, err := tlsutil.Client(*f.ca, *f.cert, *f.key)
		if err != nil {
			return fe, err
		}
		fe.Client = &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, Proxy: http.ProxyFromEnvironment}}
	}
	return fe, nil
}

func stageFetch(args []string) error {
	fs := flags("stage fetch", "MANIFEST DEST")
	ff := addFetcherFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ff.dir == "" || fs.NArg() != 2 || len(ff.sources) == 0 {
		fs.Usage()
		return flagErr
	}
	var m staging.Manifest
	if err := readJSON(fs.Arg(0), &m); err != nil {
		return err
	}
	f, err := ff.fetcher()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	st, err := f.Fetch(ctx, m, fs.Arg(1))
	printJSON(st)
	return err
}

// stageEnsure is meant for a Slurm Prolog: it makes each named artifact
// present and verified under --dest, fetching only what is missing or
// changed, and serialising concurrent jobs on the same node.
func stageEnsure(args []string) error {
	fs := flags("stage ensure", "ARTIFACT...")
	ff := addFetcherFlags(fs)
	manifests := fs.String("manifests", "/etc/flapjack/manifests", "directory of <artifact>.json manifests")
	dest := fs.String("dest", "/var/lib/flapjack/artifacts", "directory artifacts are placed in")
	timeout := fs.Duration("timeout", 30*time.Minute, "give up after this long")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ff.dir == "" || fs.NArg() == 0 || len(ff.sources) == 0 {
		fs.Usage()
		return flagErr
	}
	f, err := ff.fetcher()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	for _, name := range fs.Args() {
		if name != filepath.Base(name) || strings.HasPrefix(name, ".") {
			return fmt.Errorf("artifact name %q must be a plain file name", name)
		}
		var m staging.Manifest
		if err := readJSON(filepath.Join(*manifests, name+".json"), &m); err != nil {
			return err
		}
		start := time.Now()
		fetched, st, err := staging.Ensure(ctx, f, m, filepath.Join(*dest, name))
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if fetched {
			fmt.Fprintf(os.Stderr, "%s: fetched in %s %v\n", name, time.Since(start).Round(time.Millisecond), st.Fetched)
		} else {
			fmt.Fprintf(os.Stderr, "%s: already present\n", name)
		}
	}
	return nil
}

func eventsCorrelate(args []string) error {
	fs := flags("events correlate", "")
	logPath := fs.String("log", "", "event log (JSON lines)")
	symptom := fs.String("symptom", "health.fail", "symptom event type or prefix")
	window := fs.Duration("window", time.Hour, "how long before a failure a change counts")
	since := fs.Duration("since", 7*24*time.Hour, "look back this far")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *logPath == "" {
		fs.Usage()
		return flagErr
	}
	f, err := os.Open(*logPath)
	if err != nil {
		return err
	}
	defer f.Close()
	all, err := events.Read(f, events.Filter{Since: time.Now().Add(-*since)})
	if err != nil {
		return err
	}
	var symptoms, changes []events.Event
	sf := events.Filter{Types: []string{*symptom}}
	for _, e := range all {
		switch {
		case sf.Match(e):
			symptoms = append(symptoms, e)
		case e.Category == events.Change:
			changes = append(changes, e)
		}
	}
	return printJSON(events.Correlate(symptoms, changes, *window))
}

// listen serves h. Without TLS it only binds loopback addresses.
func listen(addr string, h http.Handler, cert, key, clientCA string) error {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	if cert != "" || key != "" {
		cfg, err := tlsutil.Server(cert, key, clientCA)
		if err != nil {
			return err
		}
		srv.TLSConfig = cfg
		return srv.ListenAndServeTLS("", "")
	}
	if clientCA != "" {
		return errors.New("--client-ca needs --tls-cert and --tls-key")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); (ip == nil || !ip.IsLoopback()) && host != "localhost" {
		return fmt.Errorf("refusing plaintext on %s: pass --tls-cert and --tls-key, or listen on loopback", addr)
	}
	return srv.ListenAndServe()
}

func mcpServe(args []string) error {
	fs := flags("mcp", "")
	statePath := fs.String("state", "/var/lib/flapjack/state.json", "state file")
	eventsPath := fs.String("events", "/var/lib/flapjack/events.jsonl", "event log")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Read-only all the way down: the store refuses writes and reloads what
	// the API server saves, and the event log is opened for reading only.
	s, err := store.OpenReadOnly(*statePath, events.OpenReadOnly(*eventsPath))
	if err != nil {
		return err
	}
	return (&mcp.Server{Store: s}).Serve(os.Stdin, os.Stdout)
}
