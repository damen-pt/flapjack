// Package agent is the node side of overlays: it keeps the node's files
// equal to its current generation. It long-polls the server, applies new
// generations with the bi-directional reconciler (paths that leave the
// overlay are removed or restored to the image's version), runs hooks,
// repairs enforce-policy drift and reports everything upstream.
package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/damen-pt/flapjack/internal/overlay"
	"github.com/damen-pt/flapjack/internal/pki"
	"github.com/damen-pt/flapjack/internal/server"
)

// Agent reconciles one node.
type Agent struct {
	Server string // the head "https://10.99.0.1:8443", or the rack tentacle "https://10.1.1.1:8443"
	// Node is this node's name; when set, a manifest for any other node is
	// refused.
	Node string
	// TrustKey is the head's generation signing key, required: every
	// generation must carry the head's signature over this node, its
	// number and its manifest digest, so a relay cannot alter it.
	TrustKey ed25519.PublicKey
	Root     *os.Root // the node's root filesystem
	Pristine fs.FS    // the booted image's read-only lower layer, if any
	State    overlay.State
	// Verify is how often the node is checked for drift (default 60s).
	Verify time.Duration
	// Hook runs an onChange/onRemove command; default sh -c with a timeout.
	Hook func(ctx context.Context, cmd string) (string, error)
	// Relabel restores SELinux labels on written paths; nil skips it.
	Relabel func(paths []string) error
	// Ready is called once, after the first successful apply or after
	// ReadyAfter (default 45s) without one, so boot is never held hostage
	// by an unreachable server.
	Ready      func()
	ReadyAfter time.Duration
	Logf       func(format string, args ...any)
	Client     *http.Client
	// Unseal opens secret content the head sealed to this node
	// (Credentials.Unseal).
	Unseal func(digest string, blob []byte) ([]byte, error)

	newest int64 // issue time of the newest envelope accepted
}

// issuedFile keeps the newest accepted envelope's issue time across agent
// restarts, so a relay cannot replay an old generation to a restarted
// agent either.
func (a *Agent) issuedFile() string { return filepath.Join(a.State.Dir, "envelope-issued") }

func (a *Agent) loadNewest() {
	b, err := os.ReadFile(a.issuedFile())
	if err == nil {
		a.newest, _ = strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	}
}

func (a *Agent) saveNewest(t int64) {
	if t <= a.newest {
		return
	}
	a.newest = t
	tmp := a.issuedFile() + ".tmp"
	err := os.MkdirAll(a.State.Dir, 0o700)
	if err == nil {
		err = os.WriteFile(tmp, []byte(strconv.FormatInt(t, 10)+"\n"), 0o600)
	}
	if err == nil {
		err = os.Rename(tmp, a.issuedFile())
	}
	if err != nil {
		a.logf("saving envelope time: %v", err)
	}
}

type remote = server.AgentManifest

func (a *Agent) logf(format string, args ...any) {
	if a.Logf != nil {
		a.Logf(format, args...)
	}
}

func (a *Agent) defaults() {
	if a.Verify == 0 {
		a.Verify = time.Minute
	}
	if a.ReadyAfter == 0 {
		a.ReadyAfter = 45 * time.Second
	}
	if a.Client == nil {
		a.Client = &http.Client{Timeout: a.Verify + 30*time.Second}
	}
	if a.Hook == nil {
		a.Hook = runHook
	}
}

// Run reconciles until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	a.defaults()
	a.loadNewest()
	applied, err := a.State.Load()
	if err != nil {
		return fmt.Errorf("agent state: %w", err)
	}
	have := -1 // ask for the current generation immediately
	if len(applied.Entries) > 0 || applied.Generation > 0 {
		have = int(applied.Generation)
	}
	ready := false
	readyTimer := time.AfterFunc(a.ReadyAfter, func() { a.signalReady(&ready) })
	defer readyTimer.Stop()
	lastVerify := time.Now()
	backoff := time.Second

	for ctx.Err() == nil {
		// Jittered, so a thousand nodes that switched together do not
		// all re-poll and verify in the same second ever after.
		wait := jitter(a.Verify)
		if have < 0 {
			wait = 0
		}
		r, err := a.fetch(ctx, have, wait)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			d := jitter(backoff)
			a.logf("server: %v (retrying in %s)", err, d.Round(time.Millisecond))
			sleep(ctx, d)
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		if r.Generation != have {
			rep := a.apply(ctx, &applied, r)
			a.send(ctx, rep)
			if rep.Error != "" {
				a.logf("generation %d: %s", r.Generation, rep.Error)
				sleep(ctx, jitter(5*time.Second))
				continue
			}
			have = r.Generation
			lastVerify = time.Now()
			readyTimer.Stop()
			a.signalReady(&ready)
			continue
		}
		if time.Since(lastVerify) >= a.Verify {
			lastVerify = time.Now()
			a.send(ctx, a.verify(ctx, &applied, have))
		}
	}
	return nil
}

func (a *Agent) signalReady(done *bool) {
	if !*done && a.Ready != nil {
		*done = true
		a.Ready()
	}
}

func (a *Agent) fetch(ctx context.Context, have int, wait time.Duration) (remote, error) {
	var r remote
	url := fmt.Sprintf("%s/agent/v1/manifest?have=%d&wait=%s", a.Server, have, wait)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return r, err
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return r, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return r, err
	}
	if r.Manifest.Entries == nil {
		r.Manifest.Entries = map[string]overlay.Entry{}
	}
	r.Manifest.Generation = uint64(r.Generation)
	if a.Node != "" && r.Node != a.Node {
		return r, fmt.Errorf("server sent %q's manifest to %q", r.Node, a.Node)
	}
	if a.TrustKey == nil {
		return r, errors.New("no generation key: refusing unsigned generations")
	}
	if r.Envelope == nil {
		return r, errors.New("generation is not signed")
	}
	if err := r.Envelope.Check(a.TrustKey, r.Node, r.Generation, overlay.ManifestDigest(r.Manifest)); err != nil {
		return r, fmt.Errorf("refusing generation %d: %w", r.Generation, err)
	}
	if err := r.Envelope.Fresh(a.newest); err != nil {
		return r, fmt.Errorf("refusing generation %d: %w", r.Generation, err)
	}
	a.saveNewest(r.Envelope.Issued)
	return r, nil
}

// content fetches overlay content by digest; the applier verifies it.
type content struct {
	a   *Agent
	ctx context.Context
}

func (c content) Open(d string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, c.a.Server+"/agent/v1/content/"+d, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.a.Client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("content %s: %s", d, resp.Status)
	}
	if resp.Header.Get("Content-Type") != pki.SealedContentType {
		return resp.Body, nil
	}
	// A secret, sealed to this node: relays never see it in the clear. The
	// applier still checks what it opens to against the signed manifest.
	defer resp.Body.Close()
	if c.a.Unseal == nil {
		return nil, fmt.Errorf("content %s is sealed and this agent has no seal key", d)
	}
	blob, err := io.ReadAll(io.LimitReader(resp.Body, 80<<20))
	if err != nil {
		return nil, err
	}
	plain, err := c.a.Unseal(d, blob)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(plain)), nil
}

func (a *Agent) applier(ctx context.Context) *overlay.Applier {
	return &overlay.Applier{Root: a.Root, Content: content{a, ctx}, Pristine: a.Pristine, Chown: os.Geteuid() == 0}
}

func (a *Agent) apply(ctx context.Context, applied *overlay.Manifest, r remote) server.AgentReport {
	rep := server.AgentReport{Generation: r.Generation}
	next, err := overlay.ResolveOwners(r.Manifest, a.Root.FS())
	if err != nil {
		rep.Error = err.Error()
		return rep
	}
	if err := a.State.Begin(next); err != nil {
		rep.Error = err.Error()
		return rep
	}
	res, err := a.applier(ctx).Apply(*applied, next)
	rep.Changes = res.Applied
	// What was written is labelled, and its hooks owed, even if the apply
	// stopped partway: the retry finds those files in place and would not
	// count them as changes.
	a.relabel(res.Applied)
	if herr := a.State.OweHooks(res.Hooks); err == nil {
		err = herr
	}
	if err != nil {
		rep.Error = err.Error()
		return rep
	}
	if err := a.State.Commit(next); err != nil {
		rep.Error = err.Error()
		return rep
	}
	*applied = next
	hooks := a.owedHooks(res.Hooks)
	rep.Hooks = a.runHooks(ctx, hooks)
	a.paidHooks()
	a.logf("generation %d applied: %d changes, %d hooks", r.Generation, len(res.Applied), len(hooks))
	for _, c := range res.Applied {
		a.logf("  %s %s", c.Action, c.Path)
	}
	rep.Changes = trim(res.Applied)
	return rep
}

// verify reports drift and repairs what the overlay enforces.
func (a *Agent) verify(ctx context.Context, applied *overlay.Manifest, gen int) server.AgentReport {
	rep := server.AgentReport{Generation: gen}
	ap := a.applier(ctx)
	drift, err := ap.Verify(*applied)
	if err != nil {
		rep.Error = err.Error()
		return rep
	}
	if slices.ContainsFunc(drift, func(d overlay.Drift) bool { return d.Policy == overlay.PolicyEnforce || d.Policy == "" }) {
		res, err := ap.Apply(*applied, *applied)
		a.relabel(res.Applied)
		if herr := a.State.OweHooks(res.Hooks); err == nil {
			err = herr
		}
		if err != nil {
			rep.Error = err.Error()
			return rep
		}
		rep.Repaired = len(res.Applied)
		rep.Hooks = a.runHooks(ctx, a.owedHooks(res.Hooks))
		a.paidHooks()
		for _, c := range res.Applied {
			a.logf("repaired drift: %s %s", c.Action, c.Path)
		}
		if drift, err = ap.Verify(*applied); err != nil {
			rep.Error = err.Error()
		}
	}
	rep.Drift = drift
	return rep
}

// owedHooks is every hook owed (State.OweHooks), or this apply's own if
// the record cannot be read.
func (a *Agent) owedHooks(hooks []string) []string {
	owed, err := a.State.Hooks()
	if err != nil {
		a.logf("reading owed hooks: %v", err)
		return hooks
	}
	return owed
}

func (a *Agent) paidHooks() {
	if err := a.State.PaidHooks(); err != nil {
		a.logf("clearing owed hooks: %v", err)
	}
}

func (a *Agent) relabel(cs []overlay.Change) {
	if a.Relabel == nil {
		return
	}
	var paths []string
	for _, c := range cs {
		if c.Action != overlay.ActionRemove {
			paths = append(paths, c.Path)
		}
	}
	if len(paths) > 0 {
		if err := a.Relabel(paths); err != nil {
			a.logf("relabel: %v", err)
		}
	}
}

func (a *Agent) runHooks(ctx context.Context, hooks []string) []server.HookResult {
	var out []server.HookResult
	for _, h := range hooks {
		o, err := a.Hook(ctx, h)
		r := server.HookResult{Command: h, Output: tail(o, 2048)}
		if err != nil {
			r.Error = err.Error()
			a.logf("hook %q: %v", h, err)
		}
		out = append(out, r)
	}
	return out
}

func runHook(ctx context.Context, cmd string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/sh", "-c", cmd).CombinedOutput()
	return string(out), err
}

func (a *Agent) send(ctx context.Context, rep server.AgentReport) {
	b, err := json.Marshal(rep)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.Server+"/agent/v1/status", bytes.NewReader(b))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.Client.Do(req)
	if err != nil {
		a.logf("report: %v", err)
		return
	}
	resp.Body.Close()
}

// trim drops entry details from changes before reporting.
func trim(cs []overlay.Change) []overlay.Change {
	out := make([]overlay.Change, len(cs))
	for i, c := range cs {
		out[i] = overlay.Change{Action: c.Action, Path: c.Path}
	}
	return out
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

// jitter returns a duration between d/2 and d, so nodes that failed or
// switched together (a head restart, a generation switch) spread out
// instead of returning in lockstep.
func jitter(d time.Duration) time.Duration {
	if d <= 1 {
		return d
	}
	return d/2 + rand.N(d/2)
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// KernelArgs returns flapjack.* parameters from the kernel command line.
func KernelArgs(cmdline string) map[string]string {
	out := map[string]string{}
	for _, f := range strings.Fields(cmdline) {
		if k, v, ok := strings.Cut(f, "="); ok && strings.HasPrefix(k, "flapjack.") {
			out[strings.TrimPrefix(k, "flapjack.")] = v
		}
	}
	return out
}

// NotifyReady tells systemd the service is ready (sd_notify READY=1).
func NotifyReady() error {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		return nil
	}
	if strings.HasPrefix(sock, "@") {
		sock = "\x00" + sock[1:]
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write([]byte("READY=1"))
	return err
}

// Restorecon relabels paths with restorecon when SELinux is enabled, so
// files the agent writes get the label policy expects (an authorized_keys
// written by a service is otherwise mislabelled and sshd ignores it).
func Restorecon(paths []string) error {
	if _, err := os.Stat("/sys/fs/selinux/enforce"); err != nil {
		return nil
	}
	bin, err := exec.LookPath("restorecon")
	if err != nil {
		return nil
	}
	out, err := exec.Command(bin, append([]string{"-F"}, paths...)...).CombinedOutput()
	if err != nil {
		return errors.New(strings.TrimSpace(string(out)))
	}
	return nil
}
