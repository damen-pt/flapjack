package tentacle

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/damen-pt/flapjack/internal/attest"
	"github.com/damen-pt/flapjack/internal/server"
	"github.com/damen-pt/flapjack/internal/staging"
)

// Boot images: the head lists the image versions the rack boots in each
// snapshot; the tentacle fetches their chunks once (from the head's
// staging origin), assembles each file under Images/<version>/, and
// serves them to the rack's iPXE and dracut over HTTPS. A version is
// reported to the head as staged only once every file is assembled and
// verified against the manifest the head sent, so the head never sends
// a node to a tentacle that cannot serve it.

const imageManifest = "manifest.json"

// wantImages hands the stager the latest snapshot's images and iPXE
// binaries.
func (t *Tentacle) wantImages(imgs []server.BootImage, firmware []staging.Manifest) {
	if t.Images == "" && t.Firmware == "" {
		return
	}
	t.mu.Lock()
	t.wanted, t.wantedFirmware, t.haveWanted = imgs, firmware, true
	t.mu.Unlock()
	select {
	case t.restage <- struct{}{}:
	default:
	}
}

// stageLoop stages wanted images and reports what is staged: after each
// pass and every Report interval, so the head's view stays fresh.
func (t *Tentacle) stageLoop(ctx context.Context) {
	every := t.Report
	if every <= 0 {
		every = time.Minute
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		t.mu.Lock()
		want, fw, have := t.wanted, t.wantedFirmware, t.haveWanted
		t.mu.Unlock()
		if have && t.Firmware != "" {
			t.stageFirmware(ctx, fw)
		}
		if have && t.Images != "" {
			t.stage(ctx, want)
		}
		if t.Images != "" {
			t.reportImages(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.restage:
		case <-tick.C:
		}
	}
}

func (t *Tentacle) stage(ctx context.Context, want []server.BootImage) {
	keep := map[string]bool{}
	for _, img := range want {
		if !validVersion(img.Version) {
			t.logf("tentacle %s: head sent image version %q; ignoring it", t.Rack, img.Version)
			continue
		}
		keep[img.Version] = true
		if t.staged(img) {
			continue
		}
		start := time.Now()
		if err := t.stageOne(ctx, img); err != nil {
			if ctx.Err() == nil {
				t.logf("tentacle %s: staging image %s: %v", t.Rack, img.Version, err)
			}
			continue
		}
		t.logf("tentacle %s: staged image %s in %s", t.Rack, img, time.Since(start).Round(time.Millisecond))
	}
	// Versions the rack no longer boots, and leftovers of failed passes.
	ents, _ := os.ReadDir(t.Images)
	for _, e := range ents {
		if !keep[e.Name()] {
			os.RemoveAll(filepath.Join(t.Images, e.Name()))
		}
	}
}

// staged reports whether img is assembled under Images exactly as the
// head describes it now.
func (t *Tentacle) staged(img server.BootImage) bool {
	b, err := os.ReadFile(filepath.Join(t.Images, img.Version, imageManifest))
	if err != nil {
		return false
	}
	var got server.BootImage
	return json.Unmarshal(b, &got) == nil && reflect.DeepEqual(got, img)
}

func (t *Tentacle) stageOne(ctx context.Context, img server.BootImage) error {
	if err := os.MkdirAll(t.Images, 0o755); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(t.Images, "."+img.Version+"-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	f := staging.Fetcher{Store: t.Artifacts, Client: t.Up, Parallel: max(t.Parallel, 4),
		Sources: []staging.Source{{Name: "head", URL: t.Head + "/tentacle/v1", Tier: staging.TierOrigin}}}
	for name, m := range img.Files {
		if !slices.Contains(server.BootFiles, name) {
			continue
		}
		if _, err := f.Fetch(ctx, m, filepath.Join(tmp, name)); err != nil { // verifies the whole file
			return err
		}
		os.Chmod(filepath.Join(tmp, name), 0o644)
	}
	for name, sig := range img.Signatures {
		if !slices.Contains(server.SignedFiles, name) {
			continue
		}
		if err := os.WriteFile(filepath.Join(tmp, name+".sig"), sig, 0o644); err != nil {
			return err
		}
	}
	b, err := json.Marshal(img)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tmp, imageManifest), b, 0o644); err != nil {
		return err
	}
	os.Chmod(tmp, 0o755)
	dest := filepath.Join(t.Images, img.Version)
	os.RemoveAll(dest) // a stale copy from a different manifest
	return os.Rename(tmp, dest)
}

// stagedVersions lists the versions fully staged on disk.
func (t *Tentacle) stagedVersions() []string {
	var out []string
	ents, _ := os.ReadDir(t.Images)
	for _, e := range ents {
		if validVersion(e.Name()) && e.IsDir() {
			if _, err := os.Stat(filepath.Join(t.Images, e.Name(), imageManifest)); err == nil {
				out = append(out, e.Name())
			}
		}
	}
	return out
}

func (t *Tentacle) reportImages(ctx context.Context) {
	vs := t.stagedVersions()
	if vs == nil {
		vs = []string{}
	}
	if err := t.postJSON(ctx, "/tentacle/v1/images", server.StagedImages{Versions: vs}); err != nil && ctx.Err() == nil {
		t.logf("tentacle %s: reporting staged images: %v", t.Rack, err)
	}
}

func validVersion(v string) bool {
	return v != "" && v != "." && v != ".." && !strings.HasPrefix(v, ".") && !strings.ContainsAny(v, `/\`)
}

// BootHandler serves staged boot images to the rack at
// /images/<version>/<token>/{vmlinuz,initrd.img,rootfs.squashfs}, each
// only with an image token the head minted into that node's script, from
// the address it names. iPXE and dracut have no client certificate, so
// this listener proves the tentacle to them (with a boot-CA certificate)
// and encrypts; the token is what keeps the images to booting nodes.
func (t *Tentacle) BootHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /images/{version}/{token}/{file}", func(w http.ResponseWriter, r *http.Request) {
		v, f := r.PathValue("version"), r.PathValue("file")
		signed, isSig := strings.CutSuffix(f, ".sig")
		if !validVersion(v) || !(slices.Contains(server.BootFiles, f) || isSig && slices.Contains(server.SignedFiles, signed)) {
			http.NotFound(w, r)
			return
		}
		t.mu.Lock()
		key := t.imageKey
		t.mu.Unlock()
		if !server.ImageAllowed(w, r, &attest.ImageTokens{Key: key}, v) {
			return
		}
		os.MkdirAll(t.Images, 0o755)
		root, err := os.OpenRoot(t.Images)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer root.Close()
		if _, err := root.Stat(v + "/" + imageManifest); err != nil {
			http.NotFound(w, r) // not (completely) staged
			return
		}
		server.ServeFile(w, r, root, v+"/"+f)
	})
	// With the rack's DHCP: scripts (relayed from the head) and iPXE
	// binaries for firmware that loads iPXE over HTTPS.
	mux.HandleFunc("GET /boot/{file}", func(w http.ResponseWriter, r *http.Request) {
		f := r.PathValue("file")
		if mac, ok := strings.CutSuffix(f, ".ipxe.sig"); ok {
			t.scriptSig(w, r, mac)
			return
		}
		if mac, ok := strings.CutSuffix(f, ".ipxe"); ok {
			t.script(w, r, mac)
			return
		}
		t.serveFirmware(w, r, f)
	})
	return mux
}
