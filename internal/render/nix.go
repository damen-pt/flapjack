package render

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/overlay"
)

//go:embed harness.nix
var harness []byte

// Nix runs the nix overlay engine: pure evaluation with a dummy store, so
// it needs no /nix, no daemon and no root, and builds nothing.
type Nix struct {
	Bin     string // nix binary
	Nixpkgs string // directory containing nixpkgs' lib/
	WorkDir string // scratch space for the harness and inputs
	Timeout time.Duration
}

type nixFile struct {
	Meta
	Text   *string `json:"text"`
	Source *string `json:"source"`
	Secret *string `json:"secret"`
}

type nixResult struct {
	Errors      []string           `json:"errors"`
	Files       map[string]nixFile `json:"files"`
	Directories map[string]Meta    `json:"directories"`
	Symlinks    map[string]string  `json:"symlinks"`
	Exclusive   []string           `json:"exclusive"`
	Warnings    []string           `json:"warnings"`
}

// Available reports whether the nix engine is configured.
func (x Nix) Available() error {
	if x.Bin == "" || x.Nixpkgs == "" {
		return errors.New("the nix engine is not configured (set nix.bin and nix.nixpkgs in server.json)")
	}
	if _, err := os.Stat(filepath.Join(x.Nixpkgs, "lib", "default.nix")); err != nil {
		return fmt.Errorf("nixpkgs lib not found: %w", err)
	}
	if _, err := exec.LookPath(x.Bin); err != nil {
		return fmt.Errorf("nix binary: %w", err)
	}
	return nil
}

func (x Nix) eval(mods []Source, class v1.NodeClass, nodes []Node, cl Cluster) (map[string]nixResult, error) {
	if err := x.Available(); err != nil {
		return nil, err
	}
	work, err := os.MkdirTemp(x.WorkDir, "nix-eval-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	harnessPath := filepath.Join(work, "harness.nix")
	if err := os.WriteFile(harnessPath, harness, 0o600); err != nil {
		return nil, err
	}
	var paths []string
	var dirs []string
	for _, m := range mods {
		abs, err := filepath.Abs(filepath.Join(m.Dir, "default.nix"))
		if err != nil {
			return nil, err
		}
		paths = append(paths, abs)
		dirs = append(dirs, filepath.Dir(abs))
	}
	in, err := json.Marshal(map[string]any{
		"nixpkgs": x.Nixpkgs, "modules": paths, "nodes": nodes, "cluster": cl,
		"class": map[string]any{"name": class.Name, "image": class.Image, "overlays": class.Overlays, "bootArgs": class.BootArgs},
	})
	if err != nil {
		return nil, err
	}
	inputPath := filepath.Join(work, "input.json")
	if err := os.WriteFile(inputPath, in, 0o600); err != nil {
		return nil, err
	}

	timeout := x.Timeout
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// --impure only lets the expression name the harness by absolute path;
	// restrict-eval still confines reads to the -I paths: the overlays being
	// evaluated, nixpkgs' lib and the harness. A module cannot read
	// secrets, other files on the server, or fetch anything.
	args := []string{"--extra-experimental-features", "nix-command", "eval", "--json", "--impure", "--store", "dummy://",
		"--option", "restrict-eval", "true", "--option", "allowed-uris", "",
		"-I", x.Nixpkgs, "-I", work}
	for _, d := range dirs {
		args = append(args, "-I", d)
	}
	args = append(args, "--expr", fmt.Sprintf("import %s { inputFile = %q; }", harnessPath, inputPath))
	cmd := exec.CommandContext(ctx, x.Bin, args...)
	cmd.Env = []string{"HOME=" + work, "XDG_CACHE_HOME=" + work, "PATH=/usr/bin:/bin", "NIX_CONFIG="}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		msg = strings.ReplaceAll(msg, work+"/", "")
		return nil, fmt.Errorf("nix evaluation failed: %v\n%s", err, msg)
	}
	var out map[string]nixResult
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return nil, fmt.Errorf("nix output: %w", err)
	}
	return out, nil
}

// nixApply layers one node's nix result onto o.
func (r *Renderer) nixApply(mods []Source, res nixResult, o *Output) error {
	name := mods[0].Name
	if len(mods) > 1 {
		var names []string
		for _, m := range mods {
			names = append(names, m.Name)
		}
		name = strings.Join(names, "+")
	}
	if len(res.Errors) > 0 {
		return fmt.Errorf("overlay %s: assertion failed: %s", name, strings.Join(res.Errors, "; "))
	}
	o.Warnings = append(o.Warnings, res.Warnings...)
	for p, f := range res.Files {
		if _, err := cleanAbs(p); err != nil {
			return fmt.Errorf("overlay %s: %w", name, err)
		}
		var content []byte
		set := 0
		if f.Text != nil {
			content, set = []byte(*f.Text), set+1
		}
		if f.Source != nil {
			b, err := readWithin(*f.Source, mods)
			if err != nil {
				return fmt.Errorf("overlay %s: %s: %w", name, p, err)
			}
			content, set = b, set+1
		}
		if f.Secret != nil {
			b, err := r.secret(*f.Secret)
			if err != nil {
				return fmt.Errorf("overlay %s: %s: %w", name, p, err)
			}
			content, set = b, set+1
		}
		if set != 1 {
			return fmt.Errorf("overlay %s: %s: set exactly one of text, source or secret", name, p)
		}
		e := overlay.Entry{Kind: overlay.KindFile, Secret: f.Secret != nil}
		if f.Secret != nil && f.Mode == "" {
			e.Mode = 0o600
		}
		if err := f.Meta.apply(&e); err != nil {
			return fmt.Errorf("overlay %s: %s: %w", name, p, err)
		}
		o.put(p, e, content, name)
	}
	for p, m := range res.Directories {
		if _, err := cleanAbs(p); err != nil {
			return fmt.Errorf("overlay %s: %w", name, err)
		}
		e := overlay.Entry{Kind: overlay.KindDir}
		if err := m.apply(&e); err != nil {
			return err
		}
		o.put(p, e, nil, name)
	}
	for p, target := range res.Symlinks {
		if _, err := cleanAbs(p); err != nil {
			return fmt.Errorf("overlay %s: %w", name, err)
		}
		o.put(p, overlay.Entry{Kind: overlay.KindSymlink, Target: target}, nil, name)
	}
	o.Manifest.Exclusive = append(o.Manifest.Exclusive, res.Exclusive...)
	return nil
}

// readWithin reads a module's source file, which must lie inside one of the
// overlay directories being evaluated.
func readWithin(p string, mods []Source) ([]byte, error) {
	for _, m := range mods {
		dir, err := filepath.Abs(m.Dir)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil || rel == ".." || strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) {
			continue
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			return nil, err
		}
		defer root.Close()
		return root.ReadFile(rel)
	}
	return nil, fmt.Errorf("source %s is outside the overlay directories", p)
}

func jsonStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
