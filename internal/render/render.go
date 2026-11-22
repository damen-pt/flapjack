// Package render turns overlay sources into per-node manifests on the
// server. Two engines produce the same manifest:
//
//   - template: a rootfs/ tree like Warewulf's; files ending in .ww are Go
//     templates rendered per node, everything else is copied as is.
//   - nix: a NixOS-style module (default.nix). All nix overlays of a class
//     are evaluated together with lib.evalModules, so one overlay can declare
//     typed options that another sets, with mkDefault/mkForce precedence,
//     list and text merging, and assertions.
//
// Overlays are layered in the order the class lists them; a later overlay's
// path replaces an earlier one's. Nodes never run an engine: they receive
// the manifest and content by digest.
package render

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/overlay"
)

// Node is what templates and modules see about a node. Credentials and
// status are deliberately absent.
type Node struct {
	Name     string            `json:"name"`
	Class    string            `json:"class"`
	Rack     string            `json:"rack"`
	Block    string            `json:"block,omitempty"`
	IP       string            `json:"ip"`
	MAC      string            `json:"mac"`
	Serial   string            `json:"serial,omitempty"`
	Firmware string            `json:"firmware,omitempty"`
	Labels   map[string]string `json:"labels"`
	// Interfaces are all of the node's NICs; IP and MAC are the first's.
	Interfaces []Interface `json:"interfaces"`
}

// Interface is one of a node's NICs.
type Interface struct {
	Name    string `json:"name"`
	MAC     string `json:"mac"`
	Network string `json:"network"`
	IP      string `json:"ip"`
}

// NodeOf converts an API node.
func NodeOf(n v1.Node) Node {
	out := Node{Name: n.Name, Class: n.Class, Rack: n.Rack, Block: n.Block, Serial: n.Serial,
		Firmware: string(n.Firmware), Labels: n.Labels}
	if out.Labels == nil {
		out.Labels = map[string]string{}
	}
	if len(n.Interfaces) > 0 {
		out.IP, out.MAC = n.Interfaces[0].IP, n.Interfaces[0].MAC
	}
	out.Interfaces = []Interface{}
	for _, i := range n.Interfaces {
		out.Interfaces = append(out.Interfaces, Interface{Name: i.Name, MAC: i.MAC, Network: i.Network, IP: i.IP})
	}
	return out
}

// Cluster is the shared context for one render.
type Cluster struct {
	Nodes  []Node `json:"nodes"`  // every node, sorted by name
	Server string `json:"server"` // head node provisioning address
	Domain string `json:"domain"`
}

// Renderer renders overlays from Dir.
type Renderer struct {
	Dir        string // one directory per overlay
	SecretsDir string // whole-file secrets referenced by "secret"
	FilesDir   string // shared files templates may Include
	Nix        Nix
}

// Output is one node's rendered overlays.
type Output struct {
	Manifest overlay.Manifest
	Content  map[string][]byte // digest → bytes
	Warnings []string
}

func (o *Output) put(p string, e overlay.Entry, data []byte, from string) {
	if old, ok := o.Manifest.Entries[p]; ok && old.Overlay != from {
		o.Warnings = append(o.Warnings, fmt.Sprintf("%s: overlay %s replaces %s", p, from, old.Overlay))
	}
	e.Overlay = from
	if e.Kind == overlay.KindFile {
		e.Digest = overlay.Digest(data)
		o.Content[e.Digest] = data
	}
	o.Manifest.Entries[p] = e
}

// Engine of an overlay.
type Engine string

const (
	EngineTemplate Engine = "template"
	EngineNix      Engine = "nix"
)

// Source is one overlay on disk.
type Source struct {
	Name   string `json:"name"`
	Engine Engine `json:"engine"`
	Dir    string `json:"dir"`
}

// Sources lists the overlays in Dir.
func (r *Renderer) Sources() ([]Source, error) {
	ents, err := os.ReadDir(r.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var out []Source
	for _, e := range ents {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		s, err := r.Source(e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// Source finds an overlay by name.
func (r *Renderer) Source(name string) (Source, error) {
	if !validName(name) {
		return Source{}, fmt.Errorf("invalid overlay name %q", name)
	}
	dir := filepath.Join(r.Dir, name)
	s := Source{Name: name, Dir: dir}
	_, nixErr := os.Stat(filepath.Join(dir, "default.nix"))
	_, tmplErr := os.Stat(filepath.Join(dir, "rootfs"))
	switch {
	case nixErr == nil && tmplErr == nil:
		return s, fmt.Errorf("overlay %s has both default.nix and rootfs/; use one engine per overlay", name)
	case nixErr == nil:
		s.Engine = EngineNix
	case tmplErr == nil:
		s.Engine = EngineTemplate
	default:
		if _, err := os.Stat(dir); err != nil {
			return s, fmt.Errorf("overlay %s does not exist in %s", name, r.Dir)
		}
		return s, fmt.Errorf("overlay %s has neither default.nix nor rootfs/", name)
	}
	return s, nil
}

func validName(s string) bool {
	return s != "" && !strings.HasPrefix(s, ".") && !strings.ContainsAny(s, `/\`) && fs.ValidPath(s)
}

// Render renders a class's overlays for each of nodes. Nix overlays are
// evaluated once for all nodes together.
func (r *Renderer) Render(class v1.NodeClass, nodes []Node, cl Cluster) (map[string]*Output, error) {
	var srcs []Source
	for _, name := range class.Overlays {
		s, err := r.Source(name)
		if err != nil {
			return nil, err
		}
		srcs = append(srcs, s)
	}
	var nixMods []Source
	for _, s := range srcs {
		if s.Engine == EngineNix {
			nixMods = append(nixMods, s)
		}
	}
	var nixOut map[string]nixResult
	if len(nixMods) > 0 && len(nodes) > 0 {
		var err error
		if nixOut, err = r.Nix.eval(nixMods, class, nodes, cl); err != nil {
			return nil, err
		}
	}

	out := map[string]*Output{}
	for _, n := range nodes {
		o := &Output{Manifest: overlay.Manifest{Entries: map[string]overlay.Entry{}}, Content: map[string][]byte{}}
		nixDone := false
		for _, s := range srcs {
			var err error
			switch {
			case s.Engine == EngineTemplate:
				err = r.template(s, n, class, cl, o)
			case !nixDone:
				// All nix overlays are one module set, layered at the
				// position of the first.
				nixDone = true
				err = r.nixApply(nixMods, nixOut[n.Name], o)
			}
			if err != nil {
				return nil, fmt.Errorf("node %s: %w", n.Name, err)
			}
		}
		o.Manifest.Exclusive = slices.Compact(slices.Sorted(slices.Values(o.Manifest.Exclusive)))
		if err := o.Manifest.Validate(); err != nil {
			return nil, fmt.Errorf("node %s: %w", n.Name, err)
		}
		out[n.Name] = o
	}
	return out, nil
}

// Meta is per-path metadata, in overlay.json (template) or a module's
// files.<path> (nix).
type Meta struct {
	Mode      string   `json:"mode,omitempty"`
	Owner     string   `json:"owner,omitempty"`
	Group     string   `json:"group,omitempty"`
	Policy    string   `json:"policy,omitempty"`
	SEContext string   `json:"seContext,omitempty"`
	OnChange  []string `json:"onChange,omitempty"`
	OnRemove  []string `json:"onRemove,omitempty"`
	// Secret names a file in the secrets directory whose bytes become the
	// content; the overlay source never holds the secret itself.
	Secret string `json:"secret,omitempty"`
}

func (m Meta) apply(e *overlay.Entry) error {
	if m.Mode != "" {
		var mode overlay.Mode
		if err := json.Unmarshal([]byte(`"`+m.Mode+`"`), &mode); err != nil {
			return err
		}
		e.Mode = mode
	}
	if m.Owner != "" && m.Owner != "root" {
		e.Owner = m.Owner
	}
	if m.Group != "" && m.Group != "root" {
		e.Group = m.Group
	}
	if m.Policy != "" {
		e.Policy = overlay.Policy(m.Policy)
	}
	if m.SEContext != "" {
		e.SEContext = m.SEContext
	}
	e.OnChange = append(e.OnChange, m.OnChange...)
	e.OnRemove = append(e.OnRemove, m.OnRemove...)
	return nil
}

func (r *Renderer) secret(name string) ([]byte, error) {
	if !validName(name) {
		return nil, fmt.Errorf("invalid secret name %q", name)
	}
	if r.SecretsDir == "" {
		return nil, errors.New("no secrets directory configured")
	}
	root, err := os.OpenRoot(r.SecretsDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.ReadFile(name)
}

// SortedNodes sorts nodes by name.
func SortedNodes(ns []Node) []Node {
	slices.SortFunc(ns, func(a, b Node) int { return cmp.Compare(a.Name, b.Name) })
	return ns
}

func cleanAbs(p string) (string, error) {
	if !path.IsAbs(p) || path.Clean(p) != p || p == "/" {
		return "", fmt.Errorf("invalid path %q: must be absolute and clean", p)
	}
	return p, nil
}
