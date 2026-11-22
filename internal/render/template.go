package render

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"text/template"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/overlay"
)

// TemplateSuffix marks a file as a template, as in Warewulf.
const TemplateSuffix = ".ww"

// templateMeta is a template overlay's optional overlay.json.
type templateMeta struct {
	// Paths sets metadata by node path or path.Match glob ("/etc/slurm/*").
	Paths map[string]Meta `json:"paths,omitempty"`
	// Directories to manage explicitly (mode, owner). Other directories in
	// rootfs/ are only containers: they are created as needed but never
	// chmod-ed or removed.
	Directories map[string]Meta `json:"directories,omitempty"`
	// Secrets adds files whose content is a secret: node path → Meta with
	// Secret set.
	Secrets map[string]Meta `json:"secrets,omitempty"`
	// Exclusive directories hold exactly what the overlays declare.
	Exclusive []string `json:"exclusive,omitempty"`
}

// TemplateData is what a .ww template sees. Id, Hostname and Ipaddr match
// Warewulf's names for the same values.
type TemplateData struct {
	Node    Node
	Nodes   []Node
	Class   v1.NodeClass
	Server  string
	Domain  string
	Overlay string

	Id, Hostname, Ipaddr string
}

var errAbort = errors.New("abort")

func (r *Renderer) template(s Source, n Node, class v1.NodeClass, cl Cluster, o *Output) error {
	var meta templateMeta
	if b, err := os.ReadFile(filepath.Join(s.Dir, "overlay.json")); err == nil {
		if err := jsonStrict(b, &meta); err != nil {
			return fmt.Errorf("overlay %s: overlay.json: %w", s.Name, err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	root, err := os.OpenRoot(filepath.Join(s.Dir, "rootfs"))
	if err != nil {
		return err
	}
	defer root.Close()
	data := TemplateData{Node: n, Nodes: cl.Nodes, Class: class, Server: cl.Server, Domain: cl.Domain, Overlay: s.Name,
		Id: n.Name, Hostname: n.Name, Ipaddr: n.IP}

	metaFor := func(p string) (Meta, error) {
		var m Meta
		for pat, pm := range meta.Paths {
			ok, err := path.Match(pat, p)
			if err != nil {
				return m, fmt.Errorf("overlay %s: bad pattern %q: %w", s.Name, pat, err)
			}
			if ok || pat == p {
				m = pm
				if pat == p {
					break // an exact path beats a glob
				}
			}
		}
		return m, nil
	}

	err = fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil || rel == "." {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		nodePath := "/" + rel
		switch {
		case d.IsDir():
			return nil
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := root.Readlink(rel)
			if err != nil {
				return err
			}
			o.put(nodePath, overlay.Entry{Kind: overlay.KindSymlink, Target: target}, nil, s.Name)
			return nil
		case !info.Mode().IsRegular():
			return fmt.Errorf("overlay %s: %s is not a regular file", s.Name, rel)
		}
		content, err := root.ReadFile(rel)
		if err != nil {
			return err
		}
		if strings.HasSuffix(rel, TemplateSuffix) {
			nodePath = strings.TrimSuffix(nodePath, TemplateSuffix)
			content, err = r.execTemplate(s, rel, string(content), data)
			if errors.Is(err, errAbort) {
				return nil // the template chose not to produce a file for this node
			}
			if err != nil {
				return err
			}
		}
		e := overlay.Entry{Kind: overlay.KindFile, Mode: overlay.Mode(info.Mode().Perm())}
		m, err := metaFor(nodePath)
		if err != nil {
			return err
		}
		if err := m.apply(&e); err != nil {
			return fmt.Errorf("overlay %s: %s: %w", s.Name, nodePath, err)
		}
		o.put(nodePath, e, content, s.Name)
		return nil
	})
	if err != nil {
		return err
	}
	for p, m := range meta.Directories {
		if _, err := cleanAbs(p); err != nil {
			return fmt.Errorf("overlay %s: %w", s.Name, err)
		}
		e := overlay.Entry{Kind: overlay.KindDir}
		if err := m.apply(&e); err != nil {
			return err
		}
		o.put(p, e, nil, s.Name)
	}
	for p, m := range meta.Secrets {
		if _, err := cleanAbs(p); err != nil {
			return fmt.Errorf("overlay %s: %w", s.Name, err)
		}
		b, err := r.secret(m.Secret)
		if err != nil {
			return fmt.Errorf("overlay %s: %s: %w", s.Name, p, err)
		}
		e := overlay.Entry{Kind: overlay.KindFile, Mode: 0o600, Secret: true}
		if err := m.apply(&e); err != nil {
			return err
		}
		o.put(p, e, b, s.Name)
	}
	o.Manifest.Exclusive = append(o.Manifest.Exclusive, meta.Exclusive...)
	return nil
}

func (r *Renderer) execTemplate(s Source, name, text string, data TemplateData) ([]byte, error) {
	funcs := template.FuncMap{
		// Include reads a file from the overlay directory or the shared
		// files directory (relative paths), never from anywhere else.
		"Include": func(p string) (string, error) { return r.include(s, p) },
		"abort":   func() (string, error) { return "", errAbort },
		"join":    strings.Join,
		"split":   strings.Split,
		"lower":   strings.ToLower,
		"upper":   strings.ToUpper,
		"trim":    strings.TrimSpace,
		"replace": strings.ReplaceAll,
		"hasPrefix": func(s, prefix string) bool {
			return strings.HasPrefix(s, prefix)
		},
		"inRack": func(rack string) []Node { return filter(data.Nodes, func(n Node) bool { return n.Rack == rack }) },
		"inClass": func(class string) []Node {
			return filter(data.Nodes, func(n Node) bool { return n.Class == class })
		},
		"label": func(n Node, k string) string { return n.Labels[k] },
	}
	t, err := template.New(name).Funcs(funcs).Option("missingkey=error").Parse(text)
	if err != nil {
		return nil, fmt.Errorf("overlay %s: %w", s.Name, err)
	}
	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		if errors.Is(err, errAbort) {
			return nil, errAbort
		}
		return nil, fmt.Errorf("overlay %s: %w", s.Name, err)
	}
	return b.Bytes(), nil
}

func (r *Renderer) include(s Source, p string) (string, error) {
	p = strings.TrimPrefix(p, "/")
	for _, dir := range []string{s.Dir, r.FilesDir} {
		if dir == "" {
			continue
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			continue
		}
		b, err := root.ReadFile(p)
		root.Close()
		if err == nil {
			return string(b), nil
		}
	}
	return "", fmt.Errorf("Include %q: not found in the overlay or %s", p, r.FilesDir)
}

func filter(ns []Node, keep func(Node) bool) []Node {
	var out []Node
	for _, n := range ns {
		if keep(n) {
			out = append(out, n)
		}
	}
	return out
}
