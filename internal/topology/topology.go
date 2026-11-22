// Package topology models the physical fabric, validates cabling against a
// blueprint and generates scheduler topology configuration from what was
// actually discovered.
package topology

import (
	"bufio"
	"cmp"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// Kind is an endpoint device type.
type Kind string

const (
	Switch Kind = "switch"
	Host   Kind = "host"
)

// Endpoint is one port on one device. Hosts with several HCAs (one per
// GPU rail) are told apart by HCA; without it node01's mlx5_0 port 1 and
// mlx5_1 port 1 would be the same endpoint.
type Endpoint struct {
	Device string `json:"device"`
	Kind   Kind   `json:"kind"`
	Port   int    `json:"port"`
	HCA    string `json:"hca,omitempty"`  // host adapter ("mlx5_3"); hosts only
	GUID   string `json:"guid,omitempty"` // port GUID as discovered; not compared
}

func (e Endpoint) String() string {
	if e.HCA != "" {
		return fmt.Sprintf("%s/%s:%d", e.Device, e.HCA, e.Port)
	}
	return fmt.Sprintf("%s:%d", e.Device, e.Port)
}

func (e Endpoint) key() string { return e.String() }

// Link is a cable between two endpoints.
type Link struct {
	A    Endpoint `json:"a"`
	B    Endpoint `json:"b"`
	Rate string   `json:"rate,omitempty"` // "4x NDR"
}

// norm orders endpoints so the same cable always compares equal.
func (l Link) norm() Link {
	if l.B.key() < l.A.key() {
		l.A, l.B = l.B, l.A
	}
	return l
}

func (l Link) String() string { return l.A.String() + " <-> " + l.B.String() }

// Fabric is a set of links.
type Fabric struct {
	Links []Link `json:"links"`
}

// ibnetdiscover -p prints one line per connected port, from each side:
//
//	SW  2  19 0x0002c9030045f8c0 4x NDR - CA  1  1 0x0002c903000ee2a1 ( 'leaf01' - 'node01 mlx5_0' )
//
// The rate is matched loosely: newer infiniband-diags print rates such as
// "4x 53.125 Gbps" for speeds they have no name for.
var ibPortLine = regexp.MustCompile(`^(SW|CA|RT)\s+\d+\s+(\d+)\s+(0x[0-9a-fA-F]+)\s+(\S+(?:\s+\S+)*?)\s+-\s+(SW|CA|RT)\s+\d+\s+(\d+)\s+(0x[0-9a-fA-F]+)\s+\(\s*'([^']*)'\s+-\s+'([^']*)'\s*\)`)

// HostName splits an HCA's node description ("node01 mlx5_0") into the
// host it belongs to and the adapter name. The default matches the usual
// "<hostname> <hca>" node description; sites with other conventions
// replace it.
var HostName = func(desc string) (host, hca string) {
	host, hca, _ = strings.Cut(strings.TrimSpace(desc), " ")
	if host == "" {
		host = "?"
	}
	return host, strings.TrimSpace(hca)
}

// ParseIBNetDiscover reads `ibnetdiscover -p` output. Unconnected ports are
// skipped and each cable, printed once from each side, is kept once.
// Validate against output from your fabric: node descriptions and switch
// names are site-configured.
func ParseIBNetDiscover(r io.Reader) (Fabric, error) {
	seen := map[Link]bool{}
	var f Fabric
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		m := ibPortLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		ep := func(typ, port, guid, desc string) Endpoint {
			e := Endpoint{Kind: Switch, Device: desc, GUID: strings.ToLower(guid)}
			if typ == "CA" {
				e.Kind = Host
				e.Device, e.HCA = HostName(desc)
			}
			fmt.Sscan(port, &e.Port)
			return e
		}
		l := Link{A: ep(m[1], m[2], m[3], m[8]), B: ep(m[5], m[6], m[7], m[9]), Rate: m[4]}.norm()
		k := l
		k.Rate = ""
		if seen[k] {
			continue
		}
		seen[k] = true
		f.Links = append(f.Links, l)
	}
	return f, sc.Err()
}

// FindingKind classifies a cabling problem.
type FindingKind string

const (
	Missing    FindingKind = "missing"    // expected cable absent; neither end connected
	Miswired   FindingKind = "miswired"   // an expected end is connected somewhere else
	WrongRate  FindingKind = "rate"       // cable present at the wrong rate
	Unexpected FindingKind = "unexpected" // cable on a blueprint device the blueprint does not list
)

// Finding is one cabling problem.
type Finding struct {
	Kind     FindingKind `json:"kind"`
	Expected *Link       `json:"expected,omitempty"`
	Observed []Link      `json:"observed,omitempty"`
	Message  string      `json:"message"`
}

// Validate compares the observed fabric with the blueprint. Devices the
// blueprint does not mention are ignored, so a partial blueprint (one rack)
// can be checked against a full fabric scan.
//
// A blueprint that names no HCA for a host is matched against that host's
// ports whatever adapter they are on, so single-rail blueprints written
// without HCAs keep working; naming HCAs makes multi-rail hosts exact.
func Validate(blueprint, observed Fabric) []Finding {
	railed := map[string]bool{}
	for _, l := range blueprint.Links {
		for _, e := range []Endpoint{l.A, l.B} {
			if e.HCA != "" {
				railed[e.Device] = true
			}
		}
	}
	strip := func(e Endpoint) Endpoint {
		if e.Kind == Host && !railed[e.Device] {
			e.HCA = ""
		}
		return e
	}
	obs := make([]Link, len(observed.Links))
	for i, l := range observed.Links {
		l.A, l.B = strip(l.A), strip(l.B)
		obs[i] = l
	}
	observed = Fabric{Links: obs}
	byEnd := map[string]Link{}
	obsSet := map[[2]string]Link{}
	for _, l := range observed.Links {
		l = l.norm()
		byEnd[l.A.key()], byEnd[l.B.key()] = l, l
		obsSet[[2]string{l.A.key(), l.B.key()}] = l
	}
	devices := map[string]bool{}
	expected := map[[2]string]bool{}
	explained := map[[2]string]bool{}
	var out []Finding

	for _, e := range blueprint.Links {
		e = e.norm()
		devices[e.A.Device], devices[e.B.Device] = true, true
		k := [2]string{e.A.key(), e.B.key()}
		expected[k] = true
		if o, ok := obsSet[k]; ok {
			if e.Rate != "" && o.Rate != e.Rate {
				out = append(out, Finding{Kind: WrongRate, Expected: &e, Observed: []Link{o},
					Message: fmt.Sprintf("%s runs at %s, expected %s", e, o.Rate, e.Rate)})
			}
			continue
		}
		var wrong []Link
		var where []string
		for _, end := range []Endpoint{e.A, e.B} {
			if o, ok := byEnd[end.key()]; ok {
				other := o.B
				if o.B.key() == end.key() {
					other = o.A
				}
				wrong = append(wrong, o)
				where = append(where, fmt.Sprintf("%s goes to %s", end, other))
				explained[[2]string{o.A.key(), o.B.key()}] = true
			}
		}
		if len(wrong) == 0 {
			out = append(out, Finding{Kind: Missing, Expected: &e, Message: fmt.Sprintf("%s not connected", e)})
		} else {
			out = append(out, Finding{Kind: Miswired, Expected: &e, Observed: wrong,
				Message: fmt.Sprintf("expected %s, but %s", e, strings.Join(where, "; "))})
		}
	}
	for _, o := range observed.Links {
		o = o.norm()
		k := [2]string{o.A.key(), o.B.key()}
		if expected[k] || explained[k] || !(devices[o.A.Device] || devices[o.B.Device]) {
			continue
		}
		out = append(out, Finding{Kind: Unexpected, Observed: []Link{o}, Message: fmt.Sprintf("%s is not in the blueprint", o)})
	}
	slices.SortStableFunc(out, func(a, b Finding) int { return cmp.Compare(a.Message, b.Message) })
	return out
}

// CheckBlueprint reports blueprint mistakes that would make validation
// meaningless: a port used by two cables, or a cable from a port to itself.
func CheckBlueprint(bp Fabric) error {
	used := map[string]Link{}
	var errs []string
	for _, l := range bp.Links {
		if l.A.key() == l.B.key() {
			errs = append(errs, fmt.Sprintf("%s is connected to itself", l.A))
			continue
		}
		for _, e := range []Endpoint{l.A, l.B} {
			if prev, ok := used[e.key()]; ok {
				errs = append(errs, fmt.Sprintf("%s is used by both %s and %s", e, prev, l))
			}
			used[e.key()] = l
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("blueprint: %s", strings.Join(errs, "; "))
	}
	return nil
}

// SlurmTree renders a Slurm topology/tree configuration: each leaf switch
// lists its hosts and each higher switch lists the switches one level
// below it. Levels are assigned breadth-first from the leaves, so this
// handles two- and three-tier fat trees.
func SlurmTree(f Fabric) string { return SlurmTreeRail(f, "") }

// SlurmTreeRail is SlurmTree using only host links on one HCA ("mlx5_0").
// On rail-optimized fabrics every host connects to one leaf per rail, so
// the full fabric would list each host under several leaves; one rail
// gives Slurm the single leaf per host it expects. hca "" uses every link.
func SlurmTreeRail(f Fabric, hca string) string {
	hosts := map[string][]string{}      // leaf → hosts
	adj := map[string]map[string]bool{} // switch ↔ switch
	addAdj := func(a, b string) {
		if adj[a] == nil {
			adj[a] = map[string]bool{}
		}
		adj[a][b] = true
	}
	for _, l := range f.Links {
		if hca != "" && ((l.A.Kind == Host && l.A.HCA != hca) || (l.B.Kind == Host && l.B.HCA != hca)) {
			continue
		}
		switch {
		case l.A.Kind == Switch && l.B.Kind == Host:
			hosts[l.A.Device] = append(hosts[l.A.Device], l.B.Device)
		case l.B.Kind == Switch && l.A.Kind == Host:
			hosts[l.B.Device] = append(hosts[l.B.Device], l.A.Device)
		case l.A.Kind == Switch && l.B.Kind == Switch && l.A.Device != l.B.Device:
			addAdj(l.A.Device, l.B.Device)
			addAdj(l.B.Device, l.A.Device)
		}
	}
	level := map[string]int{}
	frontier := slices.Sorted(maps.Keys(hosts))
	for _, s := range frontier {
		level[s] = 0
	}
	children := map[string][]string{}
	for depth := 1; len(frontier) > 0; depth++ {
		var next []string
		for _, s := range frontier {
			for _, up := range slices.Sorted(maps.Keys(adj[s])) {
				lv, seen := level[up]
				if !seen {
					level[up] = depth
					next = append(next, up)
					lv = depth
				}
				if lv == depth {
					children[up] = append(children[up], s)
				}
			}
		}
		frontier = next
	}

	var b strings.Builder
	for _, s := range slices.Sorted(maps.Keys(hosts)) {
		fmt.Fprintf(&b, "SwitchName=%s Nodes=%s\n", s, Hostlist(hosts[s]))
	}
	uppers := slices.Collect(maps.Keys(children))
	slices.SortFunc(uppers, func(a, b string) int { return cmp.Or(cmp.Compare(level[a], level[b]), cmp.Compare(a, b)) })
	for _, s := range uppers {
		fmt.Fprintf(&b, "SwitchName=%s Switches=%s\n", s, Hostlist(children[s]))
	}
	return b.String()
}

// SlurmBlocks renders a Slurm topology/block configuration from a
// block → hosts map (leaf switch groups or NVLink domains such as NVL72
// racks).
func SlurmBlocks(blocks map[string][]string, sizes []int) string {
	var b strings.Builder
	for _, name := range slices.Sorted(maps.Keys(blocks)) {
		fmt.Fprintf(&b, "BlockName=%s Nodes=%s\n", name, Hostlist(blocks[name]))
	}
	if len(sizes) > 0 {
		s := make([]string, len(sizes))
		for i, n := range sizes {
			s[i] = fmt.Sprint(n)
		}
		fmt.Fprintf(&b, "BlockSizes=%s\n", strings.Join(s, ","))
	}
	return b.String()
}

// HostGUIDs returns each host's HCA port GUIDs as discovered, sorted. The
// subnet manager places ports in partitions by these GUIDs.
func HostGUIDs(f Fabric) map[string][]string {
	out := map[string][]string{}
	for _, l := range f.Links {
		for _, e := range []Endpoint{l.A, l.B} {
			if e.Kind == Host && e.GUID != "" && !slices.Contains(out[e.Device], e.GUID) {
				out[e.Device] = append(out[e.Device], e.GUID)
			}
		}
	}
	for _, g := range out {
		slices.Sort(g)
	}
	return out
}
