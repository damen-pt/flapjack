package topology

import (
	"strings"
	"testing"
)

const ibnet = `
#
# Topology file: generated on Wed Nov  4 10:00:00 2026
#
SW     2     1 0x0002c9030045f8c0 4x NDR - CA     5     1 0x0002c903000ee2a1 ( 'leaf01' - 'node01 mlx5_0' )
SW     2     2 0x0002c9030045f8c0 4x NDR - CA     6     1 0x0002c903000ee2b1 ( 'leaf01' - 'node02 mlx5_0' )
SW     2    33 0x0002c9030045f8c0 4x NDR - SW     1     1 0x0002c9030045f000 ( 'leaf01' - 'spine01' )
SW     3     1 0x0002c9030045f9c0 4x HDR - CA     7     1 0x0002c903000ee2c1 ( 'leaf02' - 'node03 mlx5_0' )
SW     3    33 0x0002c9030045f9c0 4x NDR - SW     1     2 0x0002c9030045f000 ( 'leaf02' - 'spine01' )
SW     1     1 0x0002c9030045f000 4x NDR - SW     2    33 0x0002c9030045f8c0 ( 'spine01' - 'leaf01' )
CA     5     1 0x0002c903000ee2a1 4x NDR - SW     2     1 0x0002c9030045f8c0 ( 'node01 mlx5_0' - 'leaf01' )
SW     2     9 0x0002c9030045f8c0 4x ???                                    'leaf01'
`

func TestParseIBNetDiscover(t *testing.T) {
	f, err := ParseIBNetDiscover(strings.NewReader(ibnet))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Links) != 5 {
		t.Fatalf("each cable must appear once: %v", f.Links)
	}
	l := f.Links[0]
	if l.String() != "leaf01:1 <-> node01/mlx5_0:1" || l.Rate != "4x NDR" || l.B.Kind != Host || l.B.GUID != "0x0002c903000ee2a1" {
		t.Fatalf("first link = %+v", l)
	}
}

func link(a string, ap int, b string, bp int, rate string) Link {
	kind := func(d string) Kind {
		if strings.HasPrefix(d, "node") {
			return Host
		}
		return Switch
	}
	return Link{A: Endpoint{Device: a, Kind: kind(a), Port: ap}, B: Endpoint{Device: b, Kind: kind(b), Port: bp}, Rate: rate}
}

func TestValidate(t *testing.T) {
	blueprint := Fabric{Links: []Link{
		link("leaf01", 1, "node01", 1, "4x NDR"),
		link("leaf01", 2, "node02", 1, "4x NDR"),
		link("leaf02", 1, "node03", 1, "4x NDR"),
		link("leaf02", 2, "node04", 1, "4x NDR"),
	}}
	observed := Fabric{Links: []Link{
		link("leaf01", 1, "node01", 1, "4x NDR"),
		link("leaf01", 2, "node04", 1, "4x NDR"), // node02 and node04 cables swapped onto leaf01:2
		link("leaf02", 1, "node03", 1, "4x HDR"), // trained down
		link("leaf02", 7, "node99", 1, "4x NDR"), // not in blueprint
		link("leaf09", 1, "node42", 1, "4x NDR"), // device outside blueprint: ignored
	}}
	got := Validate(blueprint, observed)
	kinds := map[FindingKind]int{}
	var msgs []string
	for _, f := range got {
		kinds[f.Kind]++
		msgs = append(msgs, f.Message)
	}
	if kinds[Miswired] != 2 || kinds[WrongRate] != 1 || kinds[Unexpected] != 1 || kinds[Missing] != 0 || len(got) != 4 {
		t.Fatalf("findings:\n%s", strings.Join(msgs, "\n"))
	}
	all := strings.Join(msgs, "\n")
	for _, want := range []string{
		"expected leaf01:2 <-> node02:1, but leaf01:2 goes to node04:1",
		"leaf02:1 <-> node03:1 runs at 4x HDR, expected 4x NDR",
		"leaf02:7 <-> node99:1 is not in the blueprint",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
	if Validate(blueprint, Fabric{})[0].Kind != Missing {
		t.Error("empty fabric should report missing cables")
	}
}

func TestSlurmTree(t *testing.T) {
	f := Fabric{Links: []Link{
		link("leaf01", 1, "node01", 1, ""), link("leaf01", 2, "node02", 1, ""), link("leaf01", 3, "node03", 1, ""),
		link("leaf02", 1, "node04", 1, ""),
		link("leaf01", 33, "spine01", 1, ""), link("leaf02", 33, "spine01", 2, ""),
		link("leaf01", 34, "spine02", 1, ""), link("leaf02", 34, "spine02", 2, ""),
		link("spine01", 40, "core01", 1, ""), link("spine02", 40, "core01", 2, ""),
	}}
	want := "SwitchName=leaf01 Nodes=node[01-03]\n" +
		"SwitchName=leaf02 Nodes=node04\n" +
		"SwitchName=spine01 Switches=leaf[01-02]\n" +
		"SwitchName=spine02 Switches=leaf[01-02]\n" +
		"SwitchName=core01 Switches=spine[01-02]\n"
	if got := SlurmTree(f); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestSlurmBlocks(t *testing.T) {
	got := SlurmBlocks(map[string][]string{"nvl1": {"gb02", "gb01"}, "nvl2": {"gb03"}}, []int{1, 2})
	want := "BlockName=nvl1 Nodes=gb[01-02]\nBlockName=nvl2 Nodes=gb03\nBlockSizes=1,2\n"
	if got != want {
		t.Fatalf("got:\n%s", got)
	}
}

func TestHostlist(t *testing.T) {
	for in, want := range map[string]string{
		"node01,node02,node03,node05": "node[01-03,05]",
		"node9,node09,node10":         "node9,node[09-10]",
		"login,gpu1,gpu2,gpu2":        "gpu[1-2],login",
		"r1n1":                        "r1n1",
	} {
		if got := Hostlist(strings.Split(in, ",")); got != want {
			t.Errorf("Hostlist(%s) = %s, want %s", in, got, want)
		}
	}
}

const railed = `
SW 2 1 0x0002c9030045f8c0 4x NDR - CA 5 1 0x0002c903000ee2a1 ( 'rail0-leaf' - 'gpu01 mlx5_0' )
SW 3 1 0x0002c9030045f9c0 4x NDR - CA 6 1 0x0002c903000ee2a2 ( 'rail1-leaf' - 'gpu01 mlx5_1' )
SW 2 2 0x0002c9030045f8c0 4x 53.125 Gbps - CA 7 1 0x0002c903000ee2b1 ( 'rail0-leaf' - 'gpu02 mlx5_0' )
SW 3 2 0x0002c9030045f9c0 4x NDR - CA 8 1 0x0002c903000ee2b2 ( 'rail1-leaf' - 'gpu02 mlx5_1' )
`

func TestMultiRailHostsAreDistinct(t *testing.T) {
	f, err := ParseIBNetDiscover(strings.NewReader(railed))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Links) != 4 {
		t.Fatalf("rails collapsed: %v", f.Links)
	}
	if f.Links[2].Rate != "4x 53.125 Gbps" {
		t.Fatalf("numeric rate = %q", f.Links[2].Rate)
	}
	h := func(dev, hca string) Endpoint { return Endpoint{Device: dev, Kind: Host, Port: 1, HCA: hca} }
	s := func(dev string, port int) Endpoint { return Endpoint{Device: dev, Kind: Switch, Port: port} }
	bp := Fabric{Links: []Link{
		{A: s("rail0-leaf", 1), B: h("gpu01", "mlx5_0")},
		{A: s("rail1-leaf", 1), B: h("gpu01", "mlx5_1")},
		{A: s("rail0-leaf", 2), B: h("gpu02", "mlx5_1")}, // rails swapped on gpu02
		{A: s("rail1-leaf", 2), B: h("gpu02", "mlx5_0")},
	}}
	if err := CheckBlueprint(bp); err != nil {
		t.Fatal(err)
	}
	got := Validate(bp, f)
	if len(got) != 2 || got[0].Kind != Miswired || got[1].Kind != Miswired {
		t.Fatalf("findings = %+v", got)
	}
	tree := SlurmTreeRail(f, "mlx5_0")
	if tree != "SwitchName=rail0-leaf Nodes=gpu[01-02]\n" {
		t.Fatalf("rail tree = %q", tree)
	}
}

func TestBlueprintWithoutHCAsStillMatches(t *testing.T) {
	f, _ := ParseIBNetDiscover(strings.NewReader(ibnet))
	bp := Fabric{Links: []Link{link("leaf01", 1, "node01", 1, "4x NDR")}}
	for _, g := range Validate(bp, f) {
		if g.Kind != Unexpected { // leaf01's other cables are unexpected, correctly
			t.Fatalf("HCA-less blueprint did not match: %+v", g)
		}
	}
}

func TestCheckBlueprint(t *testing.T) {
	bp := Fabric{Links: []Link{link("leaf01", 1, "node01", 1, ""), link("leaf01", 1, "node02", 1, "")}}
	if err := CheckBlueprint(bp); err == nil || !strings.Contains(err.Error(), "leaf01:1 is used by both") {
		t.Fatalf("err = %v", err)
	}
}
