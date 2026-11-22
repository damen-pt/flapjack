package main

import (
	"flag"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/damen-pt/flapjack/internal/image"
)

// Completion runs every command with -h; that must only fill in its flags.
func TestEveryCommandParsesFlagsFirst(t *testing.T) {
	for _, c := range commands {
		completing, captured = true, nil
		err := c.run([]string{"-h"})
		completing = false
		if err != flag.ErrHelp || captured == nil {
			t.Errorf("%s -h: err %v, flags captured %v; define and parse flags with flags() before doing anything", c.name, err, captured != nil)
		}
	}
}

func TestComplete(t *testing.T) {
	nodeNames = func(*flag.FlagSet) []string { return []string{"r1n01", "r1n02", "r2n01"} }
	classNames = func(*flag.FlagSet) []string { return []string{"compute", "gpu", "login"} }
	imageSpecs = func(*flag.FlagSet) []string { return []string{"rocky9", "rocky9-gpu"} }
	imageVersions = func(*flag.FlagSet) []image.Version {
		return []image.Version{
			{Info: image.Info{Name: "rocky9", Version: "rocky9@aaa"}},
			{Info: image.Info{Name: "rocky9", Version: "rocky9@bbb"}},
			{Info: image.Info{Name: "rocky9-gpu", Version: "rocky9-gpu@ccc"}},
		}
	}
	for _, tc := range []struct {
		line string
		want []string // nil: exactly nothing; otherwise these, in any order
	}{
		{"ov", []string{"overlay"}},
		{"overlay ", []string{"list", "show", "plan"}},
		{"overlay s", []string{"show"}},
		{"server ", []string{"install"}},
		{"lab d", []string{"down", "destroy"}}, // not the internal "lab daemon"
		{"pki issue ", []string{"tentacle", "head", "admin"}},
		{"completion ", []string{"bash"}},
		{"switch --c", []string{"--class", "--cert-dir"}},
		{"switch --class ", []string{"compute", "gpu", "login"}},
		{"switch --class=c", []string{"--class=compute"}},
		{"switch --class compute,", []string{"compute,gpu", "compute,login"}},
		{"switch -m 'x' r1n01 ", []string{"r1n02", "r2n01"}},
		{"build r2", []string{"r2n01"}},
		{"rollback --to 3 ", []string{"r1n01", "r1n02", "r2n01"}},
		{"rollback r1n01 ", nil},
		{"nodes --phase R", []string{"Ready", "Retired"}},
		{"nodes --json ", nil},
		{"image build ", []string{"rocky9", "rocky9-gpu"}},
		{"image use ", []string{"rocky9", "rocky9-gpu"}},
		{"image use rocky9 ", []string{"rocky9@aaa", "rocky9@bbb"}},
		{"apply ", nil}, // a file: the shell completes it
		{"frobnicate ", nil},
	} {
		words := strings.Split(tc.line, " ")
		got := complete(words)
		slices.Sort(got)
		want := slices.Clone(tc.want)
		slices.Sort(want)
		if tc.want == nil {
			if len(got) != 0 {
				t.Errorf("%q: got %q, want nothing", tc.line, got)
			}
			continue
		}
		if tc.line == "switch --c" { // a prefix of several flags
			for _, w := range want {
				if !slices.Contains(got, w) {
					t.Errorf("%q: got %q, missing %q", tc.line, got, w)
				}
			}
			continue
		}
		if !slices.Equal(got, want) {
			t.Errorf("%q: got %q, want %q", tc.line, got, want)
		}
	}
}

func TestBashScriptParses(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	if out, err := exec.Command(bash, "-n", "-c", bashCompletion).CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v\n%s", err, out)
	}
}
