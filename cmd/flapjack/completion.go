package main

import (
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/image"
)

// Shell completion. The script is a thin shim: it hands the words typed so
// far to "flapjack __complete", which knows the commands and reads each
// command's flags from its own FlagSet, so completion never goes stale.

const bashCompletion = `# bash completion for flapjack. Install with:
#   flapjack completion bash > /etc/bash_completion.d/flapjack
_flapjack() {
	local line=${COMP_LINE:0:COMP_POINT} cur c
	local -a words
	read -ra words <<<"$line"
	[[ -z $line || $line == *[[:space:]] ]] && words+=("")
	cur=${words[${#words[@]}-1]}
	COMPREPLY=()
	while IFS= read -r c; do
		COMPREPLY+=("$c")
	done < <("${words[0]/#\~/$HOME}" __complete "${words[@]:1}" 2>/dev/null)
	# Bash replaces only the text after the last = or : of the word.
	if [[ $cur == *[=:]* ]]; then
		local pre=${cur%"${cur##*[=:]}"}
		COMPREPLY=("${COMPREPLY[@]#"$pre"}")
	fi
}
complete -o default -F _flapjack flapjack
`

func completionScript(args []string) error {
	fs := flags("completion", "bash")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || fs.Arg(0) != "bash" {
		fs.Usage()
		return flagErr
	}
	fmt.Print(bashCompletion)
	return nil
}

// completeWords prints the candidates for the last argument, the word
// being typed. It prints nothing, and the shell falls back to file names,
// when it has nothing better.
func completeWords(args []string) {
	for _, c := range complete(args) {
		fmt.Println(c)
	}
}

// positional names what each command's positional arguments are; a kind
// ending in "..." repeats.
var positional = map[string][]string{
	"build":             {"node..."},
	"switch":            {"node..."},
	"rollback":          {"node"},
	"generations":       {"node"},
	"diff":              {"node"},
	"overlay show":      {"node"},
	"node boot":         {"node"},
	"node revoke":       {"node"},
	"firmware converge": {"node"},
	"image build":       {"spec"},
	"image use":         {"image", "version"},
	"pki issue":         {"identity"},
	"completion":        {"shell"},
}

// Cluster data comes from the API, as the command being completed would
// reach it (honouring --api, --token-file and --cert-dir already typed).
// Tests replace these.
var (
	nodeNames = func(fs *flag.FlagSet) []string {
		var ns []v1.Node
		apiGet(fs, "/v1/nodes", &ns)
		return names(ns, func(n v1.Node) string { return n.Name })
	}
	classNames = func(fs *flag.FlagSet) []string {
		var cs []v1.NodeClass
		apiGet(fs, "/v1/classes", &cs)
		return names(cs, func(c v1.NodeClass) string { return c.Name })
	}
	imageVersions = func(fs *flag.FlagSet) []image.Version {
		vs, _ := (&image.Builder{Dir: imageDir(flagValue(fs, "dir"))}).List()
		return vs
	}
	imageSpecs = func(*flag.FlagSet) []string {
		paths, _ := filepath.Glob(filepath.Join(imageSpecDir, "*.json"))
		return names(paths, func(p string) string { return strings.TrimSuffix(filepath.Base(p), ".json") })
	}
)

var phases = []v1.Phase{v1.PhaseDiscovered, v1.PhaseBurnIn, v1.PhaseReady, v1.PhaseDraining,
	v1.PhaseQuarantined, v1.PhaseProvisioning, v1.PhaseRetired}

func complete(args []string) []string {
	if len(args) == 0 {
		args = []string{""}
	}
	typed, cur := args[:len(args)-1], args[len(args)-1]
	c, rest, ok := lookup(typed)
	if (!ok || len(rest) == 0) && !strings.HasPrefix(cur, "-") {
		if words := commandWords(typed, cur); len(words) > 0 || !ok {
			return words
		}
	}
	if !ok {
		return nil
	}
	fs := flagsOf(c)
	fs.Parse(reorder(fs, rest)) // for the values of flags already typed; errors don't matter here

	if n := len(rest); n > 0 && takesValue(fs, rest[n-1]) {
		return flagValues(fs, strings.TrimLeft(rest[n-1], "-"), "", cur)
	}
	if name, val, found := strings.Cut(cur, "="); found && strings.HasPrefix(name, "-") {
		return flagValues(fs, strings.TrimLeft(name, "-"), name+"=", val)
	}
	if strings.HasPrefix(cur, "-") {
		var out []string
		fs.VisitAll(func(f *flag.Flag) {
			if n := flagName(f.Name); strings.HasPrefix(n, cur) {
				out = append(out, n)
			}
		})
		return out
	}
	pos := positionals(fs, rest)
	kinds := positional[c.name]
	if len(kinds) == 0 {
		return nil
	}
	kind := kinds[min(len(pos), len(kinds)-1)]
	if len(pos) >= len(kinds) && !strings.HasSuffix(kind, "...") {
		return nil
	}
	var cands []string
	switch strings.TrimSuffix(kind, "...") {
	case "node":
		cands = nodeNames(fs)
		cands = slices.DeleteFunc(cands, func(n string) bool { return slices.Contains(pos, n) })
	case "spec":
		cands = imageSpecs(fs)
	case "image":
		cands = names(imageVersions(fs), func(v image.Version) string { return v.Name })
	case "version":
		for _, v := range imageVersions(fs) {
			if v.Name == pos[0] {
				cands = append(cands, v.Version)
			}
		}
	case "identity":
		cands = []string{"tentacle", "head", "admin"}
	case "shell":
		cands = []string{"bash"}
	}
	return matching(cands, "", cur)
}

// commandWords returns the next word of every visible command that starts
// with the words typed so far.
func commandWords(typed []string, cur string) []string {
	var out []string
	for _, c := range commands {
		words := strings.Fields(c.name)
		if strings.Contains(c.summary, "(internal)") || len(words) <= len(typed) || !slices.Equal(words[:len(typed)], typed) {
			continue
		}
		if w := words[len(typed)]; strings.HasPrefix(w, cur) && !slices.Contains(out, w) {
			out = append(out, w)
		}
	}
	return out
}

// flagsOf returns command c's flags. Every command defines its flags and
// then parses its arguments before doing anything else, so running it
// with -h does nothing but fill in the FlagSet that flags() captures.
func flagsOf(c command) *flag.FlagSet {
	completing, captured = true, nil
	defer func() { completing = false }()
	if err := c.run([]string{"-h"}); !errors.Is(err, flag.ErrHelp) || captured == nil {
		return flag.NewFlagSet(c.name, flag.ContinueOnError)
	}
	return captured
}

var (
	completing bool          // flags() hands its FlagSet to flagsOf
	captured   *flag.FlagSet // the FlagSet flags() made while completing
)

func flagValues(fs *flag.FlagSet, name, prefix, cur string) []string {
	switch name {
	case "class": // comma-separated
		done, last := "", cur
		if i := strings.LastIndex(cur, ","); i >= 0 {
			done, last = cur[:i+1], cur[i+1:]
		}
		cands := slices.DeleteFunc(classNames(fs), func(c string) bool { return slices.Contains(strings.Split(done, ","), c) })
		return matching(cands, prefix+done, last)
	case "phase":
		return matching(names(phases, func(p v1.Phase) string { return string(p) }), prefix, cur)
	}
	return nil
}

func matching(cands []string, prefix, cur string) []string {
	var out []string
	for _, c := range cands {
		if strings.HasPrefix(c, cur) {
			out = append(out, prefix+c)
		}
	}
	return out
}

func positionals(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return append(pos, args[i+1:]...)
		case strings.HasPrefix(a, "-") && a != "-":
			if takesValue(fs, a) {
				i++
			}
		default:
			pos = append(pos, a)
		}
	}
	return pos
}

// takesValue reports whether a is a flag that takes the next word as its value.
func takesValue(fs *flag.FlagSet, a string) bool {
	if !strings.HasPrefix(a, "-") || strings.Contains(a, "=") {
		return false
	}
	f := fs.Lookup(strings.TrimLeft(a, "-"))
	if f == nil {
		return false
	}
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return !ok || !b.IsBoolFlag()
}

func flagName(n string) string {
	if len(n) == 1 {
		return "-" + n
	}
	return "--" + n
}

func flagValue(fs *flag.FlagSet, name string) string {
	if f := fs.Lookup(name); f != nil {
		return f.Value.String()
	}
	return ""
}

// apiGet fetches path into out with the API flags of fs, quickly or not at all.
func apiGet(fs *flag.FlagSet, path string, out any) {
	cfs := flag.NewFlagSet("", flag.ContinueOnError)
	client := apiFlags(cfs)
	for _, n := range []string{"api", "token-file", "cert-dir"} {
		if f := fs.Lookup(n); f != nil {
			cfs.Set(n, f.Value.String())
		}
	}
	c, err := client()
	if err != nil {
		return
	}
	c.http.Timeout = 3 * time.Second
	c.do("GET", path, nil, out)
}

func names[T any](xs []T, name func(T) string) []string {
	var out []string
	for _, x := range xs {
		if n := name(x); !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}
