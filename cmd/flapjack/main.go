// Command flapjack is the Flapjack cluster manager. One binary runs the
// head-node service (DHCP, TFTP, HTTPS boot, API), the rack tentacles, the
// node agent, node-side health checks and distribution, and the admin tools.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

type command struct {
	name    string
	summary string
	run     func(args []string) error
	group   string // heading in the usage; "" lists it only by name
}

// commands, grouped the way an operator reaches for them. Services that
// systemd runs and node-side tools are listed by name only.
var commands = []command{
	{"apply", "FILE — create or update classes and nodes", apply, "Cluster"},
	{"nodes", "list nodes", nodesList, "Cluster"},
	{"events", "show recent events (boots, phase changes, admin actions)", eventsList, "Cluster"},
	{"events correlate", "rank changes that explain a set of failures", eventsCorrelate, "Cluster"},
	{"node boot", "NODE — open a node's boot window (bootWindow armed: after a power loss the BMC watcher missed)", nodeBoot, "Cluster"},
	{"node revoke", "NODE --reason TEXT — revoke a node's certificates; it must boot again to get one", nodeRevoke, "Cluster"},

	{"build", "NODE...|--class C|--all — render overlays and show what would change (dry run)", overlayBuild, "Configuration"},
	{"switch", "NODE...|--class C|--all — render overlays and apply them as a new generation", overlaySwitch, "Configuration"},
	{"rollback", "NODE --reason TEXT [--to N] — return a node to an earlier generation", generationRollback, "Configuration"},
	{"generations", "NODE — list a node's overlay generations", generationsList, "Configuration"},
	{"diff", "NODE [--from N] [--to M] — compare two generations", generationDiff, "Configuration"},
	{"overlay list", "list overlay sources and the classes using them", overlayList, "Configuration"},
	{"overlay show", "NODE [GEN] — the files a node's generation manages", overlayShow, "Configuration"},

	{"image build", "NAME — build a stateless node image (root, on the head node)", imageBuild, "Images"},
	{"image list", "list image versions", imageList, "Images"},
	{"image use", "NAME VERSION — make an image version current (rollback)", imageUse, "Images"},

	{"firmware converge", "NODE — flash firmware and set BIOS to the class spec over the BMC, then verify", firmwareConverge, "Hardware"},
	{"topology validate", "compare an ibnetdiscover -p scan with a cabling blueprint", topologyValidate, "Hardware"},
	{"topology slurm", "generate Slurm topology.conf from an ibnetdiscover -p scan", topologySlurm, "Hardware"},

	{"server install", "set up this head node: service user, config, API token, systemd unit", serverInstall, "Setup"},
	{"pki init", "create the cluster CA, signing keys and boot certificate (idempotent)", pkiInit, "Setup"},
	{"pki issue", "tentacle RACK | head NAME | admin NAME — issue a certificate from the cluster CA", pkiIssue, "Setup"},
	{"pki show", "CERT.pem — show a certificate's identity and validity", pkiShow, "Setup"},
	{"completion", "bash — print the shell completion script (> /etc/bash_completion.d/flapjack)", completionScript, "Setup"},

	{"lab up", "start a QEMU test cluster on this Mac", labUp, "Test lab"},
	{"lab down", "stop the test cluster", labDown, "Test lab"},
	{"lab status", "show test cluster nodes, BMCs and head node", labStatus, "Test lab"},
	{"lab ssh", "ssh to the lab head node (optionally run a command)", labSSH, "Test lab"},
	{"lab destroy", "stop the test cluster and delete its VMs and state", labDestroy, "Test lab"},

	{"server", "run the head-node service: DHCP, TFTP, HTTPS boot, agents and the API", serverRun, ""},
	{"tentacle", "run a rack's tentacle: relay and cache between its nodes and the head", tentacleRun, ""},
	{"agent", "run the node agent (on nodes)", agentRun, ""},
	{"health run", "run node health checks; optionally submit the report for admission", healthRun, ""},
	{"stage ensure", "ARTIFACT... — make artifacts present and verified (Slurm Prolog)", stageEnsure, ""},
	{"stage fetch", "MANIFEST DEST — fetch an artifact from peers, rack cache and origin", stageFetch, ""},
	{"stage serve", "serve a chunk store to peers (optionally mTLS)", stageServe, ""},
	{"stage split", "FILE — chunk a file into a store and print its manifest", stageSplit, ""},
	{"overlay plan", "OLD.json NEW.json — show what applying NEW over OLD changes", overlayPlan, ""},
	{"mcp", "run the read-only MCP server on stdio for AI assistants", mcpServe, ""},
	{"lab daemon", "(internal) run the lab switch, BMCs and VMs", labDaemon, ""},
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: flapjack <command> [flags]")
	group := ""
	var other []string
	for _, c := range commands {
		if c.group == "" {
			if !strings.Contains(c.summary, "(internal)") {
				other = append(other, c.name)
			}
			continue
		}
		if c.group != group {
			group = c.group
			fmt.Fprintf(os.Stderr, "\n%s:\n", group)
		}
		fmt.Fprintf(os.Stderr, "  %-19s %s\n", c.name, c.summary)
	}
	fmt.Fprintf(os.Stderr, "\nServices and node-side tools: %s.\n", strings.Join(other, ", "))
	fmt.Fprintln(os.Stderr, "Run 'flapjack <command> -h' for flags.")
}

// lookup finds the command args name, preferring the longest match, so
// "server install" is never taken for "server".
func lookup(args []string) (command, []string, bool) {
	var best command
	n := 0
	for _, c := range commands {
		words := strings.Fields(c.name)
		if len(words) > n && len(args) >= len(words) && slices.Equal(args[:len(words)], words) {
			best, n = c, len(words)
		}
	}
	return best, args[n:], n > 0
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "__complete" { // the completion script's helper; it reads commands, so it can't be one
		completeWords(os.Args[2:])
		return
	}
	c, args, ok := lookup(os.Args[1:])
	if !ok {
		usage()
		os.Exit(2)
	}
	if err := c.run(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "flapjack:", err)
		os.Exit(1)
	}
}

// flags returns a FlagSet whose usage line names the command. A command
// must define all its flags and parse them before it does anything else:
// shell completion runs it with -h to learn them.
func flags(name, args string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: flapjack %s [flags] %s\n", name, args)
		fs.PrintDefaults()
	}
	if completing {
		fs.SetOutput(io.Discard)
		captured = fs
	}
	return fs
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
