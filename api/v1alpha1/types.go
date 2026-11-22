// Package v1alpha1 defines Flapjack's declarative API types. They are plain
// structs so they can later be served as Kubernetes CRDs unchanged.
package v1alpha1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Firmware is how a node boots.
type Firmware string

const (
	FirmwareUEFI Firmware = "uefi"
	FirmwareBIOS Firmware = "bios"
)

// BMCDriver selects the out-of-band management protocol.
type BMCDriver string

const (
	BMCRedfish BMCDriver = "redfish"
	BMCIPMI    BMCDriver = "ipmi"
)

// RootfsMode is how a node assembles its root filesystem.
type RootfsMode string

const (
	RootfsTmpfs     RootfsMode = "tmpfs"
	RootfsEROFS     RootfsMode = "erofs"
	RootfsEROFSDisk RootfsMode = "erofs-nvme"
	RootfsAB        RootfsMode = "ab"
)

// Phase is a node's lifecycle state.
type Phase string

const (
	PhaseDiscovered   Phase = "Discovered"   // seen by a BMC or DHCP, not yet validated
	PhaseBurnIn       Phase = "BurnIn"       // running admission checks
	PhaseReady        Phase = "Ready"        // passed checks, schedulable
	PhaseDraining     Phase = "Draining"     // finishing jobs before maintenance
	PhaseQuarantined  Phase = "Quarantined"  // failed checks; needs admin release
	PhaseProvisioning Phase = "Provisioning" // booting a new generation
	PhaseRetired      Phase = "Retired"
)

var transitions = map[Phase][]Phase{
	PhaseDiscovered:   {PhaseBurnIn, PhaseRetired},
	PhaseBurnIn:       {PhaseReady, PhaseQuarantined},
	PhaseReady:        {PhaseDraining, PhaseQuarantined, PhaseProvisioning},
	PhaseDraining:     {PhaseProvisioning, PhaseQuarantined, PhaseReady},
	PhaseQuarantined:  {PhaseBurnIn, PhaseRetired},
	PhaseProvisioning: {PhaseBurnIn, PhaseQuarantined},
	PhaseRetired:      {},
}

// CanTransition reports whether a node may move from one phase to another.
// Quarantine can only be left through BurnIn, so a released node must pass
// its checks again before it is schedulable.
func CanTransition(from, to Phase) bool {
	return from == to || slices.Contains(transitions[from], to)
}

// FirmwareSpec pins firmware versions and BIOS settings. Component keys
// match inventory names exactly or as path.Match globs ("GPU* VBIOS").
type FirmwareSpec struct {
	Components map[string]string `json:"components,omitempty"` // component → version
	Images     map[string]string `json:"images,omitempty"`     // component → image URI for updates
	BIOS       map[string]string `json:"bios,omitempty"`       // BIOS attribute → value
}

// HealthPolicy selects admission checks for a class.
type HealthPolicy struct {
	Checks []string `json:"checks"`
	// Critical checks quarantine on the first failure; others must fail
	// ConsecutiveFailures times in a row.
	Critical            []string `json:"critical,omitempty"`
	ConsecutiveFailures int      `json:"consecutiveFailures,omitempty"`
}

// NodeClass is the template shared by a group of nodes.
type NodeClass struct {
	Name     string       `json:"name"`
	Image    string       `json:"image"` // OCI reference pinned by digest
	Kernel   string       `json:"kernel,omitempty"`
	BootArgs []string     `json:"bootArgs,omitempty"`
	Rootfs   RootfsMode   `json:"rootfs"`
	Overlays []string     `json:"overlays,omitempty"` // overlay manifest digests
	Firmware FirmwareSpec `json:"firmware,omitempty"`
	Health   HealthPolicy `json:"health,omitempty"`
}

// BMC is a node's out-of-band controller.
type BMC struct {
	Driver        BMCDriver `json:"driver"`
	Address       string    `json:"address"`
	CredentialRef string    `json:"credentialRef,omitempty"`
	// AllowIPMI must be set to manage this node over IPMI: IPMI's
	// login handshake hands anyone who asks a password hash to crack
	// offline. Every use is logged as insecure. Prefer Redfish.
	AllowIPMI bool `json:"allowIPMI,omitempty"`
}

// Interface is a node network interface.
type Interface struct {
	Name    string `json:"name,omitempty"`
	MAC     string `json:"mac"`
	Network string `json:"network"`
	IP      string `json:"ip,omitempty"`
}

// Node is one physical machine.
type Node struct {
	Name       string            `json:"name"`
	Class      string            `json:"class"`
	Rack       string            `json:"rack"`
	Block      string            `json:"block,omitempty"` // topology block (leaf switch / NVLink domain)
	Labels     map[string]string `json:"labels,omitempty"`
	Firmware   Firmware          `json:"firmware"`
	BMC        BMC               `json:"bmc"`
	Interfaces []Interface       `json:"interfaces,omitempty"`
	Serial     string            `json:"serial,omitempty"`
	Status     NodeStatus        `json:"status"`
}

// NodeStatus is reported state; it is never edited by hand.
type NodeStatus struct {
	Phase      Phase  `json:"phase"`
	Generation string `json:"generation,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Failures   int    `json:"failures,omitempty"` // consecutive non-critical health failures
	// Agent is what the node agent last reported.
	Agent *AgentStatus `json:"agent,omitempty"`
	// LastHealth is the time of the newest health report applied. Older
	// reports (replays, delayed agents) are ignored so they cannot undo a
	// newer verdict.
	LastHealth time.Time `json:"lastHealth,omitzero"`
	// Health is the overall status of that report: pass, warn or fail.
	Health string `json:"health,omitempty"`
	// CertsFrom revokes the node's earlier certificates: one issued before
	// it (pki.IssuedAt) is refused everywhere, renewal included. Each
	// ticket enrollment moves it to the new certificate, so a node has
	// one live identity, and an admin revoking a node moves it to now.
	CertsFrom time.Time `json:"certsFrom,omitzero"`
	// SealKey is the public key the node's secrets are sealed to
	// (pki.Seal), sent with its latest ticket enrollment. Its private half
	// never leaves the node, and is gone at reboot like its certificate's.
	SealKey []byte `json:"sealKey,omitempty"`
}

// AcceptsCert reports whether a certificate for this node issued at issued
// (pki.IssuedAt) may still be used: not by a retired node, and not if it
// predates CertsFrom.
func (s NodeStatus) AcceptsCert(issued time.Time) error {
	if s.Phase == PhaseRetired {
		return errors.New("the node is retired; its certificates are refused")
	}
	if issued.Before(s.CertsFrom) {
		return fmt.Errorf("certificate issued %s was revoked (certificates from %s are valid)",
			issued.UTC().Format(time.RFC3339Nano), s.CertsFrom.UTC().Format(time.RFC3339Nano))
	}
	return nil
}

// AgentStatus is the node agent's last report.
type AgentStatus struct {
	Applied int       `json:"applied"`         // overlay generation applied
	Drift   []string  `json:"drift,omitempty"` // paths that differ from it
	Error   string    `json:"error,omitempty"`
	Seen    time.Time `json:"seen"`
}

// Generation is everything that defines what a node runs.
type Generation struct {
	Image    string       `json:"image"`
	Kernel   string       `json:"kernel,omitempty"`
	BootArgs []string     `json:"bootArgs,omitempty"`
	Overlays []string     `json:"overlays,omitempty"`
	Firmware FirmwareSpec `json:"firmware,omitempty"`
}

// GenerationOf derives the generation a class defines.
func GenerationOf(c NodeClass) Generation {
	return Generation{Image: c.Image, Kernel: c.Kernel, BootArgs: c.BootArgs, Overlays: c.Overlays, Firmware: c.Firmware}
}

// Digest identifies the generation. encoding/json sorts map keys, so equal
// generations always hash equally.
func (g Generation) Digest() string {
	b, err := json.Marshal(g)
	if err != nil {
		panic(err) // only strings, slices and string maps: cannot fail
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Cluster is a set of classes and nodes, as read by "flapjack apply".
type Cluster struct {
	Classes []NodeClass `json:"classes,omitempty"`
	Nodes   []Node      `json:"nodes,omitempty"`
}
