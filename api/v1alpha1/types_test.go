package v1alpha1

import (
	"testing"
	"time"
)

func TestGenerationDigestIsStable(t *testing.T) {
	a := Generation{Image: "img@sha256:1", Firmware: FirmwareSpec{BIOS: map[string]string{"a": "1", "b": "2", "c": "3"}}}
	b := Generation{Image: "img@sha256:1", Firmware: FirmwareSpec{BIOS: map[string]string{"c": "3", "b": "2", "a": "1"}}}
	if a.Digest() != b.Digest() {
		t.Fatal("equal generations must hash equally")
	}
	b.Firmware.BIOS["a"] = "9"
	if a.Digest() == b.Digest() {
		t.Fatal("firmware settings must change the generation")
	}
}

func TestQuarantineOnlyExitsThroughBurnIn(t *testing.T) {
	if CanTransition(PhaseQuarantined, PhaseReady) {
		t.Fatal("quarantined node must re-pass burn-in before Ready")
	}
	if !CanTransition(PhaseQuarantined, PhaseBurnIn) {
		t.Fatal("quarantined node must be releasable to burn-in")
	}
}

func TestAcceptsCert(t *testing.T) {
	from := time.Date(2026, 11, 20, 12, 0, 0, 500, time.UTC)
	s := NodeStatus{Phase: PhaseReady, CertsFrom: from}
	if s.AcceptsCert(from.Add(-1)) == nil || s.AcceptsCert(from) != nil || s.AcceptsCert(from.Add(time.Hour)) != nil {
		t.Fatal("CertsFrom boundary wrong")
	}
	if (NodeStatus{Phase: PhaseRetired}).AcceptsCert(from) == nil {
		t.Fatal("a retired node accepted a certificate")
	}
	if (NodeStatus{}).AcceptsCert(time.Time{}.Add(time.Hour)) != nil {
		t.Fatal("a node never revoked refused a certificate")
	}
}
