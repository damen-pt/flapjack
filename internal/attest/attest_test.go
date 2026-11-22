package attest

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTickets(t *testing.T) {
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	tk := &Tickets{Key: bytes.Repeat([]byte{7}, 32), TTL: 5 * time.Minute, Now: func() time.Time { return now }}
	ticket, err := tk.Issue("AA:BB:CC:00:11:22")
	if err != nil {
		t.Fatal(err)
	}
	if err := tk.Redeem(ticket, "aa:bb:cc:00:11:99"); err == nil {
		t.Fatal("wrong MAC must be rejected")
	}
	if err := tk.Redeem(ticket, "aa:bb:cc:00:11:22"); err != nil {
		t.Fatal(err)
	}
	if err := tk.Redeem(ticket, "aa:bb:cc:00:11:22"); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("replay: %v", err)
	}

	late, _ := tk.Issue("aa:bb:cc:00:11:22")
	now = now.Add(6 * time.Minute)
	if err := tk.Redeem(late, "aa:bb:cc:00:11:22"); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expiry: %v", err)
	}

	forged := strings.Replace(late, ".", "x.", 1)
	if tk.Redeem(forged, "aa:bb:cc:00:11:22") == nil {
		t.Fatal("forged ticket accepted")
	}
	other := &Tickets{Key: bytes.Repeat([]byte{8}, 32), TTL: time.Hour}
	ot, _ := other.Issue("aa:bb:cc:00:11:22")
	if tk.Redeem(ot, "aa:bb:cc:00:11:22") == nil {
		t.Fatal("ticket from another key accepted")
	}
	if _, err := (&Tickets{Key: []byte("short")}).Issue("x"); err == nil {
		t.Fatal("short key accepted")
	}
}

// TestSpentTicketsSurviveARestart: a ticket redeemed before a restart
// (and still readable in the node's /proc/cmdline) stays spent, and a
// ticket whose use cannot be recorded is refused.
func TestSpentTicketsSurviveARestart(t *testing.T) {
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	file := filepath.Join(t.TempDir(), "tickets-used.json")
	key := bytes.Repeat([]byte{7}, 32)
	before := &Tickets{Key: key, TTL: 5 * time.Minute, Now: func() time.Time { return now }, UsedFile: file}
	ticket, _ := before.Issue("52:54:00:00:00:01")
	if err := before.Redeem(ticket, "52:54:00:00:00:01"); err != nil {
		t.Fatal(err)
	}
	after := &Tickets{Key: key, TTL: 5 * time.Minute, Now: func() time.Time { return now }, UsedFile: file}
	if err := after.Redeem(ticket, "52:54:00:00:00:01"); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("replay after a restart: %v", err)
	}
	other, _ := after.Issue("52:54:00:00:00:02")
	if err := after.Redeem(other, "52:54:00:00:00:02"); err != nil {
		t.Fatalf("a fresh ticket after a restart: %v", err)
	}

	os.WriteFile(file, []byte("not json"), 0o600)
	corrupt := &Tickets{Key: key, TTL: 5 * time.Minute, Now: func() time.Time { return now }, UsedFile: file}
	third, _ := corrupt.Issue("52:54:00:00:00:03")
	if err := corrupt.Redeem(third, "52:54:00:00:00:03"); err == nil {
		t.Fatal("redeemed without knowing which tickets were spent")
	}
	unwritable := &Tickets{Key: key, TTL: 5 * time.Minute, Now: func() time.Time { return now },
		UsedFile: filepath.Join(t.TempDir(), "missing-dir", "used.json")}
	fourth, _ := unwritable.Issue("52:54:00:00:00:04")
	if err := unwritable.Redeem(fourth, "52:54:00:00:00:04"); err == nil {
		t.Fatal("redeemed a ticket whose use was not recorded")
	}
}

func TestArmedTicketsNeedABootWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tk := &Tickets{Key: bytes.Repeat([]byte{7}, 32), TTL: time.Minute, Armed: true, ArmFor: time.Minute, Now: func() time.Time { return now }}
	if _, err := tk.Issue("52:54:00:00:00:01"); err != ErrNotArmed {
		t.Fatalf("issued outside a boot window: %v", err)
	}
	tk.Arm("52:54:00:00:00:01")
	if _, err := tk.Issue("52:54:00:00:00:02"); err != ErrNotArmed {
		t.Fatal("one MAC's window issued another's ticket")
	}
	if _, err := tk.Issue("52:54:00:00:00:01"); err != nil {
		t.Fatal(err)
	}
	if _, err := tk.Issue("52:54:00:00:00:01"); err != ErrNotArmed {
		t.Fatal("a window issued two tickets")
	}
	tk.Arm("52:54:00:00:00:01")
	now = now.Add(2 * time.Minute)
	if _, err := tk.Issue("52:54:00:00:00:01"); err != ErrNotArmed {
		t.Fatal("an expired window issued a ticket")
	}
}
