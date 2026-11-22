package server

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/damen-pt/flapjack/internal/staging"
)

// BootFiles are the files of an image version a node boots from.
var BootFiles = []string{"vmlinuz", "initrd.img", "rootfs.squashfs"}

// BootImage is one image version, as staging manifests a tentacle can
// fetch from the head's chunk origin. Versions are immutable (a rebuild
// makes a new one and moves the class's link), so a version's manifests
// never change.
type BootImage struct {
	Version string                      `json:"version"`
	Files   map[string]staging.Manifest `json:"files"`
	// Signatures are the head's CMS signatures over the kernel and
	// initrd, with signed boot. The tentacle serves them beside the files;
	// it cannot make its own, so it cannot alter what they cover.
	Signatures map[string][]byte `json:"signatures,omitempty"`
}

// StagedImages is a tentacle's report of the image versions it can serve.
type StagedImages struct {
	Versions []string `json:"versions"`
}

// ResolveImage returns the version directory an image name points at now.
func ResolveImage(images *os.Root, name string) string {
	if v, err := images.Readlink(name); err == nil && !strings.ContainsAny(v, `/\`) {
		return v
	}
	return name
}

// BootImages chunks image versions into the staging origin on demand, in
// the background: a root filesystem is gigabytes and indexing it must
// not hold up a watch. Notify is called when a version becomes ready, so
// tentacles waiting on the head get a snapshot that includes it.
type BootImages struct {
	Images *os.Root
	// Files holds the iPXE binaries firmware loads; tentacles that run
	// their rack's DHCP serve copies of them.
	Files  *os.Root
	Store  staging.Store
	Notify func()
	Logf   func(format string, args ...any)
	// Signing, with signed boot, provides each version's signatures.
	Signing *BootSigner
	// StagedFor is how long a tentacle's staged report holds (default 3m).
	// Tentacles repeat it every minute; one that goes quiet stops getting
	// its rack's boots sent to it.
	StagedFor time.Duration

	mu       sync.Mutex
	firmware map[string]firmwareIndex
	index    map[string]*imageIndex
	staged   map[string]staged // rack → report
}

type imageIndex struct {
	img     BootImage
	done    bool
	err     error
	retryAt time.Time
}

type firmwareIndex struct {
	size int64
	mod  time.Time
	m    staging.Manifest
}

// Firmware returns manifests for the iPXE binaries (*.efi, *.kpxe), chunked
// into the staging origin. They are small, so this runs inline, and each
// file is re-chunked only when it changes (an iPXE rebuilt with TRUST=).
func (b *BootImages) Firmware() []staging.Manifest {
	if b == nil || b.Files == nil {
		return nil
	}
	dir, err := b.Files.Open(".")
	if err != nil {
		return nil
	}
	ents, _ := dir.ReadDir(-1)
	dir.Close()
	var out []staging.Manifest
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.firmware == nil {
		b.firmware = map[string]firmwareIndex{}
	}
	for _, e := range ents {
		name := e.Name()
		if !IsFirmware(name) || !e.Type().IsRegular() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		ix, ok := b.firmware[name]
		if !ok || ix.size != fi.Size() || !ix.mod.Equal(fi.ModTime()) {
			f, err := b.Files.Open(name)
			if err != nil {
				continue
			}
			m, err := staging.Split(f, name, 0, b.Store)
			f.Close()
			if err != nil {
				if b.Logf != nil {
					b.Logf("images: indexing %s for tentacles: %v", name, err)
				}
				continue
			}
			ix = firmwareIndex{size: fi.Size(), mod: fi.ModTime(), m: m}
			b.firmware[name] = ix
		}
		out = append(out, ix.m)
	}
	return out
}

// IsFirmware reports whether name is an iPXE binary firmware loads.
func IsFirmware(name string) bool {
	return !strings.ContainsAny(name, `/\`) && !strings.HasPrefix(name, ".") &&
		(strings.HasSuffix(name, ".efi") || strings.HasSuffix(name, ".kpxe"))
}

type staged struct {
	versions []string
	at       time.Time
}

// Image returns version's manifests if it has been indexed, and starts
// indexing it otherwise.
func (b *BootImages) Image(version string) (BootImage, bool) {
	if b == nil || b.Images == nil || strings.ContainsAny(version, `/\`) || version == "" {
		return BootImage{}, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.index == nil {
		b.index = map[string]*imageIndex{}
	}
	ix, ok := b.index[version]
	switch {
	case ok && ix.done:
		return ix.img, true
	case ok && (ix.err == nil || time.Now().Before(ix.retryAt)):
		return BootImage{}, false // indexing, or failed recently
	}
	ix = &imageIndex{}
	b.index[version] = ix
	go b.build(version, ix)
	return BootImage{}, false
}

func (b *BootImages) build(version string, ix *imageIndex) {
	img := BootImage{Version: version, Files: map[string]staging.Manifest{}}
	var err error
	for _, f := range BootFiles {
		var fh *os.File
		fh, err = b.Images.Open(version + "/" + f)
		if os.IsNotExist(err) && f == "rootfs.squashfs" {
			err = nil // initrd-only images boot without one
			continue
		}
		if err != nil {
			break
		}
		var m staging.Manifest
		m, err = staging.Split(fh, f, 0, b.Store)
		fh.Close()
		if err != nil {
			break
		}
		img.Files[f] = m
	}
	if err == nil && b.Signing != nil {
		img.Signatures, _, err = b.Signing.Version(version)
	}
	b.mu.Lock()
	if err != nil {
		ix.err, ix.retryAt = err, time.Now().Add(time.Minute)
	} else {
		ix.img, ix.done = img, true
	}
	b.mu.Unlock()
	if err != nil {
		if b.Logf != nil {
			b.Logf("images: indexing %s for tentacles: %v", version, err)
		}
		return
	}
	if b.Notify != nil {
		b.Notify()
	}
}

// SetStaged records the versions rack's tentacle reports it can serve.
func (b *BootImages) SetStaged(rack string, versions []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.staged == nil {
		b.staged = map[string]staged{}
	}
	b.staged[rack] = staged{versions: slices.Clone(versions), at: time.Now()}
}

// Staged reports whether rack's tentacle recently said it holds version.
func (b *BootImages) Staged(rack, version string) bool {
	if b == nil {
		return false
	}
	ttl := b.StagedFor
	if ttl <= 0 {
		ttl = 3 * time.Minute
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.staged[rack]
	return ok && time.Since(s.at) < ttl && slices.Contains(s.versions, version)
}

// clearStaged forgets a rack's report (its tentacle was removed).
func (b *BootImages) clearStaged(rack string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	delete(b.staged, rack)
	b.mu.Unlock()
}

func (i BootImage) String() string {
	var n int64
	for _, m := range i.Files {
		n += m.Size
	}
	return fmt.Sprintf("%s (%d files, %d bytes)", i.Version, len(i.Files), n)
}
