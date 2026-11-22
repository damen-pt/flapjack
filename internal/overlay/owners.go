package overlay

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"strconv"
	"strings"
)

// ResolveOwners returns a copy of m with Owner and Group names replaced by
// the numeric IDs they have in root's etc/passwd and etc/group. Names must
// exist: a file meant for "munge" must not silently end up owned by root.
func ResolveOwners(m Manifest, root fs.FS) (Manifest, error) {
	users, err := idMap(root, "etc/passwd", 2)
	if err != nil {
		return m, err
	}
	groups, err := idMap(root, "etc/group", 2)
	if err != nil {
		return m, err
	}
	out := m
	out.Entries = maps.Clone(m.Entries)
	for p, e := range out.Entries {
		if e.Owner != "" {
			uid, ok := users[e.Owner]
			if !ok {
				return m, fmt.Errorf("%s: no user %q on this node", p, e.Owner)
			}
			e.UID = uid
		}
		if e.Group != "" {
			gid, ok := groups[e.Group]
			if !ok {
				return m, fmt.Errorf("%s: no group %q on this node", p, e.Group)
			}
			e.GID = gid
		}
		e.Owner, e.Group = "", ""
		out.Entries[p] = e
	}
	return out, nil
}

// idMap parses a colon-separated database into name → the numeric field.
func idMap(root fs.FS, name string, field int) (map[string]int, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ids := map[string]int{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) <= field || strings.HasPrefix(parts[0], "#") {
			continue
		}
		if id, err := strconv.Atoi(parts[field]); err == nil {
			ids[parts[0]] = id
		}
	}
	return ids, sc.Err()
}

// ManifestDigest identifies a manifest's content; the generation number is
// excluded so identical content always hashes the same.
func ManifestDigest(m Manifest) string {
	m.Generation = 0
	b, err := json.Marshal(m)
	if err != nil {
		panic(err) // strings, ints and string slices only
	}
	return Digest(b)
}
