// Command trivy-db-filter keeps the library sources of a Trivy vulnerability database (trivy-db
// schema 2) and drops every other source (0.16 debts D31-1, rulings B2-b and B2-s): Qualor's
// scanner only reads library packages, and some operating-system and vendor sources may not be
// redistributed. deploy/scanner/NOTICE.md lists the sources it keeps.
//
//	trivy-db-filter <trivy.db>                            filters the file in place
//	trivy-db-filter -check <trivy.db>                     exits 1 with the first rule the file breaks
//	trivy-db-filter -fixture <allowlist.json> <trivy.db>  cuts the file down to a test fixture in place
//
// The kept data goes into a fresh file, which also compacts it (bbolt never shrinks a file): each
// top-level bucket whose data-source ID is in KEEP, with its nested buckets; their data-source
// entries; and the vulnerability details their advisories reference, with VendorSeverity and CVSS
// reduced to the kept sources and nvd, every other byte as it was. Then the file replaces the input.
// tools/analyzers/filter-trivy-db.sh runs both.
//
// The -fixture mode (0.16 SBOM, ruling R12) makes the small database that
// server/test/fixtures/trivy-db-os commits, the same way: the top-level buckets the allowlist names,
// and in them only the keys it lists; the data-source entries of those buckets; and the vulnerability
// details their advisories reference, without Title and Description, and with VendorSeverity and
// CVSS reduced to the kept buckets' sources and nvd. tools/analyzers/make-trivy-db-fixture.sh runs it.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	bolt "go.etcd.io/bbolt"
)

const (
	vulnerabilityBucket = "vulnerability"
	dataSourceBucket    = "data-source"
	// Trivy falls back to NVD's severity when a library source gives none; NVD's data is public
	// domain (ruling B2-s).
	nvd = "nvd"
)

// KEEP lists the data-source IDs whose buckets stay: the library ecosystems that
// `trivy fs --pkg-types library` reads, without Seal's (ruling B2-b). A source that a newer
// database adds is dropped until it is listed here; tools/analyzers/trivy-db-filter.test.ts pins
// this list.
var KEEP = []string{
	"ghsa",
	"bitnami",
	"php-security-advisories",
	"glad",
	"govulndb",
	"julia",
	"k8s",
	"nodejs-security-wg",
	"aqua",
	"ruby-advisory-db",
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("trivy-db-filter", flag.ContinueOnError)
	flags.SetOutput(stderr)
	checkOnly := flags.Bool("check", false, "check a filtered database instead of filtering it")
	allowlist := flags.String("fixture", "", "cut the database down to what this allowlist names")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 1 || (*checkOnly && *allowlist != "") {
		fmt.Fprintln(stderr, "usage: trivy-db-filter [-check | -fixture <allowlist.json>] <trivy.db>")
		return 2
	}
	path := flags.Arg(0)
	if *allowlist != "" {
		if err := fixture(*allowlist, path, stdout); err != nil {
			fmt.Fprintf(stderr, "trivy-db-filter: %s: %v\n", path, err)
			return 1
		}
		return 0
	}
	if *checkOnly {
		if err := check(path); err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", path, err)
			return 1
		}
		fmt.Fprintf(stdout, "%s: holds only the kept sources\n", path)
		return 0
	}
	if err := filter(path, stdout); err != nil {
		fmt.Fprintf(stderr, "trivy-db-filter: %s: %v\n", path, err)
		return 1
	}
	return 0
}

func keptSources() map[string]bool {
	keep := map[string]bool{}
	for _, id := range KEEP {
		keep[id] = true
	}
	return keep
}

// keptVendors are the keys VendorSeverity and CVSS keep.
func keptVendors() map[string]bool {
	vendors := keptSources()
	vendors[nvd] = true
	return vendors
}

// sourceID reads the ID of a data-source entry; a bucket without an entry has the ID "".
func sourceID(entry []byte) (string, error) {
	if entry == nil {
		return "", nil
	}
	var source struct{ ID string }
	if err := json.Unmarshal(entry, &source); err != nil {
		return "", err
	}
	return source.ID, nil
}

func isMetadata(name string) bool {
	return name == vulnerabilityBucket || name == dataSourceBucket
}

// rewrite writes what fill copies from the database at path into a fresh file, which then replaces
// it, and answers both sizes. On an error the input stays as it was and the fresh file goes.
func rewrite(path string, fill func(src, dst *bolt.DB) error) (before, after int64, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, 0, err
	}
	src, err := bolt.Open(path, 0, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		return 0, 0, err
	}
	defer src.Close()
	tmp := path + ".tmp-filter"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, 0, err
	}
	dst, err := bolt.Open(tmp, info.Mode().Perm(), &bolt.Options{NoSync: true, NoGrowSync: true, Timeout: time.Second})
	if err != nil {
		return 0, 0, err
	}
	// The file grows to what its pages need, without bbolt's 16 MiB of headroom.
	dst.AllocSize = 0
	defer func() {
		if err != nil {
			_ = dst.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := fill(src, dst); err != nil {
		return 0, 0, err
	}
	if err := dst.Sync(); err != nil {
		return 0, 0, err
	}
	if err := dst.Close(); err != nil {
		return 0, 0, err
	}
	if err := src.Close(); err != nil {
		return 0, 0, err
	}
	if err := os.Chmod(tmp, info.Mode().Perm()); err != nil {
		return 0, 0, err
	}
	fresh, err := os.Stat(tmp)
	if err != nil {
		return 0, 0, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return 0, 0, err
	}
	return info.Size(), fresh.Size(), nil
}

func filter(path string, out io.Writer) error {
	var s summary
	before, after, err := rewrite(path, func(src, dst *bolt.DB) (err error) {
		s, err = copyKept(src, dst)
		return err
	})
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(s.dropped))
	for id := range s.dropped {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		label := id
		if label == "" {
			label = "(none)"
		}
		fmt.Fprintf(out, "dropped %s: %d buckets\n", label, s.dropped[id])
	}
	fmt.Fprintf(out, "kept %d buckets, and %d of %d vulnerability details\n", s.kept, s.detailsKept, s.details)
	fmt.Fprintf(out, "%d bytes before, %d bytes after\n", before, after)
	return nil
}

type summary struct {
	dropped              map[string]int // buckets by data-source ID
	kept                 int
	details, detailsKept int
}

func copyKept(src, dst *bolt.DB) (summary, error) {
	keep := keptSources()
	s := summary{dropped: map[string]int{}}
	var kept [][]byte
	entries := map[string][]byte{}
	err := src.View(func(tx *bolt.Tx) error {
		sources := tx.Bucket([]byte(dataSourceBucket))
		if sources == nil {
			return fmt.Errorf("no %s bucket", dataSourceBucket)
		}
		if tx.Bucket([]byte(vulnerabilityBucket)) == nil {
			return fmt.Errorf("no %s bucket", vulnerabilityBucket)
		}
		return tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			if isMetadata(string(name)) {
				return nil
			}
			entry := sources.Get(name)
			id, err := sourceID(entry)
			if err != nil {
				return fmt.Errorf("the data-source entry of %q: %w", name, err)
			}
			if !keep[id] {
				s.dropped[id]++
				return nil
			}
			kept = append(kept, bytes.Clone(name))
			entries[string(name)] = bytes.Clone(entry)
			return nil
		})
	})
	if err != nil {
		return s, err
	}
	if len(kept) == 0 {
		return s, errors.New("no bucket of a kept source")
	}
	s.kept = len(kept)

	// One write transaction per top-level bucket, while the source's pages stay mapped.
	ids := map[string]bool{}
	for _, name := range kept {
		err := src.View(func(stx *bolt.Tx) error {
			return dst.Update(func(dtx *bolt.Tx) error {
				to, err := dtx.CreateBucket(name)
				if err != nil {
					return err
				}
				return copyBucket(stx.Bucket(name), to, 1, ids)
			})
		})
		if err != nil {
			return s, fmt.Errorf("copying %q: %w", name, err)
		}
	}
	err = dst.Update(func(dtx *bolt.Tx) error {
		to, err := dtx.CreateBucket([]byte(dataSourceBucket))
		if err != nil {
			return err
		}
		to.FillPercent = 1.0
		for _, name := range kept {
			if err := to.Put(name, entries[string(name)]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return s, err
	}
	vendors := keptVendors()
	err = src.View(func(stx *bolt.Tx) error {
		return dst.Update(func(dtx *bolt.Tx) error {
			to, err := dtx.CreateBucket([]byte(vulnerabilityBucket))
			if err != nil {
				return err
			}
			to.FillPercent = 1.0
			c := stx.Bucket([]byte(vulnerabilityBucket)).Cursor()
			for k, v := c.First(); k != nil; k, v = c.Next() {
				if v == nil {
					return fmt.Errorf("a nested bucket %q in %s", k, vulnerabilityBucket)
				}
				s.details++
				if !ids[string(k)] {
					continue
				}
				trimmed, err := trimDetail(v, vendors, nil)
				if err != nil {
					return fmt.Errorf("the detail of %q: %w", k, err)
				}
				if err := to.Put(k, trimmed); err != nil {
					return err
				}
				s.detailsKept++
			}
			return nil
		})
	})
	return s, err
}

// copyBucket copies a bucket with its nested buckets, its keys in order and its pages full, and
// collects every key at depth 2 or more below a top-level bucket: an advisory's vulnerability id.
func copyBucket(from, to *bolt.Bucket, depth int, ids map[string]bool) error {
	to.FillPercent = 1.0
	if err := to.SetSequence(from.Sequence()); err != nil {
		return err
	}
	c := from.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if v == nil {
			if nested := from.Bucket(k); nested != nil {
				child, err := to.CreateBucket(k)
				if err != nil {
					return err
				}
				if err := copyBucket(nested, child, depth+1, ids); err != nil {
					return err
				}
				continue
			}
		}
		if depth >= 2 {
			ids[string(k)] = true
		}
		if err := to.Put(k, v); err != nil {
			return err
		}
	}
	return nil
}

// collect is copyBucket's walk without the copy.
func collect(b *bolt.Bucket, depth int, ids map[string]bool) {
	c := b.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if v == nil {
			if nested := b.Bucket(k); nested != nil {
				collect(nested, depth+1, ids)
				continue
			}
		}
		if depth >= 2 {
			ids[string(k)] = true
		}
	}
}

type field struct {
	name       string
	key, value []byte // as written, the key with its quotes
}

var errNotObject = errors.New("not a JSON object")

// fields splits a JSON object into its members, keeping the bytes of each key and value.
func fields(object []byte) ([]field, error) {
	dec := json.NewDecoder(bytes.NewReader(object))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errNotObject
	}
	var members []field
	for dec.More() {
		start := dec.InputOffset()
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, _ := tok.(string)
		key := bytes.TrimLeft(object[start:dec.InputOffset()], " \t\r\n,")
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		members = append(members, field{name: name, key: key, value: value})
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, errNotObject
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("data after the JSON object")
	}
	return members, nil
}

func join(members []field) []byte {
	out := []byte{'{'}
	for i, m := range members {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, m.key...)
		out = append(out, ':')
		out = append(out, m.value...)
	}
	return append(out, '}')
}

func isVendorMap(name string) bool {
	return name == "VendorSeverity" || name == "CVSS"
}

// trimDetail reduces a vulnerability detail's VendorSeverity and CVSS to the vendors' keys, in
// their order, and leaves either out when nothing is left (trivy-db's omitempty); it drops the
// members that drop names, and every other member keeps its bytes.
func trimDetail(detail []byte, vendors, drop map[string]bool) ([]byte, error) {
	members, err := fields(detail)
	if err != nil {
		return nil, err
	}
	out := members[:0]
	for _, m := range members {
		if drop[m.name] {
			continue
		}
		if isVendorMap(m.name) && !bytes.Equal(m.value, []byte("null")) {
			inner, err := fields(m.value)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", m.name, err)
			}
			inner = slices.DeleteFunc(inner, func(v field) bool { return !vendors[v.name] })
			if len(inner) == 0 {
				continue
			}
			m.value = join(inner)
		}
		out = append(out, m)
	}
	return join(out), nil
}

// texts are the members of a vulnerability detail that the -fixture mode drops (ruling R12).
var texts = map[string]bool{"Title": true, "Description": true}

// allowlist says what the -fixture mode keeps of a bucket: a JSON list of keys that stay whole (a
// value, or a nested bucket with everything in it), or a JSON object of nested buckets, each with
// its own allowlist. The file is an object of top-level buckets.
type allowlist struct {
	keys   []string
	nested map[string]*allowlist // nil for a list
}

var errNotAllowlist = errors.New("not a list of keys or an object of nested buckets")

func (a *allowlist) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	switch {
	case bytes.HasPrefix(data, []byte("[")):
		return json.Unmarshal(data, &a.keys)
	case bytes.HasPrefix(data, []byte("{")):
		a.nested = map[string]*allowlist{}
		return json.Unmarshal(data, &a.nested)
	}
	return errNotAllowlist
}

func readAllowlist(path string) (map[string]*allowlist, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	var top map[string]*allowlist
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, fmt.Errorf("the allowlist %s: %w", path, err)
	}
	if len(top) == 0 {
		return nil, fmt.Errorf("the allowlist %s names no bucket", path)
	}
	for name := range top {
		if isMetadata(name) {
			return nil, fmt.Errorf("the allowlist %s names %q, which the fixture fills itself", path, name)
		}
	}
	return top, nil
}

func fixture(allowlistPath, path string, out io.Writer) error {
	top, err := readAllowlist(allowlistPath)
	if err != nil {
		return err
	}
	var kept, details int
	before, after, err := rewrite(path, func(src, dst *bolt.DB) (err error) {
		kept, details, err = copyListed(src, dst, top)
		return err
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "kept %d buckets, and %d vulnerability details\n", kept, details)
	fmt.Fprintf(out, "%d bytes before, %d bytes after\n", before, after)
	return nil
}

// copyListed copies the buckets of the allowlist, as much of each as it lists; their data-source
// entries; and the vulnerability details they reference, without texts, with VendorSeverity and
// CVSS reduced to their sources and nvd. It answers the counts of buckets and details.
func copyListed(src, dst *bolt.DB, top map[string]*allowlist) (kept, details int, err error) {
	names := slices.Sorted(maps.Keys(top))
	entries := map[string][]byte{}
	vendors := map[string]bool{nvd: true}
	err = src.View(func(tx *bolt.Tx) error {
		sources := tx.Bucket([]byte(dataSourceBucket))
		if sources == nil || tx.Bucket([]byte(vulnerabilityBucket)) == nil {
			return fmt.Errorf("the %s or %s bucket is missing", dataSourceBucket, vulnerabilityBucket)
		}
		for _, name := range names {
			if tx.Bucket([]byte(name)) == nil {
				return fmt.Errorf("no bucket %q", name)
			}
			entry := sources.Get([]byte(name))
			if entry == nil {
				continue
			}
			id, err := sourceID(entry)
			if err != nil {
				return fmt.Errorf("the data-source entry of %q: %w", name, err)
			}
			vendors[id] = true
			entries[name] = bytes.Clone(entry)
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}

	err = src.View(func(stx *bolt.Tx) error {
		for _, name := range names {
			path := [][]byte{[]byte(name)}
			if err := copyAllowed(stx.Bucket(path[0]), dst, path, top[name], strconv.Quote(name)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	ids := map[string]bool{}
	err = dst.View(func(dtx *bolt.Tx) error {
		for _, name := range names {
			referenced(dtx.Bucket([]byte(name)), 1, ids)
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	err = dst.Update(func(dtx *bolt.Tx) error {
		to, err := dtx.CreateBucket([]byte(dataSourceBucket))
		if err != nil {
			return err
		}
		to.FillPercent = 1.0
		for _, name := range names {
			if entry, ok := entries[name]; ok {
				if err := to.Put([]byte(name), entry); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	err = src.View(func(stx *bolt.Tx) error {
		from := stx.Bucket([]byte(vulnerabilityBucket))
		return dst.Update(func(dtx *bolt.Tx) error {
			to, err := dtx.CreateBucket([]byte(vulnerabilityBucket))
			if err != nil {
				return err
			}
			to.FillPercent = 1.0
			for _, id := range slices.Sorted(maps.Keys(ids)) {
				// An RHSA id or a Red Hat CPE key has no detail.
				v := from.Get([]byte(id))
				if v == nil {
					continue
				}
				trimmed, err := trimDetail(v, vendors, texts)
				if err != nil {
					return fmt.Errorf("the detail of %q: %w", id, err)
				}
				if err := to.Put([]byte(id), trimmed); err != nil {
					return err
				}
				details++
			}
			return nil
		})
	})
	return len(names), details, err
}

// whole is the allowlist of a bucket that a list keeps with everything in it.
var whole = &allowlist{}

// copyAllowed creates the bucket at path in dst and copies into it what the allowlist keeps of the
// source bucket `from`, which `at` names in errors. Each bucket gets its own write transaction:
// bbolt writes the buckets a transaction changed in Go's map order, so two in one transaction would
// land on pages in a random order, and the same input would not give the same file.
func copyAllowed(from *bolt.Bucket, dst *bolt.DB, path [][]byte, list *allowlist, at string) error {
	if list == nil {
		return fmt.Errorf("the allowlist of %s: %w", at, errNotAllowlist)
	}
	// The source's keys and values stay valid while the caller's read transaction is open.
	var values [][2][]byte
	var children []string
	lists := map[string]*allowlist{}
	switch {
	case list == whole:
		c := from.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if v == nil && from.Bucket(k) != nil {
				children = append(children, string(k))
				lists[string(k)] = whole
			} else {
				values = append(values, [2][]byte{k, v})
			}
		}
	case list.nested != nil:
		for _, name := range slices.Sorted(maps.Keys(list.nested)) {
			if from.Bucket([]byte(name)) == nil {
				return fmt.Errorf("%s / %q is not a bucket", at, name)
			}
			children = append(children, name)
			lists[name] = list.nested[name]
		}
	default:
		for _, key := range slices.Sorted(slices.Values(list.keys)) {
			if from.Bucket([]byte(key)) != nil {
				children = append(children, key)
				lists[key] = whole
				continue
			}
			v := from.Get([]byte(key))
			if v == nil {
				return fmt.Errorf("%s has no key %q", at, key)
			}
			values = append(values, [2][]byte{[]byte(key), v})
		}
	}
	err := dst.Update(func(tx *bolt.Tx) error {
		var to *bolt.Bucket
		var err error
		if len(path) == 1 {
			to, err = tx.CreateBucket(path[0])
		} else {
			parent := tx.Bucket(path[0])
			for _, name := range path[1 : len(path)-1] {
				parent = parent.Bucket(name)
			}
			to, err = parent.CreateBucket(path[len(path)-1])
		}
		if err != nil {
			return fmt.Errorf("%s: %w", at, err)
		}
		to.FillPercent = 1.0
		if err := to.SetSequence(from.Sequence()); err != nil {
			return err
		}
		for _, kv := range values {
			if err := to.Put(kv[0], kv[1]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, name := range children {
		where := at + " / " + strconv.Quote(name)
		nested := append(slices.Clip(path), []byte(name))
		if err := copyAllowed(from.Bucket([]byte(name)), dst, nested, lists[name], where); err != nil {
			return err
		}
	}
	return nil
}

// referenced collects the vulnerability ids that a kept bucket's advisories reference: every key
// at depth 2 or more below a top-level bucket, as collect does, and the CVE IDs that a Red Hat
// advisory lists in Entries[].Cves, since an RHSA advisory's key is not a vulnerability id.
func referenced(b *bolt.Bucket, depth int, ids map[string]bool) {
	c := b.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if v == nil {
			if nested := b.Bucket(k); nested != nil {
				referenced(nested, depth+1, ids)
				continue
			}
		}
		if depth < 2 {
			continue
		}
		ids[string(k)] = true
		var advisory struct {
			Entries []struct{ Cves []struct{ ID string } }
		}
		// Other advisories, and Red Hat CPE's lists of indices, name no CVE there.
		if json.Unmarshal(v, &advisory) != nil {
			continue
		}
		for _, entry := range advisory.Entries {
			for _, cve := range entry.Cves {
				if cve.ID != "" {
					ids[cve.ID] = true
				}
			}
		}
	}
}

// check applies the filter's rules to a database and returns the first one it breaks.
func check(path string) error {
	db, err := bolt.Open(path, 0, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		return err
	}
	defer db.Close()
	keep := keptSources()
	vendors := keptVendors()
	return db.View(func(tx *bolt.Tx) error {
		sources := tx.Bucket([]byte(dataSourceBucket))
		vulns := tx.Bucket([]byte(vulnerabilityBucket))
		if sources == nil || vulns == nil {
			return fmt.Errorf("the %s or %s bucket is missing", dataSourceBucket, vulnerabilityBucket)
		}
		// 1. The top-level buckets are the two metadata buckets and buckets of the kept sources.
		kept := map[string]bool{}
		err := tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			if isMetadata(string(name)) {
				return nil
			}
			entry := sources.Get(name)
			if entry == nil {
				return fmt.Errorf("the top-level bucket %q has no data-source entry", name)
			}
			id, err := sourceID(entry)
			if err != nil {
				return fmt.Errorf("the data-source entry of %q: %w", name, err)
			}
			if !keep[id] {
				return fmt.Errorf("the top-level bucket %q is of the source %q, which is not kept", name, id)
			}
			kept[string(name)] = true
			return nil
		})
		if err != nil {
			return err
		}
		// 2. The data-source keys are those buckets (rule 1 found an entry for each).
		err = sources.ForEach(func(name, _ []byte) error {
			if !kept[string(name)] {
				return fmt.Errorf("the data-source entry %q names no bucket", name)
			}
			return nil
		})
		if err != nil {
			return err
		}
		// 3. A kept bucket references every detail; 4. no detail names a dropped source.
		ids := map[string]bool{}
		for name := range kept {
			collect(tx.Bucket([]byte(name)), 1, ids)
		}
		return vulns.ForEach(func(k, v []byte) error {
			if !ids[string(k)] {
				return fmt.Errorf("no kept bucket references the vulnerability detail %q", k)
			}
			members, err := fields(v)
			if err != nil {
				return fmt.Errorf("the detail of %q: %w", k, err)
			}
			for _, m := range members {
				if !isVendorMap(m.name) || bytes.Equal(m.value, []byte("null")) {
					continue
				}
				inner, err := fields(m.value)
				if err != nil {
					return fmt.Errorf("the detail of %q: %s: %w", k, m.name, err)
				}
				for _, vendor := range inner {
					if !vendors[vendor.name] {
						return fmt.Errorf("the detail of %q has the %s of %q, which is not kept", k, m.name, vendor.name)
					}
				}
			}
			return nil
		})
	})
}
