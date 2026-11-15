// Command trivy-db-filter keeps the library sources of a Trivy vulnerability database (trivy-db
// schema 2) and drops every other source (0.16 debts D31-1, rulings B2-b and B2-s): Qualor's
// scanner only reads library packages, and some operating-system and vendor sources may not be
// redistributed. deploy/scanner/NOTICE.md lists the sources it keeps.
//
//	trivy-db-filter <trivy.db>         filters the file in place
//	trivy-db-filter -check <trivy.db>  exits 1 with the first rule the file breaks
//
// The kept data goes into a fresh file, which also compacts it (bbolt never shrinks a file): each
// top-level bucket whose data-source ID is in KEEP, with its nested buckets; their data-source
// entries; and the vulnerability details their advisories reference, with VendorSeverity and CVSS
// reduced to the kept sources and nvd, every other byte as it was. Then the file replaces the input.
// tools/analyzers/filter-trivy-db.sh runs both.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
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
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: trivy-db-filter [-check] <trivy.db>")
		return 2
	}
	path := flags.Arg(0)
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

func filter(path string, out io.Writer) (err error) {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	src, err := bolt.Open(path, 0, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		return err
	}
	defer src.Close()
	tmp := path + ".tmp-filter"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dst, err := bolt.Open(tmp, info.Mode().Perm(), &bolt.Options{NoSync: true, NoGrowSync: true, Timeout: time.Second})
	if err != nil {
		return err
	}
	// The file grows to what its pages need, without bbolt's 16 MiB of headroom.
	dst.AllocSize = 0
	defer func() {
		if err != nil {
			_ = dst.Close()
			_ = os.Remove(tmp)
		}
	}()
	s, err := copyKept(src, dst)
	if err != nil {
		return err
	}
	if err := dst.Sync(); err != nil {
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	if err := src.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, info.Mode().Perm()); err != nil {
		return err
	}
	after, err := os.Stat(tmp)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
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
	fmt.Fprintf(out, "%d bytes before, %d bytes after\n", info.Size(), after.Size())
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
				trimmed, err := keepVendors(v, vendors)
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

// keepVendors reduces a vulnerability detail's VendorSeverity and CVSS to the vendors' keys, in
// their order, and leaves either out when nothing is left (trivy-db's omitempty); every other
// member keeps its bytes.
func keepVendors(detail []byte, vendors map[string]bool) ([]byte, error) {
	members, err := fields(detail)
	if err != nil {
		return nil, err
	}
	out := members[:0]
	for _, m := range members {
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
