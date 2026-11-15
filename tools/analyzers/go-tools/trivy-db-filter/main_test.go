package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

const (
	ghsaNpm   = "npm::GitHub Security Advisory npm"
	goVulnDB  = "go::The Go Vulnerability Database"
	sealNpm   = "seal npm::Seal Security Database"
	debian    = "debian 12"
	redHatCPE = "Red Hat CPE"
)

// The fixture's data-source entries; Red Hat CPE has none, as in the real database.
var fixtureSources = map[string]string{
	ghsaNpm:  `{"ID":"ghsa","Name":"GitHub Security Advisory npm","URL":"https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm"}`,
	goVulnDB: `{"ID":"govulndb","Name":"The Go Vulnerability Database","URL":"https://pkg.go.dev/vuln/"}`,
	sealNpm:  `{"ID":"seal","Name":"Seal Security Database","URL":"https://vulnfeed.sealsecurity.io"}`,
	debian:   `{"ID":"debian","Name":"Debian Security Tracker","URL":"https://salsa.debian.org/security-tracker-team/security-tracker"}`,
}

var advisory = `{"PatchedVersions":["9.9.9"],"VulnerableVersions":["<9.9.9"],"Note":"` + strings.Repeat("x", 200) + `"}`

// detail is a vulnerability detail as trivy-db writes it: a VendorSeverity and a CVSS entry per
// vendor (both left out without one, as trivy-db's omitempty does), and HTML characters and a \u
// escape that re-encoding the JSON would change.
func detail(id string, vendors ...string) string {
	var severity, cvss []string
	for _, v := range vendors {
		severity = append(severity, fmt.Sprintf(`"%s":3`, v))
		cvss = append(cvss, fmt.Sprintf(`"%s":{"V3Vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","V3Score":9.8}`, v))
	}
	vendorFields := ""
	if len(vendors) > 0 {
		vendorFields = fmt.Sprintf(`"VendorSeverity":{%s},"CVSS":{%s},`, strings.Join(severity, ","), strings.Join(cvss, ","))
	}
	return fmt.Sprintf(`{"Title":"%s: <script> & café","Description":"a > b && c < d","Severity":"HIGH",`+
		`"CweIDs":["CWE-1321"],%s"References":["https://example.test/advisory?id=%s&x=1"],"PublishedDate":"2022-03-17T16:15:00Z"}`,
		id, vendorFields, id)
}

type creator interface {
	CreateBucket(name []byte) (*bolt.Bucket, error)
}

// writeFixture writes a small Trivy database: two kept library buckets, Seal's npm bucket, a
// Debian bucket of 2000 filler advisories and Red Hat CPE without a data-source entry, and the
// details of the kept buckets' ids plus one id no bucket references.
func writeFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trivy.db")
	db, err := bolt.Open(path, 0o644, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	advisories := map[string]map[string][]string{
		ghsaNpm:  {"minimist": {"CVE-2021-44906"}, "lodash": {"CVE-2021-23337", "GHSA-jf85-cpcp-j695"}},
		goVulnDB: {"golang.org/x/net": {"CVE-2023-44487"}},
		sealNpm:  {"minimist": {"CVE-2021-44906"}},
		debian:   {},
	}
	for i := range 2000 {
		advisories[debian][fmt.Sprintf("package-%04d", i)] = []string{fmt.Sprintf("CVE-2024-%05d", i)}
	}
	details := map[string]string{
		"CVE-2021-44906":      detail("CVE-2021-44906", "ghsa", "nvd", "ubuntu"),
		"CVE-2021-23337":      detail("CVE-2021-23337", "ghsa", "ubuntu", "nvd"),
		"GHSA-jf85-cpcp-j695": detail("GHSA-jf85-cpcp-j695", "ubuntu"),
		"CVE-2023-44487":      detail("CVE-2023-44487", "govulndb", "nvd", "ubuntu"),
		"CVE-2000-0001":       detail("CVE-2000-0001", "nvd"),
	}
	err = db.Update(func(tx *bolt.Tx) error {
		bucket := func(parent creator, name string) *bolt.Bucket {
			b, err := parent.CreateBucket([]byte(name))
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
		put := func(b *bolt.Bucket, key, value string) {
			if err := b.Put([]byte(key), []byte(value)); err != nil {
				t.Fatal(err)
			}
		}
		sources := bucket(tx, dataSourceBucket)
		for name, value := range fixtureSources {
			put(sources, name, value)
		}
		for name, packages := range advisories {
			b := bucket(tx, name)
			for pkg, ids := range packages {
				p := bucket(b, pkg)
				for _, id := range ids {
					put(p, id, advisory)
				}
			}
		}
		put(bucket(bucket(tx, redHatCPE), "repository"), "rhel-8-for-x86_64-baseos-rpms", "[1,2]")
		vulns := bucket(tx, vulnerabilityBucket)
		for id, d := range details {
			put(vulns, id, d)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// read lists a database's top-level buckets and data-source keys, and returns its vulnerability
// details and the advisory at ghsaNpm/lodash/CVE-2021-23337.
func read(t *testing.T, path string) (top, sources []string, details map[string]string, lodash string) {
	t.Helper()
	db, err := bolt.Open(path, 0, &bolt.Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	details = map[string]string{}
	err = db.View(func(tx *bolt.Tx) error {
		_ = tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			top = append(top, string(name))
			return nil
		})
		_ = tx.Bucket([]byte(dataSourceBucket)).ForEach(func(k, _ []byte) error {
			sources = append(sources, string(k))
			return nil
		})
		_ = tx.Bucket([]byte(vulnerabilityBucket)).ForEach(func(k, v []byte) error {
			details[string(k)] = string(v)
			return nil
		})
		if npm := tx.Bucket([]byte(ghsaNpm)); npm != nil {
			lodash = string(npm.Bucket([]byte("lodash")).Get([]byte("CVE-2021-23337")))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return top, sources, details, lodash
}

func size(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

func TestFilterKeepsTheLibrarySourcesAndTheDetailsTheyReference(t *testing.T) {
	path := writeFixture(t)
	before := size(t, path)
	var out bytes.Buffer
	if err := filter(path, &out); err != nil {
		t.Fatal(err)
	}

	top, sources, details, lodash := read(t, path)
	if want := []string{dataSourceBucket, goVulnDB, ghsaNpm, vulnerabilityBucket}; !slices.Equal(top, want) {
		t.Errorf("top-level buckets %q, want %q", top, want)
	}
	if want := []string{goVulnDB, ghsaNpm}; !slices.Equal(sources, want) {
		t.Errorf("data-source keys %q, want %q", sources, want)
	}
	// The orphan goes; ubuntu leaves both maps (and the maps themselves when nothing is left);
	// every other byte of a detail stays.
	want := map[string]string{
		"CVE-2021-44906":      detail("CVE-2021-44906", "ghsa", "nvd"),
		"CVE-2021-23337":      detail("CVE-2021-23337", "ghsa", "nvd"),
		"GHSA-jf85-cpcp-j695": detail("GHSA-jf85-cpcp-j695"),
		"CVE-2023-44487":      detail("CVE-2023-44487", "govulndb", "nvd"),
	}
	if !maps.Equal(details, want) {
		t.Errorf("vulnerability details\n%q\nwant\n%q", details, want)
	}
	if lodash != advisory {
		t.Errorf("advisory %q, want %q", lodash, advisory)
	}

	if after := size(t, path); after >= before {
		t.Errorf("the filtered file has %d bytes, the input %d", after, before)
	}
	for _, line := range []string{"dropped (none): 1 buckets\n", "dropped debian: 1 buckets\n", "dropped seal: 1 buckets\n"} {
		if !strings.Contains(out.String(), line) {
			t.Errorf("output %q lacks %q", out.String(), line)
		}
	}
	if _, err := os.Stat(path + ".tmp-filter"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the temporary file is left: %v", err)
	}
	if err := check(path); err != nil {
		t.Errorf("check of the filtered file: %v", err)
	}
}

func TestFilterRefusesADatabaseWithoutDataSources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trivy.db")
	db, err := bolt.Open(path, 0o644, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucket([]byte(vulnerabilityBucket))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := filter(path, io.Discard); err == nil || !strings.Contains(err.Error(), dataSourceBucket) {
		t.Errorf("filter: %v, want an error naming %q", err, dataSourceBucket)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, before) {
		t.Error("the input changed")
	}
	if _, err := os.Stat(path + ".tmp-filter"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the temporary file is left: %v", err)
	}
}

func TestCheckFailsWithTheFirstRuleTheFileBreaks(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-check", writeFixture(t)}, &stdout, &stderr); code != 1 {
		t.Errorf("-check of the unfiltered file: exit %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), `"Red Hat CPE"`) {
		t.Errorf("-check of the unfiltered file: %q, want the first bucket it may not hold", stderr.String())
	}

	put := func(bucket, key, value string) func(*bolt.Tx) error {
		return func(tx *bolt.Tx) error { return tx.Bucket([]byte(bucket)).Put([]byte(key), []byte(value)) }
	}
	for _, tc := range []struct {
		name    string
		change  func(*bolt.Tx) error
		message string
	}{
		{"a dropped source's bucket", func(tx *bolt.Tx) error {
			if _, err := tx.CreateBucket([]byte(debian)); err != nil {
				return err
			}
			return put(dataSourceBucket, debian, fixtureSources[debian])(tx)
		}, `"debian 12"`},
		{"a bucket without a data-source entry", func(tx *bolt.Tx) error {
			_, err := tx.CreateBucket([]byte(redHatCPE))
			return err
		}, `"Red Hat CPE"`},
		{"a data-source entry without its bucket", put(dataSourceBucket, sealNpm, fixtureSources[sealNpm]), `"seal npm::Seal Security Database"`},
		{"a detail no kept bucket references", put(vulnerabilityBucket, "CVE-2000-0001", detail("CVE-2000-0001", "nvd")), `"CVE-2000-0001"`},
		{"a dropped source's severity", put(vulnerabilityBucket, "CVE-2021-44906", detail("CVE-2021-44906", "ghsa", "ubuntu")), `"ubuntu"`},
		{"a dropped source's CVSS", put(vulnerabilityBucket, "CVE-2021-44906", `{"VendorSeverity":{"ghsa":3},"CVSS":{"redhat":{"V3Score":9.8}}}`), `"redhat"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeFixture(t)
			if err := filter(path, io.Discard); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			if code := run([]string{"-check", path}, &stdout, &stderr); code != 0 {
				t.Fatalf("-check of the filtered file: exit %d, %s", code, stderr.String())
			}
			db, err := bolt.Open(path, 0o644, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Update(tc.change); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			if err := check(path); err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Errorf("check: %v, want an error naming %s", err, tc.message)
			}
		})
	}
}
