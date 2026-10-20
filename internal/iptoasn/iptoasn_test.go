package iptoasn

import (
	"compress/gzip"
	"net"
	"os"
	"path/filepath"
	"testing"
)

const sample = `1.0.0.0	1.0.0.255	13335	US	CLOUDFLARENET
8.8.8.0	8.8.8.255	15169	US	GOOGLE
192.0.2.0	192.0.2.255	64496	DE	TEST-NET
2001:db8::	2001:db8:ffff:ffff:ffff:ffff:ffff:ffff	64497	NL	TEST-V6
`

func writeSample(t *testing.T, compressed bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ip2asn.tsv")
	if compressed {
		path += ".gz"
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		zw := gzip.NewWriter(f)
		if _, err := zw.Write([]byte(sample)); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if err := os.WriteFile(path, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOpenAndLookup(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		db, err := Open(writeSample(t, compressed))
		if err != nil {
			t.Fatalf("compressed=%v: %v", compressed, err)
		}
		if db.Len() != 4 {
			t.Fatalf("compressed=%v: len = %d, want 4", compressed, db.Len())
		}

		tests := []struct {
			ip      string
			asn     uint32
			country string
			org     string
			ok      bool
		}{
			{"1.0.0.1", 13335, "US", "CLOUDFLARENET", true},
			{"1.0.0.255", 13335, "US", "CLOUDFLARENET", true},
			{"8.8.8.8", 15169, "US", "GOOGLE", true},
			{"192.0.2.42", 64496, "DE", "TEST-NET", true},
			{"1.0.1.0", 0, "", "", false},
			{"2001:db8::1", 64497, "NL", "TEST-V6", true},
			{"2001:db9::", 0, "", "", false},
			{"::ffff:8.8.8.8", 15169, "US", "GOOGLE", true},
		}
		for _, tt := range tests {
			rec, ok := db.Lookup(net.ParseIP(tt.ip))
			if ok != tt.ok || rec.ASN != tt.asn || rec.Country != tt.country || rec.Org != tt.org {
				t.Errorf("compressed=%v lookup %s = %+v, %v; want ASN %d country %q org %q ok %v",
					compressed, tt.ip, rec, ok, tt.asn, tt.country, tt.org, tt.ok)
			}
		}
	}
}

func TestOpenRejectsEmptyDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.tsv")
	if err := os.WriteFile(path, []byte("# nothing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("expected an error for an empty database")
	}
}

func TestParseInvalidGzip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.tsv.gz")
	if err := os.WriteFile(path, []byte("\x1f\x8bnot-gzip"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("expected an error for invalid gzip data")
	}
}
