package routing

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

const geoTestData = `1.0.0.0	1.0.0.255	13335	US	CLOUDFLARENET
8.8.8.0	8.8.8.255	15169	US	GOOGLE
192.0.2.0	192.0.2.255	64496	DE	TEST-NET
2001:db8::	2001:db8:ffff:ffff:ffff:ffff:ffff:ffff	64497	NL	TEST-V6
`

func TestGeoTSVMatching(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip2asn.tsv")
	if err := os.WriteFile(path, []byte(geoTestData), 0o600); err != nil {
		t.Fatal(err)
	}
	e := New(testStore(t), testLogger())
	if err := e.ReloadGeo("", "", path); err != nil {
		t.Fatal(err)
	}

	if !e.matchGeo("DE", []net.IP{net.ParseIP("192.0.2.1")}) {
		t.Fatal("expected DE match")
	}
	if e.matchGeo("US", []net.IP{net.ParseIP("192.0.2.1")}) {
		t.Fatal("unexpected US match")
	}
	if !e.matchGeo("NL", []net.IP{net.ParseIP("2001:db8::1")}) {
		t.Fatal("expected IPv6 country match")
	}
	if !e.matchASN("AS15169", []net.IP{net.ParseIP("8.8.8.8")}) {
		t.Fatal("expected ASN match with AS prefix")
	}
	if !e.matchASN("64496", []net.IP{net.ParseIP("192.0.2.1")}) {
		t.Fatal("expected numeric ASN match")
	}
	if e.matchASN("15169", []net.IP{net.ParseIP("192.0.2.1")}) {
		t.Fatal("unexpected ASN match")
	}

	info, ok := e.LookupIP(net.ParseIP("1.0.0.1"))
	if !ok || info.ASN != 13335 || info.Country != "US" || info.Org != "CLOUDFLARENET" {
		t.Fatalf("LookupIP = %+v, %v", info, ok)
	}
}
