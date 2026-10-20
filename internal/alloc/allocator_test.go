package alloc

import (
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"idips/internal/secret"
	"idips/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestAllocatorStickyAndUnique(t *testing.T) {
	st := testStore(t)
	a, err := New(st, "10.50.0.0/29", func() time.Duration { return time.Hour }, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	ips := []net.IP{net.ParseIP("1.2.3.4")}
	first, err := a.GetOrCreate("one.example", ips, "")
	if err != nil {
		t.Fatal(err)
	}
	if !a.Contains(net.ParseIP(first.FakeIP)) {
		t.Fatalf("fake IP %s outside pool", first.FakeIP)
	}
	second, err := a.GetOrCreate("one.example", ips, "")
	if err != nil {
		t.Fatal(err)
	}
	if first.FakeIP != second.FakeIP {
		t.Fatalf("expected stable fake IP, got %s then %s", first.FakeIP, second.FakeIP)
	}
	other, err := a.GetOrCreate("two.example", ips, "")
	if err != nil {
		t.Fatal(err)
	}
	if other.FakeIP == first.FakeIP {
		t.Fatal("expected unique fake IP")
	}
	byIP, err := a.GetActiveByIP(first.FakeIP)
	if err != nil {
		t.Fatal(err)
	}
	if byIP.TargetDomain != "one.example" {
		t.Fatalf("unexpected domain %q", byIP.TargetDomain)
	}
}

func TestAllocatorExhaustionAndDelete(t *testing.T) {
	st := testStore(t)
	a, err := New(st, "10.51.0.0/29", func() time.Duration { return time.Hour }, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	// /29 reserves network and broadcast, leaving 6 usable addresses.
	var leases []string
	for i := 0; i < 6; i++ {
		l, err := a.GetOrCreate("d"+string(rune('a'+i))+".example", nil, "")
		if err != nil {
			t.Fatalf("lease %d: %v", i, err)
		}
		leases = append(leases, l.FakeIP)
	}
	if _, err := a.GetOrCreate("full.example", nil, ""); err != ErrPoolExhausted {
		t.Fatalf("expected pool exhausted, got %v", err)
	}
	if err := a.Delete(1); err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetOrCreate("new.example", nil, ""); err != nil {
		t.Fatalf("expected allocation after delete: %v", err)
	}
}

func TestAllocatorGC(t *testing.T) {
	st := testStore(t)
	a, err := New(st, "10.52.0.0/29", func() time.Duration { return 50 * time.Millisecond }, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetOrCreate("expire.example", nil, ""); err != nil {
		t.Fatal(err)
	}
	time.Sleep(120 * time.Millisecond)
	if err := a.GC(); err != nil {
		t.Fatal(err)
	}
	if got := a.Stats().Used; got != 0 {
		t.Fatalf("expected 0 used after GC, got %d", got)
	}
	n, err := st.CountLeases(false)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expected 0 leases after GC, got %d", n)
	}
}
