package routing

import (
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"

	"idips/internal/model"
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

func TestDecideDomainPriorityBlockAndFailover(t *testing.T) {
	st := testStore(t)
	upID, err := st.CreateUpstream(model.Upstream{Name: "up", Type: model.UpstreamSOCKS5, Address: "127.0.0.1:1", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	downID, err := st.CreateUpstream(model.Upstream{Name: "down", Type: model.UpstreamSOCKS5, Address: "127.0.0.1:2", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateUpstreamHealth(downID, model.HealthDown); err != nil {
		t.Fatal(err)
	}

	mustRule(t, st, model.Rule{Name: "regex ads", Priority: 5, Enabled: true, MatchDomain: `^ads\.`, DomainMode: "regex", Action: model.ActionBlock})
	mustRule(t, st, model.Rule{Name: "down first", Priority: 10, Enabled: true, MatchDomain: "down.example", DomainMode: "suffix", Action: model.ActionProxy, UpstreamID: downID})
	mustRule(t, st, model.Rule{Name: "down failover", Priority: 20, Enabled: true, MatchDomain: "down.example", DomainMode: "suffix", Action: model.ActionProxy, UpstreamID: upID})
	mustRule(t, st, model.Rule{Name: "blocked", Priority: 30, Enabled: true, MatchDomain: "blocked.example", DomainMode: "exact", Action: model.ActionBlock})
	mustRule(t, st, model.Rule{Name: "cidr", Priority: 40, Enabled: true, MatchCIDR: "203.0.113.0/24", MatchClientCIDR: "192.168.0.0/16", MatchPort: "443", Action: model.ActionProxy, UpstreamID: upID})

	e := New(st, testLogger())
	defer e.Close()

	check := func(host string, ips []net.IP, client net.IP, port int, action string, upstream int64) {
		t.Helper()
		d, err := e.Decide(host, ips, client, port)
		if err != nil {
			t.Fatal(err)
		}
		if d.Action != action || d.UpstreamID != upstream {
			t.Fatalf("%s: got action=%s upstream=%d, want action=%s upstream=%d (reason %s)", host, d.Action, d.UpstreamID, action, upstream, d.Reason)
		}
	}

	check("ads.example.org", nil, net.ParseIP("10.0.0.1"), 443, model.ActionBlock, 0)
	check("www.down.example", nil, net.ParseIP("10.0.0.1"), 443, model.ActionProxy, upID)
	check("blocked.example", nil, net.ParseIP("10.0.0.1"), 443, model.ActionBlock, 0)
	check("other.example", []net.IP{net.ParseIP("203.0.113.9")}, net.ParseIP("192.168.1.2"), 443, model.ActionProxy, upID)
	check("other.example", []net.IP{net.ParseIP("203.0.113.9")}, net.ParseIP("192.168.1.2"), 80, model.ActionDirect, 0)
	check("other.example", []net.IP{net.ParseIP("203.0.113.9")}, net.ParseIP("10.0.0.1"), 443, model.ActionDirect, 0)
	check("netflix.com", nil, net.ParseIP("10.0.0.1"), 443, model.ActionDirect, 0)
}

func mustRule(t *testing.T, st *store.Store, r model.Rule) {
	t.Helper()
	if _, err := st.CreateRule(r); err != nil {
		t.Fatal(err)
	}
}
