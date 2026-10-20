package upstream

import (
	"strings"
	"testing"
)

func TestRenderWireproxyConfig(t *testing.T) {
	raw := `[Interface]
PrivateKey = priv
Address = 10.0.0.2/32, fd00::2/128
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = pub
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`
	cfg, err := parseWireguardConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	out, err := renderWireproxyConfig(cfg, "127.0.0.1:12345")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"PrivateKey = priv",
		"Address = 10.0.0.2/32, fd00::2/128",
		"PublicKey = pub",
		"Endpoint = vpn.example.com:51820",
		"AllowedIPs = 0.0.0.0/0",
		"BindAddress = 127.0.0.1:12345",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("generated config missing %q:\n%s", want, out)
		}
	}
}

func TestParseWireguardConfigMultiplePeers(t *testing.T) {
	raw := `[Interface]
PrivateKey = priv
Address = 10.0.0.2/32

[Peer]
PublicKey = peer1
Endpoint = host1:51820

[Peer]
PublicKey = peer2
Endpoint = host2:51820
AllowedIPs = 10.0.0.0/8, 192.168.0.0/16
`
	cfg, err := parseWireguardConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(cfg.Peers))
	}
	if got := strings.Join(cfg.Peers[0].AllowedIPs, ","); got != "0.0.0.0/0,::/0" {
		t.Fatalf("unexpected default allowed IPs: %s", got)
	}
	if got := strings.Join(cfg.Peers[1].AllowedIPs, ","); got != "10.0.0.0/8,192.168.0.0/16" {
		t.Fatalf("unexpected peer allowed IPs: %s", got)
	}
}

func TestParseWireguardConfigValidation(t *testing.T) {
	if err := ValidateWireguardConfig(`[Interface]
Address = 10.0.0.2/32
`); err == nil {
		t.Fatal("expected missing PrivateKey error")
	}
	if err := ValidateWireguardConfig(`[Interface]
PrivateKey = x
Address = 10.0.0.2/32
`); err == nil {
		t.Fatal("expected missing Peer error")
	}
	if err := ValidateWireguardConfig(`[Interface]
PrivateKey = x
Address = 10.0.0.2/32

[Peer]
PublicKey = y
Endpoint = host:1
`); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
