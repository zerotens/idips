package model

import "time"

const (
	UpstreamSOCKS5    = "socks5"
	UpstreamHTTP      = "http"
	UpstreamWireGuard = "wireguard"

	ActionProxy  = "proxy"
	ActionDirect = "direct"
	ActionBlock  = "block"

	LogicAnd = "and"
	LogicOr  = "or"

	HealthUnknown = "unknown"
	HealthUp      = "up"
	HealthDown    = "down"
)

type Upstream struct {
	ID            int64     `json:"id"`
	Name          string    `json:"name"`
	Type          string    `json:"type"`
	Address       string    `json:"address"`
	Username      string    `json:"username,omitempty"`
	Password      string    `json:"-"`
	ClearPassword bool      `json:"-"`
	WGConfig      string    `json:"-"`
	Enabled       bool      `json:"enabled"`
	Priority      int       `json:"priority"`
	Health        string    `json:"health"`
	LastCheck     time.Time `json:"last_check"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type Rule struct {
	ID              int64     `json:"id"`
	Name            string    `json:"name"`
	Priority        int       `json:"priority"`
	Enabled         bool      `json:"enabled"`
	MatchDomain     string    `json:"match_domain"`
	DomainMode      string    `json:"domain_mode"`
	MatchLogic      string    `json:"match_logic"`
	MatchCIDR       string    `json:"match_cidr"`
	MatchGeoIP      string    `json:"match_geoip"`
	MatchASN        string    `json:"match_asn"`
	MatchClientCIDR string    `json:"match_client_cidr"`
	MatchPort       string    `json:"match_port"`
	Action          string    `json:"action"`
	UpstreamID      int64     `json:"upstream_id"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type Lease struct {
	ID           int64     `json:"id"`
	FakeIP       string    `json:"fake_ip"`
	TargetDomain string    `json:"target_domain"`
	TargetIPs    []string  `json:"target_ips"`
	ClientKey    string    `json:"client_key,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Admin struct {
	ID           int64
	Username     string
	PasswordHash string
	CreatedAt    time.Time
}

type AuditEntry struct {
	ID     int64     `json:"id"`
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Detail string    `json:"detail"`
}

type Settings struct {
	PoolCIDR              string `json:"pool_cidr"`
	LeaseTTLSeconds       int    `json:"lease_ttl_seconds"`
	DNSTTL                uint32 `json:"dns_ttl"`
	DNSListen             string `json:"dns_listen"`
	DNSUpstream           string `json:"dns_upstream"`
	DNSUpstreamProtocol   string `json:"dns_upstream_protocol"`
	DNSUpstreamUpstreamID int64  `json:"dns_upstream_upstream_id"`
	BlockAAAA             bool   `json:"block_aaaa"`
	FakeAll               bool   `json:"fake_all"`
	DefaultAction         string `json:"default_action"`
	DefaultUpstreamID     int64  `json:"default_upstream_id"`
	SOCKS5Listen          string `json:"socks5_listen"`
	SOCKS5Username        string `json:"socks5_username"`
	SOCKS5Password        string `json:"socks5_password"`
	HTTPListen            string `json:"http_listen"`
	HTTPUsername          string `json:"http_username"`
	HTTPPassword          string `json:"http_password"`
	TProxyEnabled         bool   `json:"tproxy_enabled"`
	TProxyListen          string `json:"tproxy_listen"`
	AdminListen           string `json:"admin_listen"`
	AdminTLSCert          string `json:"admin_tls_cert"`
	AdminTLSKey           string `json:"admin_tls_key"`
	DoHListen             string `json:"doh_listen"`
	DoTListen             string `json:"dot_listen"`
	DNSCert               string `json:"dns_cert"`
	DNSKey                string `json:"dns_key"`
	WireproxyBinary       string `json:"wireproxy_binary"`
	WireproxyDataDir      string `json:"wireproxy_data_dir"`
	HealthTarget          string `json:"health_target"`
	GeoIPCityDB           string `json:"geoip_city_db"`
	GeoIPASNDB            string `json:"geoip_asn_db"`
	GeoIPTSV              string `json:"geoip_tsv"`
	APIToken              string `json:"api_token"`
	LogLevel              string `json:"log_level"`
}

func (s Settings) LeaseTTL() time.Duration {
	if s.LeaseTTLSeconds <= 0 {
		return 24 * time.Hour
	}
	return time.Duration(s.LeaseTTLSeconds) * time.Second
}

func DefaultSettings() Settings {
	return Settings{
		PoolCIDR:            "10.100.0.0/16",
		LeaseTTLSeconds:     86400,
		DNSTTL:              60,
		DNSListen:           ":53",
		DNSUpstream:         "1.1.1.1:53",
		DNSUpstreamProtocol: "udp",
		BlockAAAA:           true,
		FakeAll:             false,
		DefaultAction:       ActionDirect,
		SOCKS5Listen:        ":1080",
		HTTPListen:          ":8081",
		TProxyEnabled:       true,
		TProxyListen:        ":1082",
		AdminListen:         ":8080",
		WireproxyBinary:     "wireproxy",
		WireproxyDataDir:    "wireproxy",
		HealthTarget:        "1.1.1.1:443",
		LogLevel:            "info",
	}
}
