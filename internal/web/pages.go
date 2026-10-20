package web

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"idips/internal/model"
	"idips/internal/store"
	"idips/internal/upstream"
)

type dashboardData struct {
	Upstreams    []model.Upstream
	Rules        []model.Rule
	LeaseCount   int64
	RuleCount    int
	UpCount      int
	DownCount    int
	Stats        any
	Audit        []model.AuditEntry
	Settings     model.Settings
	UsagePercent float64
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	upstreams, _ := s.store.ListUpstreams()
	rules, _ := s.store.ListRules()
	leaseCount, _ := s.store.CountLeases(true)
	audit, _ := s.store.ListAudit(8)
	stats := s.alloc.Stats()
	up, down := 0, 0
	for _, u := range upstreams {
		switch u.Health {
		case model.HealthUp:
			up++
		case model.HealthDown:
			down++
		}
	}
	usage := 0.0
	if stats.Size > 0 {
		usage = float64(stats.Used) / float64(stats.Size) * 100
	}
	s.render(w, r, "dashboard.html", "Dashboard", "dashboard", dashboardData{
		Upstreams: upstreams, Rules: rules, LeaseCount: leaseCount, RuleCount: len(rules),
		UpCount: up, DownCount: down, Stats: stats, Audit: audit, Settings: s.settings(), UsagePercent: usage,
	})
}

func (s *Server) upstreamsList(w http.ResponseWriter, r *http.Request) {
	upstreams, err := s.store.ListUpstreams()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, r, "upstreams.html", "Upstreams", "upstreams", struct {
		Upstreams []model.Upstream
	}{upstreams})
}

type upstreamFormData struct {
	Upstream model.Upstream
	IsNew    bool
	Types    []string
	SampleWG string
}

func (s *Server) upstreamNew(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "upstream_form.html", "New upstream", "upstreams", upstreamFormData{
		Upstream: model.Upstream{Enabled: true, Type: model.UpstreamSOCKS5, Health: model.HealthUnknown},
		IsNew:    true,
		Types:    []string{model.UpstreamSOCKS5, model.UpstreamHTTP, model.UpstreamWireGuard},
		SampleWG: sampleWireguardConfig,
	})
}

func (s *Server) upstreamEdit(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	u, err := s.store.GetUpstream(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.render(w, r, "upstream_form.html", "Edit upstream", "upstreams", upstreamFormData{
		Upstream: u, IsNew: false,
		Types:    []string{model.UpstreamSOCKS5, model.UpstreamHTTP, model.UpstreamWireGuard},
		SampleWG: sampleWireguardConfig,
	})
}

func (s *Server) upstreamSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	u := model.Upstream{
		Name:          strings.TrimSpace(r.FormValue("name")),
		Type:          strings.TrimSpace(r.FormValue("type")),
		Address:       strings.TrimSpace(r.FormValue("address")),
		Username:      strings.TrimSpace(r.FormValue("username")),
		Password:      r.FormValue("password"),
		ClearPassword: formBool(r, "clear_password"),
		WGConfig:      strings.TrimSpace(r.FormValue("wg_config")),
		Enabled:       formBool(r, "enabled"),
		Priority:      atoiDefault(r.FormValue("priority"), 0),
	}
	info, _ := s.session(r)
	if err := validateUpstream(u); err != nil {
		redirectMsg(w, r, "/upstreams", "", err.Error())
		return
	}
	if raw := r.PathValue("id"); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			http.Error(w, "invalid id", http.StatusBadRequest)
			return
		}
		u.ID = id
		if err := s.store.UpdateUpstream(u); err != nil {
			redirectMsg(w, r, "/upstreams", "", err.Error())
			return
		}
		_ = s.store.AddAudit(info.Admin.Username, "upstream_update", u.Name)
	} else {
		if _, err := s.store.CreateUpstream(u); err != nil {
			redirectMsg(w, r, "/upstreams", "", err.Error())
			return
		}
		_ = s.store.AddAudit(info.Admin.Username, "upstream_create", u.Name)
	}
	redirectMsg(w, r, "/upstreams", "Upstream saved", "")
}

func (s *Server) upstreamDelete(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	u, _ := s.store.GetUpstream(id)
	if err := s.store.DeleteUpstream(id); err != nil {
		redirectMsg(w, r, "/upstreams", "", err.Error())
		return
	}
	info, _ := s.session(r)
	_ = s.store.AddAudit(info.Admin.Username, "upstream_delete", fmt.Sprintf("%d %s", id, u.Name))
	redirectMsg(w, r, "/upstreams", "Upstream deleted", "")
}

func (s *Server) upstreamTest(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	u, _ := s.store.GetUpstream(id)
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	start := time.Now()
	_, testErr := s.manager.Test(ctx, id)
	data := struct {
		ID       int64
		Name     string
		Duration time.Duration
		Error    string
	}{ID: id, Name: u.Name, Duration: time.Since(start)}
	if testErr != nil {
		data.Error = testErr.Error()
	}
	if r.Header.Get("HX-Request") != "" {
		s.renderPartial(w, "partial_test.html", data)
		return
	}
	if testErr != nil {
		redirectMsg(w, r, "/upstreams", "", testErr.Error())
	} else {
		redirectMsg(w, r, "/upstreams", fmt.Sprintf("%s: OK in %s", u.Name, data.Duration.Round(time.Millisecond)), "")
	}
}

type ruleRow struct {
	Rule         model.Rule
	UpstreamName string
}

func (s *Server) rulesList(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListRules()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	upstreams, _ := s.store.ListUpstreams()
	names := make(map[int64]string, len(upstreams))
	for _, u := range upstreams {
		names[u.ID] = u.Name
	}
	rows := make([]ruleRow, 0, len(rules))
	for _, rule := range rules {
		rows = append(rows, ruleRow{Rule: rule, UpstreamName: names[rule.UpstreamID]})
	}
	s.render(w, r, "rules.html", "Routing rules", "rules", struct {
		Rules []ruleRow
	}{rows})
}

type ruleFormData struct {
	Rule      model.Rule
	IsNew     bool
	Upstreams []model.Upstream
}

func (s *Server) ruleNew(w http.ResponseWriter, r *http.Request) {
	upstreams, _ := s.store.ListUpstreams()
	s.render(w, r, "rule_form.html", "New rule", "rules", ruleFormData{
		Rule:      model.Rule{Enabled: true, Priority: 100, DomainMode: "suffix", MatchLogic: model.LogicAnd, Action: model.ActionProxy},
		IsNew:     true,
		Upstreams: upstreams,
	})
}

func (s *Server) ruleEdit(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	rule, err := s.store.GetRule(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	upstreams, _ := s.store.ListUpstreams()
	s.render(w, r, "rule_form.html", "Edit rule", "rules", ruleFormData{Rule: rule, Upstreams: upstreams})
}

func (s *Server) ruleSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	rule := model.Rule{
		Name:            strings.TrimSpace(r.FormValue("name")),
		Priority:        atoiDefault(r.FormValue("priority"), 100),
		Enabled:         formBool(r, "enabled"),
		MatchDomain:     strings.TrimSpace(r.FormValue("match_domain")),
		DomainMode:      strings.TrimSpace(r.FormValue("domain_mode")),
		MatchLogic:      strings.ToLower(strings.TrimSpace(r.FormValue("match_logic"))),
		MatchCIDR:       strings.TrimSpace(r.FormValue("match_cidr")),
		MatchGeoIP:      strings.TrimSpace(r.FormValue("match_geoip")),
		MatchASN:        strings.TrimSpace(r.FormValue("match_asn")),
		MatchClientCIDR: strings.TrimSpace(r.FormValue("match_client_cidr")),
		MatchPort:       strings.TrimSpace(r.FormValue("match_port")),
		Action:          strings.TrimSpace(r.FormValue("action")),
	}
	if rule.MatchLogic == "" {
		rule.MatchLogic = model.LogicAnd
	}
	if raw := r.FormValue("upstream_id"); raw != "" {
		rule.UpstreamID, _ = strconv.ParseInt(raw, 10, 64)
	}
	if err := validateRule(s.store, rule); err != nil {
		redirectMsg(w, r, "/rules", "", err.Error())
		return
	}
	info, _ := s.session(r)
	if raw := r.PathValue("id"); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			http.Error(w, "invalid id", http.StatusBadRequest)
			return
		}
		rule.ID = id
		if err := s.store.UpdateRule(rule); err != nil {
			redirectMsg(w, r, "/rules", "", err.Error())
			return
		}
		_ = s.store.AddAudit(info.Admin.Username, "rule_update", rule.Name)
	} else {
		if _, err := s.store.CreateRule(rule); err != nil {
			redirectMsg(w, r, "/rules", "", err.Error())
			return
		}
		_ = s.store.AddAudit(info.Admin.Username, "rule_create", rule.Name)
	}
	redirectMsg(w, r, "/rules", "Rule saved", "")
}

func (s *Server) ruleDelete(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	info, _ := s.session(r)
	if err := s.store.DeleteRule(id); err != nil {
		redirectMsg(w, r, "/rules", "", err.Error())
		return
	}
	_ = s.store.AddAudit(info.Admin.Username, "rule_delete", strconv.FormatInt(id, 10))
	redirectMsg(w, r, "/rules", "Rule deleted", "")
}

func (s *Server) leasesList(w http.ResponseWriter, r *http.Request) {
	search := strings.TrimSpace(r.URL.Query().Get("q"))
	leases, err := s.store.ListLeases(200, 0, search)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	count, _ := s.store.CountLeases(true)
	cfg := s.settings()
	s.render(w, r, "leases.html", "Fake-IP leases", "leases", struct {
		Leases   []model.Lease
		Search   string
		Count    int64
		Stats    any
		LeaseTTL int
	}{leases, search, count, s.alloc.Stats(), cfg.LeaseTTLSeconds})
}

func (s *Server) leaseDelete(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	info, _ := s.session(r)
	if err := s.alloc.Delete(id); err != nil {
		redirectMsg(w, r, "/leases", "", err.Error())
		return
	}
	_ = s.store.AddAudit(info.Admin.Username, "lease_revoke", strconv.FormatInt(id, 10))
	redirectMsg(w, r, "/leases", "Lease revoked", "")
}

func (s *Server) settingsGet(w http.ResponseWriter, r *http.Request) {
	upstreams, _ := s.store.ListUpstreams()
	s.render(w, r, "settings.html", "Settings", "settings", struct {
		Settings  model.Settings
		Upstreams []model.Upstream
	}{s.settings(), upstreams})
}

func (s *Server) settingsSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	cfg := model.Settings{
		PoolCIDR:            strings.TrimSpace(r.FormValue("pool_cidr")),
		LeaseTTLSeconds:     atoiDefault(r.FormValue("lease_ttl_seconds"), 86400),
		DNSTTL:              uint32(atoiDefault(r.FormValue("dns_ttl"), 60)),
		DNSListen:           strings.TrimSpace(r.FormValue("dns_listen")),
		DNSUpstream:         strings.TrimSpace(r.FormValue("dns_upstream")),
		DNSUpstreamProtocol: strings.TrimSpace(r.FormValue("dns_upstream_protocol")),
		BlockAAAA:           formBool(r, "block_aaaa"),
		FakeAll:             formBool(r, "fake_all"),
		DefaultAction:       strings.TrimSpace(r.FormValue("default_action")),
		SOCKS5Listen:        strings.TrimSpace(r.FormValue("socks5_listen")),
		SOCKS5Username:      strings.TrimSpace(r.FormValue("socks5_username")),
		SOCKS5Password:      r.FormValue("socks5_password"),
		HTTPListen:          strings.TrimSpace(r.FormValue("http_listen")),
		HTTPUsername:        strings.TrimSpace(r.FormValue("http_username")),
		HTTPPassword:        r.FormValue("http_password"),
		TProxyEnabled:       formBool(r, "tproxy_enabled"),
		TProxyListen:        strings.TrimSpace(r.FormValue("tproxy_listen")),
		AdminListen:         strings.TrimSpace(r.FormValue("admin_listen")),
		AdminTLSCert:        strings.TrimSpace(r.FormValue("admin_tls_cert")),
		AdminTLSKey:         strings.TrimSpace(r.FormValue("admin_tls_key")),
		DoHListen:           strings.TrimSpace(r.FormValue("doh_listen")),
		DoTListen:           strings.TrimSpace(r.FormValue("dot_listen")),
		DNSCert:             strings.TrimSpace(r.FormValue("dns_cert")),
		DNSKey:              strings.TrimSpace(r.FormValue("dns_key")),
		WireproxyBinary:     strings.TrimSpace(r.FormValue("wireproxy_binary")),
		WireproxyDataDir:    strings.TrimSpace(r.FormValue("wireproxy_data_dir")),
		HealthTarget:        strings.TrimSpace(r.FormValue("health_target")),
		GeoIPCityDB:         strings.TrimSpace(r.FormValue("geoip_city_db")),
		GeoIPASNDB:          strings.TrimSpace(r.FormValue("geoip_asn_db")),
		GeoIPTSV:            strings.TrimSpace(r.FormValue("geoip_tsv")),
		APIToken:            strings.TrimSpace(r.FormValue("api_token")),
		LogLevel:            strings.TrimSpace(r.FormValue("log_level")),
	}
	cfg.DNSUpstreamUpstreamID, _ = strconv.ParseInt(r.FormValue("dns_upstream_upstream_id"), 10, 64)
	cfg.DefaultUpstreamID, _ = strconv.ParseInt(r.FormValue("default_upstream_id"), 10, 64)
	if err := validateSettings(s.store, cfg); err != nil {
		redirectMsg(w, r, "/settings", "", err.Error())
		return
	}
	if err := s.store.SaveSettings(cfg); err != nil {
		redirectMsg(w, r, "/settings", "", err.Error())
		return
	}
	if s.reload != nil {
		s.reload()
	}
	info, _ := s.session(r)
	_ = s.store.AddAudit(info.Admin.Username, "settings_update", "")
	redirectMsg(w, r, "/settings", "Settings saved. Changes to listen addresses require a restart.", "")
}

func (s *Server) accountGet(w http.ResponseWriter, r *http.Request) {
	info, _ := s.session(r)
	s.render(w, r, "account.html", "Account", "account", struct{ Username string }{info.Admin.Username})
}

func (s *Server) accountSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	info, _ := s.session(r)
	current := r.FormValue("current_password")
	newPass := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")
	if len(newPass) < 8 {
		redirectMsg(w, r, "/account", "", "new password must be at least 8 characters")
		return
	}
	if newPass != confirm {
		redirectMsg(w, r, "/account", "", "new passwords do not match")
		return
	}
	admin, err := s.store.GetAdminByID(info.Admin.ID)
	if err != nil {
		redirectMsg(w, r, "/account", "", "admin not found")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(current)) != nil {
		redirectMsg(w, r, "/account", "", "current password is incorrect")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
	if err != nil {
		redirectMsg(w, r, "/account", "", err.Error())
		return
	}
	if err := s.store.UpdateAdminPassword(admin.ID, string(hash)); err != nil {
		redirectMsg(w, r, "/account", "", err.Error())
		return
	}
	_ = s.store.AddAudit(admin.Username, "password_change", "")
	redirectMsg(w, r, "/account", "Password updated", "")
}

func (s *Server) auditList(w http.ResponseWriter, r *http.Request) {
	entries, err := s.store.ListAudit(500)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, r, "audit.html", "Audit log", "audit", struct {
		Entries []model.AuditEntry
	}{entries})
}

func (s *Server) renderPartial(w http.ResponseWriter, name string, data any) {
	t, err := templateParse(content, name, s.funcs())
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = t.ExecuteTemplate(w, name, data)
}

func parseID(r *http.Request) (int64, error) {
	raw := r.PathValue("id")
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("invalid id %q", raw)
	}
	return id, nil
}

func validateUpstream(u model.Upstream) error {
	if u.Name == "" {
		return fmt.Errorf("name is required")
	}
	switch u.Type {
	case model.UpstreamSOCKS5, model.UpstreamHTTP:
		if u.Address == "" {
			return fmt.Errorf("address is required (host:port)")
		}
		host, portRaw, err := net.SplitHostPort(u.Address)
		if err != nil || host == "" {
			return fmt.Errorf("invalid address %q: expected host:port", u.Address)
		}
		port, err := strconv.Atoi(portRaw)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid port in address %q", u.Address)
		}
	case model.UpstreamWireGuard:
		if err := upstream.ValidateWireguardConfig(u.WGConfig); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid upstream type %q", u.Type)
	}
	return nil
}

func validateRule(st *store.Store, rule model.Rule) error {
	if rule.Name == "" {
		return fmt.Errorf("name is required")
	}
	switch rule.DomainMode {
	case "exact", "suffix", "regex":
	default:
		return fmt.Errorf("invalid domain mode %q", rule.DomainMode)
	}
	switch strings.ToLower(strings.TrimSpace(rule.MatchLogic)) {
	case "", model.LogicAnd, model.LogicOr:
	default:
		return fmt.Errorf("invalid match logic %q (use \"and\" or \"or\")", rule.MatchLogic)
	}
	if rule.DomainMode == "regex" && rule.MatchDomain != "" {
		if _, err := regexp.Compile("(?i)" + rule.MatchDomain); err != nil {
			return fmt.Errorf("invalid domain regex: %w", err)
		}
	}
	if err := validateCIDRs(rule.MatchCIDR); err != nil {
		return fmt.Errorf("match_cidr: %w", err)
	}
	if err := validateCIDRs(rule.MatchClientCIDR); err != nil {
		return fmt.Errorf("match_client_cidr: %w", err)
	}
	if err := validatePorts(rule.MatchPort); err != nil {
		return fmt.Errorf("match_port: %w", err)
	}
	switch rule.Action {
	case model.ActionProxy:
		if rule.UpstreamID <= 0 {
			return fmt.Errorf("proxy action requires an upstream")
		}
		if _, err := st.GetUpstream(rule.UpstreamID); err != nil {
			return fmt.Errorf("selected upstream does not exist")
		}
	case model.ActionDirect, model.ActionBlock:
	default:
		return fmt.Errorf("invalid action %q", rule.Action)
	}
	return nil
}

func validateCIDRs(raw string) error {
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(part); err != nil {
			return fmt.Errorf("invalid CIDR %q", part)
		}
	}
	return nil
}

func validatePorts(raw string) error {
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			lo, hi, ok := strings.Cut(part, "-")
			if !ok {
				return fmt.Errorf("invalid port range %q", part)
			}
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b {
				return fmt.Errorf("invalid port range %q", part)
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("invalid port %q", part)
		}
	}
	return nil
}

func validateSettings(st *store.Store, cfg model.Settings) error {
	if cfg.AdminListen == "" {
		return fmt.Errorf("admin_listen is required")
	}
	if _, network, err := net.ParseCIDR(cfg.PoolCIDR); err != nil {
		return fmt.Errorf("invalid pool CIDR: %w", err)
	} else if network.IP.To4() == nil {
		return fmt.Errorf("pool CIDR must be IPv4")
	} else if ones, _ := network.Mask.Size(); ones < 8 || ones > 30 {
		return fmt.Errorf("pool prefix must be between /8 and /30")
	}
	if cfg.LeaseTTLSeconds <= 0 {
		return fmt.Errorf("lease TTL must be positive")
	}
	if cfg.DNSTTL == 0 {
		return fmt.Errorf("DNS TTL must be positive")
	}
	for name, addr := range map[string]string{
		"dns_listen": cfg.DNSListen, "socks5_listen": cfg.SOCKS5Listen, "http_listen": cfg.HTTPListen,
		"tproxy_listen": cfg.TProxyListen, "admin_listen": cfg.AdminListen, "doh_listen": cfg.DoHListen,
		"dot_listen": cfg.DoTListen, "health_target": cfg.HealthTarget, "dns_upstream": cfg.DNSUpstream,
	} {
		if addr == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return fmt.Errorf("%s: invalid host:port %q", name, addr)
		}
	}
	if cfg.DNSUpstreamProtocol != "udp" && cfg.DNSUpstreamProtocol != "tcp" {
		return fmt.Errorf("dns_upstream_protocol must be udp or tcp")
	}
	switch cfg.DefaultAction {
	case model.ActionDirect, model.ActionBlock:
	case model.ActionProxy:
		if cfg.DefaultUpstreamID <= 0 {
			return fmt.Errorf("default proxy action requires an upstream")
		}
		if _, err := st.GetUpstream(cfg.DefaultUpstreamID); err != nil {
			return fmt.Errorf("default upstream does not exist")
		}
	default:
		return fmt.Errorf("invalid default action %q", cfg.DefaultAction)
	}
	if (cfg.AdminTLSCert == "") != (cfg.AdminTLSKey == "") {
		return fmt.Errorf("admin TLS cert and key must both be set or both be empty")
	}
	if (cfg.DNSCert == "") != (cfg.DNSKey == "") {
		return fmt.Errorf("DNS cert and key must both be set or both be empty")
	}
	if cfg.APIToken != "" && len(cfg.APIToken) < 16 {
		return fmt.Errorf("API token must be at least 16 characters")
	}
	return nil
}

const sampleWireguardConfig = `[Interface]
PrivateKey = BASE64_PRIVATE_KEY=
Address = 10.0.0.2/32
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = BASE64_PEER_PUBLIC_KEY=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25`
