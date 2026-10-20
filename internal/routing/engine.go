package routing

import (
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/oschwald/geoip2-golang"

	"idips/internal/model"
	"idips/internal/store"
)

var regexCache sync.Map

type Decision struct {
	Action       string
	UpstreamID   int64
	UpstreamName string
	Rule         *model.Rule
	Matched      bool
	Reason       string
}

type Engine struct {
	store *store.Store
	log   *slog.Logger

	geoMu    sync.RWMutex
	city     *geoip2.Reader
	asn      *geoip2.Reader
	cityPath string
	asnPath  string
}

func New(st *store.Store, log *slog.Logger) *Engine {
	return &Engine{store: st, log: log}
}

func (e *Engine) ReloadGeo(cityPath, asnPath string) error {
	e.geoMu.Lock()
	defer e.geoMu.Unlock()
	if e.city != nil {
		_ = e.city.Close()
		e.city = nil
	}
	if e.asn != nil {
		_ = e.asn.Close()
		e.asn = nil
	}
	e.cityPath, e.asnPath = cityPath, asnPath
	if cityPath != "" {
		r, err := geoip2.Open(cityPath)
		if err != nil {
			return fmt.Errorf("open GeoIP city db: %w", err)
		}
		e.city = r
	}
	if asnPath != "" {
		r, err := geoip2.Open(asnPath)
		if err != nil {
			return fmt.Errorf("open GeoIP ASN db: %w", err)
		}
		e.asn = r
	}
	return nil
}

func (e *Engine) Close() {
	e.geoMu.Lock()
	defer e.geoMu.Unlock()
	if e.city != nil {
		_ = e.city.Close()
		e.city = nil
	}
	if e.asn != nil {
		_ = e.asn.Close()
		e.asn = nil
	}
}

func (e *Engine) Decide(host string, ips []net.IP, clientIP net.IP, port int) (Decision, error) {
	rules, err := e.store.ListRules()
	if err != nil {
		return Decision{}, err
	}
	upstreams, err := e.store.ListUpstreamRuntime()
	if err != nil {
		return Decision{}, err
	}
	byID := make(map[int64]model.Upstream, len(upstreams))
	for _, u := range upstreams {
		byID[u.ID] = u
	}

	host = normalizeHost(host)
	for i := range rules {
		r := &rules[i]
		if !r.Enabled {
			continue
		}
		if !e.matches(r, host, ips, clientIP, port) {
			continue
		}
		switch r.Action {
		case model.ActionBlock:
			return Decision{Action: model.ActionBlock, Rule: r, Matched: true, Reason: "rule " + r.Name}, nil
		case model.ActionDirect:
			return Decision{Action: model.ActionDirect, Rule: r, Matched: true, Reason: "rule " + r.Name}, nil
		case model.ActionProxy:
			u, ok := byID[r.UpstreamID]
			if !ok || !u.Enabled || u.Health == model.HealthDown {
				e.log.Debug("rule upstream unavailable, trying next rule", "rule", r.Name, "upstream_id", r.UpstreamID)
				continue
			}
			return Decision{Action: model.ActionProxy, UpstreamID: u.ID, UpstreamName: u.Name, Rule: r, Matched: true, Reason: "rule " + r.Name}, nil
		}
	}

	settings, err := e.store.GetSettings()
	if err != nil {
		return Decision{}, err
	}
	switch settings.DefaultAction {
	case model.ActionBlock:
		return Decision{Action: model.ActionBlock, Reason: "default"}, nil
	case model.ActionProxy:
		u, ok := byID[settings.DefaultUpstreamID]
		if ok && u.Enabled && u.Health != model.HealthDown {
			return Decision{Action: model.ActionProxy, UpstreamID: u.ID, UpstreamName: u.Name, Reason: "default"}, nil
		}
		e.log.Debug("default upstream unavailable, falling back to direct", "upstream_id", settings.DefaultUpstreamID)
		return Decision{Action: model.ActionDirect, Reason: "default fallback"}, nil
	default:
		return Decision{Action: model.ActionDirect, Reason: "default"}, nil
	}
}

func (e *Engine) matches(r *model.Rule, host string, ips []net.IP, clientIP net.IP, port int) bool {
	if r.MatchDomain != "" && !matchDomain(r.DomainMode, r.MatchDomain, host) {
		return false
	}
	if r.MatchCIDR != "" && !matchCIDRList(r.MatchCIDR, ips) {
		return false
	}
	if r.MatchClientCIDR != "" && !matchCIDRList(r.MatchClientCIDR, []net.IP{clientIP}) {
		return false
	}
	if r.MatchPort != "" && port > 0 && !matchPortList(r.MatchPort, port) {
		return false
	}
	if r.MatchGeoIP != "" && !e.matchGeo(r.MatchGeoIP, ips) {
		return false
	}
	if r.MatchASN != "" && !e.matchASN(r.MatchASN, ips) {
		return false
	}
	return true
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	return host
}

func matchDomain(mode, pattern, host string) bool {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "suffix"
	}
	if mode == "regex" {
		re, err := compileRegex(pattern)
		if err != nil {
			return false
		}
		return re.MatchString(host)
	}
	for _, p := range strings.Split(pattern, ",") {
		p = normalizeHost(p)
		p = strings.TrimPrefix(p, "*.")
		p = strings.TrimPrefix(p, ".")
		if p == "" {
			continue
		}
		switch mode {
		case "exact":
			if host == p {
				return true
			}
		case "suffix":
			if host == p || strings.HasSuffix(host, "."+p) {
				return true
			}
		}
	}
	return false
}

func matchCIDRList(raw string, ips []net.IP) bool {
	if len(ips) == 0 {
		return false
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, network, err := net.ParseCIDR(part)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if ip != nil && network.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func compileRegex(pattern string) (*regexp.Regexp, error) {
	if v, ok := regexCache.Load(pattern); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return nil, err
	}
	regexCache.Store(pattern, re)
	return re, nil
}

func matchPortList(raw string, port int) bool {
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			lo, hi, ok := strings.Cut(part, "-")
			if !ok {
				continue
			}
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 == nil && err2 == nil && port >= a && port <= b {
				return true
			}
			continue
		}
		if p, err := strconv.Atoi(part); err == nil && p == port {
			return true
		}
	}
	return false
}

func (e *Engine) matchGeo(raw string, ips []net.IP) bool {
	e.geoMu.RLock()
	db := e.city
	e.geoMu.RUnlock()
	if db == nil || len(ips) == 0 {
		return false
	}
	wanted := make(map[string]struct{})
	for _, p := range strings.Split(raw, ",") {
		p = strings.ToUpper(strings.TrimSpace(p))
		if p != "" {
			wanted[p] = struct{}{}
		}
	}
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		rec, err := db.Country(ip)
		if err != nil || rec == nil {
			continue
		}
		code := rec.Country.IsoCode
		if code == "" {
			code = rec.RegisteredCountry.IsoCode
		}
		if _, ok := wanted[strings.ToUpper(code)]; ok {
			return true
		}
	}
	return false
}

func (e *Engine) matchASN(raw string, ips []net.IP) bool {
	e.geoMu.RLock()
	db := e.asn
	e.geoMu.RUnlock()
	if db == nil || len(ips) == 0 {
		return false
	}
	wanted := make(map[uint]struct{})
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(p), "AS"))
		if p == "" {
			continue
		}
		if n, err := strconv.ParseUint(p, 10, 32); err == nil {
			wanted[uint(n)] = struct{}{}
		}
	}
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		rec, err := db.ASN(ip)
		if err != nil || rec == nil {
			continue
		}
		if _, ok := wanted[uint(rec.AutonomousSystemNumber)]; ok {
			return true
		}
	}
	return false
}
