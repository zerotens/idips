package routing

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/oschwald/geoip2-golang"

	"idips/internal/iptoasn"
	"idips/internal/model"
	"idips/internal/store"
)

var regexCache sync.Map

type IPInfo struct {
	IP      string
	ASN     uint32
	Country string
	Org     string
}

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
	tsv      *iptoasn.DB
	cityPath string
	asnPath  string
	tsvPath  string
}

func New(st *store.Store, log *slog.Logger) *Engine {
	return &Engine{store: st, log: log}
}

func (e *Engine) ReloadGeo(cityPath, asnPath, tsvPath string) error {
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
	e.tsv = nil
	e.cityPath, e.asnPath, e.tsvPath = cityPath, asnPath, tsvPath

	var errs []error
	if cityPath != "" {
		r, err := geoip2.Open(cityPath)
		if err != nil {
			errs = append(errs, fmt.Errorf("open GeoIP city db: %w", err))
		} else {
			e.city = r
		}
	}
	if asnPath != "" {
		r, err := geoip2.Open(asnPath)
		if err != nil {
			errs = append(errs, fmt.Errorf("open GeoIP ASN db: %w", err))
		} else {
			e.asn = r
		}
	}
	if tsvPath != "" {
		db, err := iptoasn.Open(tsvPath)
		if err != nil {
			errs = append(errs, fmt.Errorf("open IPtoASN db: %w", err))
		} else {
			e.tsv = db
			e.log.Info("IPtoASN database loaded", "path", tsvPath, "ranges", db.Len())
		}
	}
	return errors.Join(errs...)
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
	e.tsv = nil
}

func (e *Engine) LookupIP(ip net.IP) (IPInfo, bool) {
	if ip == nil {
		return IPInfo{}, false
	}
	e.geoMu.RLock()
	tsv := e.tsv
	city := e.city
	asnDB := e.asn
	e.geoMu.RUnlock()

	info := IPInfo{IP: ip.String()}
	found := false
	if tsv != nil {
		if rec, ok := tsv.Lookup(ip); ok {
			info.ASN, info.Country, info.Org = rec.ASN, rec.Country, rec.Org
			found = found || rec.ASN != 0 || rec.Country != "" || rec.Org != ""
		}
	}
	if asnDB != nil && (info.ASN == 0 || info.Org == "") {
		if rec, err := asnDB.ASN(ip); err == nil && rec != nil {
			if info.ASN == 0 {
				info.ASN = uint32(rec.AutonomousSystemNumber)
			}
			if info.Org == "" {
				info.Org = rec.AutonomousSystemOrganization
			}
			found = found || info.ASN != 0 || info.Org != ""
		}
	}
	if city != nil && info.Country == "" {
		if rec, err := city.Country(ip); err == nil && rec != nil {
			code := rec.Country.IsoCode
			if code == "" {
				code = rec.RegisteredCountry.IsoCode
			}
			info.Country = code
			found = found || code != ""
		}
	}
	return info, found
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
	logicOr := strings.EqualFold(strings.TrimSpace(r.MatchLogic), model.LogicOr)
	active := false
	matched := false

	if r.MatchDomain != "" {
		active = true
		ok := matchDomain(r.DomainMode, r.MatchDomain, host)
		if logicOr {
			matched = matched || ok
		} else if !ok {
			return false
		}
	}
	if r.MatchCIDR != "" {
		active = true
		ok := matchCIDRList(r.MatchCIDR, ips)
		if logicOr {
			matched = matched || ok
		} else if !ok {
			return false
		}
	}
	if r.MatchClientCIDR != "" {
		active = true
		ok := matchCIDRList(r.MatchClientCIDR, []net.IP{clientIP})
		if logicOr {
			matched = matched || ok
		} else if !ok {
			return false
		}
	}
	if r.MatchPort != "" && port > 0 {
		active = true
		ok := matchPortList(r.MatchPort, port)
		if logicOr {
			matched = matched || ok
		} else if !ok {
			return false
		}
	}
	if r.MatchGeoIP != "" {
		active = true
		ok := e.matchGeo(r.MatchGeoIP, ips)
		if logicOr {
			matched = matched || ok
		} else if !ok {
			return false
		}
	}
	if r.MatchASN != "" {
		active = true
		ok := e.matchASN(r.MatchASN, ips)
		if logicOr {
			matched = matched || ok
		} else if !ok {
			return false
		}
	}

	if !active {
		return true
	}
	if logicOr {
		return matched
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
	tsv := e.tsv
	db := e.city
	e.geoMu.RUnlock()
	if (tsv == nil && db == nil) || len(ips) == 0 {
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
		code := ""
		if tsv != nil {
			if rec, ok := tsv.Lookup(ip); ok {
				code = rec.Country
			}
		}
		if code == "" && db != nil {
			rec, err := db.Country(ip)
			if err == nil && rec != nil {
				code = rec.Country.IsoCode
				if code == "" {
					code = rec.RegisteredCountry.IsoCode
				}
			}
		}
		if code == "" {
			continue
		}
		if _, ok := wanted[strings.ToUpper(code)]; ok {
			return true
		}
	}
	return false
}

func (e *Engine) matchASN(raw string, ips []net.IP) bool {
	e.geoMu.RLock()
	tsv := e.tsv
	db := e.asn
	e.geoMu.RUnlock()
	if (tsv == nil && db == nil) || len(ips) == 0 {
		return false
	}
	wanted := make(map[uint32]struct{})
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(p), "AS"))
		if p == "" {
			continue
		}
		if n, err := strconv.ParseUint(p, 10, 32); err == nil {
			wanted[uint32(n)] = struct{}{}
		}
	}
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		var asn uint32
		found := false
		if tsv != nil {
			if rec, ok := tsv.Lookup(ip); ok && rec.ASN != 0 {
				asn, found = rec.ASN, true
			}
		}
		if !found && db != nil {
			rec, err := db.ASN(ip)
			if err == nil && rec != nil {
				asn, found = uint32(rec.AutonomousSystemNumber), true
			}
		}
		if !found {
			continue
		}
		if _, ok := wanted[asn]; ok {
			return true
		}
	}
	return false
}
