package store

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"idips/internal/model"
	"idips/internal/secret"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

var ErrNotFound = errors.New("not found")

type Store struct {
	db  *sql.DB
	box *secret.Box
}

func Open(path string, box *secret.Box) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, box: box}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	if _, err := s.db.Exec(schemaSQL); err != nil {
		return err
	}
	return s.seedSettings()
}

func (s *Store) seedSettings() error {
	def := model.DefaultSettings()
	for k, v := range settingsToMap(def) {
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)`, k, v); err != nil {
			return err
		}
	}
	return nil
}

func settingsToMap(s model.Settings) map[string]string {
	return map[string]string{
		"pool_cidr":                s.PoolCIDR,
		"lease_ttl_seconds":        strconv.Itoa(s.LeaseTTLSeconds),
		"dns_ttl":                  strconv.FormatUint(uint64(s.DNSTTL), 10),
		"dns_listen":               s.DNSListen,
		"dns_upstream":             s.DNSUpstream,
		"dns_upstream_protocol":    s.DNSUpstreamProtocol,
		"dns_upstream_upstream_id": strconv.FormatInt(s.DNSUpstreamUpstreamID, 10),
		"block_aaaa":               strconv.FormatBool(s.BlockAAAA),
		"fake_all":                 strconv.FormatBool(s.FakeAll),
		"default_action":           s.DefaultAction,
		"default_upstream_id":      strconv.FormatInt(s.DefaultUpstreamID, 10),
		"socks5_listen":            s.SOCKS5Listen,
		"socks5_username":          s.SOCKS5Username,
		"socks5_password":          s.SOCKS5Password,
		"http_listen":              s.HTTPListen,
		"http_username":            s.HTTPUsername,
		"http_password":            s.HTTPPassword,
		"tproxy_enabled":           strconv.FormatBool(s.TProxyEnabled),
		"tproxy_listen":            s.TProxyListen,
		"admin_listen":             s.AdminListen,
		"admin_tls_cert":           s.AdminTLSCert,
		"admin_tls_key":            s.AdminTLSKey,
		"doh_listen":               s.DoHListen,
		"dot_listen":               s.DoTListen,
		"dns_cert":                 s.DNSCert,
		"dns_key":                  s.DNSKey,
		"wireproxy_binary":         s.WireproxyBinary,
		"wireproxy_data_dir":       s.WireproxyDataDir,
		"health_target":            s.HealthTarget,
		"geoip_city_db":            s.GeoIPCityDB,
		"geoip_asn_db":             s.GeoIPASNDB,
		"geoip_tsv":                s.GeoIPTSV,
		"api_token":                s.APIToken,
		"log_level":                s.LogLevel,
	}
}

func (s *Store) GetSettings() (model.Settings, error) {
	def := model.DefaultSettings()
	rows, err := s.db.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return def, err
	}
	defer rows.Close()
	m := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return def, err
		}
		m[k] = v
	}
	if err := rows.Err(); err != nil {
		return def, err
	}
	out := def
	setStr := func(key string, dst *string) {
		if v, ok := m[key]; ok {
			*dst = v
		}
	}
	setInt := func(key string, dst *int) {
		if v, ok := m[key]; ok {
			if n, err := strconv.Atoi(v); err == nil {
				*dst = n
			}
		}
	}
	setInt64 := func(key string, dst *int64) {
		if v, ok := m[key]; ok {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				*dst = n
			}
		}
	}
	setUint32 := func(key string, dst *uint32) {
		if v, ok := m[key]; ok {
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				*dst = uint32(n)
			}
		}
	}
	setBool := func(key string, dst *bool) {
		if v, ok := m[key]; ok {
			if b, err := strconv.ParseBool(v); err == nil {
				*dst = b
			}
		}
	}

	setStr("pool_cidr", &out.PoolCIDR)
	setInt("lease_ttl_seconds", &out.LeaseTTLSeconds)
	setUint32("dns_ttl", &out.DNSTTL)
	setStr("dns_listen", &out.DNSListen)
	setStr("dns_upstream", &out.DNSUpstream)
	setStr("dns_upstream_protocol", &out.DNSUpstreamProtocol)
	setInt64("dns_upstream_upstream_id", &out.DNSUpstreamUpstreamID)
	setBool("block_aaaa", &out.BlockAAAA)
	setBool("fake_all", &out.FakeAll)
	setStr("default_action", &out.DefaultAction)
	setInt64("default_upstream_id", &out.DefaultUpstreamID)
	setStr("socks5_listen", &out.SOCKS5Listen)
	setStr("socks5_username", &out.SOCKS5Username)
	setStr("socks5_password", &out.SOCKS5Password)
	setStr("http_listen", &out.HTTPListen)
	setStr("http_username", &out.HTTPUsername)
	setStr("http_password", &out.HTTPPassword)
	setBool("tproxy_enabled", &out.TProxyEnabled)
	setStr("tproxy_listen", &out.TProxyListen)
	setStr("admin_listen", &out.AdminListen)
	setStr("admin_tls_cert", &out.AdminTLSCert)
	setStr("admin_tls_key", &out.AdminTLSKey)
	setStr("doh_listen", &out.DoHListen)
	setStr("dot_listen", &out.DoTListen)
	setStr("dns_cert", &out.DNSCert)
	setStr("dns_key", &out.DNSKey)
	setStr("wireproxy_binary", &out.WireproxyBinary)
	setStr("wireproxy_data_dir", &out.WireproxyDataDir)
	setStr("health_target", &out.HealthTarget)
	setStr("geoip_city_db", &out.GeoIPCityDB)
	setStr("geoip_asn_db", &out.GeoIPASNDB)
	setStr("geoip_tsv", &out.GeoIPTSV)
	setStr("api_token", &out.APIToken)
	setStr("log_level", &out.LogLevel)
	return out, nil
}

func (s *Store) SaveSettings(v model.Settings) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for k, val := range settingsToMap(v) {
		if _, err := tx.Exec(`INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, k, val); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) scanUpstream(sc interface{ Scan(dest ...any) error }) (model.Upstream, error) {
	var u model.Upstream
	var pwEnc, wgEnc string
	var enabled int
	var lastCheck, created, updated int64
	if err := sc.Scan(&u.ID, &u.Name, &u.Type, &u.Address, &u.Username, &pwEnc, &wgEnc, &enabled, &u.Priority, &u.Health, &lastCheck, &created, &updated); err != nil {
		return u, err
	}
	u.Enabled = enabled != 0
	if lastCheck > 0 {
		u.LastCheck = time.Unix(lastCheck, 0)
	}
	if created > 0 {
		u.CreatedAt = time.Unix(created, 0)
	}
	if updated > 0 {
		u.UpdatedAt = time.Unix(updated, 0)
	}
	var err error
	if u.Password, err = s.box.Decrypt(pwEnc); err != nil {
		return u, fmt.Errorf("decrypt upstream password: %w", err)
	}
	if u.WGConfig, err = s.box.Decrypt(wgEnc); err != nil {
		return u, fmt.Errorf("decrypt wireguard config: %w", err)
	}
	return u, nil
}

const upstreamCols = `id, name, type, address, username, password_enc, wg_config_enc, enabled, priority, health, last_check, created_at, updated_at`

func (s *Store) ListUpstreams() ([]model.Upstream, error) {
	rows, err := s.db.Query(`SELECT ` + upstreamCols + ` FROM upstreams ORDER BY priority, name, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Upstream
	for rows.Next() {
		u, err := s.scanUpstream(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) ListUpstreamRuntime() ([]model.Upstream, error) {
	rows, err := s.db.Query(`SELECT id, name, type, address, enabled, priority, health, last_check FROM upstreams ORDER BY priority, name, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Upstream
	for rows.Next() {
		var u model.Upstream
		var enabled int
		var lastCheck int64
		if err := rows.Scan(&u.ID, &u.Name, &u.Type, &u.Address, &enabled, &u.Priority, &u.Health, &lastCheck); err != nil {
			return nil, err
		}
		u.Enabled = enabled != 0
		if lastCheck > 0 {
			u.LastCheck = time.Unix(lastCheck, 0)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) GetUpstream(id int64) (model.Upstream, error) {
	row := s.db.QueryRow(`SELECT `+upstreamCols+` FROM upstreams WHERE id=?`, id)
	u, err := s.scanUpstream(row)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

func (s *Store) CreateUpstream(u model.Upstream) (int64, error) {
	pw, err := s.box.Encrypt(u.Password)
	if err != nil {
		return 0, err
	}
	wg, err := s.box.Encrypt(u.WGConfig)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	res, err := s.db.Exec(`INSERT INTO upstreams(name, type, address, username, password_enc, wg_config_enc, enabled, priority, health, last_check, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.Name, u.Type, u.Address, u.Username, pw, wg, boolInt(u.Enabled), u.Priority, model.HealthUnknown, 0, now.Unix(), now.Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateUpstream(u model.Upstream) error {
	var oldPW, oldWG string
	err := s.db.QueryRow(`SELECT password_enc, wg_config_enc FROM upstreams WHERE id=?`, u.ID).Scan(&oldPW, &oldWG)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	pw, wg := oldPW, oldWG
	if u.ClearPassword {
		if pw, err = s.box.Encrypt(""); err != nil {
			return err
		}
	} else if u.Password != "" {
		if pw, err = s.box.Encrypt(u.Password); err != nil {
			return err
		}
	}
	if u.WGConfig != "" {
		if wg, err = s.box.Encrypt(u.WGConfig); err != nil {
			return err
		}
	}
	_, err = s.db.Exec(`UPDATE upstreams SET name=?, type=?, address=?, username=?, password_enc=?, wg_config_enc=?, enabled=?, priority=?, updated_at=? WHERE id=?`,
		u.Name, u.Type, u.Address, u.Username, pw, wg, boolInt(u.Enabled), u.Priority, time.Now().Unix(), u.ID)
	return err
}

func (s *Store) DeleteUpstream(id int64) error {
	res, err := s.db.Exec(`DELETE FROM upstreams WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) UpdateUpstreamHealth(id int64, health string) error {
	_, err := s.db.Exec(`UPDATE upstreams SET health=?, last_check=? WHERE id=?`, health, time.Now().Unix(), id)
	return err
}

func (s *Store) scanRule(sc interface{ Scan(dest ...any) error }) (model.Rule, error) {
	var r model.Rule
	var enabled int
	var created, updated int64
	err := sc.Scan(&r.ID, &r.Name, &r.Priority, &enabled, &r.MatchDomain, &r.DomainMode, &r.MatchCIDR,
		&r.MatchGeoIP, &r.MatchASN, &r.MatchClientCIDR, &r.MatchPort, &r.Action, &r.UpstreamID, &created, &updated)
	if err != nil {
		return r, err
	}
	r.Enabled = enabled != 0
	r.CreatedAt = time.Unix(created, 0)
	r.UpdatedAt = time.Unix(updated, 0)
	return r, nil
}

const ruleCols = `id, name, priority, enabled, match_domain, domain_mode, match_cidr, match_geoip, match_asn, match_client_cidr, match_port, action, upstream_id, created_at, updated_at`

func (s *Store) ListRules() ([]model.Rule, error) {
	rows, err := s.db.Query(`SELECT ` + ruleCols + ` FROM rules ORDER BY priority, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Rule
	for rows.Next() {
		r, err := s.scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetRule(id int64) (model.Rule, error) {
	row := s.db.QueryRow(`SELECT `+ruleCols+` FROM rules WHERE id=?`, id)
	r, err := s.scanRule(row)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}

func (s *Store) CreateRule(r model.Rule) (int64, error) {
	now := time.Now()
	res, err := s.db.Exec(`INSERT INTO rules(name, priority, enabled, match_domain, domain_mode, match_cidr, match_geoip, match_asn, match_client_cidr, match_port, action, upstream_id, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Name, r.Priority, boolInt(r.Enabled), r.MatchDomain, r.DomainMode, r.MatchCIDR, r.MatchGeoIP, r.MatchASN,
		r.MatchClientCIDR, r.MatchPort, r.Action, r.UpstreamID, now.Unix(), now.Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateRule(r model.Rule) error {
	_, err := s.db.Exec(`UPDATE rules SET name=?, priority=?, enabled=?, match_domain=?, domain_mode=?, match_cidr=?, match_geoip=?, match_asn=?, match_client_cidr=?, match_port=?, action=?, upstream_id=?, updated_at=? WHERE id=?`,
		r.Name, r.Priority, boolInt(r.Enabled), r.MatchDomain, r.DomainMode, r.MatchCIDR, r.MatchGeoIP, r.MatchASN,
		r.MatchClientCIDR, r.MatchPort, r.Action, r.UpstreamID, time.Now().Unix(), r.ID)
	return err
}

func (s *Store) DeleteRule(id int64) error {
	res, err := s.db.Exec(`DELETE FROM rules WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) scanLease(sc interface{ Scan(dest ...any) error }) (model.Lease, error) {
	var l model.Lease
	var ips string
	var expires, created, updated int64
	if err := sc.Scan(&l.ID, &l.FakeIP, &l.TargetDomain, &ips, &l.ClientKey, &expires, &created, &updated); err != nil {
		return l, err
	}
	if err := json.Unmarshal([]byte(ips), &l.TargetIPs); err != nil {
		l.TargetIPs = nil
	}
	l.ExpiresAt = time.Unix(expires, 0)
	l.CreatedAt = time.Unix(created, 0)
	l.UpdatedAt = time.Unix(updated, 0)
	return l, nil
}

const leaseCols = `id, fake_ip, target_domain, target_ips, client_key, expires_at, created_at, updated_at`

func (s *Store) GetLeaseByDomain(domain string) (model.Lease, error) {
	row := s.db.QueryRow(`SELECT `+leaseCols+` FROM leases WHERE target_domain=?`, domain)
	l, err := s.scanLease(row)
	if errors.Is(err, sql.ErrNoRows) {
		return l, ErrNotFound
	}
	return l, err
}

func (s *Store) GetLeaseByIP(ip string) (model.Lease, error) {
	row := s.db.QueryRow(`SELECT `+leaseCols+` FROM leases WHERE fake_ip=?`, ip)
	l, err := s.scanLease(row)
	if errors.Is(err, sql.ErrNoRows) {
		return l, ErrNotFound
	}
	return l, err
}

func (s *Store) GetLeaseByID(id int64) (model.Lease, error) {
	row := s.db.QueryRow(`SELECT `+leaseCols+` FROM leases WHERE id=?`, id)
	l, err := s.scanLease(row)
	if errors.Is(err, sql.ErrNoRows) {
		return l, ErrNotFound
	}
	return l, err
}

func (s *Store) CreateLease(l model.Lease) (int64, error) {
	ips, _ := json.Marshal(l.TargetIPs)
	now := time.Now()
	res, err := s.db.Exec(`INSERT INTO leases(fake_ip, target_domain, target_ips, client_key, expires_at, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?)`,
		l.FakeIP, l.TargetDomain, string(ips), l.ClientKey, l.ExpiresAt.Unix(), now.Unix(), now.Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateLease(l model.Lease) error {
	ips, _ := json.Marshal(l.TargetIPs)
	_, err := s.db.Exec(`UPDATE leases SET target_ips=?, client_key=?, expires_at=?, updated_at=? WHERE id=?`,
		string(ips), l.ClientKey, l.ExpiresAt.Unix(), time.Now().Unix(), l.ID)
	return err
}

func (s *Store) TouchLease(id int64, expires time.Time) error {
	_, err := s.db.Exec(`UPDATE leases SET expires_at=?, updated_at=? WHERE id=?`, expires.Unix(), time.Now().Unix(), id)
	return err
}

func (s *Store) DeleteLease(id int64) error {
	res, err := s.db.Exec(`DELETE FROM leases WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteExpiredLeases(now time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM leases WHERE expires_at <= ?`, now.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) LoadActiveLeases(now time.Time) ([]model.Lease, error) {
	rows, err := s.db.Query(`SELECT `+leaseCols+` FROM leases WHERE expires_at > ?`, now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Lease
	for rows.Next() {
		l, err := s.scanLease(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *Store) ListLeases(limit, offset int, search string) ([]model.Lease, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := `SELECT ` + leaseCols + ` FROM leases`
	args := []any{}
	if search != "" {
		q += ` WHERE target_domain LIKE ? OR fake_ip LIKE ?`
		like := "%" + search + "%"
		args = append(args, like, like)
	}
	q += ` ORDER BY updated_at DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Lease
	for rows.Next() {
		l, err := s.scanLease(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *Store) CountLeases(activeOnly bool) (int64, error) {
	q := `SELECT COUNT(*) FROM leases`
	if activeOnly {
		q += ` WHERE expires_at > ?`
	}
	var n int64
	var err error
	if activeOnly {
		err = s.db.QueryRow(q, time.Now().Unix()).Scan(&n)
	} else {
		err = s.db.QueryRow(q).Scan(&n)
	}
	return n, err
}

func (s *Store) CountAdmins() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM admins`).Scan(&n)
	return n, err
}

func (s *Store) CreateAdmin(username, passwordHash string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO admins(username, password_hash, created_at) VALUES(?, ?, ?)`, username, passwordHash, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) GetAdminByUsername(username string) (model.Admin, error) {
	var a model.Admin
	var created int64
	err := s.db.QueryRow(`SELECT id, username, password_hash, created_at FROM admins WHERE username=?`, username).
		Scan(&a.ID, &a.Username, &a.PasswordHash, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	a.CreatedAt = time.Unix(created, 0)
	return a, err
}

func (s *Store) GetAdminByID(id int64) (model.Admin, error) {
	var a model.Admin
	var created int64
	err := s.db.QueryRow(`SELECT id, username, password_hash, created_at FROM admins WHERE id=?`, id).
		Scan(&a.ID, &a.Username, &a.PasswordHash, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	a.CreatedAt = time.Unix(created, 0)
	return a, err
}

func (s *Store) UpdateAdminPassword(id int64, passwordHash string) error {
	res, err := s.db.Exec(`UPDATE admins SET password_hash=? WHERE id=?`, passwordHash, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) CreateSession(tokenHash string, adminID int64, expires time.Time) error {
	_, err := s.db.Exec(`INSERT INTO sessions(token_hash, admin_id, expires_at, created_at) VALUES(?, ?, ?, ?)`,
		tokenHash, adminID, expires.Unix(), time.Now().Unix())
	return err
}

func (s *Store) GetSession(tokenHash string) (int64, time.Time, error) {
	var adminID int64
	var expires int64
	err := s.db.QueryRow(`SELECT admin_id, expires_at FROM sessions WHERE token_hash=?`, tokenHash).Scan(&adminID, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, time.Time{}, ErrNotFound
	}
	return adminID, time.Unix(expires, 0), err
}

func (s *Store) DeleteSession(tokenHash string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token_hash=?`, tokenHash)
	return err
}

func (s *Store) DeleteExpiredSessions(now time.Time) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at <= ?`, now.Unix())
	return err
}

func (s *Store) AddAudit(actor, action, detail string) error {
	_, err := s.db.Exec(`INSERT INTO audit_log(ts, actor, action, detail) VALUES(?, ?, ?, ?)`,
		time.Now().Unix(), actor, action, detail)
	return err
}

func (s *Store) ListAudit(limit int) ([]model.AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id, ts, actor, action, detail FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AuditEntry
	for rows.Next() {
		var e model.AuditEntry
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Action, &e.Detail); err != nil {
			return nil, err
		}
		e.Time = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func NormalizeCIDRList(raw string) string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, ",")
}
