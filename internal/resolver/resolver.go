package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"idips/internal/model"
	"idips/internal/store"
)

type ProxyDialer interface {
	Dial(ctx context.Context, upstreamID int64, network, addr string) (net.Conn, error)
}

type Resolver struct {
	store    *store.Store
	dialer   ProxyDialer
	settings func() model.Settings
	log      *slog.Logger

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	ips     []net.IP
	expires time.Time
}

func New(st *store.Store, dialer ProxyDialer, settings func() model.Settings, log *slog.Logger) *Resolver {
	return &Resolver{
		store:    st,
		dialer:   dialer,
		settings: settings,
		log:      log,
		cache:    make(map[string]cacheEntry),
	}
}

func (r *Resolver) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	if host == "" {
		return nil, errors.New("empty host")
	}

	r.mu.Lock()
	if e, ok := r.cache[host]; ok && e.expires.After(time.Now()) {
		ips := append([]net.IP(nil), e.ips...)
		r.mu.Unlock()
		return ips, nil
	}
	r.mu.Unlock()

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(host), dns.TypeA)
	req.RecursionDesired = true
	resp, err := r.Exchange(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns lookup %s: %s", host, dns.RcodeToString[resp.Rcode])
	}
	var ips []net.IP
	var minTTL uint32
	for _, rr := range resp.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		ips = append(ips, a.A)
		if minTTL == 0 || a.Hdr.Ttl < minTTL {
			minTTL = a.Hdr.Ttl
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("dns lookup %s: no A records", host)
	}
	if minTTL < 30 {
		minTTL = 30
	}
	if minTTL > 600 {
		minTTL = 600
	}
	r.mu.Lock()
	r.cache[host] = cacheEntry{ips: append([]net.IP(nil), ips...), expires: time.Now().Add(time.Duration(minTTL) * time.Second)}
	if len(r.cache) > 20000 {
		for k, v := range r.cache {
			if v.expires.Before(time.Now()) {
				delete(r.cache, k)
			}
		}
	}
	r.mu.Unlock()
	return ips, nil
}

func (r *Resolver) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	s := r.settings()
	if s.DNSUpstream == "" {
		return nil, errors.New("no DNS upstream configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var cancel context.CancelFunc
	if _, ok := ctx.Deadline(); !ok {
		ctx, cancel = context.WithTimeout(ctx, 6*time.Second)
		defer cancel()
	}

	if s.DNSUpstreamUpstreamID > 0 && r.dialer != nil {
		conn, err := r.dialer.Dial(ctx, s.DNSUpstreamUpstreamID, "tcp", s.DNSUpstream)
		if err != nil {
			return nil, fmt.Errorf("dial DNS upstream via proxy: %w", err)
		}
		defer conn.Close()
		return exchangeTCP(ctx, conn, req)
	}

	proto := strings.ToLower(strings.TrimSpace(s.DNSUpstreamProtocol))
	if proto == "" {
		proto = "udp"
	}
	client := &dns.Client{Net: proto, Timeout: 5 * time.Second}
	resp, _, err := client.ExchangeContext(ctx, req, s.DNSUpstream)
	if err != nil && proto == "udp" {
		client.Net = "tcp"
		resp, _, err = client.ExchangeContext(ctx, req, s.DNSUpstream)
	}
	if err != nil {
		return nil, err
	}
	if proto == "udp" && resp != nil && resp.Truncated {
		client.Net = "tcp"
		resp, _, err = client.ExchangeContext(ctx, req, s.DNSUpstream)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

func exchangeTCP(ctx context.Context, conn net.Conn, req *dns.Msg) (*dns.Msg, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	}
	msg, err := req.Pack()
	if err != nil {
		return nil, err
	}
	if len(msg) > 65535 {
		return nil, errors.New("dns message too large")
	}
	buf := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(buf, uint16(len(msg)))
	copy(buf[2:], msg)
	if _, err := conn.Write(buf); err != nil {
		return nil, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	var resp dns.Msg
	if err := resp.Unpack(body); err != nil {
		return nil, err
	}
	return &resp, nil
}
