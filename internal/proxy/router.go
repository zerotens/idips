package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"idips/internal/alloc"
	"idips/internal/model"
	"idips/internal/resolver"
	"idips/internal/routing"
	"idips/internal/upstream"
)

var ErrBlocked = errors.New("blocked by routing rule")

type Router struct {
	alloc    *alloc.Allocator
	engine   *routing.Engine
	resolver *resolver.Resolver
	manager  *upstream.Manager
	settings func() model.Settings
	log      *slog.Logger
}

func NewRouter(allocator *alloc.Allocator, engine *routing.Engine, res *resolver.Resolver, manager *upstream.Manager, settings func() model.Settings, log *slog.Logger) *Router {
	return &Router{alloc: allocator, engine: engine, resolver: res, manager: manager, settings: settings, log: log}
}

func (r *Router) Route(ctx context.Context, host string, port int, clientIP net.IP) (net.Conn, routing.Decision, string, error) {
	host = normalizeTargetHost(host)
	if host == "" {
		return nil, routing.Decision{}, "", errors.New("empty target host")
	}
	if port <= 0 || port > 65535 {
		return nil, routing.Decision{}, "", fmt.Errorf("invalid target port %d", port)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var cancel context.CancelFunc
	if _, ok := ctx.Deadline(); !ok {
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}

	targetHost := host
	var ips []net.IP
	fakeIP := ""
	if ip := net.ParseIP(host); ip != nil {
		if r.alloc.Contains(ip) {
			lease, err := r.alloc.GetActiveByIP(ip.String())
			if err != nil {
				return nil, routing.Decision{}, "", fmt.Errorf("fake IP %s has no active lease: %w", ip, err)
			}
			targetHost = lease.TargetDomain
			ips = parseIPs(lease.TargetIPs)
			fakeIP = ip.String()
			r.alloc.TouchIP(fakeIP)
		} else {
			ips = []net.IP{ip}
		}
	} else {
		if lease, err := r.alloc.GetActiveByDomain(targetHost); err == nil {
			ips = parseIPs(lease.TargetIPs)
			r.alloc.TouchDomain(targetHost)
		} else {
			resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			resolved, err := r.resolver.Resolve(resolveCtx, targetHost)
			cancel()
			if err == nil {
				ips = resolved
			}
		}
	}

	decision, err := r.engine.Decide(targetHost, ips, clientIP, port)
	if err != nil {
		return nil, decision, "", err
	}

	fields := []any{
		"client", ipString(clientIP),
		"target", net.JoinHostPort(targetHost, fmt.Sprint(port)),
		"fake_ip", fakeIP,
		"action", decision.Action,
		"reason", decision.Reason,
	}
	if decision.Rule != nil {
		fields = append(fields, "rule", decision.Rule.Name)
	}
	if decision.UpstreamID != 0 {
		fields = append(fields, "upstream", decision.UpstreamName)
	}

	var conn net.Conn
	switch decision.Action {
	case model.ActionBlock:
		r.log.Info("connection blocked", fields...)
		return nil, decision, "", ErrBlocked
	case model.ActionDirect:
		dialAddr := net.JoinHostPort(targetHost, fmt.Sprint(port))
		if fakeIP != "" && len(ips) > 0 {
			dialAddr = net.JoinHostPort(ips[0].String(), fmt.Sprint(port))
		}
		conn, err = (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", dialAddr)
		if err != nil {
			r.log.Info("direct dial failed", append(fields, "dial", dialAddr, "error", err)...)
			return nil, decision, dialAddr, err
		}
		r.log.Info("connection direct", append(fields, "dial", dialAddr)...)
		return conn, decision, dialAddr, nil
	case model.ActionProxy:
		dialAddr := net.JoinHostPort(targetHost, fmt.Sprint(port))
		conn, err = r.manager.Dial(ctx, decision.UpstreamID, "tcp", dialAddr)
		if err != nil {
			r.log.Info("proxy dial failed", append(fields, "dial", dialAddr, "error", err)...)
			return nil, decision, dialAddr, err
		}
		r.log.Info("connection proxied", append(fields, "dial", dialAddr)...)
		return conn, decision, dialAddr, nil
	default:
		return nil, decision, "", fmt.Errorf("unknown routing action %q", decision.Action)
	}
}

func normalizeTargetHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.Trim(host, "[]")
	host = strings.TrimSuffix(host, ".")
	if net.ParseIP(host) == nil {
		host = strings.ToLower(host)
	}
	return host
}

func parseIPs(raw []string) []net.IP {
	out := make([]net.IP, 0, len(raw))
	for _, s := range raw {
		if ip := net.ParseIP(s); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
