package dnsserver

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"

	"idips/internal/alloc"
	"idips/internal/model"
	"idips/internal/resolver"
	"idips/internal/routing"
	"idips/internal/store"
)

type Handler struct {
	alloc    *alloc.Allocator
	engine   *routing.Engine
	resolver *resolver.Resolver
	settings func() model.Settings
	log      *slog.Logger
}

func New(st *store.Store, allocator *alloc.Allocator, engine *routing.Engine, res *resolver.Resolver, settings func() model.Settings, log *slog.Logger) *Handler {
	return &Handler{alloc: allocator, engine: engine, resolver: res, settings: settings, log: log}
}

func (h *Handler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	clientIP := ipFromAddr(w.RemoteAddr())
	resp := h.Handle(req, clientIP)
	if resp == nil {
		return
	}
	if err := w.WriteMsg(resp); err != nil {
		h.log.Debug("write dns response failed", "error", err)
	}
}

func (h *Handler) Handle(req *dns.Msg, clientIP net.IP) *dns.Msg {
	if req == nil || len(req.Question) != 1 {
		resp := new(dns.Msg)
		if req != nil {
			resp.SetRcode(req, dns.RcodeFormatError)
		}
		return resp
	}
	q := req.Question[0]
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	s := h.settings()

	switch q.Qtype {
	case dns.TypeA:
		if strings.HasSuffix(name, ".arpa") {
			return h.forward(req, clientIP)
		}
		if lease, err := h.alloc.GetActiveByDomain(name); err == nil {
			h.alloc.TouchDomain(name)
			return fakeReply(req, lease.FakeIP, s.DNSTTL)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		ips, resolveErr := h.resolver.Resolve(ctx, name)
		decision, decideErr := h.engine.Decide(name, ips, clientIP, 0)
		if decideErr != nil {
			h.log.Warn("routing decision failed", "domain", name, "error", decideErr)
		}
		fake := s.FakeAll || decision.Action == model.ActionProxy || decision.Action == model.ActionBlock
		if fake {
			lease, err := h.alloc.GetOrCreate(name, ips, "")
			if err != nil {
				h.log.Error("fake-IP allocation failed", "domain", name, "error", err)
				return rcodeReply(req, dns.RcodeServerFailure)
			}
			h.log.Debug("dns fake-IP", "domain", name, "fake_ip", lease.FakeIP, "action", decision.Action, "reason", decision.Reason)
			return fakeReply(req, lease.FakeIP, s.DNSTTL)
		}
		if resolveErr != nil {
			h.log.Debug("dns resolution failed", "domain", name, "error", resolveErr)
			return rcodeReply(req, dns.RcodeServerFailure)
		}
		return h.forward(req, clientIP)

	case dns.TypeAAAA:
		if s.BlockAAAA {
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.RecursionAvailable = true
			return resp
		}
		return h.forward(req, clientIP)

	default:
		return h.forward(req, clientIP)
	}
}

func (h *Handler) forward(req *dns.Msg, clientIP net.IP) *dns.Msg {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	resp, err := h.resolver.Exchange(ctx, req.Copy())
	if err != nil {
		h.log.Debug("dns forward failed", "question", req.Question[0].Name, "error", err)
		return rcodeReply(req, dns.RcodeServerFailure)
	}
	resp.Id = req.Id
	return resp
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var raw []byte
	var err error
	if r.Method == http.MethodGet {
		enc := r.URL.Query().Get("dns")
		if enc == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		raw, err = base64.RawURLEncoding.DecodeString(enc)
		if err != nil {
			raw, err = base64.URLEncoding.DecodeString(enc)
		}
	} else {
		raw, err = io.ReadAll(io.LimitReader(r.Body, 65536))
	}
	if err != nil {
		http.Error(w, "invalid dns message", http.StatusBadRequest)
		return
	}
	var req dns.Msg
	if err := req.Unpack(raw); err != nil {
		http.Error(w, "invalid dns message", http.StatusBadRequest)
		return
	}
	clientIP := ipFromAddrString(r.RemoteAddr)
	resp := h.Handle(&req, clientIP)
	if resp == nil {
		http.Error(w, "no response", http.StatusInternalServerError)
		return
	}
	out, err := resp.Pack()
	if err != nil {
		http.Error(w, "pack response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "max-age=60")
	_, _ = w.Write(out)
}

func fakeReply(req *dns.Msg, fakeIP string, ttl uint32) *dns.Msg {
	ip := net.ParseIP(fakeIP).To4()
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true
	if ip == nil {
		resp.Rcode = dns.RcodeServerFailure
		return resp
	}
	if ttl == 0 {
		ttl = 60
	}
	q := req.Question[0]
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   ip,
	})
	return resp
}

func rcodeReply(req *dns.Msg, rcode int) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetRcode(req, rcode)
	return resp
}

func ipFromAddr(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	return ipFromAddrString(addr.String())
}

func ipFromAddrString(addr string) net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return net.ParseIP(strings.Trim(host, "[]"))
}

type Servers struct {
	servers []*dns.Server
	http    *http.Server
	log     *slog.Logger
}

func Start(ctx context.Context, s model.Settings, handler *Handler, log *slog.Logger) *Servers {
	set := &Servers{log: log}
	if s.DNSListen != "" {
		udp := &dns.Server{Addr: s.DNSListen, Net: "udp", Handler: handler, UDPSize: 4096}
		tcp := &dns.Server{Addr: s.DNSListen, Net: "tcp", Handler: handler}
		set.servers = append(set.servers, udp, tcp)
		go func() {
			log.Info("dns udp listening", "addr", s.DNSListen)
			if err := udp.ListenAndServe(); err != nil {
				log.Error("dns udp server stopped", "error", err)
			}
		}()
		go func() {
			log.Info("dns tcp listening", "addr", s.DNSListen)
			if err := tcp.ListenAndServe(); err != nil {
				log.Error("dns tcp server stopped", "error", err)
			}
		}()
	}

	if s.DoTListen != "" {
		if s.DNSCert == "" || s.DNSKey == "" {
			log.Warn("DoT disabled: dns_cert/dns_key not configured", "addr", s.DoTListen)
		} else {
			cert, err := tls.LoadX509KeyPair(s.DNSCert, s.DNSKey)
			if err != nil {
				log.Error("DoT certificate load failed", "error", err)
			} else {
				dot := &dns.Server{
					Addr:      s.DoTListen,
					Net:       "tcp-tls",
					Handler:   handler,
					TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
				}
				set.servers = append(set.servers, dot)
				go func() {
					log.Info("dns DoT listening", "addr", s.DoTListen)
					if err := dot.ListenAndServe(); err != nil {
						log.Error("dns DoT server stopped", "error", err)
					}
				}()
			}
		}
	}

	if s.DoHListen != "" && s.DoHListen != s.AdminListen {
		mux := http.NewServeMux()
		mux.Handle("/dns-query", handler)
		hs := &http.Server{Addr: s.DoHListen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		set.http = hs
		go func() {
			log.Info("dns DoH listening", "addr", s.DoHListen)
			if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("dns DoH server stopped", "error", err)
			}
		}()
	}
	_ = ctx
	return set
}

func (s *Servers) Stop(ctx context.Context) {
	for _, srv := range s.servers {
		if err := srv.ShutdownContext(ctx); err != nil {
			s.log.Debug("dns shutdown failed", "error", err)
		}
	}
	if s.http != nil {
		_ = s.http.Shutdown(ctx)
	}
}

func ValidateAddress(addr string) error {
	if addr == "" {
		return nil
	}
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", addr, err)
	}
	return nil
}
