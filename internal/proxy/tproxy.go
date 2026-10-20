package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"idips/internal/model"
)

type TProxyServer struct {
	addr     string
	router   *Router
	settings func() model.Settings
	log      *slog.Logger

	ln net.Listener
	wg sync.WaitGroup
}

func NewTProxy(addr string, router *Router, settings func() model.Settings, log *slog.Logger) *TProxyServer {
	return &TProxyServer{addr: addr, router: router, settings: settings, log: log}
}

func (s *TProxyServer) Start(ctx context.Context) error {
	cfg := s.settings()
	if !cfg.TProxyEnabled || s.addr == "" {
		return nil
	}
	ln, err := ListenTProxy(s.addr)
	if err != nil {
		return err
	}
	s.ln = ln
	s.log.Info("tproxy inbound listening", "addr", s.addr)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if errors.Is(err, net.ErrClosed) {
					return
				}
				s.log.Warn("tproxy accept failed", "error", err)
				continue
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.handle(conn)
			}()
		}
	}()
	return nil
}

func (s *TProxyServer) Close() {
	if s.ln != nil {
		_ = s.ln.Close()
	}
	s.wg.Wait()
}

func (s *TProxyServer) handle(conn net.Conn) {
	defer conn.Close()
	clientIP := ipFromNetAddr(conn.RemoteAddr())
	local, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	host := local.IP.String()
	port := local.Port
	if !s.router.alloc.Contains(local.IP) {
		if orig, err := originalDst(conn); err == nil {
			host = orig.IP.String()
			port = orig.Port
		}
	}
	if host == "" || host == "<nil>" || port == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	target, decision, _, err := s.router.Route(ctx, host, port, clientIP)
	if err != nil {
		s.log.Debug("tproxy connect failed", "target", net.JoinHostPort(host, strconv.Itoa(port)), "client", clientIP, "action", decision.Action, "error", err)
		return
	}
	_ = conn.SetDeadline(time.Time{})
	relay(conn, conn, target)
}
