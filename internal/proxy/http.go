package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"idips/internal/model"
)

type HTTPProxyServer struct {
	addr     string
	router   *Router
	settings func() model.Settings
	log      *slog.Logger

	ln net.Listener
	wg sync.WaitGroup
}

func NewHTTPProxy(addr string, router *Router, settings func() model.Settings, log *slog.Logger) *HTTPProxyServer {
	return &HTTPProxyServer{addr: addr, router: router, settings: settings, log: log}
}

func (s *HTTPProxyServer) Start(ctx context.Context) error {
	if s.addr == "" {
		return nil
	}
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.ln = ln
	s.log.Info("http proxy inbound listening", "addr", s.addr)
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
				s.log.Warn("http proxy accept failed", "error", err)
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

func (s *HTTPProxyServer) Close() {
	if s.ln != nil {
		_ = s.ln.Close()
	}
	s.wg.Wait()
}

func (s *HTTPProxyServer) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		writeHTTPResponse(conn, http.StatusMethodNotAllowed, "only CONNECT is supported")
		return
	}
	cfg := s.settings()
	if cfg.HTTPUsername != "" && !checkBasicAuth(req.Header.Get("Proxy-Authorization"), cfg.HTTPUsername, cfg.HTTPPassword) {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"idips\"\r\nContent-Length: 0\r\n\r\n")
		return
	}

	hostport := req.Host
	if hostport == "" {
		hostport = req.URL.Host
	}
	host, port := splitHostPortDefault(hostport, 443)
	if host == "" {
		writeHTTPResponse(conn, http.StatusBadRequest, "missing host")
		return
	}
	clientIP := ipFromNetAddr(conn.RemoteAddr())

	_ = conn.SetDeadline(time.Now().Add(45 * time.Second))
	target, decision, _, err := s.router.Route(context.Background(), host, port, clientIP)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, ErrBlocked) {
			status = http.StatusForbidden
		}
		s.log.Debug("http connect failed", "target", net.JoinHostPort(host, strconv.Itoa(port)), "client", clientIP, "action", decision.Action, "error", err)
		writeHTTPResponse(conn, status, err.Error())
		return
	}
	_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	_ = conn.SetDeadline(time.Time{})
	relay(conn, br, target)
}

func splitHostPortDefault(hostport string, defaultPort int) (string, int) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return "", 0
	}
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		host = strings.Trim(hostport, "[]")
		return host, defaultPort
	}
	if host == "" {
		host = strings.Trim(hostport, "[]")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return host, defaultPort
	}
	return host, port
}

func checkBasicAuth(header, user, pass string) bool {
	const prefix = "Basic "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if err != nil {
		return false
	}
	u, p, ok := strings.Cut(string(raw), ":")
	if !ok {
		return false
	}
	return u == user && p == pass
}

func writeHTTPResponse(w net.Conn, status int, body string) {
	if body == "" {
		body = http.StatusText(status)
	}
	_, _ = fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
}
