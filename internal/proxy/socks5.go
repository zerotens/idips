package proxy

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"idips/internal/model"
)

type SOCKS5Server struct {
	addr     string
	router   *Router
	settings func() model.Settings
	log      *slog.Logger

	ln net.Listener
	wg sync.WaitGroup
}

func NewSOCKS5(addr string, router *Router, settings func() model.Settings, log *slog.Logger) *SOCKS5Server {
	return &SOCKS5Server{addr: addr, router: router, settings: settings, log: log}
}

func (s *SOCKS5Server) Start(ctx context.Context) error {
	if s.addr == "" {
		return nil
	}
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.ln = ln
	s.log.Info("socks5 inbound listening", "addr", s.addr)
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
				s.log.Warn("socks5 accept failed", "error", err)
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

func (s *SOCKS5Server) Close() {
	if s.ln != nil {
		_ = s.ln.Close()
	}
	s.wg.Wait()
}

func (s *SOCKS5Server) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(conn)

	var head [2]byte
	if _, err := io.ReadFull(br, head[:]); err != nil {
		return
	}
	if head[0] != 5 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	cfg := s.settings()
	requireAuth := cfg.SOCKS5Username != ""
	if requireAuth {
		if !containsByte(methods, 2) {
			_, _ = conn.Write([]byte{5, 0xFF})
			return
		}
		if _, err := conn.Write([]byte{5, 2}); err != nil {
			return
		}
		user, pass, err := readUserPass(br)
		if err != nil {
			return
		}
		userOK := subtle.ConstantTimeCompare([]byte(user), []byte(cfg.SOCKS5Username)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(cfg.SOCKS5Password)) == 1
		if !userOK || !passOK {
			_, _ = conn.Write([]byte{1, 1})
			return
		}
		if _, err := conn.Write([]byte{1, 0}); err != nil {
			return
		}
	} else {
		if !containsByte(methods, 0) {
			_, _ = conn.Write([]byte{5, 0xFF})
			return
		}
		if _, err := conn.Write([]byte{5, 0}); err != nil {
			return
		}
	}

	var req [4]byte
	if _, err := io.ReadFull(br, req[:]); err != nil {
		return
	}
	if req[0] != 5 || req[1] != 1 {
		writeSOCKSReply(conn, 7, nil, 0)
		return
	}
	host, err := readSOCKSAddr(br, req[3])
	if err != nil {
		writeSOCKSReply(conn, 8, nil, 0)
		return
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(br, portBuf[:]); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(portBuf[:]))
	clientIP := ipFromNetAddr(conn.RemoteAddr())

	_ = conn.SetDeadline(time.Now().Add(45 * time.Second))
	target, decision, _, err := s.router.Route(context.Background(), host, port, clientIP)
	if err != nil {
		code := byte(1)
		if errors.Is(err, ErrBlocked) {
			code = 2
		}
		s.log.Debug("socks5 connect failed", "target", net.JoinHostPort(host, strconv.Itoa(port)), "client", clientIP, "action", decision.Action, "error", err)
		writeSOCKSReply(conn, code, nil, 0)
		return
	}
	if err := writeSOCKSReply(conn, 0, net.IPv4zero, 0); err != nil {
		_ = target.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})
	relay(conn, br, target)
}

func readUserPass(r io.Reader) (string, string, error) {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", "", err
	}
	if b[0] != 1 {
		return "", "", fmt.Errorf("unsupported auth version %d", b[0])
	}
	user := make([]byte, int(b[1]))
	if _, err := io.ReadFull(r, user); err != nil {
		return "", "", err
	}
	var plen [1]byte
	if _, err := io.ReadFull(r, plen[:]); err != nil {
		return "", "", err
	}
	pass := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(r, pass); err != nil {
		return "", "", err
	}
	return string(user), string(pass), nil
}

func readSOCKSAddr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case 1:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		return net.IP(b[:]).String(), nil
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return "", err
		}
		b := make([]byte, int(n[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return string(b), nil
	case 4:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		return net.IP(b[:]).String(), nil
	default:
		return "", fmt.Errorf("unsupported address type %d", atyp)
	}
}

func writeSOCKSReply(w io.Writer, code byte, ip net.IP, port int) error {
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = net.IPv4zero.To4()
	}
	buf := []byte{5, code, 0, 1, ip4[0], ip4[1], ip4[2], ip4[3], 0, 0}
	binary.BigEndian.PutUint16(buf[8:10], uint16(port))
	_, err := w.Write(buf)
	return err
}

func containsByte(b []byte, v byte) bool {
	for _, x := range b {
		if x == v {
			return true
		}
	}
	return false
}

func ipFromNetAddr(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}
