package upstream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/proxy"

	"idips/internal/model"
)

type dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type contextDialer struct {
	d proxy.ContextDialer
}

func (d contextDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.d.DialContext(ctx, network, addr)
}

type plainDialer struct {
	d proxy.Dialer
}

func (d plainDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := d.d.Dial(network, addr)
		ch <- result{c: c, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.c, r.err
	}
}

func newSOCKS5Dialer(addr, username, password string) (dialer, error) {
	if addr == "" {
		return nil, errors.New("socks5 address is empty")
	}
	var auth *proxy.Auth
	if username != "" {
		auth = &proxy.Auth{User: username, Password: password}
	}
	d, err := proxy.SOCKS5("tcp", addr, auth, &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second})
	if err != nil {
		return nil, err
	}
	if cd, ok := d.(proxy.ContextDialer); ok {
		return contextDialer{d: cd}, nil
	}
	return plainDialer{d: d}, nil
}

func connectorFor(u model.Upstream) (dialer, error) {
	switch u.Type {
	case model.UpstreamSOCKS5:
		return newSOCKS5Dialer(u.Address, u.Username, u.Password)
	case model.UpstreamHTTP:
		return newHTTPConnectDialer(u.Address, u.Username, u.Password)
	default:
		return nil, fmt.Errorf("unsupported upstream type %q", u.Type)
	}
}
