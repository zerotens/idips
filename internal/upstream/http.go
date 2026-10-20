package upstream

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type httpConnectDialer struct {
	proxyAddr string
	username  string
	password  string
	dialer    *net.Dialer
}

func newHTTPConnectDialer(addr, username, password string) (dialer, error) {
	if addr == "" {
		return nil, errors.New("http proxy address is empty")
	}
	return &httpConnectDialer{
		proxyAddr: addr,
		username:  username,
		password:  password,
		dialer:    &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second},
	}, nil
}

func (d *httpConnectDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("http CONNECT only supports TCP, got %s", network)
	}
	conn, err := d.dialer.DialContext(ctx, "tcp", d.proxyAddr)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	if deadline, has := ctx.Deadline(); has {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n", addr, addr)
	if d.username != "" {
		token := base64.StdEncoding.EncodeToString([]byte(d.username + ":" + d.password))
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", token)
	}
	b.WriteString("\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http proxy CONNECT failed: %s", resp.Status)
	}
	_ = conn.SetDeadline(time.Time{})
	ok = true
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}
