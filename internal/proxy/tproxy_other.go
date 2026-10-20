//go:build !linux

package proxy

import (
	"errors"
	"net"
)

func ListenTProxy(addr string) (net.Listener, error) {
	return nil, errors.New("TPROXY is only supported on Linux")
}

func originalDst(conn net.Conn) (*net.TCPAddr, error) {
	return nil, errors.New("TPROXY is only supported on Linux")
}
