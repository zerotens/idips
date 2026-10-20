//go:build linux

package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func ListenTProxy(addr string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var innerErr error
			if err := c.Control(func(fd uintptr) {
				if innerErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); innerErr != nil {
					return
				}
				if innerErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); innerErr != nil {
					return
				}
				innerErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_FREEBIND, 1)
			}); err != nil {
				return err
			}
			return innerErr
		},
	}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen tproxy %s (requires CAP_NET_ADMIN): %w", addr, err)
	}
	return ln, nil
}

func originalDst(conn net.Conn) (*net.TCPAddr, error) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, errors.New("not a TCP connection")
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return nil, err
	}
	var sa syscall.RawSockaddrInet4
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		var buf [128]byte
		size := uint32(len(buf))
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, uintptr(unix.SOL_IP), uintptr(unix.SO_ORIGINAL_DST),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
		if errno != 0 {
			sockErr = errno
			return
		}
		if int(size) < int(unsafe.Sizeof(sa)) {
			sockErr = errors.New("short sockaddr from SO_ORIGINAL_DST")
			return
		}
		sa = *(*syscall.RawSockaddrInet4)(unsafe.Pointer(&buf[0]))
	}); err != nil {
		return nil, err
	}
	if sockErr != nil {
		return nil, sockErr
	}
	if sa.Family != syscall.AF_INET {
		return nil, fmt.Errorf("unsupported original address family %d", sa.Family)
	}
	port := int(sa.Port>>8 | sa.Port<<8)
	ip := net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3])
	return &net.TCPAddr{IP: ip, Port: port}, nil
}
