package proxy

import (
	"io"
	"net"
	"sync"
)

func relay(client net.Conn, clientReader io.Reader, target net.Conn) {
	if clientReader == nil {
		clientReader = client
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(target, clientReader)
		closeWrite(target)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, target)
		closeWrite(client)
	}()
	wg.Wait()
	_ = client.Close()
	_ = target.Close()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
