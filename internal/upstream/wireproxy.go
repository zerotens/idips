package upstream

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"idips/internal/model"
)

type wireguardConfig struct {
	PrivateKey string
	Address    []string
	DNS        []string
	MTU        int
	Peers      []wireguardPeer
}

type wireguardPeer struct {
	PublicKey           string
	PresharedKey        string
	Endpoint            string
	AllowedIPs          []string
	PersistentKeepalive int
}

type wireproxyInstance struct {
	cmd        *exec.Cmd
	addr       string
	configPath string
	sourceHash string
	done       chan struct{}
	mu         sync.Mutex
	err        error
}

func (i *wireproxyInstance) setErr(err error) {
	i.mu.Lock()
	i.err = err
	i.mu.Unlock()
}

func (i *wireproxyInstance) getErr() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.err
}

func (i *wireproxyInstance) stop() {
	if i == nil || i.cmd == nil || i.cmd.Process == nil {
		return
	}
	select {
	case <-i.done:
		return
	default:
	}
	_ = i.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-i.done:
		return
	case <-time.After(3 * time.Second):
	}
	_ = i.cmd.Process.Kill()
	select {
	case <-i.done:
	case <-time.After(2 * time.Second):
	}
}

func (m *Manager) ensureWireproxy(ctx context.Context, u model.Upstream) (*wireproxyInstance, error) {
	m.wpMu.Lock()
	defer m.wpMu.Unlock()

	sum := sha256.Sum256([]byte(u.WGConfig + "\x00" + m.settings().WireproxyBinary))
	sourceHash := hex.EncodeToString(sum[:])

	if i := m.instances[u.ID]; i != nil {
		select {
		case <-i.done:
			_ = os.Remove(i.configPath)
			delete(m.instances, u.ID)
		default:
			if i.sourceHash == sourceHash {
				return i, nil
			}
			m.log.Info("wireguard config changed, restarting wireproxy", "upstream", u.Name)
			i.stop()
			_ = os.Remove(i.configPath)
			delete(m.instances, u.ID)
		}
	}

	cfg, err := parseWireguardConfig(u.WGConfig)
	if err != nil {
		return nil, fmt.Errorf("upstream %q: %w", u.Name, err)
	}
	binary := m.settings().WireproxyBinary
	if binary == "" {
		binary = "wireproxy"
	}
	if _, err := exec.LookPath(binary); err != nil {
		return nil, fmt.Errorf("wireproxy binary %q not found: %w", binary, err)
	}

	dir := m.wireproxyDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	configPath := filepath.Join(dir, fmt.Sprintf("wg-%d.conf", u.ID))

	bind, err := freeTCPAddr()
	if err != nil {
		return nil, err
	}
	conf, err := renderWireproxyConfig(cfg, bind)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(configPath, []byte(conf), 0o600); err != nil {
		return nil, err
	}

	inst := &wireproxyInstance{addr: bind, configPath: configPath, sourceHash: sourceHash, done: make(chan struct{})}
	cmd := exec.CommandContext(m.ctx, binary, "-c", configPath, "-s")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	inst.cmd = cmd
	if err := cmd.Start(); err != nil {
		_ = os.Remove(configPath)
		return nil, fmt.Errorf("start wireproxy: %w", err)
	}
	m.log.Info("wireproxy started", "upstream", u.Name, "socks5", bind, "pid", cmd.Process.Pid)

	go func() {
		err := cmd.Wait()
		inst.setErr(err)
		close(inst.done)
		m.log.Warn("wireproxy exited", "upstream", u.Name, "error", err)
	}()

	deadline := time.Now().Add(12 * time.Second)
	for {
		select {
		case <-ctx.Done():
			inst.stop()
			return nil, ctx.Err()
		case <-inst.done:
			_ = os.Remove(configPath)
			err := inst.getErr()
			if err == nil {
				err = errors.New("wireproxy exited during startup")
			}
			return nil, err
		case <-time.After(100 * time.Millisecond):
			c, err := net.DialTimeout("tcp", bind, 250*time.Millisecond)
			if err == nil {
				_ = c.Close()
				m.instances[u.ID] = inst
				return inst, nil
			}
			if time.Now().After(deadline) {
				inst.stop()
				_ = os.Remove(configPath)
				return nil, fmt.Errorf("wireproxy did not open %s within timeout", bind)
			}
		}
	}
}

func ValidateWireguardConfig(raw string) error {
	_, err := parseWireguardConfig(raw)
	return err
}

func parseWireguardConfig(raw string) (wireguardConfig, error) {
	cfg := wireguardConfig{MTU: 1420}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return cfg, errors.New("wireguard config is empty")
	}
	if strings.HasPrefix(trimmed, "{") {
		return cfg, errors.New("wireguard config: JSON is no longer supported, use the standard wg-quick INI format")
	}

	section := ""
	peerIndex := -1
	for n, rawLine := range strings.Split(raw, "\n") {
		lineNo := n + 1
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return cfg, fmt.Errorf("wireguard config line %d: invalid section header %q", lineNo, line)
			}
			name := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch name {
			case "interface":
				section = "interface"
			case "peer":
				section = "peer"
				cfg.Peers = append(cfg.Peers, wireguardPeer{})
				peerIndex = len(cfg.Peers) - 1
			default:
				// Ignore wireproxy-specific sections such as [Socks5] or [http].
				section = "ignore"
				peerIndex = -1
			}
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return cfg, fmt.Errorf("wireguard config line %d: expected key = value", lineNo)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)

		switch section {
		case "interface":
			switch key {
			case "privatekey":
				cfg.PrivateKey = value
			case "address":
				cfg.Address = append(cfg.Address, splitList(value)...)
			case "dns":
				cfg.DNS = append(cfg.DNS, splitList(value)...)
			case "mtu":
				if value == "" {
					continue
				}
				mtu, err := strconv.Atoi(value)
				if err != nil {
					return cfg, fmt.Errorf("wireguard config line %d: invalid MTU %q", lineNo, value)
				}
				cfg.MTU = mtu
			}
		case "peer":
			if peerIndex < 0 {
				return cfg, fmt.Errorf("wireguard config line %d: peer key without [Peer]", lineNo)
			}
			p := &cfg.Peers[peerIndex]
			switch key {
			case "publickey":
				p.PublicKey = value
			case "presharedkey":
				p.PresharedKey = value
			case "endpoint":
				p.Endpoint = value
			case "allowedips":
				p.AllowedIPs = append(p.AllowedIPs, splitList(value)...)
			case "persistentkeepalive":
				if value == "" {
					continue
				}
				keepalive, err := strconv.Atoi(value)
				if err != nil {
					return cfg, fmt.Errorf("wireguard config line %d: invalid PersistentKeepalive %q", lineNo, value)
				}
				p.PersistentKeepalive = keepalive
			}
		case "ignore":
			// Ignore keys in sections that IDIPS manages itself.
		default:
			return cfg, fmt.Errorf("wireguard config line %d: key outside [Interface] or [Peer]", lineNo)
		}
	}

	if cfg.PrivateKey == "" {
		return cfg, errors.New("wireguard config: PrivateKey is required in [Interface]")
	}
	if len(cfg.Address) == 0 {
		return cfg, errors.New("wireguard config: Address is required in [Interface]")
	}
	if len(cfg.Peers) == 0 {
		return cfg, errors.New("wireguard config: at least one [Peer] section is required")
	}
	for i := range cfg.Peers {
		p := &cfg.Peers[i]
		if p.PublicKey == "" {
			return cfg, fmt.Errorf("wireguard config: PublicKey is required in [Peer] #%d", i+1)
		}
		if p.Endpoint == "" {
			return cfg, fmt.Errorf("wireguard config: Endpoint is required in [Peer] #%d", i+1)
		}
		if len(p.AllowedIPs) == 0 {
			p.AllowedIPs = []string{"0.0.0.0/0", "::/0"}
		}
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1420
	}
	return cfg, nil
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func renderWireproxyConfig(cfg wireguardConfig, bind string) (string, error) {
	var b strings.Builder
	b.WriteString("# generated by IDIPS - do not edit\n")
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", cfg.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", strings.Join(cfg.Address, ", "))
	if len(cfg.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(cfg.DNS, ", "))
	}
	if cfg.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", cfg.MTU)
	}
	b.WriteString("\n")
	for _, p := range cfg.Peers {
		b.WriteString("[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
		}
		fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", "))
		if p.PersistentKeepalive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.PersistentKeepalive)
		}
		b.WriteString("\n")
	}
	b.WriteString("[Socks5]\n")
	fmt.Fprintf(&b, "BindAddress = %s\n", bind)
	return b.String(), nil
}

func freeTCPAddr() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := l.Addr().(*net.TCPAddr)
	port := addr.Port
	if err := l.Close(); err != nil {
		return "", err
	}
	return "127.0.0.1:" + strconv.Itoa(port), nil
}
