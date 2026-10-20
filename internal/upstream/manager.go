package upstream

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"time"

	"idips/internal/model"
	"idips/internal/store"
)

type Manager struct {
	store    *store.Store
	settings func() model.Settings
	baseDir  string
	log      *slog.Logger

	wpMu      sync.Mutex
	instances map[int64]*wireproxyInstance

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New(st *store.Store, settings func() model.Settings, baseDir string, log *slog.Logger) *Manager {
	return &Manager{
		store:     st,
		settings:  settings,
		baseDir:   baseDir,
		log:       log,
		instances: make(map[int64]*wireproxyInstance),
	}
}

func (m *Manager) Start(ctx context.Context) {
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.healthLoop()
	}()
}

func (m *Manager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	m.wpMu.Lock()
	list := make([]*wireproxyInstance, 0, len(m.instances))
	for id, inst := range m.instances {
		list = append(list, inst)
		delete(m.instances, id)
	}
	m.wpMu.Unlock()
	for _, inst := range list {
		inst.stop()
	}
}

func (m *Manager) connector(ctx context.Context, u model.Upstream) (dialer, error) {
	switch u.Type {
	case model.UpstreamSOCKS5, model.UpstreamHTTP:
		return connectorFor(u)
	case model.UpstreamWireGuard:
		inst, err := m.ensureWireproxy(ctx, u)
		if err != nil {
			return nil, err
		}
		return newSOCKS5Dialer(inst.addr, "", "")
	default:
		return nil, fmt.Errorf("unsupported upstream type %q", u.Type)
	}
}

func (m *Manager) Dial(ctx context.Context, upstreamID int64, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("only TCP is supported, got %s", network)
	}
	u, err := m.store.GetUpstream(upstreamID)
	if err != nil {
		return nil, fmt.Errorf("get upstream %d: %w", upstreamID, err)
	}
	if !u.Enabled {
		return nil, fmt.Errorf("upstream %q is disabled", u.Name)
	}
	d, err := m.connector(ctx, u)
	if err != nil {
		return nil, err
	}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s via %s: %w", addr, u.Name, err)
	}
	return conn, nil
}

func (m *Manager) Test(ctx context.Context, upstreamID int64) (time.Duration, error) {
	u, err := m.store.GetUpstream(upstreamID)
	if err != nil {
		return 0, err
	}
	if !u.Enabled {
		return 0, errors.New("upstream is disabled")
	}
	d, testErr := m.testUpstream(ctx, u)
	status := model.HealthUp
	if testErr != nil {
		status = model.HealthDown
	}
	_ = m.store.UpdateUpstreamHealth(u.ID, status)
	return d, testErr
}

func (m *Manager) testUpstream(ctx context.Context, u model.Upstream) (time.Duration, error) {
	d, err := m.connector(ctx, u)
	if err != nil {
		return 0, err
	}
	target := m.settings().HealthTarget
	if target == "" {
		target = "1.1.1.1:443"
	}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return time.Since(start), err
	}
	_ = conn.Close()
	return time.Since(start), nil
}

func (m *Manager) healthLoop() {
	m.runHealth()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.runHealth()
		}
	}
}

func (m *Manager) runHealth() {
	upstreams, err := m.store.ListUpstreams()
	if err != nil {
		m.log.Warn("health check: list upstreams failed", "error", err)
		return
	}
	activeWG := make(map[int64]struct{})
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, u := range upstreams {
		if !u.Enabled {
			continue
		}
		if u.Type == model.UpstreamWireGuard {
			activeWG[u.ID] = struct{}{}
		}
		wg.Add(1)
		go func(u model.Upstream) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(m.ctx, 15*time.Second)
			defer cancel()
			_, err := m.testUpstream(ctx, u)
			status := model.HealthUp
			if err != nil {
				status = model.HealthDown
			}
			if err := m.store.UpdateUpstreamHealth(u.ID, status); err != nil {
				m.log.Warn("health check: update failed", "upstream", u.Name, "error", err)
			}
			if err != nil {
				m.log.Debug("upstream health check failed", "upstream", u.Name, "error", err)
			}
		}(u)
	}
	wg.Wait()

	m.wpMu.Lock()
	var stale []*wireproxyInstance
	for id, inst := range m.instances {
		if _, ok := activeWG[id]; !ok {
			stale = append(stale, inst)
			delete(m.instances, id)
		}
	}
	m.wpMu.Unlock()
	for _, inst := range stale {
		inst.stop()
	}
}

func (m *Manager) wireproxyDir() string {
	dir := m.settings().WireproxyDataDir
	if dir == "" {
		dir = "wireproxy"
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(m.baseDir, dir)
	}
	return dir
}
