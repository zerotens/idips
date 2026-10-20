package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"

	"idips/internal/alloc"
	"idips/internal/dnsserver"
	"idips/internal/logstream"
	"idips/internal/model"
	"idips/internal/proxy"
	"idips/internal/resolver"
	"idips/internal/routing"
	"idips/internal/secret"
	"idips/internal/store"
	"idips/internal/upstream"
	"idips/internal/web"
)

var Version = "0.2.0"

type App struct {
	DataDir string
	Log     *slog.Logger
	Store   *store.Store

	settings atomic.Pointer[model.Settings]
	box      *secret.Box
	level    *slog.LevelVar

	alloc      *alloc.Allocator
	engine     *routing.Engine
	manager    *upstream.Manager
	resolver   *resolver.Resolver
	dnsHandler *dnsserver.Handler
	dnsServers *dnsserver.Servers
	web        *web.Server

	socks  *proxy.SOCKS5Server
	http   *proxy.HTTPProxyServer
	tproxy *proxy.TProxyServer

	admin  *http.Server
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New(ctx context.Context, dataDir string, log *slog.Logger, level *slog.LevelVar, logs *logstream.Hub) (*App, error) {
	if dataDir == "" {
		dataDir = "data"
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, err
	}
	key, err := secret.LoadOrCreateKey(abs)
	if err != nil {
		return nil, err
	}
	box, err := secret.NewBox(key)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(filepath.Join(abs, "idips.db"), box)
	if err != nil {
		return nil, err
	}
	cleanup := func() { _ = st.Close() }

	settings, err := st.GetSettings()
	if err != nil {
		cleanup()
		return nil, err
	}
	if level != nil && os.Getenv("IDIPS_LOG_LEVEL") == "" {
		level.Set(parseLevel(settings.LogLevel))
	}
	if err := bootstrapAdmin(st, log); err != nil {
		cleanup()
		return nil, err
	}

	a := &App{DataDir: abs, Log: log, Store: st, box: box, level: level}
	a.settings.Store(&settings)

	a.alloc, err = alloc.New(st, settings.PoolCIDR, func() time.Duration { return a.Settings().LeaseTTL() }, log)
	if err != nil {
		cleanup()
		return nil, err
	}
	a.engine = routing.New(st, log)
	if err := a.engine.ReloadGeo(settings.GeoIPCityDB, settings.GeoIPASNDB, resolveIPtoASN(settings.GeoIPTSV, abs)); err != nil {
		log.Warn("GeoIP databases not loaded", "error", err)
	}
	a.manager = upstream.New(st, a.Settings, abs, log)
	a.resolver = resolver.New(st, a.manager, a.Settings, log)
	a.dnsHandler = dnsserver.New(st, a.alloc, a.engine, a.resolver, a.Settings, log)
	router := proxy.NewRouter(a.alloc, a.engine, a.resolver, a.manager, a.Settings, log)
	a.socks = proxy.NewSOCKS5(settings.SOCKS5Listen, router, a.Settings, log)
	a.http = proxy.NewHTTPProxy(settings.HTTPListen, router, a.Settings, log)
	a.tproxy = proxy.NewTProxy(settings.TProxyListen, router, a.Settings, log)
	a.web = web.New(web.Config{
		Store: st, Settings: a.Settings, Reload: a.Reload,
		Manager: a.manager, Alloc: a.alloc, DNSHandler: a.dnsHandler,
		MasterKey: key, Log: log, Logs: logs, Version: Version,
	})
	_ = ctx
	return a, nil
}

func resolveIPtoASN(explicit, dataDir string) string {
	if explicit != "" {
		return explicit
	}
	if p := strings.TrimSpace(os.Getenv("IDIPS_IPTOASN_DB")); p != "" {
		return p
	}
	candidates := []string{
		filepath.Join(dataDir, "ip2asn-combined.tsv.gz"),
		"/usr/share/idips/ip2asn-combined.tsv.gz",
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "ip2asn-combined.tsv.gz"))
	}
	candidates = append(candidates, "ip2asn-combined.tsv.gz")
	for _, path := range candidates {
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			return path
		}
	}
	return ""
}

func parseLevel(raw string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func bootstrapAdmin(st *store.Store, log *slog.Logger) error {
	n, err := st.CountAdmins()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	user := os.Getenv("IDIPS_ADMIN_USER")
	if user == "" {
		user = "admin"
	}
	pass := os.Getenv("IDIPS_ADMIN_PASSWORD")
	if pass == "" {
		pass = "admin"
		log.Warn("no admin exists, created bootstrap admin with default password; set IDIPS_ADMIN_PASSWORD and restart or change it in the database", "username", user)
	} else {
		log.Info("created bootstrap admin", "username", user)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if _, err := st.CreateAdmin(user, string(hash)); err != nil {
		return err
	}
	_ = st.AddAudit("system", "admin_bootstrap", user)
	return nil
}

func (a *App) Settings() model.Settings {
	p := a.settings.Load()
	if p == nil {
		return model.DefaultSettings()
	}
	return *p
}

func (a *App) Reload() {
	cfg, err := a.Store.GetSettings()
	if err != nil {
		a.Log.Error("reload settings failed", "error", err)
		return
	}
	old := a.Settings()
	a.settings.Store(&cfg)
	if a.level != nil && os.Getenv("IDIPS_LOG_LEVEL") == "" {
		a.level.Set(parseLevel(cfg.LogLevel))
	}
	if old.PoolCIDR != cfg.PoolCIDR {
		if err := a.alloc.Reconfigure(cfg.PoolCIDR); err != nil {
			a.Log.Error("reconfigure fake-IP pool failed", "error", err)
		}
	}
	if old.GeoIPCityDB != cfg.GeoIPCityDB || old.GeoIPASNDB != cfg.GeoIPASNDB || old.GeoIPTSV != cfg.GeoIPTSV {
		if err := a.engine.ReloadGeo(cfg.GeoIPCityDB, cfg.GeoIPASNDB, resolveIPtoASN(cfg.GeoIPTSV, a.DataDir)); err != nil {
			a.Log.Warn("reload GeoIP failed", "error", err)
		}
	}
	a.Log.Info("settings reloaded", "pool", cfg.PoolCIDR, "default_action", cfg.DefaultAction)
}

func (a *App) Run(ctx context.Context) error {
	cfg := a.Settings()
	runCtx, cancel := context.WithCancel(ctx)
	a.cancel = cancel
	a.manager.Start(runCtx)

	a.dnsServers = dnsserver.Start(runCtx, cfg, a.dnsHandler, a.Log)

	if err := a.socks.Start(runCtx); err != nil {
		a.Log.Error("socks5 inbound failed to start", "error", err)
	}
	if err := a.http.Start(runCtx); err != nil {
		a.Log.Error("http inbound failed to start", "error", err)
	}
	if err := a.tproxy.Start(runCtx); err != nil {
		a.Log.Warn("tproxy inbound failed to start (requires CAP_NET_ADMIN and nftables rules)", "error", err)
	}

	handler := a.web.Handler()
	a.admin = &http.Server{
		Addr:              cfg.AdminListen,
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		if cfg.AdminTLSCert != "" && cfg.AdminTLSKey != "" {
			a.admin.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			a.Log.Info("admin UI listening (https)", "addr", cfg.AdminListen)
			if err := a.admin.ListenAndServeTLS(cfg.AdminTLSCert, cfg.AdminTLSKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
			return
		}
		a.Log.Info("admin UI listening (http)", "addr", cfg.AdminListen)
		if err := a.admin.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := a.alloc.GC(); err != nil {
					a.Log.Warn("lease GC failed", "error", err)
				}
				_ = a.Store.DeleteExpiredSessions(time.Now())
			}
		}
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		a.shutdown()
		return err
	}
	a.shutdown()
	return nil
}

func (a *App) shutdown() {
	a.Log.Info("shutting down")
	if a.cancel != nil {
		a.cancel()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if a.admin != nil {
		_ = a.admin.Shutdown(shutdownCtx)
	}
	if a.dnsServers != nil {
		a.dnsServers.Stop(shutdownCtx)
	}

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		if a.socks != nil {
			a.socks.Close()
		}
	}()
	go func() {
		defer wg.Done()
		if a.http != nil {
			a.http.Close()
		}
	}()
	go func() {
		defer wg.Done()
		if a.tproxy != nil {
			a.tproxy.Close()
		}
	}()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-shutdownCtx.Done():
		a.Log.Warn("proxy shutdown timed out")
	}

	a.manager.Stop()
	a.engine.Close()
	a.wg.Wait()
	if err := a.Store.Close(); err != nil {
		a.Log.Warn("close store failed", "error", err)
	}
	a.Log.Info("shutdown complete")
}

func (a *App) AdminURL() string {
	cfg := a.Settings()
	scheme := "http"
	if cfg.AdminTLSCert != "" && cfg.AdminTLSKey != "" {
		scheme = "https"
	}
	addr := cfg.AdminListen
	if host, port, err := net.SplitHostPort(addr); err == nil {
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		addr = net.JoinHostPort(host, port)
	} else if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	return fmt.Sprintf("%s://%s", scheme, addr)
}
