package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"idips/internal/alloc"
	"idips/internal/logstream"
	"idips/internal/model"
	"idips/internal/store"
	"idips/internal/upstream"
)

//go:embed templates/*.html static/*
var content embed.FS

type Config struct {
	Store      *store.Store
	Settings   func() model.Settings
	Reload     func()
	Manager    *upstream.Manager
	Alloc      *alloc.Allocator
	DNSHandler http.Handler
	MasterKey  []byte
	Log        *slog.Logger
	Logs       *logstream.Hub
	Version    string
}

type Server struct {
	store      *store.Store
	settings   func() model.Settings
	reload     func()
	manager    *upstream.Manager
	alloc      *alloc.Allocator
	dnsHandler http.Handler
	masterKey  []byte
	log        *slog.Logger
	logs       *logstream.Hub
	version    string

	mux  *http.ServeMux
	tmpl sync.Map
}

func New(cfg Config) *Server {
	s := &Server{
		store:      cfg.Store,
		settings:   cfg.Settings,
		reload:     cfg.Reload,
		manager:    cfg.Manager,
		alloc:      cfg.Alloc,
		dnsHandler: cfg.DNSHandler,
		masterKey:  cfg.MasterKey,
		log:        cfg.Log,
		logs:       cfg.Logs,
		version:    cfg.Version,
		mux:        http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler {
	return s.securityHeaders(s.recoverer(s.logRequests(s.mux)))
}

func (s *Server) routes() {
	staticFS, err := fs.Sub(content, "static")
	if err != nil {
		panic(err)
	}
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	s.mux.HandleFunc("GET /login", s.loginGet)
	s.mux.HandleFunc("POST /login", s.loginPost)

	s.mux.HandleFunc("POST /logout", s.requireAuth(s.logout))

	s.mux.HandleFunc("GET /{$}", s.requireAuth(s.dashboard))
	s.mux.HandleFunc("GET /upstreams", s.requireAuth(s.upstreamsList))
	s.mux.HandleFunc("GET /upstreams/new", s.requireAuth(s.upstreamNew))
	s.mux.HandleFunc("POST /upstreams", s.requireAuth(s.upstreamSave))
	s.mux.HandleFunc("GET /upstreams/{id}/edit", s.requireAuth(s.upstreamEdit))
	s.mux.HandleFunc("POST /upstreams/{id}", s.requireAuth(s.upstreamSave))
	s.mux.HandleFunc("POST /upstreams/{id}/delete", s.requireAuth(s.upstreamDelete))
	s.mux.HandleFunc("POST /upstreams/{id}/test", s.requireAuth(s.upstreamTest))

	s.mux.HandleFunc("GET /rules", s.requireAuth(s.rulesList))
	s.mux.HandleFunc("GET /rules/new", s.requireAuth(s.ruleNew))
	s.mux.HandleFunc("POST /rules", s.requireAuth(s.ruleSave))
	s.mux.HandleFunc("GET /rules/{id}/edit", s.requireAuth(s.ruleEdit))
	s.mux.HandleFunc("POST /rules/{id}", s.requireAuth(s.ruleSave))
	s.mux.HandleFunc("POST /rules/{id}/delete", s.requireAuth(s.ruleDelete))

	s.mux.HandleFunc("GET /leases", s.requireAuth(s.leasesList))
	s.mux.HandleFunc("POST /leases/{id}/delete", s.requireAuth(s.leaseDelete))

	s.mux.HandleFunc("GET /settings", s.requireAuth(s.settingsGet))
	s.mux.HandleFunc("POST /settings", s.requireAuth(s.settingsSave))

	s.mux.HandleFunc("GET /audit", s.requireAuth(s.auditList))
	s.mux.HandleFunc("GET /account", s.requireAuth(s.accountGet))
	s.mux.HandleFunc("POST /account", s.requireAuth(s.accountSave))
	s.mux.HandleFunc("GET /logs/stream", s.requireAuth(s.logStream))

	if s.dnsHandler != nil {
		s.mux.Handle("GET /dns-query", s.dnsHandler)
		s.mux.Handle("POST /dns-query", s.dnsHandler)
	}

	s.mux.HandleFunc("GET /api/health", s.apiHealth)
	s.mux.HandleFunc("GET /api/upstreams", s.requireAPI(s.apiUpstreamsGet))
	s.mux.HandleFunc("POST /api/upstreams", s.requireAPI(s.apiUpstreamsPost))
	s.mux.HandleFunc("GET /api/upstreams/{id}", s.requireAPI(s.apiUpstreamGet))
	s.mux.HandleFunc("PUT /api/upstreams/{id}", s.requireAPI(s.apiUpstreamPut))
	s.mux.HandleFunc("DELETE /api/upstreams/{id}", s.requireAPI(s.apiUpstreamDelete))
	s.mux.HandleFunc("POST /api/upstreams/{id}/test", s.requireAPI(s.apiUpstreamTest))
	s.mux.HandleFunc("GET /api/rules", s.requireAPI(s.apiRulesGet))
	s.mux.HandleFunc("POST /api/rules", s.requireAPI(s.apiRulesPost))
	s.mux.HandleFunc("DELETE /api/rules/{id}", s.requireAPI(s.apiRuleDelete))
	s.mux.HandleFunc("GET /api/leases", s.requireAPI(s.apiLeasesGet))
	s.mux.HandleFunc("DELETE /api/leases/{id}", s.requireAPI(s.apiLeaseDelete))
	s.mux.HandleFunc("GET /api/settings", s.requireAPI(s.apiSettingsGet))
	s.mux.HandleFunc("PUT /api/settings", s.requireAPI(s.apiSettingsPut))
}

type pageData struct {
	Title   string
	Active  string
	Admin   string
	CSRF    string
	Msg     string
	Err     string
	Version string
	Data    any
}

type sessionInfo struct {
	Token string
	Admin model.Admin
}

type ctxKey int

const sessionCtxKey ctxKey = 1

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, ok := s.authenticate(r)
		if !ok {
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch || r.Method == http.MethodDelete {
			if !s.validCSRF(r, info.Token) {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		ctx := context.WithValue(r.Context(), sessionCtxKey, info)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) session(r *http.Request) (sessionInfo, bool) {
	v := r.Context().Value(sessionCtxKey)
	info, ok := v.(sessionInfo)
	return info, ok
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name, title, active string, data any) {
	info, _ := s.session(r)
	csrf := ""
	if info.Token != "" {
		csrf = s.csrfToken(info.Token)
	}
	pd := pageData{
		Title:   title,
		Active:  active,
		Admin:   info.Admin.Username,
		CSRF:    csrf,
		Msg:     r.URL.Query().Get("msg"),
		Err:     r.URL.Query().Get("err"),
		Version: s.version,
		Data:    data,
	}
	var tmpl *template.Template
	if v, ok := s.tmpl.Load(name); ok {
		tmpl = v.(*template.Template)
	} else {
		var err error
		if name == "login.html" {
			tmpl, err = template.New(name).Funcs(s.funcs()).ParseFS(content, "templates/"+name)
		} else {
			tmpl, err = template.New("layout").Funcs(s.funcs()).ParseFS(content, "templates/layout.html", "templates/"+name)
		}
		if err != nil {
			s.log.Error("parse template failed", "template", name, "error", err)
			http.Error(w, "template error", http.StatusInternalServerError)
			return
		}
		s.tmpl.Store(name, tmpl)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var err error
	if name == "login.html" {
		err = tmpl.ExecuteTemplate(w, "login.html", data)
	} else {
		err = tmpl.ExecuteTemplate(w, "layout", pd)
	}
	if err != nil {
		s.log.Error("render template failed", "template", name, "error", err)
	}
}

func (s *Server) funcs() template.FuncMap {
	return template.FuncMap{
		"fmtTime": func(t time.Time) string {
			if t.IsZero() || t.Unix() <= 0 {
				return "-"
			}
			return t.Local().Format("2006-01-02 15:04:05")
		},
		"remaining": func(t time.Time) string {
			d := time.Until(t)
			if d <= 0 {
				return "expired"
			}
			if d > 48*time.Hour {
				return d.Round(time.Hour).String()
			}
			return d.Round(time.Minute).String()
		},
		"statusClass": func(status string) string {
			switch status {
			case model.HealthUp:
				return "badge ok"
			case model.HealthDown:
				return "badge bad"
			default:
				return "badge"
			}
		},
		"join": strings.Join,
		"inc":  func(i int) int { return i + 1 },
		"yesno": func(b bool) string {
			if b {
				return "yes"
			}
			return "no"
		},
		"actionLabel": func(a string) string {
			switch a {
			case model.ActionProxy:
				return "Proxy"
			case model.ActionBlock:
				return "Block"
			default:
				return "Direct"
			}
		},
		"typeLabel": func(t string) string {
			switch t {
			case model.UpstreamWireGuard:
				return "WireGuard"
			case model.UpstreamHTTP:
				return "HTTP CONNECT"
			default:
				return "SOCKS5"
			}
		},
	}
}

func (s *Server) csrfToken(sessionToken string) string {
	mac := hmac.New(sha256.New, s.masterKey)
	_, _ = mac.Write([]byte("csrf:" + sessionToken))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) validCSRF(r *http.Request, sessionToken string) bool {
	got := r.Header.Get("X-CSRF-Token")
	if got == "" {
		got = r.FormValue("csrf")
	}
	want := s.csrfToken(sessionToken)
	return hmac.Equal([]byte(got), []byte(want))
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				s.log.Error("panic in http handler", "panic", v, "path", r.URL.Path)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		if strings.HasPrefix(r.URL.Path, "/static/") {
			return
		}
		s.log.Debug("http request", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
	})
}

func templateParse(fsys fs.FS, name string, funcs template.FuncMap) (*template.Template, error) {
	return template.New(name).Funcs(funcs).ParseFS(fsys, "templates/"+name)
}

func redirectMsg(w http.ResponseWriter, r *http.Request, path, msg, errMsg string) {
	q := url.Values{}
	if msg != "" {
		q.Set("msg", msg)
	}
	if errMsg != "" {
		q.Set("err", errMsg)
	}
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

func formBool(r *http.Request, name string) bool {
	v := strings.ToLower(r.FormValue(name))
	return v == "on" || v == "1" || v == "true" || v == "yes"
}

func atoiDefault(raw string, def int) int {
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(raw), "%d", &n); err != nil {
		return def
	}
	return n
}
