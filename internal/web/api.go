package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"idips/internal/model"
)

func (s *Server) actor(r *http.Request) string {
	if info, ok := s.session(r); ok {
		return info.Admin.Username
	}
	return "api"
}

func (s *Server) apiHealth(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	code := http.StatusOK
	if err := s.store.Ping(r.Context()); err != nil {
		status = "degraded"
		code = http.StatusServiceUnavailable
	}
	leases, _ := s.store.CountLeases(true)
	upstreams, _ := s.store.ListUpstreams()
	up := 0
	for _, u := range upstreams {
		if u.Health == model.HealthUp {
			up++
		}
	}
	writeJSON(w, code, map[string]any{
		"status":        status,
		"version":       s.version,
		"time":          time.Now(),
		"upstreams":     len(upstreams),
		"upstreams_up":  up,
		"active_leases": leases,
		"pool":          s.alloc.Stats(),
	})
}

func (s *Server) apiUpstreamsGet(w http.ResponseWriter, r *http.Request) {
	upstreams, err := s.store.ListUpstreams()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, upstreams)
}

func (s *Server) apiUpstreamGet(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	u, err := s.store.GetUpstream(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, u)
}

type apiUpstreamInput struct {
	Name          string  `json:"name"`
	Type          string  `json:"type"`
	Address       string  `json:"address"`
	Username      *string `json:"username"`
	Password      string  `json:"password"`
	ClearPassword bool    `json:"clear_password"`
	WGConfig      string  `json:"wg_config"`
	Enabled       *bool   `json:"enabled"`
	Priority      *int    `json:"priority"`
}

func (in apiUpstreamInput) apply(u model.Upstream) model.Upstream {
	if in.Name != "" {
		u.Name = strings.TrimSpace(in.Name)
	}
	if in.Type != "" {
		u.Type = strings.TrimSpace(in.Type)
	}
	if in.Address != "" {
		u.Address = strings.TrimSpace(in.Address)
	}
	if in.Username != nil {
		u.Username = *in.Username
	}
	u.Password = in.Password
	u.ClearPassword = in.ClearPassword
	if in.WGConfig != "" {
		u.WGConfig = in.WGConfig
	}
	if in.Enabled != nil {
		u.Enabled = *in.Enabled
	}
	if in.Priority != nil {
		u.Priority = *in.Priority
	}
	return u
}

func (s *Server) apiUpstreamsPost(w http.ResponseWriter, r *http.Request) {
	var in apiUpstreamInput
	if err := decodeJSON(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	u := in.apply(model.Upstream{Enabled: true})
	if err := validateUpstream(u); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	id, err := s.store.CreateUpstream(u)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	_ = s.store.AddAudit(s.actor(r), "api_upstream_create", u.Name)
	created, err := s.store.GetUpstream(id)
	if err != nil {
		created = u
		created.ID = id
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) apiUpstreamPut(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	existing, err := s.store.GetUpstream(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	var in apiUpstreamInput
	if err := decodeJSON(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	u := in.apply(existing)
	if err := validateUpstream(u); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := s.store.UpdateUpstream(u); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	_ = s.store.AddAudit(s.actor(r), "api_upstream_update", u.Name)
	updated, err := s.store.GetUpstream(id)
	if err != nil {
		updated = u
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) apiUpstreamDelete(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	if err := s.store.DeleteUpstream(id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	_ = s.store.AddAudit(s.actor(r), "api_upstream_delete", strconv.FormatInt(id, 10))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiUpstreamTest(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	start := time.Now()
	_, testErr := s.manager.Test(ctx, id)
	resp := map[string]any{"id": id, "duration_ms": time.Since(start).Milliseconds(), "ok": testErr == nil}
	if testErr != nil {
		resp["error"] = testErr.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) apiRulesGet(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListRules()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) apiRulesPost(w http.ResponseWriter, r *http.Request) {
	var rule model.Rule
	if err := decodeJSON(r, &rule); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	rule.ID = 0
	if err := validateRule(s.store, rule); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	id, err := s.store.CreateRule(rule)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	rule.ID = id
	_ = s.store.AddAudit(s.actor(r), "api_rule_create", rule.Name)
	if created, err := s.store.GetRule(id); err == nil {
		rule = created
	}
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) apiRuleDelete(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	if err := s.store.DeleteRule(id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	_ = s.store.AddAudit(s.actor(r), "api_rule_delete", strconv.FormatInt(id, 10))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiLeasesGet(w http.ResponseWriter, r *http.Request) {
	search := strings.TrimSpace(r.URL.Query().Get("q"))
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	leases, err := s.store.ListLeases(limit, 0, search)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, leases)
}

func (s *Server) apiLeaseDelete(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	if err := s.alloc.Delete(id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	_ = s.store.AddAudit(s.actor(r), "api_lease_revoke", strconv.FormatInt(id, 10))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiSettingsGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.settings())
}

func (s *Server) apiSettingsPut(w http.ResponseWriter, r *http.Request) {
	cfg := s.settings()
	if err := decodeJSON(r, &cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := validateSettings(s.store, cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := s.store.SaveSettings(cfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if s.reload != nil {
		s.reload()
	}
	_ = s.store.AddAudit(s.actor(r), "api_settings_update", "")
	writeJSON(w, http.StatusOK, s.settings())
}

func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 2<<20))
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}
