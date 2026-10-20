package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"idips/internal/model"
)

type loginData struct {
	Next  string
	Error string
}

func (s *Server) loginGet(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authenticate(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, "login.html", "Login", "", loginData{Next: r.URL.Query().Get("next")})
}

func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	next := safeNext(r.FormValue("next"))
	admin, err := s.store.GetAdminByUsername(username)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password)) != nil {
		_ = s.store.AddAudit(username, "login_failed", r.RemoteAddr)
		s.render(w, r, "login.html", "Login", "", loginData{Next: next, Error: "Invalid username or password"})
		return
	}

	token, err := newSessionToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	hash := sha256.Sum256([]byte(token))
	_ = s.store.DeleteExpiredSessions(time.Now())
	if err := s.store.CreateSession(hex.EncodeToString(hash[:]), admin.ID, time.Now().Add(12*time.Hour)); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "idips_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
		MaxAge:   int((12 * time.Hour).Seconds()),
	})
	_ = s.store.AddAudit(admin.Username, "login", r.RemoteAddr)
	if next == "" {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	info, ok := s.session(r)
	if ok {
		hash := sha256.Sum256([]byte(info.Token))
		_ = s.store.DeleteSession(hex.EncodeToString(hash[:]))
		_ = s.store.AddAudit(info.Admin.Username, "logout", "")
	}
	http.SetCookie(w, &http.Cookie{Name: "idips_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) authenticate(r *http.Request) (sessionInfo, bool) {
	cookie, err := r.Cookie("idips_session")
	if err != nil || cookie.Value == "" {
		return sessionInfo{}, false
	}
	hash := sha256.Sum256([]byte(cookie.Value))
	adminID, expires, err := s.store.GetSession(hex.EncodeToString(hash[:]))
	if err != nil {
		return sessionInfo{}, false
	}
	if !expires.After(time.Now()) {
		_ = s.store.DeleteSession(hex.EncodeToString(hash[:]))
		return sessionInfo{}, false
	}
	admin, err := s.store.GetAdminByID(adminID)
	if err != nil {
		return sessionInfo{}, false
	}
	return sessionInfo{Token: cookie.Value, Admin: admin}, true
}

func (s *Server) requireAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := s.settings().APIToken
		header := r.Header.Get("Authorization")
		if token != "" && strings.HasPrefix(header, "Bearer ") {
			got := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
			if subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1 {
				info := sessionInfo{Admin: model.Admin{Username: "api"}}
				next(w, r.WithContext(context.WithValue(r.Context(), sessionCtxKey, info)))
				return
			}
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid API token"})
			return
		}
		info, ok := s.authenticate(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			got := r.Header.Get("X-CSRF-Token")
			if got == "" {
				got = r.FormValue("csrf")
			}
			if !validCSRFRaw(s.csrfToken(info.Token), got) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid CSRF token"})
				return
			}
		}
		next(w, r.WithContext(context.WithValue(r.Context(), sessionCtxKey, info)))
	}
}

func validCSRFRaw(want, got string) bool {
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

func newSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func safeNext(next string) string {
	next = strings.TrimSpace(next)
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.Contains(next, "\\") {
		return "/"
	}
	return next
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil && !errors.Is(err, http.ErrHandlerTimeout) {
		_ = err
	}
}
