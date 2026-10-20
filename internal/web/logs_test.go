package web

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"idips/internal/logstream"
)

func TestLogStreamSendsHistoryAndLiveLines(t *testing.T) {
	hub := logstream.New(10)
	_, _ = hub.Write([]byte("history line\n"))

	s := &Server{logs: hub}
	srv := httptest.NewServer(http.HandlerFunc(s.logStream))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	reader := bufio.NewReader(resp.Body)
	found := func(want string) {
		t.Helper()
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("reading stream: %v", err)
			}
			if strings.Contains(line, want) {
				return
			}
		}
	}

	found("data: history line")
	_, _ = hub.Write([]byte("live line\n"))
	found("data: live line")
}

func TestLogStreamUnavailableWithoutHub(t *testing.T) {
	s := &Server{}
	rr := httptest.NewRecorder()
	s.logStream(rr, httptest.NewRequest(http.MethodGet, "/logs/stream", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
}
