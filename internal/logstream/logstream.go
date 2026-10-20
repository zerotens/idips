package logstream

import (
	"strings"
	"sync"
)

const defaultBuffer = 500

type Hub struct {
	mu    sync.Mutex
	max   int
	lines []string
	subs  map[chan string]struct{}
}

func New(maxLines int) *Hub {
	if maxLines <= 0 {
		maxLines = defaultBuffer
	}
	return &Hub{
		max:  maxLines,
		subs: make(map[chan string]struct{}),
	}
}

func (h *Hub) Write(p []byte) (int, error) {
	text := strings.TrimRight(string(p), "\r\n")
	if text == "" {
		return len(p), nil
	}
	h.mu.Lock()
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		h.lines = append(h.lines, line)
		if len(h.lines) > h.max {
			h.lines = h.lines[len(h.lines)-h.max:]
		}
		for ch := range h.subs {
			select {
			case ch <- line:
			default:
			}
		}
	}
	h.mu.Unlock()
	return len(p), nil
}

func (h *Hub) Subscribe() (<-chan string, func()) {
	h.mu.Lock()
	ch := make(chan string, len(h.lines)+128)
	for _, line := range h.lines {
		ch <- line
	}
	h.subs[ch] = struct{}{}
	h.mu.Unlock()

	unsubscribe := func() {
		h.mu.Lock()
		if _, ok := h.subs[ch]; ok {
			delete(h.subs, ch)
			close(ch)
		}
		h.mu.Unlock()
	}
	return ch, unsubscribe
}

func (h *Hub) History() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, len(h.lines))
	copy(out, h.lines)
	return out
}
