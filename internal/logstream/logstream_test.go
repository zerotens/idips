package logstream

import (
	"reflect"
	"testing"
)

func TestHubHistoryAndSubscription(t *testing.T) {
	h := New(3)
	_, _ = h.Write([]byte("one\n"))
	_, _ = h.Write([]byte("two\nthree\n"))

	ch, cancel := h.Subscribe()
	defer cancel()

	var got []string
	for i := 0; i < 3; i++ {
		got = append(got, <-ch)
	}
	if want := []string{"one", "two", "three"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("history = %v, want %v", got, want)
	}

	_, _ = h.Write([]byte("four\n"))
	if line := <-ch; line != "four" {
		t.Fatalf("live line = %q, want four", line)
	}
}

func TestHubKeepsLimitedHistory(t *testing.T) {
	h := New(2)
	_, _ = h.Write([]byte("a\nb\nc\n"))
	if got, want := h.History(), []string{"b", "c"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("history = %v, want %v", got, want)
	}
}

func TestHubUnsubscribeClosesChannel(t *testing.T) {
	h := New(1)
	ch, cancel := h.Subscribe()
	cancel()
	if _, ok := <-ch; ok {
		t.Fatal("expected closed channel")
	}
}

func TestHubIgnoresEmptyWrites(t *testing.T) {
	h := New(5)
	_, _ = h.Write([]byte("\n\r\n"))
	if got := h.History(); len(got) != 0 {
		t.Fatalf("history = %v, want empty", got)
	}
}
