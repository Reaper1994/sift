package main

import (
	"testing"
	"time"

	"github.com/Reaper1994/sift/internal/triage"
)

func TestAuthBackoffDoublesToCap(t *testing.T) {
	var got []time.Duration
	var w time.Duration
	for range 8 {
		w = authBackoff(w, 5*time.Second)
		got = append(got, w)
	}
	want := []time.Duration{1, 2, 4, 8, 16, 30, 30, 30}
	for i := range want {
		if got[i] != want[i]*time.Minute {
			t.Fatalf("step %d: got %v, want %v (all: %v)", i, got[i], want[i]*time.Minute, got)
		}
	}
}

func TestAuthBackoffNeverShorterThanPoll(t *testing.T) {
	if w := authBackoff(0, time.Hour); w != time.Hour {
		t.Fatalf("got %v, want 1h", w)
	}
	if w := authBackoff(time.Hour, time.Hour); w != time.Hour {
		t.Fatalf("got %v, want 1h", w)
	}
}

func TestAuthStalled(t *testing.T) {
	for _, tc := range []struct {
		name string
		st   triage.Stats
		want bool
	}{
		{"all mailboxes rejected", triage.Stats{Failed: 2, AuthFailed: 2}, true},
		{"healthy", triage.Stats{Seen: 3, Tagged: 3}, false},
		{"one mailbox still works", triage.Stats{Seen: 1, Failed: 1, AuthFailed: 1}, false},
		{"other failures too", triage.Stats{Failed: 2, AuthFailed: 1}, false},
		{"transient failure only", triage.Stats{Failed: 1}, false},
	} {
		if got := authStalled(tc.st); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
