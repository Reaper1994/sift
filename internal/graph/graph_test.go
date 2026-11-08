package graph

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Reaper1994/sift/internal/httpx"
)

func TestTokenCachingListAndTag(t *testing.T) {
	tokenCalls := 0
	var patched map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			tokenCalls++
			_ = r.ParseForm()
			if r.Form.Get("grant_type") != "client_credentials" {
				t.Errorf("wrong grant")
			}
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/mailFolders/inbox/messages"):
			if r.Header.Get("Authorization") != "Bearer tok" {
				t.Errorf("no bearer")
			}
			if !strings.Contains(r.URL.Query().Get("$filter"), "receivedDateTime ge") {
				t.Errorf("filter missing")
			}
			_, _ = w.Write([]byte(`{"value":[{"id":"m1","subject":"s","categories":[]}]}`))
		case r.Method == http.MethodPatch:
			_ = json.NewDecoder(r.Body).Decode(&patched)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := New("tenant", "id", "secret")
	c.GraphBase, c.LoginBase = srv.URL, srv.URL
	ctx := context.Background()

	msgs, err := c.ListRecentInbox(ctx, "a@x.com", time.Now().Add(-time.Hour), 10)
	if err != nil || len(msgs) != 1 || msgs[0].ID != "m1" {
		t.Fatalf("%v %v", msgs, err)
	}
	if err := c.Tag(ctx, "a@x.com", "m1", []string{"Sift: FYI"}, true); err != nil {
		t.Fatal(err)
	}
	if tokenCalls != 1 {
		t.Errorf("token not cached: %d calls", tokenCalls)
	}
	if patched["flag"] == nil || patched["categories"].([]any)[0] != "Sift: FYI" {
		t.Errorf("bad patch %v", patched)
	}
}

func TestErrorsRedactIdentifiers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"ErrorAccessDenied"}}`))
	}))
	defer srv.Close()
	c := New("t", "i", "s")
	c.GraphBase, c.LoginBase = srv.URL, srv.URL
	err := c.Tag(context.Background(), "ceo@example.com", "AAMkSECRET", nil, false)
	if err == nil || strings.Contains(err.Error(), "ceo@") || strings.Contains(err.Error(), "AAMkSECRET") {
		t.Fatalf("identifiers leaked into error: %v", err)
	}
	if !strings.Contains(err.Error(), "ErrorAccessDenied") {
		t.Errorf("lost error code: %v", err)
	}
}

func TestNetworkErrorsHideIdentifiers(t *testing.T) {
	c := New("t", "c", "s")
	c.token, c.expires = "tok", time.Now().Add(time.Hour)
	c.GraphBase = "http://127.0.0.1:1" // nothing listens here
	_, err := c.GetBodyText(context.Background(), "me@example.com", "msg-id")
	if err == nil {
		t.Fatal("expected a connection error")
	}
	for _, leak := range []string{"example.com", "msg-id"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("leaked %q: %v", leak, err)
		}
	}
}

func TestThrottledRequestsRetryAndHonourRetryAfter(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
			return
		}
		hits++
		switch hits {
		case 1:
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
		case 2:
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			_, _ = w.Write([]byte(`{"value":[]}`))
		}
	}))
	defer srv.Close()
	c := New("t", "id", "secret")
	c.GraphBase, c.LoginBase, c.retryDelay = srv.URL, srv.URL, time.Millisecond

	start := time.Now()
	if _, err := c.ListRecentInbox(context.Background(), "me@x.com", time.Now(), 10); err != nil {
		t.Fatal(err)
	}
	if hits != 3 {
		t.Fatalf("hits = %d, want 3", hits)
	}
	if time.Since(start) < time.Second {
		t.Errorf("did not wait for Retry-After: %v", time.Since(start))
	}
}

func TestClientErrorsAreNotRetried(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
			return
		}
		hits++
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	c := New("t", "id", "secret")
	c.GraphBase, c.LoginBase = srv.URL, srv.URL
	if _, err := c.ListRecentInbox(context.Background(), "me@x.com", time.Now(), 10); err == nil || hits != 1 {
		t.Fatalf("err=%v hits=%d", err, hits)
	}
}

func TestRetryAfterParsing(t *testing.T) {
	for in, want := range map[string]time.Duration{"": 0, "x": 0, "-3": 0, "5": 5 * time.Second, "9999": maxRetryAfter} {
		if got := retryAfter(in); got != want {
			t.Errorf("retryAfter(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestRejectedClientSecretIsAuthError(t *testing.T) {
	for _, tc := range []struct {
		status int
		auth   bool
	}{{http.StatusUnauthorized, true}, {http.StatusBadRequest, true}, {http.StatusInternalServerError, false}} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
		}))
		c := New("tenant", "id", "secret")
		c.LoginBase, c.GraphBase = srv.URL, srv.URL
		_, err := c.ListRecentInbox(context.Background(), "a@b.c", time.Now(), 10)
		srv.Close()
		if err == nil || errors.Is(err, httpx.ErrAuth) != tc.auth {
			t.Errorf("status %d: got %v, want ErrAuth=%v", tc.status, err, tc.auth)
		}
	}
}
