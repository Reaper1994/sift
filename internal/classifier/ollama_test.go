package classifier

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// redirectingServer answers every request with a redirect to a second server
// and reports whether that second server was ever reached.
func redirectingServer(t *testing.T) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	t.Cleanup(target.Close)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestOllamaPrivateOnlyDialControl(t *testing.T) {
	for _, tc := range []struct {
		addr        string
		allowRemote bool
		ok          bool
	}{
		{"127.0.0.1:11434", false, true},
		{"10.1.2.3:11434", false, true},
		{"[::1]:11434", false, true},
		{"8.8.8.8:11434", false, false},
		{"[2001:4860:4860::8888]:11434", false, false},
		{"8.8.8.8:11434", true, true},
	} {
		err := privateOnly(tc.allowRemote)("tcp", tc.addr, nil)
		if (err == nil) != tc.ok {
			t.Errorf("addr=%s allowRemote=%t: err=%v", tc.addr, tc.allowRemote, err)
		}
	}
}

func TestOllamaRefusesPublicIP(t *testing.T) {
	// The dialer's Control func runs before connect, so nothing is sent.
	o := NewOllama("http://8.8.8.8:9", "m", false)
	_, err := o.Classify(context.Background(), Email{})
	if err == nil || !strings.Contains(err.Error(), "refusing to connect to public address") {
		t.Fatalf("expected refusal, got %v", err)
	}
}

func TestOllamaClassifiesOnLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"message":{"content":"{\"label\":\"fyi\",\"reason\":\"status\"}"}}`))
	}))
	t.Cleanup(srv.Close)
	r, err := NewOllama(srv.URL, "m", false).Classify(context.Background(), Email{})
	if err != nil || r.Label != FYI {
		t.Fatalf("r=%+v err=%v", r, err)
	}
}

func TestOllamaDoesNotFollowRedirects(t *testing.T) {
	srv, hits := redirectingServer(t)
	_, err := NewOllama(srv.URL, "m", false).Classify(context.Background(), Email{})
	if err == nil || *hits != 0 {
		t.Fatalf("redirect followed: err=%v hits=%d", err, *hits)
	}
}

func TestJevDoesNotFollowRedirects(t *testing.T) {
	srv, hits := redirectingServer(t)
	j := NewJev(srv.URL, "k", "m")
	j.MaxRetries = 0
	_, err := j.Classify(context.Background(), Email{})
	if err == nil || *hits != 0 {
		t.Fatalf("redirect followed: err=%v hits=%d", err, *hits)
	}
}
