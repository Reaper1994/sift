package httpx

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A JSON decoder stops before the trailing newline; without draining, every
// request would need a new connection.
func TestCloseKeepsConnectionsReusable(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{\"ok\":true}\n"))
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	c := NewClient(5 * time.Second)
	for range 20 {
		resp, err := c.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		var v struct{ OK bool }
		if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
			t.Fatal(err)
		}
		Close(resp.Body)
	}
	if n := conns.Load(); n != 1 {
		t.Fatalf("opened %d connections for 20 sequential requests, want 1", n)
	}
}
