// Package httpx holds the HTTP plumbing shared by the Graph, Gmail and
// classifier clients: one tuned transport and a body-closing helper that keeps
// connections reusable.
package httpx

import (
	"io"
	"net/http"
	"time"
)

// transport is shared by every client. The default transport keeps only two
// idle connections per host, so a run with SIFT_CONCURRENCY=8 would re-dial
// (and re-handshake TLS) for most requests.
var transport = func() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 64
	t.MaxIdleConnsPerHost = 16 // SIFT_CONCURRENCY is capped at 16
	t.ForceAttemptHTTP2 = true
	return t
}()

// NewClient returns a client with the given per-request timeout that reuses
// the shared transport.
func NewClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: transport}
}

// drainLimit bounds how much unread body is discarded to save a connection.
const drainLimit = 64 << 10

// Close drains a little of what is left of a response body, then closes it.
// A body that is not read to EOF cannot be reused by the transport, and a JSON
// decoder usually stops before the trailing newline.
func Close(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, drainLimit))
	_ = body.Close()
}
