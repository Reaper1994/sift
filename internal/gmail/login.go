package gmail

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Login runs Google's desktop sign-in: it prints a URL, waits for the browser
// to come back to a one-time server on 127.0.0.1, and returns a refresh token.
func (c *Client) Login(ctx context.Context, out io.Writer) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	redirect := fmt.Sprintf("http://127.0.0.1:%d/", ln.Addr().(*net.TCPAddr).Port)
	state, verifier := randomString(), randomString()
	challenge := sha256.Sum256([]byte(verifier))

	type result struct {
		code string
		err  error
	}
	done := make(chan result, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		res := result{code: q.Get("code")}
		if res.code == "" {
			res.err = fmt.Errorf("google sign-in failed: %s", q.Get("error"))
			fmt.Fprintln(w, "Sign-in failed. You can close this tab.")
		} else {
			fmt.Fprintln(w, "Signed in. You can close this tab and go back to Sift.")
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush() // the server closes as soon as Login returns
		}
		select {
		case done <- res:
		default:
		}
	})}
	go srv.Serve(ln) //nolint:errcheck // Serve always returns an error on Close
	defer srv.Close()

	auth := url.Values{
		"client_id":             {c.clientID},
		"redirect_uri":          {redirect},
		"response_type":         {"code"},
		"scope":                 {Scope},
		"access_type":           {"offline"},
		"prompt":                {"consent"}, // Google only returns a refresh token on consent
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}
	fmt.Fprintf(out, "Open this link in a browser on this computer and sign in to Gmail:\n\n%s?%s\n\n", c.AuthURL, auth.Encode())

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	var res result
	select {
	case res = <-done:
	case <-ctx.Done():
		return "", errors.New("timed out waiting for the browser sign-in")
	}
	if res.err != nil {
		return "", res.err
	}

	tr, err := c.tokenRequest(ctx, url.Values{
		"client_id":     {c.clientID},
		"client_secret": {c.secret},
		"code":          {res.code},
		"code_verifier": {verifier},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {redirect},
	})
	if err != nil {
		return "", err
	}
	if tr.RefreshToken == "" {
		return "", errors.New("google did not return a refresh token; run `sift gmail-login` again")
	}
	return tr.RefreshToken, nil
}

func randomString() string {
	b := make([]byte, 32)
	rand.Read(b) //nolint:errcheck // crypto/rand.Read never fails
	return base64.RawURLEncoding.EncodeToString(b)
}
