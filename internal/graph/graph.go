// Package graph is a minimal, dependency-free Microsoft Graph client covering
// only what triage needs: app-only token, list recent inbox mail, read a
// message body, and set categories/flag. Nothing is cached to disk.
package graph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Reaper1994/sift/internal/httpx"
)

const (
	defaultGraph = "https://graph.microsoft.com/v1.0"
	defaultLogin = "https://login.microsoftonline.com"

	maxAttempts   = 4
	maxRetryAfter = 30 * time.Second
)

type Client struct {
	tenant, clientID, secret string
	GraphBase, LoginBase     string
	HTTP                     *http.Client

	retryDelay time.Duration // first wait after a throttled request; doubles each attempt

	mu      sync.Mutex
	token   string
	expires time.Time
}

func New(tenant, clientID, secret string) *Client {
	return &Client{
		tenant: tenant, clientID: clientID, secret: secret,
		GraphBase: defaultGraph, LoginBase: defaultLogin,
		HTTP: httpx.NewClient(30 * time.Second), retryDelay: 500 * time.Millisecond,
	}
}

type Message struct {
	ID               string    `json:"id"`
	Subject          string    `json:"subject"`
	BodyPreview      string    `json:"bodyPreview"`
	Importance       string    `json:"importance"`
	ReceivedDateTime time.Time `json:"receivedDateTime"`
	Categories       []string  `json:"categories"`
	From             struct {
		EmailAddress struct {
			Name    string `json:"name"`
			Address string `json:"address"`
		} `json:"emailAddress"`
	} `json:"from"`
	Body struct {
		Content string `json:"content"`
	} `json:"body"`
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Until(c.expires) > 2*time.Minute {
		return c.token, nil
	}
	form := url.Values{
		"client_id":     {c.clientID},
		"client_secret": {c.secret},
		"scope":         {"https://graph.microsoft.com/.default"},
		"grant_type":    {"client_credentials"},
	}
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", c.LoginBase, url.PathEscape(c.tenant))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer httpx.Close(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed: %s", resp.Status) // body omitted: may echo client details
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", err
	}
	c.token, c.expires = tr.AccessToken, time.Now().Add(time.Duration(tr.ExpiresIn)*time.Second)
	return c.token, nil
}

// do sends a request, retrying when Graph throttles (429) or is briefly
// unavailable (503/504). Every request Sift makes is safe to repeat: reads, a
// category PATCH that sets a fixed value, and an idempotent category create.
func (c *Client) do(ctx context.Context, method, path string, body any, headers map[string]string, out any) error {
	tok, err := c.accessToken(ctx)
	if err != nil {
		return err
	}
	var payload []byte
	if body != nil {
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	delay := c.retryDelay
	if delay <= 0 { // zero-value Client: rand.N panics on a non-positive argument
		delay = 500 * time.Millisecond
	}
	for attempt := 1; ; attempt++ {
		wait, err := c.send(ctx, method, path, tok, payload, headers, out)
		if wait < 0 || attempt == maxAttempts {
			return err
		}
		if wait == 0 {
			wait = delay + rand.N(delay) // jitter so parallel workers don't retry together
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		delay *= 2
	}
}

// send makes one attempt. A negative wait means the result is final; zero
// means retry after the default backoff; positive is the server's Retry-After.
func (c *Client) send(ctx context.Context, method, path, tok string, payload []byte, headers map[string]string, out any) (wait time.Duration, err error) {
	var rdr io.Reader
	if payload != nil {
		rdr = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.GraphBase+path, rdr)
	if err != nil {
		return -1, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) { // its text holds the full URL: mailbox and message ID
			err = ue.Err
		}
		return -1, fmt.Errorf("graph %s %s: %w", method, redactPath(path), err)
	}
	defer httpx.Close(resp.Body)
	if resp.StatusCode >= 300 {
		var ge struct {
			Error struct{ Code string } `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&ge)
		err := fmt.Errorf("graph %s %s: %s %s", method, redactPath(path), resp.Status, ge.Error.Code)
		switch resp.StatusCode {
		case http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return retryAfter(resp.Header.Get("Retry-After")), err
		}
		return -1, err
	}
	if out != nil {
		return -1, json.NewDecoder(resp.Body).Decode(out)
	}
	return -1, nil
}

// retryAfter parses a Retry-After value in seconds, capped at maxRetryAfter.
// It returns 0 when absent or unusable, so the caller uses its own backoff.
func retryAfter(v string) time.Duration {
	secs, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || secs <= 0 {
		return 0
	}
	return min(time.Duration(secs)*time.Second, maxRetryAfter)
}

// ListRecentInbox returns inbox messages received since `since`, newest first.
func (c *Client) ListRecentInbox(ctx context.Context, mailbox string, since time.Time, max int) ([]Message, error) {
	q := url.Values{
		"$select":  {"id,subject,from,bodyPreview,importance,receivedDateTime,categories"},
		"$filter":  {"receivedDateTime ge " + since.UTC().Format(time.RFC3339)},
		"$orderby": {"receivedDateTime desc"},
		"$top":     {fmt.Sprint(min(max, 100))},
	}
	path := fmt.Sprintf("/users/%s/mailFolders/inbox/messages?%s", url.PathEscape(mailbox), q.Encode())
	var res struct {
		Value []Message `json:"value"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, nil, &res); err != nil {
		return nil, err
	}
	return res.Value, nil
}

// GetBodyText fetches the plain-text body of a message.
func (c *Client) GetBodyText(ctx context.Context, mailbox, id string) (string, error) {
	path := fmt.Sprintf("/users/%s/messages/%s?$select=body", url.PathEscape(mailbox), url.PathEscape(id))
	var m Message
	err := c.do(ctx, http.MethodGet, path, nil, map[string]string{"Prefer": `outlook.body-content-type="text"`}, &m)
	return m.Body.Content, err
}

// Tag sets the message's categories and optionally flags it for follow-up.
// It never moves, deletes, forwards or replies to mail.
func (c *Client) Tag(ctx context.Context, mailbox, id string, categories []string, flag bool) error {
	patch := map[string]any{"categories": categories}
	if flag {
		patch["flag"] = map[string]string{"flagStatus": "flagged"}
	}
	path := fmt.Sprintf("/users/%s/messages/%s", url.PathEscape(mailbox), url.PathEscape(id))
	return c.do(ctx, http.MethodPatch, path, patch, nil, nil)
}

// EnsureCategory creates a coloured master category if missing (best effort;
// needs MailboxSettings.ReadWrite — categories still work without it).
func (c *Client) EnsureCategory(ctx context.Context, mailbox, name, color string) error {
	path := fmt.Sprintf("/users/%s/outlook/masterCategories", url.PathEscape(mailbox))
	var res struct {
		Value []struct{ DisplayName string } `json:"value"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, nil, &res); err != nil {
		return err
	}
	for _, v := range res.Value {
		if strings.EqualFold(v.DisplayName, name) {
			return nil
		}
	}
	return c.do(ctx, http.MethodPost, path, map[string]string{"displayName": name, "color": color}, nil, nil)
}

// redactPath strips mailbox and message identifiers from error messages so
// logs don't accumulate who-emailed-whom metadata.
func redactPath(p string) string {
	parts := strings.Split(strings.SplitN(p, "?", 2)[0], "/")
	for i := range parts {
		if i > 0 && (parts[i-1] == "users" || parts[i-1] == "messages") {
			parts[i] = "…"
		}
	}
	return strings.Join(parts, "/")
}
