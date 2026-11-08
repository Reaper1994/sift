// Package gmail is a minimal, dependency-free Gmail API client covering only
// what triage needs: refresh a token, list recent inbox mail, read a message
// body, and add labels and a star. It is the Gmail counterpart of the graph
// package and fills in the same graph.Message. Nothing is cached to disk.
package gmail

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"math/rand/v2"
	"mime"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Reaper1994/sift/internal/classifier"
	"github.com/Reaper1994/sift/internal/graph"
	"github.com/Reaper1994/sift/internal/httpx"
)

const (
	defaultAPI   = "https://gmail.googleapis.com/gmail/v1"
	defaultToken = "https://oauth2.googleapis.com/token"
	defaultAuth  = "https://accounts.google.com/o/oauth2/v2/auth"

	// Scope lets Sift read mail and change labels. Google has no narrower
	// scope that can do both; this client only ever adds labels and stars.
	Scope = "https://www.googleapis.com/auth/gmail.modify"

	// parentLabel groups Sift's labels, e.g. "Sift/Urgent".
	parentLabel = "Sift"

	maxAttempts = 5
	// maxFetches caps parallel fetches: 8 ran cleanly on a real mailbox, 16 failed.
	maxFetches = 8
)

type Client struct {
	clientID, secret, refresh  string
	APIBase, TokenURL, AuthURL string
	HTTP                       *http.Client

	// ExcludeSenders stay out of listings, so they can't fill every pass.
	ExcludeSenders []string
	// Concurrency limits parallel message fetches.
	Concurrency int

	retryDelay time.Duration // first wait after a rate limit; doubles each attempt

	mu      sync.Mutex
	token   string
	expires time.Time

	labelMu sync.Mutex
	labels  map[string]string // Gmail label name → ID
}

func New(clientID, secret, refreshToken string) *Client {
	return &Client{
		clientID: clientID, secret: secret, refresh: refreshToken,
		APIBase: defaultAPI, TokenURL: defaultToken, AuthURL: defaultAuth,
		HTTP: httpx.NewClient(30 * time.Second), Concurrency: 4, retryDelay: 500 * time.Millisecond,
	}
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Until(c.expires) > 2*time.Minute {
		return c.token, nil
	}
	tr, err := c.tokenRequest(ctx, url.Values{
		"client_id":     {c.clientID},
		"client_secret": {c.secret},
		"refresh_token": {c.refresh},
		"grant_type":    {"refresh_token"},
	})
	if err != nil {
		return "", err
	}
	c.token, c.expires = tr.AccessToken, time.Now().Add(time.Duration(tr.ExpiresIn)*time.Second)
	return c.token, nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

func (c *Client) tokenRequest(ctx context.Context, form url.Values) (*tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpx.Close(resp.Body)
	if resp.StatusCode != http.StatusOK {
		var te struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&te) // only the code: the rest may echo client details
		if te.Error == "invalid_grant" {
			return nil, errors.New("google rejected the sign-in (invalid_grant): run `sift gmail-login` again. " +
				"If this happens weekly, publish the OAuth app to production (see README)")
		}
		return nil, fmt.Errorf("token request failed: %s %s", resp.Status, te.Error)
	}
	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
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
	for attempt := 1; ; attempt++ {
		retry, err := c.send(ctx, method, path, tok, payload, out)
		if !retry || attempt == maxAttempts {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay + rand.N(delay)): // jitter so parallel fetches don't retry together
		}
		delay *= 2
	}
}

// send makes one attempt and reports whether a failure is worth retrying.
func (c *Client) send(ctx context.Context, method, path, tok string, payload []byte, out any) (retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, method, c.APIBase+path, bytes.NewReader(payload))
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) { // its text holds the full URL: mailbox, message ID, query
			err = ue.Err
		}
		return false, fmt.Errorf("gmail %s %s: %w", method, redactPath(path), err)
	}
	defer httpx.Close(resp.Body)
	if resp.StatusCode >= 300 {
		var ge struct {
			Error struct {
				Status string
				Errors []struct{ Reason string }
			} `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&ge) // codes only: messages can echo the mailbox
		reason := ge.Error.Status
		if len(ge.Error.Errors) > 0 {
			reason += " " + ge.Error.Errors[0].Reason
		}
		err := fmt.Errorf("gmail %s %s: %s %s", method, redactPath(path), resp.Status, reason)
		if strings.HasSuffix(reason, "accessNotConfigured") {
			return false, fmt.Errorf("%w: enable the Gmail API in your Google Cloud project (see README)", err)
		}
		return resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 ||
			strings.HasSuffix(reason, "ateLimitExceeded"), err // Gmail also sends rate limits as 403
	}
	if out != nil {
		return false, json.NewDecoder(resp.Body).Decode(out)
	}
	return false, nil
}

type header struct{ Name, Value string }

type part struct {
	MimeType string   `json:"mimeType"`
	Filename string   `json:"filename"`
	Headers  []header `json:"headers"`
	Body     struct {
		Data string `json:"data"`
	} `json:"body"`
	Parts []part `json:"parts"`
}

type message struct {
	ID           string   `json:"id"`
	LabelIDs     []string `json:"labelIds"`
	Snippet      string   `json:"snippet"`
	InternalDate string   `json:"internalDate"`
	Payload      part     `json:"payload"`
}

// ListRecentInbox returns inbox messages received since `since`, newest first.
// Gmail labels come back as categories, so the engine can spot "Sift: " ones.
func (c *Client) ListRecentInbox(ctx context.Context, mailbox string, since time.Time, max int) ([]graph.Message, error) {
	names, err := c.refreshLabels(ctx, mailbox)
	if err != nil {
		return nil, err
	}
	q := url.Values{
		"q":          {inboxQuery(since, names, c.ExcludeSenders)},
		"maxResults": {fmt.Sprint(min(max, 100))},
	}
	var res struct {
		Messages []struct {
			ID string `json:"id"`
		} `json:"messages"`
	}
	if err := c.do(ctx, http.MethodGet, messagesPath(mailbox)+"?"+q.Encode(), nil, &res); err != nil {
		return nil, err
	}

	// Bodies come with the listing, which saves a second request per message.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	out := make([]graph.Message, len(res.Messages))
	sem := make(chan struct{}, min(c.Concurrency, maxFetches))
	var (
		wg       sync.WaitGroup
		firstErr error
		once     sync.Once
	)
	for i, r := range res.Messages {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			var m message
			if err := c.do(ctx, http.MethodGet, messagesPath(mailbox)+"/"+url.PathEscape(r.ID)+"?format=full", nil, &m); err != nil {
				once.Do(func() { firstErr = err; cancel() })
				return
			}
			out[i] = convert(m, names)
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// inboxQuery leaves out mail that already has a Sift label, so each pass moves
// on to the next unlabelled messages instead of seeing the same newest ones.
func inboxQuery(since time.Time, labelNames map[string]string, excludeSenders []string) string {
	var skip []string
	for _, name := range labelNames {
		if strings.HasPrefix(name, parentLabel+"/") {
			// Gmail search writes "Sift/Action Required" as sift-action-required.
			skip = append(skip, "-label:"+strings.NewReplacer("/", "-", " ", "-").Replace(strings.ToLower(name)))
		}
	}
	for _, sender := range excludeSenders {
		skip = append(skip, "-from:"+sender)
	}
	slices.Sort(skip)
	return strings.Join(append([]string{fmt.Sprintf("in:inbox after:%d", since.Unix())}, skip...), " ")
}

func convert(m message, labelNames map[string]string) graph.Message {
	out := graph.Message{ID: m.ID, BodyPreview: html.UnescapeString(m.Snippet), Importance: "normal"}
	out.Body.Content = bodyText(m.Payload)
	if ms, err := strconv.ParseInt(m.InternalDate, 10, 64); err == nil {
		out.ReceivedDateTime = time.UnixMilli(ms)
	}
	for _, id := range m.LabelIDs {
		out.Categories = append(out.Categories, categoryName(labelNames[id]))
	}
	for _, h := range m.Payload.Headers {
		switch strings.ToLower(h.Name) {
		case "subject":
			out.Subject = decodeHeader(h.Value)
		case "from":
			out.From.EmailAddress.Name, out.From.EmailAddress.Address = parseFrom(h.Value)
		case "importance":
			if strings.EqualFold(strings.TrimSpace(h.Value), "high") {
				out.Importance = "high"
			}
		case "x-priority":
			if strings.HasPrefix(strings.TrimSpace(h.Value), "1") {
				out.Importance = "high"
			}
		}
	}
	return out
}

var reAngleAddress = regexp.MustCompile(`<([^<>\s]+@[^<>\s]+)>`)

// parseFrom returns the first sender. A malformed header never passes through
// whole, because it could smuggle a trusted domain into the domain checks.
func parseFrom(header string) (name, address string) {
	if list, err := mail.ParseAddressList(header); err == nil && len(list) > 0 {
		return list[0].Name, list[0].Address
	}
	if m := reAngleAddress.FindStringSubmatch(header); m != nil {
		return "", m[1]
	}
	return "", ""
}

func decodeHeader(s string) string {
	if d, err := new(mime.WordDecoder).DecodeHeader(s); err == nil {
		return d
	}
	return s
}

// GetBodyText fetches the plain-text body of a message. HTML-only mail is
// reduced to text; attachments are never read.
func (c *Client) GetBodyText(ctx context.Context, mailbox, id string) (string, error) {
	var m message
	err := c.do(ctx, http.MethodGet, messagesPath(mailbox)+"/"+url.PathEscape(id)+"?format=full", nil, &m)
	if err != nil {
		return "", err
	}
	return bodyText(m.Payload), nil
}

func bodyText(p part) string {
	if s := findPart(p, "text/plain"); strings.TrimSpace(s) != "" {
		return s
	}
	return stripHTML(findPart(p, "text/html"))
}

// findPart returns the first non-attachment part of the given type.
func findPart(p part, mimeType string) string {
	if p.Filename != "" {
		return ""
	}
	if strings.EqualFold(p.MimeType, mimeType) {
		if b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(p.Body.Data, "=")); err == nil {
			return string(b)
		}
	}
	for _, child := range p.Parts {
		if s := findPart(child, mimeType); s != "" {
			return s
		}
	}
	return ""
}

var (
	reInvisible = regexp.MustCompile(`(?is)<script\b.*?</script>|<style\b.*?</style>|<head\b.*?</head>|<!--.*?-->`)
	reLineBreak = regexp.MustCompile(`(?i)<br\s*/?>|</(p|div|tr|li|h[1-6])>`)
	reTag       = regexp.MustCompile(`<[^>]*>`)
	reBlank     = regexp.MustCompile(`\n[ \t\n]*\n`)
)

func stripHTML(s string) string {
	s = reInvisible.ReplaceAllString(s, "")
	s = reLineBreak.ReplaceAllString(s, "\n")
	s = reTag.ReplaceAllString(s, "")
	return strings.TrimSpace(reBlank.ReplaceAllString(html.UnescapeString(s), "\n\n"))
}

// Tag adds the message's Sift labels and optionally stars it. Labels it didn't
// add are left alone. It never moves, deletes, forwards or replies to mail,
// and the inbox and read state are unchanged.
func (c *Client) Tag(ctx context.Context, mailbox, id string, categories []string, flag bool) error {
	add := []string{}
	for _, cat := range categories {
		if !strings.HasPrefix(cat, classifier.CategoryPrefix) {
			continue
		}
		labelID, err := c.ensureLabel(ctx, mailbox, cat, "")
		if err != nil {
			return err
		}
		add = append(add, labelID)
	}
	if flag {
		add = append(add, "STARRED")
	}
	path := messagesPath(mailbox) + "/" + url.PathEscape(id) + "/modify"
	return c.do(ctx, http.MethodPost, path, map[string]any{"addLabelIds": add}, nil)
}

// EnsureCategory creates a coloured Gmail label if missing.
func (c *Client) EnsureCategory(ctx context.Context, mailbox, name, color string) error {
	_, err := c.ensureLabel(ctx, mailbox, name, color)
	return err
}

func (c *Client) ensureLabel(ctx context.Context, mailbox, category, color string) (string, error) {
	c.labelMu.Lock()
	defer c.labelMu.Unlock()
	if c.labels == nil {
		if _, err := c.loadLabels(ctx, mailbox); err != nil {
			return "", err
		}
	}
	name := labelName(category)
	if id, ok := c.labels[name]; ok {
		return id, nil
	}
	// Gmail only nests "Sift/Urgent" under a "Sift" label that already exists.
	if _, ok := c.labels[parentLabel]; !ok {
		if err := c.createLabel(ctx, mailbox, parentLabel, ""); err != nil {
			return "", err
		}
	}
	if err := c.createLabel(ctx, mailbox, name, color); err != nil {
		return "", err
	}
	return c.labels[name], nil
}

func (c *Client) createLabel(ctx context.Context, mailbox, name, color string) error {
	body := map[string]any{"name": name, "labelListVisibility": "labelShow", "messageListVisibility": "show"}
	if p, ok := palette[color]; ok {
		body["color"] = map[string]string{"backgroundColor": p.bg, "textColor": p.text}
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, labelsPath(mailbox), body, &created); err != nil {
		return err
	}
	c.labels[name] = created.ID
	return nil
}

// refreshLabels reloads the label list, in case labels changed between passes,
// and returns it as ID → name.
func (c *Client) refreshLabels(ctx context.Context, mailbox string) (map[string]string, error) {
	c.labelMu.Lock()
	defer c.labelMu.Unlock()
	return c.loadLabels(ctx, mailbox)
}

// loadLabels needs labelMu held.
func (c *Client) loadLabels(ctx context.Context, mailbox string) (map[string]string, error) {
	var res struct {
		Labels []struct{ ID, Name string } `json:"labels"`
	}
	if err := c.do(ctx, http.MethodGet, labelsPath(mailbox), nil, &res); err != nil {
		return nil, err
	}
	c.labels = make(map[string]string, len(res.Labels))
	names := make(map[string]string, len(res.Labels))
	for _, l := range res.Labels {
		c.labels[l.Name] = l.ID
		names[l.ID] = l.Name
	}
	return names, nil
}

// labelName turns the category "Sift: Urgent" into the Gmail label "Sift/Urgent".
func labelName(category string) string {
	if rest, ok := strings.CutPrefix(category, classifier.CategoryPrefix); ok {
		return parentLabel + "/" + rest
	}
	return category
}

// categoryName is the reverse of labelName.
func categoryName(label string) string {
	if rest, ok := strings.CutPrefix(label, parentLabel+"/"); ok {
		return classifier.CategoryPrefix + rest
	}
	return label
}

// palette maps Outlook colour presets to colours from Gmail's fixed label palette.
var palette = map[string]struct{ bg, text string }{
	"preset0":  {"#cc3a21", "#ffffff"}, // red
	"preset1":  {"#eaa041", "#000000"}, // orange
	"preset7":  {"#3c78d8", "#ffffff"}, // blue
	"preset4":  {"#16a766", "#ffffff"}, // green
	"preset12": {"#666666", "#ffffff"}, // grey
	"preset9":  {"#83334c", "#ffffff"}, // cranberry
	"preset3":  {"#fad165", "#000000"}, // yellow
}

// The API refuses any address but the signed-in account's, so a mismatch
// between SIFT_MAILBOXES and the token fails instead of labelling the wrong mail.
func messagesPath(mailbox string) string {
	return "/users/" + url.PathEscape(mailbox) + "/messages"
}

func labelsPath(mailbox string) string { return "/users/" + url.PathEscape(mailbox) + "/labels" }

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
