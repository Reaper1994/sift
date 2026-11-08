package gmail

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Reaper1994/sift/internal/classifier"
)

// fakeGmail records every request and refuses anything triage shouldn't do.
type fakeGmail struct {
	t        *testing.T
	mu       sync.Mutex
	labels   []map[string]string
	created  []map[string]any
	modified map[string][]string
	token    func(w http.ResponseWriter, form url.Values)
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func (f *fakeGmail) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/token" {
		_ = r.ParseForm()
		if f.token != nil {
			f.token(w, r.PostForm)
			return
		}
		fmt.Fprint(w, `{"access_token":"tok","expires_in":3600}`)
		return
	}
	if r.Header.Get("Authorization") != "Bearer tok" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	const base = "/users/me@gmail.com"
	p := r.URL.EscapedPath()
	switch {
	case r.Method == "GET" && p == base+"/labels":
		json.NewEncoder(w).Encode(map[string]any{"labels": f.labels})
	case r.Method == "POST" && p == base+"/labels":
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		f.created = append(f.created, body)
		id := fmt.Sprintf("Label_%d", len(f.created))
		f.labels = append(f.labels, map[string]string{"id": id, "name": body["name"].(string)})
		fmt.Fprintf(w, `{"id":%q}`, id)
	case r.Method == "GET" && p == base+"/messages":
		if q := r.URL.Query().Get("q"); q != "in:inbox after:1700000000" {
			f.t.Errorf("query %q", q)
		}
		if m := r.URL.Query().Get("maxResults"); m != "100" {
			f.t.Errorf("maxResults %q", m)
		}
		fmt.Fprint(w, `{"messages":[{"id":"m1"}]}`)
	case r.Method == "GET" && p == base+"/messages/m1":
		fmt.Fprintf(w, `{"id":"m1","labelIds":["INBOX","Label_9"],"snippet":"Tom &amp; Jerry","internalDate":"1700000500000",
			"payload":{"mimeType":"multipart/mixed","headers":[{"name":"From","value":"Ann Lee <ann@example.com>"},
			{"name":"Subject","value":"=?UTF-8?Q?Caf=C3=A9?="},{"name":"X-Priority","value":"1 (Highest)"}],"parts":[
			{"mimeType":"text/plain","filename":"secret.txt","body":{"data":%q}},
			{"mimeType":"text/html","body":{"data":%q}},
			{"mimeType":"text/plain","body":{"data":%q}}]}}`, b64("attachment"), b64("<b>html</b>"), b64("plain body"))
	case r.Method == "POST" && p == base+"/messages/m1/modify":
		var body struct {
			AddLabelIds    []string `json:"addLabelIds"`
			RemoveLabelIds []string `json:"removeLabelIds"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if len(body.RemoveLabelIds) > 0 {
			f.t.Errorf("removed labels %v", body.RemoveLabelIds)
		}
		f.modified["m1"] = body.AddLabelIds
		fmt.Fprint(w, `{}`)
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, p)
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":{"status":"PERMISSION_DENIED"}}`)
	}
}

func setup(t *testing.T) (*fakeGmail, *Client) {
	t.Helper()
	f := &fakeGmail{t: t, modified: map[string][]string{}, labels: []map[string]string{
		{"id": "INBOX", "name": "INBOX"}, {"id": "Label_9", "name": "Personal"},
	}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c := New("id", "secret", "refresh")
	c.APIBase, c.TokenURL, c.AuthURL, c.HTTP = srv.URL, srv.URL+"/token", srv.URL+"/auth", srv.Client()
	return f, c
}

const box = "me@gmail.com"

func TestListRecentInbox(t *testing.T) {
	_, c := setup(t)
	msgs, err := c.ListRecentInbox(context.Background(), box, time.Unix(1700000000, 0), 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d messages", len(msgs))
	}
	m := msgs[0]
	if m.Subject != "Café" || m.BodyPreview != "Tom & Jerry" || m.Importance != "high" || m.Body.Content != "plain body" {
		t.Errorf("got %+v", m)
	}
	if m.From.EmailAddress.Address != "ann@example.com" || m.From.EmailAddress.Name != "Ann Lee" {
		t.Errorf("from %+v", m.From)
	}
	if !m.ReceivedDateTime.Equal(time.UnixMilli(1700000500000)) {
		t.Errorf("received %v", m.ReceivedDateTime)
	}
	if strings.Join(m.Categories, ",") != "INBOX,Personal" {
		t.Errorf("categories %v", m.Categories)
	}
}

func TestInboxQuerySkipsLabelledMail(t *testing.T) {
	got := inboxQuery(time.Unix(1700000000, 0), map[string]string{
		"1": "INBOX", "2": "Sift", "3": "Sift/Urgent", "4": "Sift/Action Required", "5": "Personal",
	}, []string{"mybank.com"})
	if want := "in:inbox after:1700000000 -from:mybank.com -label:sift-action-required -label:sift-urgent"; got != want {
		t.Fatalf("got %q", got)
	}
}

func TestSiftLabelsReadBackAsCategories(t *testing.T) {
	if got := categoryName(labelName("Sift: Action Required")); got != "Sift: Action Required" {
		t.Fatalf("got %q", got)
	}
	if got := labelName("Sift: Urgent"); got != "Sift/Urgent" {
		t.Fatalf("got %q", got)
	}
	if got := categoryName("Personal"); got != "Personal" {
		t.Fatalf("got %q", got)
	}
}

func TestGetBodySkipsAttachmentsAndPrefersPlain(t *testing.T) {
	_, c := setup(t)
	got, err := c.GetBodyText(context.Background(), box, "m1")
	if err != nil || got != "plain body" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestStripHTML(t *testing.T) {
	got := stripHTML(`<html><head><title>x</title></head><style>p{}</style><p>Hi &amp; bye</p><script>bad()</script>next<br>line</html>`)
	if want := "Hi & bye\nnext\nline"; got != want {
		t.Fatalf("got %q", got)
	}
}

func TestTagOnlyAddsSiftLabelsAndStar(t *testing.T) {
	f, c := setup(t)
	err := c.Tag(context.Background(), box, "m1", []string{"INBOX", "Personal", "Sift: Urgent"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.modified["m1"], ","); got != "Label_2,STARRED" {
		t.Fatalf("added %q", got)
	}
	if f.created[0]["name"] != "Sift" || f.created[1]["name"] != "Sift/Urgent" {
		t.Fatalf("created %v", f.created)
	}
}

func TestTagWithoutFlagDoesNotStar(t *testing.T) {
	f, c := setup(t)
	if err := c.Tag(context.Background(), box, "m1", []string{"Sift: FYI"}, false); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.modified["m1"], ","); got != "Label_2" {
		t.Fatalf("added %q", got)
	}
}

func TestEnsureCategoryIsIdempotentAndUsesPalette(t *testing.T) {
	f, c := setup(t)
	for _, l := range classifier.AllLabels {
		cat := classifier.Category[l]
		if _, ok := palette[cat.Color]; !ok {
			t.Errorf("no Gmail colour for %s (%s)", cat.Name, cat.Color)
		}
		for range 2 {
			if err := c.EnsureCategory(context.Background(), box, cat.Name, cat.Color); err != nil {
				t.Fatal(err)
			}
		}
	}
	if want := len(classifier.AllLabels) + 1; len(f.created) != want { // +1 for the parent
		t.Fatalf("created %d labels, want %d", len(f.created), want)
	}
	if color, _ := f.created[1]["color"].(map[string]any); color["backgroundColor"] != "#cc3a21" {
		t.Fatalf("color %v", f.created[1]["color"])
	}
}

func TestErrorsHideIdentifiers(t *testing.T) {
	got := redactPath("/users/me@gmail.com/messages/abc123/modify?x=1")
	if strings.Contains(got, "gmail.com") || strings.Contains(got, "abc123") {
		t.Fatalf("leaked: %s", got)
	}
}

func TestExpiredSignInSaysWhatToDo(t *testing.T) {
	f, c := setup(t)
	f.token = func(w http.ResponseWriter, _ url.Values) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_grant"}`)
	}
	_, err := c.ListRecentInbox(context.Background(), box, time.Now(), 10)
	if err == nil || !strings.Contains(err.Error(), "sift gmail-login") {
		t.Fatalf("got %v", err)
	}
}

type browserVisit struct {
	challenge string
	status    int
}

// followLogin plays the browser: it finds the sign-in URL and calls the
// redirect with the given parameters added.
func followLogin(t *testing.T, r io.Reader, extra func(state string) url.Values) <-chan browserVisit {
	t.Helper()
	visit := make(chan browserVisit, 1)
	go func() {
		defer close(visit)
		sc := bufio.NewScanner(r)
		sc.Buffer(nil, 1<<20)
		re := regexp.MustCompile(`https?://\S+/auth\?\S+`)
		for sc.Scan() {
			link := re.FindString(sc.Text())
			if link == "" {
				continue
			}
			u, _ := url.Parse(link)
			q := u.Query()
			if q.Get("scope") != Scope || q.Get("access_type") != "offline" || q.Get("code_challenge_method") != "S256" {
				t.Errorf("auth params %v", q)
			}
			if !strings.HasPrefix(q.Get("redirect_uri"), "http://127.0.0.1:") {
				t.Errorf("redirect %q", q.Get("redirect_uri"))
			}
			resp, err := http.Get(q.Get("redirect_uri") + "?" + extra(q.Get("state")).Encode())
			if err != nil {
				t.Error(err)
				break
			}
			resp.Body.Close()
			visit <- browserVisit{q.Get("code_challenge"), resp.StatusCode}
			break
		}
		io.Copy(io.Discard, r)
	}()
	return visit
}

func TestLoginExchangesCode(t *testing.T) {
	f, c := setup(t)
	var form url.Values
	f.token = func(w http.ResponseWriter, got url.Values) {
		form = got
		fmt.Fprint(w, `{"access_token":"tok","refresh_token":"new-refresh","expires_in":3600}`)
	}
	pr, pw := io.Pipe()
	defer pw.Close()
	visited := followLogin(t, pr, func(state string) url.Values {
		return url.Values{"state": {state}, "code": {"abc"}}
	})
	got, err := c.Login(context.Background(), pw)
	if err != nil || got != "new-refresh" {
		t.Fatalf("got %q, %v", got, err)
	}
	if form.Get("code") != "abc" || form.Get("grant_type") != "authorization_code" {
		t.Fatalf("form %v", form)
	}
	sum := sha256.Sum256([]byte(form.Get("code_verifier")))
	if v := <-visited; v.challenge != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatalf("code_verifier doesn't match challenge %q", v.challenge)
	}
}

func TestLoginReportsDeniedConsent(t *testing.T) {
	_, c := setup(t)
	pr, pw := io.Pipe()
	defer pw.Close()
	visited := followLogin(t, pr, func(state string) url.Values {
		return url.Values{"state": {state}, "error": {"access_denied"}}
	})
	if _, err := c.Login(context.Background(), pw); err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("got %v", err)
	}
	<-visited
}

func TestLoginIgnoresWrongState(t *testing.T) {
	f, c := setup(t)
	f.token = func(http.ResponseWriter, url.Values) { t.Error("forged callback reached the token exchange") }
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	pr, pw := io.Pipe()
	defer pw.Close()
	visited := followLogin(t, pr, func(string) url.Values {
		return url.Values{"state": {"forged"}, "code": {"abc"}}
	})
	if _, err := c.Login(ctx, pw); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("got %v", err)
	}
	if v := <-visited; v.status != http.StatusBadRequest {
		t.Fatalf("status %d", v.status)
	}
}

func TestNetworkErrorsHideIdentifiers(t *testing.T) {
	c := New("id", "secret", "refresh")
	c.token, c.expires = "tok", time.Now().Add(time.Hour)
	c.APIBase = "http://127.0.0.1:1" // nothing listens here
	c.ExcludeSenders = []string{"private.example"}
	_, err := c.ListRecentInbox(context.Background(), box, time.Now(), 10)
	if err == nil {
		t.Fatal("expected a connection error")
	}
	if _, err2 := c.GetBodyText(context.Background(), box, "msg-id"); err2 == nil {
		t.Fatal("expected a connection error")
	} else {
		err = errors.Join(err, err2)
	}
	for _, leak := range []string{"gmail.com", "msg-id", "private.example", "in:inbox"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("leaked %q: %v", leak, err)
		}
	}
}

func TestParseFrom(t *testing.T) {
	for header, want := range map[string]string{
		"Ann Lee <ann@example.com>": "ann@example.com",
		"Acme, Inc <a@corp.com>":    "a@corp.com",
		"x@evil.com, ceo@corp.com":  "x@evil.com",
		"not an address @corp.com":  "",
	} {
		if _, got := parseFrom(header); got != want {
			t.Errorf("%q: got %q, want %q", header, got, want)
		}
	}
}

// listServer serves n messages after a short delay and tracks peak parallelism.
func listServer(t *testing.T, n int, peak *atomic.Int32, fail func(id string) int) *Client {
	t.Helper()
	var active atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			fmt.Fprint(w, `{"access_token":"tok","expires_in":3600}`)
		case strings.HasSuffix(r.URL.Path, "/labels"):
			fmt.Fprint(w, `{"labels":[]}`)
		case strings.HasSuffix(r.URL.Path, "/messages"):
			ids := make([]map[string]string, n)
			for i := range ids {
				ids[i] = map[string]string{"id": fmt.Sprint("m", i)}
			}
			json.NewEncoder(w).Encode(map[string]any{"messages": ids})
		default:
			now := active.Add(1)
			defer active.Add(-1)
			for p := peak.Load(); now > p && !peak.CompareAndSwap(p, now); p = peak.Load() {
			}
			time.Sleep(10 * time.Millisecond)
			id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			if status := fail(id); status != 0 {
				w.WriteHeader(status)
				fmt.Fprint(w, `{"error":{"status":"RESOURCE_EXHAUSTED","errors":[{"reason":"userRateLimitExceeded"}]}}`)
				return
			}
			fmt.Fprintf(w, `{"id":%q}`, id)
		}
	}))
	t.Cleanup(srv.Close)
	c := New("id", "secret", "refresh")
	c.APIBase, c.TokenURL, c.HTTP, c.retryDelay = srv.URL, srv.URL+"/token", srv.Client(), time.Millisecond
	return c
}

func TestListFetchesInParallelAndKeepsOrder(t *testing.T) {
	var peak atomic.Int32
	c := listServer(t, 20, &peak, func(string) int { return 0 })
	c.Concurrency = 4
	msgs, err := c.ListRecentInbox(context.Background(), box, time.Now(), 100)
	if err != nil || len(msgs) != 20 {
		t.Fatalf("got %d messages, %v", len(msgs), err)
	}
	for i, m := range msgs {
		if m.ID != fmt.Sprint("m", i) {
			t.Fatalf("position %d holds %s", i, m.ID)
		}
	}
	if p := peak.Load(); p < 2 || p > 4 {
		t.Fatalf("peak parallelism %d, want 2 to 4", p)
	}
}

func TestFetchesAreCapped(t *testing.T) {
	var peak atomic.Int32
	c := listServer(t, 40, &peak, func(string) int { return 0 })
	c.Concurrency = 16
	if _, err := c.ListRecentInbox(context.Background(), box, time.Now(), 100); err != nil {
		t.Fatal(err)
	}
	if p := peak.Load(); p > maxFetches {
		t.Fatalf("peak parallelism %d", p)
	}
}

func TestRateLimitsAreRetried(t *testing.T) {
	var peak, tries atomic.Int32
	c := listServer(t, 1, &peak, func(string) int {
		if tries.Add(1) < 3 {
			return http.StatusForbidden // Gmail reports per-user rate limits as 403
		}
		return 0
	})
	if msgs, err := c.ListRecentInbox(context.Background(), box, time.Now(), 10); err != nil || len(msgs) != 1 {
		t.Fatalf("got %d messages, %v", len(msgs), err)
	}
	if got := tries.Load(); got != 3 {
		t.Fatalf("tried %d times", got)
	}
}

func TestRetriesGiveUp(t *testing.T) {
	var peak, tries atomic.Int32
	c := listServer(t, 1, &peak, func(string) int {
		tries.Add(1)
		return http.StatusTooManyRequests
	})
	if _, err := c.ListRecentInbox(context.Background(), box, time.Now(), 10); err == nil {
		t.Fatal("expected an error")
	}
	if got := tries.Load(); got != maxAttempts {
		t.Fatalf("tried %d times", got)
	}
}

func TestDisabledAPISaysWhatToDo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			fmt.Fprint(w, `{"access_token":"tok","expires_in":3600}`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":{"status":"PERMISSION_DENIED","message":"me@gmail.com","errors":[{"reason":"accessNotConfigured"}]}}`)
	}))
	defer srv.Close()
	c := New("id", "secret", "refresh")
	c.APIBase, c.TokenURL, c.HTTP = srv.URL, srv.URL+"/token", srv.Client()
	_, err := c.ListRecentInbox(context.Background(), box, time.Now(), 10)
	if err == nil || !strings.Contains(err.Error(), "enable the Gmail API") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "me@gmail.com") {
		t.Fatalf("leaked mailbox: %v", err)
	}
}
