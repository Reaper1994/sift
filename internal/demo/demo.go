// Package demo runs Sift end to end against a simulated mailbox and a
// simulated Jev API, entirely in-process. It needs no credentials and makes
// no network calls beyond loopback, so anyone can see how triage behaves.
//
// The real redaction, Jev client, decision policy and triage engine are
// used; only Microsoft Graph and TypeSafe's servers are replaced by fakes.
package demo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/Reaper1994/sift/internal/classifier"
	"github.com/Reaper1994/sift/internal/graph"
	"github.com/Reaper1994/sift/internal/triage"
)

// sample is a fictional email plus the answers the simulated Jev returns.
type sample struct {
	from, subject, body string
	category            string
	categoryConf        float64
	urgency, reply      float64
	phishing            float64
}

var samples = []sample{
	{"ops-lead@client.example", "URGENT: outage — need your sign-off by 5pm",
		"Can you approve the rollback today? Call me on +44 20 7946 0958.",
		"request", 0.94, 1.9, 0.95, 0.01},
	{"anna@partner.example", "Contract draft — your review please",
		"Could you review clause 7 of the attached draft by Friday? Ref 4482019377.",
		"request", 0.88, 0.8, 0.85, 0.02},
	{"it-helpdesk@example-support.net", "Your mailbox will be suspended",
		"Verify your password within 24 hours at https://example-login.net/verify?u=you",
		"request", 0.70, 1.8, 0.4, 0.93},
	{"calendar@example.com", "Quarterly planning — Tue 10:00",
		"Invitation: quarterly planning, Room 2.",
		"meeting", 0.97, 0.5, 0.2, 0.0},
	{"news@tech-weekly.example", "This week in tech: AI agents everywhere",
		"Our weekly roundup of industry news. Unsubscribe any time.",
		"newsletter", 0.98, 0.0, 0.0, 0.03},
	{"noreply@example.com", "Monthly backup completed",
		"FYI: last night's backup finished successfully. No action needed.",
		"update", 0.91, 0.1, 0.05, 0.0},
	{"sam@friend.example", "Following up on our chat",
		"Good to catch up. Let me know your thoughts when you get a chance.",
		"social", 0.38, 0.3, 0.45, 0.02},
}

const demoMailbox = "you@example.com"

// Run executes the demo and writes a human-readable report to w.
func Run(ctx context.Context, w io.Writer) error {
	jev := newFakeJev()
	defer jev.srv.Close()

	mail := newFakeMail()
	clf := classifier.NewJev(jev.srv.URL, "demo-key", "jev-latest")

	eng := &triage.Engine{
		Mail: mail, Classifier: clf,
		Log:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		InternalDomains: []string{"example.com"},
		Lookback:        24 * time.Hour, MaxPerRun: 50, MaxBodyChars: 3000,
		Concurrency: 4, Flag: true,
	}

	fmt.Fprintln(w, "Sift demo — simulated mailbox and simulated Jev answers.")
	fmt.Fprintln(w, "Real redaction, decision rules and triage engine. Nothing leaves this machine.")
	fmt.Fprintln(w)

	start := time.Now()
	st := eng.Run(ctx, []string{demoMailbox})
	took := time.Since(start)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "LABEL\tCONF\tFLAG\tSUBJECT")
	for i, s := range samples {
		id := fmt.Sprint(i)
		cats, flag := mail.result(id)
		label := strings.TrimPrefix(last(cats), classifier.CategoryPrefix)
		f := ""
		if flag {
			f = "⚑"
		}
		fmt.Fprintf(tw, "%s\t%.2f\t%s\t%s\n", label, jev.confidence(s), f, trunc(s.subject, 44))
	}
	tw.Flush()

	fmt.Fprintf(w, "\nTriaged %d messages in %s (%d flagged for attention).\n", st.Tagged, took.Round(time.Millisecond), mail.flagged())
	fmt.Fprintln(w, "\nWhat the classifier saw for the phishing email (after redaction):")
	fmt.Fprintf(w, "  sender_domain: %s\n  body: %s\n", jev.seenDomain(2), jev.seenBody(2))
	return nil
}

// ── fake Microsoft Graph ──

type fakeMail struct {
	mu     sync.Mutex
	tagged map[string][]string
	flags  map[string]bool
}

func newFakeMail() *fakeMail {
	return &fakeMail{tagged: map[string][]string{}, flags: map[string]bool{}}
}

func (f *fakeMail) ListRecentInbox(_ context.Context, _ string, _ time.Time, _ int) ([]graph.Message, error) {
	out := make([]graph.Message, len(samples))
	for i, s := range samples {
		var m graph.Message
		m.ID, m.Subject, m.BodyPreview = fmt.Sprint(i), s.subject, s.body
		m.Importance, m.ReceivedDateTime = "normal", time.Now().Add(-time.Duration(i)*time.Minute)
		m.From.EmailAddress.Address = s.from
		out[i] = m
	}
	return out, nil
}

func (f *fakeMail) GetBodyText(_ context.Context, _, id string) (string, error) {
	var i int
	fmt.Sscan(id, &i)
	return samples[i].body, nil
}

func (f *fakeMail) EnsureCategory(context.Context, string, string, string) error { return nil }

func (f *fakeMail) Tag(_ context.Context, _, id string, cats []string, flag bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tagged[id], f.flags[id] = cats, flag
	return nil
}

func (f *fakeMail) result(id string) ([]string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tagged[id], f.flags[id]
}

func (f *fakeMail) flagged() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, v := range f.flags {
		if v {
			n++
		}
	}
	return n
}

// ── fake Jev API (loopback only) ──

type fakeJev struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen map[string]map[string]any // subject → state the classifier received
}

func newFakeJev() *fakeJev {
	j := &fakeJev{seen: map[string]map[string]any{}}
	j.srv = httptest.NewServer(http.HandlerFunc(j.handle))
	return j
}

func (j *fakeJev) handle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		State map[string]any `json:"state"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusUnprocessableEntity)
		return
	}
	subj, _ := req.State["subject"].(string)
	j.mu.Lock()
	j.seen[subj] = req.State
	j.mu.Unlock()

	s, ok := lookup(subj)
	if !ok {
		http.Error(w, "unknown", http.StatusUnprocessableEntity)
		return
	}
	time.Sleep(60 * time.Millisecond) // roughly Jev's real latency
	_ = json.NewEncoder(w).Encode(map[string]any{
		"model": "jev-latest (simulated)",
		"answers": map[string]any{
			"category":    map[string]any{"type": "choice", "choice": s.category, "confidence": s.categoryConf},
			"urgency":     map[string]any{"type": "score", "score": s.urgency, "confidence": 0.8},
			"needs_reply": map[string]any{"type": "noul", "noul": s.reply},
			"phishing":    map[string]any{"type": "noul", "noul": s.phishing},
		},
	})
}

// lookup matches on subject; subjects contain nothing the redactor changes.
func lookup(subject string) (sample, bool) {
	for _, s := range samples {
		if s.subject == subject {
			return s, true
		}
	}
	return sample{}, false
}

func (j *fakeJev) confidence(s sample) float64 {
	if s.phishing >= 0.7 {
		return s.phishing
	}
	return s.categoryConf
}

func (j *fakeJev) state(i int) map[string]any {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.seen[samples[i].subject]
}

func (j *fakeJev) seenDomain(i int) string { v, _ := j.state(i)["sender_domain"].(string); return v }
func (j *fakeJev) seenBody(i int) string   { v, _ := j.state(i)["body"].(string); return v }

func last(s []string) string {
	if len(s) == 0 {
		return "-"
	}
	return s[len(s)-1]
}

func trunc(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}
