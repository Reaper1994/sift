package triage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Reaper1994/sift/internal/classifier"
	"github.com/Reaper1994/sift/internal/graph"
	"github.com/Reaper1994/sift/internal/httpx"
)

type fakeMail struct {
	mu     sync.Mutex
	msgs   []graph.Message
	body   string
	tagged map[string][]string
	flags  map[string]bool

	bodyFetches int
	listErr     map[string]error // per-mailbox ListRecentInbox failure
}

func (f *fakeMail) ListRecentInbox(_ context.Context, mb string, _ time.Time, _ int) ([]graph.Message, error) {
	if err := f.listErr[mb]; err != nil {
		return nil, err
	}
	return f.msgs, nil
}
func (f *fakeMail) GetBodyText(context.Context, string, string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bodyFetches++
	return f.body, nil
}
func (f *fakeMail) EnsureCategory(context.Context, string, string, string) error { return nil }
func (f *fakeMail) Tag(_ context.Context, _, id string, cats []string, flag bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tagged[id], f.flags[id] = cats, flag
	return nil
}

type spyClf struct {
	mu   sync.Mutex
	seen []classifier.Email
	out  classifier.Label
}

func (s *spyClf) Name() string { return "spy" }
func (s *spyClf) Classify(_ context.Context, e classifier.Email) (classifier.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, e)
	return classifier.Result{Label: s.out, Confidence: 0.9}, nil
}

func msg(id, from, subject string, cats ...string) graph.Message {
	var m graph.Message
	m.ID, m.Subject, m.Categories = id, subject, cats
	m.From.EmailAddress.Address = from
	return m
}

func engine(m *fakeMail, c *spyClf, logs *bytes.Buffer) *Engine {
	return &Engine{
		Mail: m, Classifier: c, Log: slog.New(slog.NewTextHandler(logs, nil)),
		InternalDomains: []string{"example.com"}, ExcludeSenders: []string{"hr.example.com"},
		Lookback: time.Hour, MaxPerRun: 10, MaxBodyChars: 1000, Concurrency: 2, Flag: true,
	}
}

func TestRunTagsRedactsSkipsAndExcludes(t *testing.T) {
	m := &fakeMail{
		msgs: []graph.Message{
			msg("1", "jane@broker.com", "Bind cover for 4111 1111 1111 1111", "Personal"),
			msg("2", "bob@example.com", "Done", "Sift: FYI"),   // already triaged
			msg("3", "payroll@hr.example.com", "Your payslip"), // excluded sender
		},
		body:   "Call me on 07700 900123 about the contract. secret@broker.com",
		tagged: map[string][]string{}, flags: map[string]bool{},
	}
	c := &spyClf{out: classifier.Urgent}
	var logs bytes.Buffer
	st := engine(m, c, &logs).Run(context.Background(), []string{"me@example.com"})

	if st.Tagged != 1 || st.Skipped != 1 || st.Excluded != 1 || st.Failed != 0 {
		t.Fatalf("stats %+v", st)
	}
	got := m.tagged["1"]
	if len(got) != 2 || got[0] != "Personal" || got[1] != "Sift: Urgent" || !m.flags["1"] {
		t.Fatalf("tags %v flag %v", got, m.flags["1"])
	}
	e := c.seen[0]
	for _, leak := range []string{"4111", "07700", "secret@", "jane@"} {
		if strings.Contains(e.Subject+e.Body+e.FromDomain, leak) {
			t.Errorf("classifier saw %q", leak)
		}
	}
	if e.FromDomain != "broker.com" || e.SenderInternal {
		t.Errorf("sender info wrong: %+v", e)
	}
	for _, leak := range []string{"Bind cover", "contract", "me@", "jane@"} {
		if strings.Contains(logs.String(), leak) {
			t.Errorf("logs contain %q", leak)
		}
	}
}

func TestDryRunDoesNotWrite(t *testing.T) {
	m := &fakeMail{msgs: []graph.Message{msg("1", "a@b.com", "hi")}, tagged: map[string][]string{}, flags: map[string]bool{}}
	e := engine(m, &spyClf{out: classifier.FYI}, &bytes.Buffer{})
	e.DryRun = true
	if st := e.Run(context.Background(), []string{"x"}); st.Tagged != 1 || len(m.tagged) != 0 {
		t.Fatalf("dry run wrote: %+v %v", st, m.tagged)
	}
}

func TestNoFlagForFYI(t *testing.T) {
	m := &fakeMail{msgs: []graph.Message{msg("1", "a@b.com", "hi")}, tagged: map[string][]string{}, flags: map[string]bool{}}
	engine(m, &spyClf{out: classifier.FYI}, &bytes.Buffer{}).Run(context.Background(), []string{"x"})
	if m.flags["1"] {
		t.Fatal("FYI was flagged")
	}
}

func TestUsesBodyFromListingWithoutFetchingAgain(t *testing.T) {
	m := msg("1", "a@b.com", "hi")
	m.Body.Content = "listed body"
	mail := &fakeMail{msgs: []graph.Message{m}, tagged: map[string][]string{}, flags: map[string]bool{}}
	clf := &spyClf{out: classifier.FYI}
	e := &Engine{Mail: mail, Classifier: clf, Log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		Lookback: time.Hour, MaxPerRun: 10, MaxBodyChars: 1000, Concurrency: 1}
	e.Run(context.Background(), []string{"mb"})
	if mail.bodyFetches != 0 {
		t.Fatalf("fetched the body %d times", mail.bodyFetches)
	}
	if len(clf.seen) != 1 || !strings.Contains(clf.seen[0].Body, "listed body") {
		t.Fatalf("classifier saw %+v", clf.seen)
	}
}

func TestCancelledContextDoesNotCountMailboxesAsFailed(t *testing.T) {
	m := &fakeMail{msgs: []graph.Message{msg("1", "a@b.com", "hi")}, tagged: map[string][]string{}, flags: map[string]bool{}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	st := engine(m, &spyClf{out: classifier.FYI}, &bytes.Buffer{}).Run(ctx, []string{"a", "b", "c"})
	if st.Seen != 0 || st.Failed != 0 || len(m.tagged) != 0 {
		t.Fatalf("stats %+v tagged %v", st, m.tagged)
	}
}

func TestRejectedSignInsAreCountedSeparately(t *testing.T) {
	m := &fakeMail{tagged: map[string][]string{}, flags: map[string]bool{}, listErr: map[string]error{
		"a": fmt.Errorf("%w: run `sift gmail-login`", httpx.ErrAuth),
		"b": errors.New("connection reset"),
	}}
	st := engine(m, &spyClf{out: classifier.FYI}, &bytes.Buffer{}).Run(context.Background(), []string{"a", "b", "c"})
	if st.Failed != 2 || st.AuthFailed != 1 {
		t.Fatalf("stats %+v, want Failed=2 AuthFailed=1", st)
	}
}
