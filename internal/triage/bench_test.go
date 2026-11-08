package triage

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/Reaper1994/sift/internal/classifier"
	"github.com/Reaper1994/sift/internal/graph"
)

type nopClf struct{}

func (nopClf) Name() string { return "nop" }
func (nopClf) Classify(context.Context, classifier.Email) (classifier.Result, error) {
	return classifier.Result{Label: classifier.FYI, Confidence: 1}, nil
}

// BenchmarkRun measures engine overhead (redaction, bookkeeping, scheduling)
// over a mailbox of 200 messages with an instant classifier and mailbox.
func BenchmarkRun(b *testing.B) {
	body := "Hi Sam, please review the attached proposal before Thursday. Call 07700 900123 or mail jo@broker.com. " +
		"Reference 98765432101. Thanks for your help with the renewal, the team really appreciates it."
	var msgs []graph.Message
	for i := range 200 {
		m := msg(fmt.Sprint(i), "jane@broker.com", "Renewal 4111 1111 1111 1111")
		m.Body.Content = body
		msgs = append(msgs, m)
	}
	mail := &fakeMail{msgs: msgs, tagged: map[string][]string{}, flags: map[string]bool{}}
	e := &Engine{
		Mail: mail, Classifier: nopClf{}, Log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		Lookback: time.Hour, MaxPerRun: 200, MaxBodyChars: 1000, Concurrency: 4, Flag: true,
	}
	b.ReportAllocs()
	for b.Loop() {
		if st := e.Run(context.Background(), []string{"me@example.com"}); st.Tagged != 200 {
			b.Fatalf("stats %+v", st)
		}
	}
}
