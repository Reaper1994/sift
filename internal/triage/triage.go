// Package triage runs one pass over a set of mailboxes: find untriaged inbox
// mail, redact it, classify it, and apply an Outlook category (plus a flag
// when it needs attention). It never moves, deletes, forwards or replies.
package triage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/Reaper1994/sift/internal/classifier"
	"github.com/Reaper1994/sift/internal/graph"
	"github.com/Reaper1994/sift/internal/httpx"
	"github.com/Reaper1994/sift/internal/redact"
)

// Mail is the subset of the Graph client the engine needs (eases testing).
type Mail interface {
	ListRecentInbox(ctx context.Context, mailbox string, since time.Time, max int) ([]graph.Message, error)
	GetBodyText(ctx context.Context, mailbox, id string) (string, error)
	Tag(ctx context.Context, mailbox, id string, categories []string, flag bool) error
	EnsureCategory(ctx context.Context, mailbox, name, color string) error
}

type Engine struct {
	Mail            Mail
	Classifier      classifier.Classifier
	Log             *slog.Logger
	InternalDomains []string
	ExcludeSenders  []string
	Lookback        time.Duration
	MaxPerRun       int
	MaxBodyChars    int
	Concurrency     int
	DryRun          bool
	Flag            bool
	Now             func() time.Time
}

type Stats struct {
	Seen, Skipped, Excluded, Tagged, Failed int
	// AuthFailed counts the mailboxes (included in Failed) whose provider
	// rejected Sift's sign-in; retrying soon won't fix those.
	AuthFailed int
	ByLabel    map[classifier.Label]int
}

func (e *Engine) EnsureCategories(ctx context.Context, mailboxes []string) {
	for _, mb := range mailboxes {
		for _, l := range classifier.AllLabels {
			c := classifier.Category[l]
			if err := e.Mail.EnsureCategory(ctx, mb, c.Name, c.Color); err != nil {
				e.Log.Warn("could not create coloured category (on Microsoft 365 this needs MailboxSettings.ReadWrite; labels still work)",
					"mailbox", hash(mb), "err", err)
				break
			}
		}
	}
}

func (e *Engine) Run(ctx context.Context, mailboxes []string) Stats {
	st := Stats{ByLabel: map[classifier.Label]int{}}
	var mu sync.Mutex
	sem := make(chan struct{}, e.Concurrency)
	var wg sync.WaitGroup
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}

	for _, mb := range mailboxes {
		if ctx.Err() != nil {
			break // shutting down: don't count every remaining mailbox as failed
		}
		msgs, err := e.Mail.ListRecentInbox(ctx, mb, now().Add(-e.Lookback), e.MaxPerRun)
		if err != nil {
			e.Log.Error("list inbox failed", "mailbox", hash(mb), "err", err)
			st.Failed++
			if errors.Is(err, httpx.ErrAuth) {
				st.AuthFailed++
			}
			continue
		}
		for _, m := range msgs {
			if ctx.Err() != nil {
				break
			}
			mu.Lock()
			st.Seen++
			mu.Unlock()
			if alreadyTriaged(m.Categories) {
				mu.Lock()
				st.Skipped++
				mu.Unlock()
				continue
			}
			if e.excluded(m.From.EmailAddress.Address) {
				mu.Lock()
				st.Excluded++
				mu.Unlock()
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(mb string, m graph.Message) {
				defer wg.Done()
				defer func() { <-sem }()
				label, err := e.one(ctx, mb, m)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					st.Failed++
					return
				}
				st.Tagged++
				st.ByLabel[label]++
			}(mb, m)
		}
	}
	wg.Wait()
	return st
}

func (e *Engine) one(ctx context.Context, mb string, m graph.Message) (classifier.Label, error) {
	log := e.Log.With("mailbox", hash(mb), "msg", hash(m.ID)) // identifiers hashed; content never logged

	body := m.Body.Content // Gmail lists bodies; Graph doesn't
	if body == "" {
		var err error
		if body, err = e.Mail.GetBodyText(ctx, mb, m.ID); err != nil {
			log.Warn("body fetch failed; using preview", "err", err)
			body = m.BodyPreview
		}
	}
	dom := redact.Domain(m.From.EmailAddress.Address)
	email := classifier.Email{
		FromDomain:     dom,
		SenderInternal: e.internal(dom),
		Subject:        redact.Text(m.Subject),
		Body:           redact.Body(body, e.MaxBodyChars),
		Importance:     m.Importance,
		Received:       m.ReceivedDateTime,
	}

	res, err := e.Classifier.Classify(ctx, email)
	if err != nil {
		log.Error("classify failed", "backend", e.Classifier.Name(), "err", err)
		return "", err
	}

	cats := append(append([]string{}, m.Categories...), classifier.Category[res.Label].Name)
	flag := e.Flag && res.Label.NeedsAttention()
	if e.DryRun {
		log.Info("dry-run", "label", res.Label, "confidence", round(res.Confidence), "flag", flag, "reason", res.Reason)
		return res.Label, nil
	}
	if err := e.Mail.Tag(ctx, mb, m.ID, cats, flag); err != nil {
		log.Error("tag failed", "err", err)
		return "", err
	}
	log.Info("tagged", "label", res.Label, "confidence", round(res.Confidence), "flag", flag, "reason", res.Reason)
	return res.Label, nil
}

func alreadyTriaged(cats []string) bool {
	for _, c := range cats {
		if strings.HasPrefix(c, classifier.CategoryPrefix) {
			return true
		}
	}
	return false
}

func (e *Engine) internal(domain string) bool {
	for _, d := range e.InternalDomains {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}

func (e *Engine) excluded(addr string) bool {
	addr = strings.ToLower(addr)
	dom := redact.Domain(addr)
	for _, x := range e.ExcludeSenders {
		if addr == x || dom == x || strings.HasSuffix(dom, "."+x) {
			return true
		}
	}
	return false
}

// hash gives a stable, non-reversible reference for logs.
func hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:6])
}

func round(f float64) float64 { return float64(int(f*100+0.5)) / 100 }
