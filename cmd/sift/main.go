// Command sift triages Microsoft 365 and Gmail mailboxes: it labels each new
// inbox message (Urgent, Action Required, Meeting, FYI, Newsletter, Suspicious,
// Review) and flags or stars the ones that need attention.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Reaper1994/sift/internal/classifier"
	"github.com/Reaper1994/sift/internal/config"
	"github.com/Reaper1994/sift/internal/demo"
	"github.com/Reaper1994/sift/internal/gmail"
	"github.com/Reaper1994/sift/internal/graph"
	"github.com/Reaper1994/sift/internal/triage"
)

var version = "dev"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version":
			fmt.Println("sift", version)
			return
		case "demo":
			// Simulated mailbox + simulated Jev; no credentials, no network.
			if err := demo.Run(context.Background(), os.Stdout); err != nil {
				fmt.Fprintln(os.Stderr, "demo failed:", err)
				os.Exit(1)
			}
			return
		case "gmail-login":
			if err := gmailLogin(); err != nil {
				fmt.Fprintln(os.Stderr, "gmail login failed:", err)
				os.Exit(1)
			}
			return
		case "help", "--help", "-h":
			fmt.Println("usage: sift [demo|gmail-login|version]\n\nWith no arguments, sift triages the mailboxes configured in sift.env.\n  demo         run against a simulated mailbox (no credentials, nothing sent)\n  gmail-login  sign in to Gmail and save the token to sift.env\n  version      print the version")
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown command %q (try: sift help)\n", os.Args[1])
			os.Exit(2)
		}
	}

	envPath := config.DefaultEnvFile()
	if found, err := config.LoadEnvFile(envPath); err != nil {
		log.Error("could not load config file", "path", envPath, "err", err)
		os.Exit(2)
	} else if found {
		log.Info("loaded config file", "path", envPath)
	}

	cfg, err := config.Load()
	if err != nil {
		log.Error("invalid configuration", "err", err)
		os.Exit(2)
	}

	var clf classifier.Classifier
	switch cfg.Backend {
	case "jev":
		j := classifier.NewJev(cfg.JevURL, cfg.JevAPIKey, cfg.JevModel)
		j.MinConfidence = cfg.JevMinConfidence
		clf = j
	case "ollama":
		clf = classifier.NewOllama(cfg.OllamaURL, cfg.OllamaModel)
	}

	var mail triage.Mail
	switch cfg.MailProvider {
	case "m365":
		mail = graph.New(cfg.TenantID, cfg.ClientID, cfg.ClientSecret)
	case "gmail":
		g := gmail.New(cfg.GmailClientID, cfg.GmailClientSecret, cfg.GmailRefreshToken)
		g.ExcludeSenders = cfg.ExcludeSenders
		g.Concurrency = cfg.Concurrency
		mail = g
	}

	eng := &triage.Engine{
		Mail:            mail,
		Classifier:      clf,
		Log:             log,
		InternalDomains: cfg.InternalDomains,
		ExcludeSenders:  cfg.ExcludeSenders,
		Lookback:        cfg.Lookback,
		MaxPerRun:       cfg.MaxPerRun,
		MaxBodyChars:    cfg.MaxBodyChars,
		Concurrency:     cfg.Concurrency,
		DryRun:          cfg.DryRun,
		Flag:            cfg.Flag,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("sift starting", "version", version, "provider", cfg.MailProvider, "backend", clf.Name(), "mailboxes", len(cfg.Mailboxes), "dry_run", cfg.DryRun)
	if !cfg.DryRun {
		eng.EnsureCategories(ctx, cfg.Mailboxes)
	}

	var authWait time.Duration // current back-off while every sign-in is rejected
	for {
		start := time.Now()
		st := eng.Run(ctx, cfg.Mailboxes)
		log.Info("pass complete", "seen", st.Seen, "tagged", st.Tagged, "skipped", st.Skipped,
			"excluded", st.Excluded, "failed", st.Failed, "by_label", st.ByLabel, "took", time.Since(start).Round(time.Millisecond).String())

		if cfg.PollInterval == 0 {
			if st.Failed > 0 {
				os.Exit(1)
			}
			return
		}
		wait := cfg.PollInterval
		if authStalled(st) {
			// Nothing worked and every failure was a rejected sign-in: polling
			// every few seconds can't fix that, it only floods the log and the
			// provider. Back off until a person signs in again.
			authWait = authBackoff(authWait, cfg.PollInterval)
			wait = authWait
			log.Warn("sign-in rejected; backing off",
				"next_try_in", wait.String(),
				"fix", "Gmail: run `sift gmail-login`; Microsoft 365: check the client secret. Then restart sift")
		} else {
			authWait = 0
		}
		select {
		case <-ctx.Done():
			log.Info("shutting down")
			return
		case <-time.After(wait):
		}
	}
}

// gmailLogin signs in with Google and saves the refresh token to sift.env. The
// token is never printed.
func gmailLogin() error {
	path := config.DefaultEnvFile()
	found, err := config.LoadEnvFile(path)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%s not found: copy sift.env.example to sift.env first", path)
	}
	id, secret := os.Getenv("SIFT_GMAIL_CLIENT_ID"), os.Getenv("SIFT_GMAIL_CLIENT_SECRET")
	if id == "" || secret == "" {
		return fmt.Errorf("set SIFT_GMAIL_CLIENT_ID and SIFT_GMAIL_CLIENT_SECRET in %s first", path)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	token, err := gmail.New(id, secret, "").Login(ctx, os.Stdout)
	if err != nil {
		return err
	}
	if err := config.SetEnvValue(path, "SIFT_GMAIL_REFRESH_TOKEN", token); err != nil {
		return err
	}
	fmt.Println("Signed in. Saved the token to", path)
	return nil
}

const (
	minAuthBackoff = time.Minute
	maxAuthBackoff = 30 * time.Minute
)

// authStalled reports whether a pass made no progress and every failure was a
// rejected sign-in.
func authStalled(st triage.Stats) bool {
	return st.AuthFailed > 0 && st.AuthFailed == st.Failed && st.Seen == 0
}

// authBackoff returns the next wait while sign-ins are rejected: it starts at
// a minute (or the poll interval, if longer) and doubles up to 30 minutes.
func authBackoff(prev, poll time.Duration) time.Duration {
	next := max(minAuthBackoff, poll)
	if prev > 0 {
		next = max(next, min(2*prev, maxAuthBackoff))
	}
	return next
}
