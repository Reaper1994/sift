// Package config loads and validates runtime settings from the environment.
// Secrets are only read from env vars (inject them from Azure Key Vault or
// your secrets manager), never from files in the repo.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	MailProvider string // "m365" or "gmail"

	// Microsoft Graph (Entra app registration, client-credentials flow)
	TenantID, ClientID, ClientSecret string
	// Gmail (Google OAuth desktop client; `sift gmail-login` sets the refresh token)
	GmailClientID, GmailClientSecret, GmailRefreshToken string
	// Mailboxes to triage. On Microsoft 365 the app must ALSO be scoped in
	// Exchange to exactly these mailboxes (RBAC for Applications) — see README.
	// Gmail takes one, the account the refresh token belongs to.
	Mailboxes []string
	// Your organisation's email domains; used to mark senders internal/external.
	InternalDomains []string
	// Sender domains/addresses never sent to the classifier (e.g. HR, legal).
	ExcludeSenders []string

	Backend string // "jev" or "ollama"

	// Jev (TypeSafe hosted API)
	JevURL, JevAPIKey, JevModel string
	JevMinConfidence            float64
	// Explicit acknowledgement that redacted mail content will be processed
	// by TypeSafe (a third-party sub-processor). Required for the jev backend.
	ExternalProcessingApproved bool

	// Ollama (self-hosted)
	OllamaURL, OllamaModel string
	AllowRemoteOllama      bool

	Lookback     time.Duration
	PollInterval time.Duration // 0 = run once and exit (cron / k8s CronJob)
	MaxPerRun    int
	MaxBodyChars int
	Concurrency  int
	DryRun       bool
	Flag         bool // flag urgent/action-required messages for follow-up
}

func Load() (*Config, error) {
	c := &Config{
		MailProvider:               strings.ToLower(envOr("SIFT_MAIL_PROVIDER", "m365")),
		TenantID:                   os.Getenv("SIFT_TENANT_ID"),
		ClientID:                   os.Getenv("SIFT_CLIENT_ID"),
		ClientSecret:               os.Getenv("SIFT_CLIENT_SECRET"),
		GmailClientID:              os.Getenv("SIFT_GMAIL_CLIENT_ID"),
		GmailClientSecret:          os.Getenv("SIFT_GMAIL_CLIENT_SECRET"),
		GmailRefreshToken:          os.Getenv("SIFT_GMAIL_REFRESH_TOKEN"),
		Mailboxes:                  splitList(os.Getenv("SIFT_MAILBOXES")),
		InternalDomains:            lower(splitList(os.Getenv("SIFT_INTERNAL_DOMAINS"))),
		ExcludeSenders:             lower(splitList(os.Getenv("SIFT_EXCLUDE_SENDERS"))),
		Backend:                    strings.ToLower(envOr("SIFT_BACKEND", "jev")),
		JevURL:                     envOr("SIFT_JEV_URL", "https://api.typesafe.ai"),
		JevAPIKey:                  os.Getenv("TYPESAFE_API_KEY"),
		JevModel:                   envOr("SIFT_JEV_MODEL", "jev-latest"),
		ExternalProcessingApproved: envBool("SIFT_EXTERNAL_PROCESSING_APPROVED"),
		OllamaURL:                  envOr("SIFT_OLLAMA_URL", "http://127.0.0.1:11434"),
		OllamaModel:                envOr("SIFT_OLLAMA_MODEL", "llama3.1:8b"),
		AllowRemoteOllama:          envBool("SIFT_ALLOW_REMOTE_OLLAMA"),
		DryRun:                     envBool("SIFT_DRY_RUN"),
		Flag:                       envOr("SIFT_FLAG", "true") == "true",
	}
	var errs []error
	get := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	var err error
	c.Lookback, err = envDur("SIFT_LOOKBACK", 24*time.Hour)
	get(err)
	c.PollInterval, err = envDur("SIFT_POLL_INTERVAL", 0)
	get(err)
	c.MaxPerRun, err = envInt("SIFT_MAX_PER_RUN", 50)
	get(err)
	c.MaxBodyChars, err = envInt("SIFT_MAX_BODY_CHARS", 3000)
	get(err)
	c.Concurrency, err = envInt("SIFT_CONCURRENCY", 4)
	get(err)
	c.JevMinConfidence, err = envFloat("SIFT_JEV_MIN_CONFIDENCE", 0.5)
	get(err)
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, c.Validate()
}

func (c *Config) Validate() error {
	var errs []error
	req := func(name, v string) {
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}
	if len(c.Mailboxes) == 0 {
		errs = append(errs, errors.New("SIFT_MAILBOXES is required (comma-separated)"))
	}
	switch c.MailProvider {
	case "m365":
		req("SIFT_TENANT_ID", c.TenantID)
		req("SIFT_CLIENT_ID", c.ClientID)
		req("SIFT_CLIENT_SECRET", c.ClientSecret)
		if len(c.InternalDomains) == 0 {
			errs = append(errs, errors.New("SIFT_INTERNAL_DOMAINS is required (e.g. example.com)"))
		}
	case "gmail":
		req("SIFT_GMAIL_CLIENT_ID", c.GmailClientID)
		req("SIFT_GMAIL_CLIENT_SECRET", c.GmailClientSecret)
		if c.GmailRefreshToken == "" {
			errs = append(errs, errors.New("SIFT_GMAIL_REFRESH_TOKEN is required: run `sift gmail-login`"))
		}
		if len(c.Mailboxes) > 1 {
			errs = append(errs, errors.New("the gmail provider handles one account: list only that address in SIFT_MAILBOXES"))
		}
	default:
		errs = append(errs, fmt.Errorf("SIFT_MAIL_PROVIDER must be m365 or gmail, got %q", c.MailProvider))
	}
	if c.Concurrency < 1 || c.Concurrency > 16 || c.MaxPerRun < 1 || c.MaxBodyChars < 200 {
		errs = append(errs, errors.New("need 1<=SIFT_CONCURRENCY<=16, SIFT_MAX_PER_RUN>=1, SIFT_MAX_BODY_CHARS>=200"))
	}

	switch c.Backend {
	case "jev":
		req("TYPESAFE_API_KEY", c.JevAPIKey)
		if !c.ExternalProcessingApproved {
			errs = append(errs, errors.New("the jev backend sends redacted email content to TypeSafe (US). "+
				"Set SIFT_EXTERNAL_PROCESSING_APPROVED=true once your DPO/security team has approved it, or use SIFT_BACKEND=ollama"))
		}
		if u, err := url.Parse(c.JevURL); err != nil || u.Scheme != "https" || u.Hostname() == "" {
			errs = append(errs, fmt.Errorf("SIFT_JEV_URL must be an https URL, got %q", c.JevURL))
		}
		if c.JevMinConfidence < 0 || c.JevMinConfidence > 1 {
			errs = append(errs, errors.New("SIFT_JEV_MIN_CONFIDENCE must be between 0 and 1"))
		}
	case "ollama":
		if err := CheckPrivateURL(c.OllamaURL, c.AllowRemoteOllama); err != nil {
			errs = append(errs, err)
		}
	default:
		errs = append(errs, fmt.Errorf("SIFT_BACKEND must be jev or ollama, got %q", c.Backend))
	}
	return errors.Join(errs...)
}

// CheckPrivateURL ensures the self-hosted model really is on your network, so
// a typo can't silently send mail to an outside server.
func CheckPrivateURL(raw string, allowRemote bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("SIFT_OLLAMA_URL %q is not a valid URL", raw)
	}
	if allowRemote {
		return nil
	}
	host := u.Hostname()
	ips := []net.IP{net.ParseIP(host)}
	if ips[0] == nil {
		addrs, err := net.LookupIP(host)
		if err != nil {
			return fmt.Errorf("SIFT_OLLAMA_URL host %q does not resolve: %w", host, err)
		}
		ips = addrs
	}
	for _, ip := range ips {
		if !(ip.IsLoopback() || ip.IsPrivate()) {
			return fmt.Errorf("SIFT_OLLAMA_URL %q resolves to public address %s; refusing (set SIFT_ALLOW_REMOTE_OLLAMA=true to override)", raw, ip)
		}
	}
	return nil
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envBool(k string) bool { b, _ := strconv.ParseBool(os.Getenv(k)); return b }

func envInt(k string, def int) (int, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", k, err)
	}
	return n, nil
}

func envFloat(k string, def float64) (float64, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", k, err)
	}
	return f, nil
}

func envDur(k string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", k, err)
	}
	return d, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func lower(in []string) []string {
	for i := range in {
		in[i] = strings.ToLower(in[i])
	}
	return in
}
