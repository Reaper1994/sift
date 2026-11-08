package config

import (
	"strings"
	"testing"
)

func base() *Config {
	return &Config{
		MailProvider: "m365", TenantID: "t", ClientID: "c", ClientSecret: "s",
		Mailboxes: []string{"a@x.com"}, InternalDomains: []string{"x.com"},
		Backend: "jev", JevURL: "https://api.typesafe.ai", JevAPIKey: "k", JevMinConfidence: 0.5,
		ExternalProcessingApproved: true,
		OllamaURL:                  "http://127.0.0.1:11434",
		Concurrency:                2, MaxPerRun: 10, MaxBodyChars: 1000,
	}
}

func TestValidBase(t *testing.T) {
	if err := base().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestJevRequiresExplicitApproval(t *testing.T) {
	c := base()
	c.ExternalProcessingApproved = false
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "SIFT_EXTERNAL_PROCESSING_APPROVED") {
		t.Fatalf("got %v", err)
	}
}

func TestJevRequiresHTTPS(t *testing.T) {
	c := base()
	c.JevURL = "http://api.typesafe.ai"
	if c.Validate() == nil {
		t.Fatal("accepted plain http")
	}
}

func TestOllamaMustBePrivate(t *testing.T) {
	for _, u := range []string{"http://127.0.0.1:11434", "http://10.1.2.3:11434", "http://192.168.0.5"} {
		if err := CheckPrivateURL(u, false); err != nil {
			t.Errorf("%s rejected: %v", u, err)
		}
	}
	if CheckPrivateURL("http://8.8.8.8:11434", false) == nil {
		t.Error("public IP accepted")
	}
	if CheckPrivateURL("http://8.8.8.8:11434", true) != nil {
		t.Error("override ignored")
	}
}

func TestUnknownBackend(t *testing.T) {
	c := base()
	c.Backend = "gpt"
	if c.Validate() == nil {
		t.Fatal("accepted unknown backend")
	}
}

func gmailBase() *Config {
	c := base()
	c.MailProvider, c.TenantID, c.ClientID, c.ClientSecret, c.InternalDomains = "gmail", "", "", "", nil
	c.GmailClientID, c.GmailClientSecret, c.GmailRefreshToken = "id", "secret", "refresh"
	return c
}

func TestGmailNeedsNoMicrosoftSettings(t *testing.T) {
	if err := gmailBase().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestGmailRequiresLogin(t *testing.T) {
	c := gmailBase()
	c.GmailRefreshToken = ""
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "sift gmail-login") {
		t.Fatalf("got %v", err)
	}
}

func TestGmailTakesOneMailbox(t *testing.T) {
	c := gmailBase()
	c.Mailboxes = []string{"a@gmail.com", "b@gmail.com"}
	if c.Validate() == nil {
		t.Fatal("accepted two Gmail accounts")
	}
}

func TestUnknownMailProvider(t *testing.T) {
	c := base()
	c.MailProvider = "yahoo"
	if c.Validate() == nil {
		t.Fatal("accepted unknown provider")
	}
}
