package redact

import (
	"strings"
	"testing"
)

func TestTextRedactsIdentifiers(t *testing.T) {
	in := `Hi, email john.smith@broker.co.uk or call +44 20 7946 0958.
Card 4111 1111 1111 1111, IBAN GB82 WEST 1234 5698 7654 32, sort 12-34-56 acct 12345678.
NI: QQ 12 34 56 C. Policy ref 98765432101. See https://evil-login.example.com/reset?u=john`
	out := Text(in)
	for _, leak := range []string{"john.smith", "7946", "4111", "GB82", "12-34-56", "12345678", "QQ 12", "98765432101", "reset?u=john"} {
		if strings.Contains(out, leak) {
			t.Errorf("leaked %q in: %s", leak, out)
		}
	}
	for _, keep := range []string{"[email@broker.co.uk]", "[link:evil-login.example.com]", "[card]", "[iban]", "[ni-number]"} {
		if !strings.Contains(out, keep) {
			t.Errorf("expected %q in: %s", keep, out)
		}
	}
}

func TestNonLuhnNumbersNotCalledCards(t *testing.T) {
	if got := Text("order 1234 5678 9012 3456"); strings.Contains(got, "[card]") {
		t.Errorf("non-Luhn number marked as card: %s", got)
	}
}

func TestBodyStripsThreadAndTruncates(t *testing.T) {
	in := "Please approve the contract renewal today.\n\nOn Mon, 12 Oct 2026, Jane wrote:\n> older text\nsecret history"
	out := Body(in, 1000)
	if strings.Contains(out, "secret history") || strings.Contains(out, "older text") {
		t.Errorf("quoted history not stripped: %q", out)
	}
	if !strings.Contains(out, "approve the contract") {
		t.Errorf("lost the new message: %q", out)
	}
	long := strings.Repeat("a", 500)
	if got := Body(long, 100); len([]rune(got)) > 110 {
		t.Errorf("not truncated: %d", len(got))
	}
}

func TestOnLineWithoutWroteIsKept(t *testing.T) {
	in := "Status update.\nOn track for Friday."
	if out := Body(in, 1000); !strings.Contains(out, "On track") {
		t.Errorf("cut a normal line starting with 'On': %q", out)
	}
}

func TestDomain(t *testing.T) {
	if Domain("A.B@Example.COM") != "example.com" || Domain("nope") != "" {
		t.Fatal("Domain broken")
	}
}

func TestTextRedactsNewIdentifiers(t *testing.T) {
	for _, tc := range []struct{ in, leak, want string }{
		{"SSN 123-45-6789 on file", "123-45-6789", "[ssn]"},
		{"born 01/02/1980.", "01/02/1980", "[date-of-birth]"},
		{"DOB 1/2/80", "1/2/80", "[date-of-birth]"},
		{"DOB: 1980-02-01", "1980-02-01", "[date-of-birth]"},
		{"see www.evil-login.example.com/reset?u=john now", "reset?u=john", "[link:www.evil-login.example.com]"},
		{"(WWW.Example.com/a)", "/a", "[link:WWW.Example.com]"},
		{"mail jürgen.müller@bücher.de today", "jürgen", "[email@bücher.de]"},
		{"write to 山田@例え.jp", "山田", "[email@例え.jp]"},
		{"account 1234567 please", "1234567", "[number]"},
		{"account 12345678 please", "12345678", "[number]"},
	} {
		out := Text(tc.in)
		if strings.Contains(out, tc.leak) {
			t.Errorf("Text(%q) leaked %q: %s", tc.in, tc.leak, out)
		}
		if !strings.Contains(out, tc.want) {
			t.Errorf("Text(%q) = %q, want %q", tc.in, out, tc.want)
		}
	}
}

func TestTextKeepsOrdinaryText(t *testing.T) {
	for _, in := range []string{
		"Meeting at 10:30 or 14:45 tomorrow.",
		"Price is $12.50, or £1,299.99 for 12 months.",
		"Order 123456 shipped; room 4-12; version 1.25.3.",
		"Review due 2026-11-20 and 20/11/2026.",
		"Half of 3/4 is 3/8.",
		"Email a@www.example.com about https://www.example.com/x",
	} {
		out := Text(in)
		if strings.Contains(out, "[ssn]") || strings.Contains(out, "[date-of-birth]") || strings.Contains(out, "[number]") || strings.Contains(out, "[phone]") {
			t.Errorf("over-redacted %q: %q", in, out)
		}
	}
	if got := Text("Email a@www.example.com"); got != "Email [email@www.example.com]" {
		t.Errorf("www inside an address: %q", got)
	}
	if got := Text("go to https://www.example.com/x"); got != "go to [link:www.example.com]" {
		t.Errorf("www inside a URL: %q", got)
	}
}
