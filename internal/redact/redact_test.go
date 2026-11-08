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
