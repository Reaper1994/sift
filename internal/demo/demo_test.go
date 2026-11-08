package demo

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestDemoLabelsEveryKindAndRedacts(t *testing.T) {
	var out bytes.Buffer
	if err := Run(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{"Urgent", "Action Required", "Suspicious", "Meeting", "Newsletter", "FYI", "Review", "Triaged 7 messages"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in output:\n%s", want, s)
		}
	}
	if strings.Contains(s, "verify?u=you") || !strings.Contains(s, "[link:example-login.net]") {
		t.Errorf("phishing link not redacted:\n%s", s)
	}
}
