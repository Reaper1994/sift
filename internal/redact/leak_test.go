package redact

import (
	"strings"
	"testing"
)

// leakCases pairs inputs with the sensitive substrings that must never survive
// Text or Body. These guard the rule that no personal data reaches the AI.
var leakCases = []struct {
	name, in string
	secrets  []string
}{
	{"email", "write to jane.doe+x@Corp-Mail.example.org now", []string{"jane.doe", "+x@"}},
	{"url path and query", "go to HTTP://Pay.Example.com/acct/9981?token=abc123def", []string{"acct/9981", "token=abc123def"}},
	{"url with port", "https://host.example.com:8443/secret/path", []string{"secret/path", "8443"}},
	{"iban", "IBAN DE89 3704 0044 0532 0130 00 thanks", []string{"3704", "0532", "DE89"}},
	{"compact iban", "GB82WEST12345698765432", []string{"WEST1234", "98765432"}},
	{"card spaces", "pay with 4111 1111 1111 1111 today", []string{"4111"}},
	{"card dashes", "pay with 5500-0000-0000-0004 today", []string{"5500", "0004"}},
	{"nino", "NI number qq123456c", []string{"123456"}},
	{"sort and account", "sort code 20-00-00 account 55779911", []string{"20-00-00", "55779911"}},
	{"phone intl", "ring +1 (415) 555-2671", []string{"555-2671", "415"}},
	{"phone uk", "ring 020 7946 0958", []string{"7946", "0958"}},
	{"long number", "reference 123456789012", []string{"123456789012"}},
	{"mixed line", "Contact a@b.co, 07700 900123, ref 99887766", []string{"a@b.co", "900123", "99887766"}},
}

func TestNoPIILeaks(t *testing.T) {
	for _, tc := range leakCases {
		t.Run(tc.name, func(t *testing.T) {
			for fn, out := range map[string]string{"Text": Text(tc.in), "Body": Body(tc.in, 4000)} {
				for _, s := range tc.secrets {
					if strings.Contains(strings.ToLower(out), strings.ToLower(s)) {
						t.Errorf("%s leaked %q: %s", fn, s, out)
					}
				}
			}
		})
	}
}
