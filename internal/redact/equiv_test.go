package redact

import (
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"
)

// The reference implementation below is the original, unoptimised redaction:
// every pattern runs on every input. The optimised Text and Body must produce
// byte-identical output, which proves the speed-ups cannot let more through.
var (
	refEmail    = regexp.MustCompile(`[\p{L}\p{N}._%+\-]+@([\p{L}\p{N}.\-]+\.\p{L}{2,})`)
	refURL      = regexp.MustCompile(`(?i)\bhttps?://([^/\s:?#]+)[^\s<>"')\]]*`)
	refWWW      = regexp.MustCompile(`(?i)(^|[^\w@.\-/:])(www\.[^/\s:?#]+)[^\s<>"')\]]*`)
	refIBAN     = regexp.MustCompile(`\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?\b`)
	refSSN      = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	refDOB      = regexp.MustCompile(`\b(?:\d{1,2}/\d{1,2}/(?:\d{2}|(?:19\d|20[01])\d)|(?:19\d|20[01])\d-\d{2}-\d{2})\b`)
	refNINO     = regexp.MustCompile(`(?i)\b[A-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b`)
	refSortAcct = regexp.MustCompile(`\b\d{2}-\d{2}-\d{2}\b(?:\D{0,20}\b\d{8}\b)?`)
	refCardLike = regexp.MustCompile(`\b(?:\d[ \-]?){13,19}\b`)
	refPhone    = regexp.MustCompile(`(?:\+\d{1,3}[\s\-]?)?(?:\(?\d{2,5}\)?[\s\-]?)\d{3,4}[\s\-]?\d{3,4}\b`)
	refLongNum  = regexp.MustCompile(`\b\d{7,}\b`)
	refSpaces   = regexp.MustCompile(`[ \t]{2,}`)
	refBlank    = regexp.MustCompile(`\n{3,}`)
)

func refText(s string) string {
	s = refWWW.ReplaceAllString(s, "$1[link:$2]")
	s = refURL.ReplaceAllString(s, "[link:$1]")
	s = refEmail.ReplaceAllString(s, "[email@$1]")
	s = refIBAN.ReplaceAllString(s, "[iban]")
	s = refDOB.ReplaceAllString(s, "[date-of-birth]")
	s = refSSN.ReplaceAllString(s, "[ssn]")
	s = refNINO.ReplaceAllString(s, "[ni-number]")
	s = refSortAcct.ReplaceAllString(s, "[bank-details]")
	s = refCardLike.ReplaceAllStringFunc(s, func(m string) string {
		if luhn(m) {
			return "[card]"
		}
		return m
	})
	s = refLongNum.ReplaceAllString(s, "[number]")
	s = refPhone.ReplaceAllString(s, "[phone]")
	return s
}

func refStripQuoted(s string) string {
	markers := []string{"\nFrom: ", "\n-----Original Message-----", "\n________________________________", "\nOn "}
	cut := len(s)
	for _, m := range markers {
		i := strings.Index(s, m)
		if i < 0 || i >= cut {
			continue
		}
		if m == "\nOn " {
			line := s[i+1:]
			if nl := strings.IndexByte(line, '\n'); nl >= 0 {
				line = line[:nl]
			}
			if !strings.Contains(line, "wrote:") {
				continue
			}
		}
		cut = i
	}
	lines := strings.Split(s[:cut], "\n")
	out := lines[:0]
	for _, l := range lines {
		if !strings.HasPrefix(strings.TrimSpace(l), ">") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func refBody(s string, max int) string {
	s = refStripQuoted(s)
	s = refText(s)
	s = refSpaces.ReplaceAllString(s, " ")
	s = refBlank.ReplaceAllString(strings.TrimSpace(s), "\n\n")
	if r := []rune(s); len(r) > max {
		s = string(r[:max]) + " […]"
	}
	return s
}

var fragments = []string{
	"john@acme.co.uk", "a@b", "@", "http://x.example.com/p?q=1", "HTTPS://Evil.COM:99/a", "://", "mailto:x@y.org", "www.Example.com/x?y=1", "WWW.", "a@www.b.com", "https://www.c.com/p", "jürgen@münchen.de",
	"4111 1111 1111 1111", "4111-1111-1111-1112", "12345678", "1234567", "98765432101", "12-34-56", "12-34-56 acct 12345678",
	"GB82 WEST 1234 5698 7654 32", "GB82WEST12345698765432", "DE89", "QQ 12 34 56 C", "qq123456c",
	"+44 20 7946 0958", "(415) 555-2671", "020 7946 0958", "07700 900123", "5", "42", "2026", "2026-11-08", "1980-02-01", "01/02/1980", "1/2/80", "123-45-6789", "10:30", "$12.50",
	" ", "  ", "   ", "\t", "\t\t", " \t ", "\n", "\n\n", "\n\n\n", "\n\n\n\n\n", "\r\n", "> quoted", "\n> q\n", "\nOn Mon, X wrote:\n",
	"\nOn track\n", "\nFrom: a\n", "\n-----Original Message-----\n", "hello", "Thanks", "é", "日本語", "[ ]", "x",
}

func randomText(r *rand.Rand) string {
	var b strings.Builder
	for n := r.IntN(14); n >= 0; n-- {
		b.WriteString(fragments[r.IntN(len(fragments))])
		if r.IntN(3) == 0 {
			b.WriteByte(" \n-.,"[r.IntN(5)])
		}
	}
	return b.String()
}

func TestOptimisedMatchesReference(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	inputs := []string{"", benchPII, benchPlain, benchThread}
	for _, tc := range leakCases {
		inputs = append(inputs, tc.in)
	}
	for range 2500 {
		inputs = append(inputs, randomText(r))
	}
	for _, in := range inputs {
		if got, want := Text(in), refText(in); got != want {
			t.Fatalf("Text(%q)\n got %q\nwant %q", in, got, want)
		}
		for _, max := range []int{0, 1, 7, 60, 4000} {
			if got, want := Body(in, max), refBody(in, max); got != want {
				t.Fatalf("Body(%q, %d)\n got %q\nwant %q", in, max, got, want)
			}
		}
	}
}

func FuzzOptimisedMatchesReference(f *testing.F) {
	for _, s := range fragments {
		f.Add(s)
	}
	f.Add(benchPII)
	f.Fuzz(func(t *testing.T, in string) {
		if got, want := Text(in), refText(in); got != want {
			t.Fatalf("Text mismatch for %q: %q vs %q", in, got, want)
		}
		if got, want := Body(in, 50), refBody(in, 50); got != want {
			t.Fatalf("Body mismatch for %q: %q vs %q", in, got, want)
		}
	})
}
