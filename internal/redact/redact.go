// Package redact removes personal and financial identifiers from email text
// before it is sent to a classifier. None of these are needed to decide
// whether a message is urgent, a meeting, or phishing.
package redact

import (
	"regexp"
	"strings"
	"unicode"
)

var (
	reEmail    = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@([a-z0-9.\-]+\.[a-z]{2,})`)
	reURL      = regexp.MustCompile(`(?i)\bhttps?://([^/\s:?#]+)[^\s<>"')\]]*`)
	reIBAN     = regexp.MustCompile(`\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?\b`)
	reNINO     = regexp.MustCompile(`(?i)\b[A-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b`) // over-matches on purpose
	reSortAcct = regexp.MustCompile(`\b\d{2}-\d{2}-\d{2}\b(?:\D{0,20}\b\d{8}\b)?`)
	reCardLike = regexp.MustCompile(`\b(?:\d[ \-]?){13,19}\b`)
	rePhone    = regexp.MustCompile(`(?:\+\d{1,3}[\s\-]?)?(?:\(?\d{2,5}\)?[\s\-]?)\d{3,4}[\s\-]?\d{3,4}\b`)
	reLongNum  = regexp.MustCompile(`\b\d{8,}\b`) // account / policy / reference numbers
	reSpaces   = regexp.MustCompile(`[ \t]{2,}`)
	reBlank    = regexp.MustCompile(`\n{3,}`)
)

// Text redacts identifiers but keeps the domain of links and addresses, which
// is a useful phishing signal (e.g. "paypa1-secure.com").
func Text(s string) string {
	s = reURL.ReplaceAllString(s, "[link:$1]")
	s = reEmail.ReplaceAllString(s, "[email@$1]")
	s = reIBAN.ReplaceAllString(s, "[iban]")
	s = reNINO.ReplaceAllString(s, "[ni-number]")
	s = reSortAcct.ReplaceAllString(s, "[bank-details]")
	s = reCardLike.ReplaceAllStringFunc(s, func(m string) string {
		if luhn(m) {
			return "[card]"
		}
		return m
	})
	s = reLongNum.ReplaceAllString(s, "[number]")
	s = rePhone.ReplaceAllString(s, "[phone]")
	return s
}

// Body redacts, strips quoted reply history and long signatures, compacts
// whitespace and truncates to max runes.
func Body(s string, max int) string {
	s = stripQuoted(s)
	s = Text(s)
	s = reSpaces.ReplaceAllString(s, " ")
	s = reBlank.ReplaceAllString(strings.TrimSpace(s), "\n\n")
	if r := []rune(s); len(r) > max {
		s = string(r[:max]) + " […]"
	}
	return s
}

// stripQuoted drops earlier messages in a thread: they were classified when
// they arrived and only add exposure.
func stripQuoted(s string) string {
	markers := []string{"\nFrom: ", "\n-----Original Message-----", "\n________________________________", "\nOn "}
	cut := len(s)
	for _, m := range markers {
		i := strings.Index(s, m)
		if i < 0 || i >= cut {
			continue
		}
		if m == "\nOn " { // only cut at "On <date>, <name> wrote:"
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

func luhn(s string) bool {
	var digits []int
	for _, r := range s {
		if unicode.IsDigit(r) {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 {
		return false
	}
	sum := 0
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if (len(digits)-1-i)%2 == 1 {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

// Domain returns the lower-cased domain of an email address ("" if none).
func Domain(addr string) string {
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		return strings.ToLower(strings.TrimSpace(addr[i+1:]))
	}
	return ""
}
