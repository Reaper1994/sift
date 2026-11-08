// Package redact removes personal and financial identifiers from email text
// before it is sent to a classifier. None of these are needed to decide
// whether a message is urgent, a meeting, or phishing.
package redact

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
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
)

// Text redacts identifiers but keeps the domain of links and addresses, which
// is a useful phishing signal (e.g. "paypa1-secure.com").
//
// Each pattern is only run when the text could possibly contain a match: an
// address needs '@', a link needs "://", and the numeric patterns need a
// minimum number of digits. The gates are necessary conditions of the regexps,
// so the output is identical to running every pattern unconditionally; they
// only skip work (replacements never add digits, so counting once is safe).
func Text(s string) string {
	digits := countDigits(s)
	if strings.Contains(s, "://") {
		s = reURL.ReplaceAllString(s, "[link:$1]")
	}
	if strings.Contains(s, "@") {
		s = reEmail.ReplaceAllString(s, "[email@$1]")
	}
	if digits >= 2 { // IBAN: two check digits
		s = reIBAN.ReplaceAllString(s, "[iban]")
	}
	if digits >= 6 { // NINO and sort code: six digits
		s = reNINO.ReplaceAllString(s, "[ni-number]")
		s = reSortAcct.ReplaceAllString(s, "[bank-details]")
	}
	if digits >= 13 {
		s = reCardLike.ReplaceAllStringFunc(s, func(m string) string {
			if luhn(m) {
				return "[card]"
			}
			return m
		})
	}
	if digits >= 8 {
		s = reLongNum.ReplaceAllString(s, "[number]")
		s = rePhone.ReplaceAllString(s, "[phone]")
	}
	return s
}

// countDigits counts ASCII digits, the only runes \d matches in RE2.
func countDigits(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			n++
		}
	}
	return n
}

// Body redacts, strips quoted reply history and long signatures, compacts
// whitespace and truncates to max runes.
func Body(s string, max int) string {
	s = stripQuoted(s)
	s = Text(s)
	s = compact(strings.TrimSpace(compactSpaces(s)))
	if max < 0 {
		max = 0
	}
	if utf8.RuneCountInString(s) > max {
		if !utf8.ValidString(s) { // keep the []rune conversion's U+FFFD substitution
			return string([]rune(s)[:max]) + " […]"
		}
		cut := 0
		for n := 0; n < max; n++ {
			_, w := utf8.DecodeRuneInString(s[cut:])
			cut += w
		}
		s = s[:cut] + " […]"
	}
	return s
}

// compactSpaces replaces each run of two or more spaces or tabs with one
// space (the same as regexp `[ \t]{2,}` -> " ").
func compactSpaces(s string) string {
	i := strings.IndexAny(s, " \t")
	for i >= 0 && !(i+1 < len(s) && (s[i+1] == ' ' || s[i+1] == '\t')) {
		j := strings.IndexAny(s[i+1:], " \t")
		if j < 0 {
			return s
		}
		i += 1 + j
	}
	if i < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	b.WriteString(s[:i])
	for i < len(s) {
		if s[i] != ' ' && s[i] != '\t' {
			b.WriteByte(s[i])
			i++
			continue
		}
		j := i
		for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
			j++
		}
		if j-i >= 2 {
			b.WriteByte(' ')
		} else {
			b.WriteByte(s[i])
		}
		i = j
	}
	return b.String()
}

// compact replaces each run of three or more newlines with two (the same as
// regexp `\n{3,}` -> "\n\n").
func compact(s string) string {
	if !strings.Contains(s, "\n\n\n") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '\n' {
			b.WriteByte(s[i])
			i++
			continue
		}
		j := i
		for j < len(s) && s[j] == '\n' {
			j++
		}
		n := j - i
		if n >= 3 {
			n = 2
		}
		for ; n > 0; n-- {
			b.WriteByte('\n')
		}
		i = j
	}
	return b.String()
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
	s = s[:cut]
	if !strings.Contains(s, ">") {
		return s // no quoted lines: nothing to drop, no allocation
	}
	var b strings.Builder
	first := true
	for line := range strings.SplitSeq(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), ">") {
			continue
		}
		if !first {
			b.WriteByte('\n')
		}
		first = false
		b.WriteString(line)
	}
	return b.String()
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
