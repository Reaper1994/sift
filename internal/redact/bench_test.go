package redact

import (
	"strings"
	"testing"
)

const benchPII = `Hi Sam, please wire the deposit. Email john.smith@broker.co.uk or call +44 20 7946 0958.
Card 4111 1111 1111 1111, IBAN GB82 WEST 1234 5698 7654 32, sort 12-34-56 acct 12345678.
NI: QQ 12 34 56 C. Policy ref 98765432101. See https://evil-login.example.com/reset?u=john`

var benchPlain = strings.Repeat("Thanks for the update, the team will review the proposal on Thursday and come back to you. ", 40)

var benchThread = benchPII + "\n" + benchPlain + "\n\nOn Mon, 12 Oct 2026, Jane wrote:\n> older text\n> more older text\n"

var sink string

func BenchmarkTextPII(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		sink = Text(benchPII)
	}
}

func BenchmarkTextPlain(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		sink = Text(benchPlain)
	}
}

func BenchmarkBodyThread(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		sink = Body(benchThread, 4000)
	}
}

func BenchmarkBodyShort(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		sink = Body("Quick question: can you approve the renewal today?", 4000)
	}
}
