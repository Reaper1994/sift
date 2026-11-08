// Package classifier turns an email into one triage label. Two backends are
// provided: Jev (TypeSafe's hosted System One model, the default) and a local
// Ollama model for fully on-network operation.
//
// In both, email content is untrusted data. A backend's only possible effect
// is picking a label from the fixed set below — it cannot trigger any other
// action, so a prompt-injection attempt can at worst mislabel one message.
package classifier

import (
	"context"
	"strings"
	"time"
)

type Label string

const (
	Urgent         Label = "urgent"
	ActionRequired Label = "action_required"
	Meeting        Label = "meeting"
	FYI            Label = "fyi"
	Newsletter     Label = "newsletter"
	Suspicious     Label = "suspicious"
	Review         Label = "review" // model wasn't confident enough to decide
)

var AllLabels = []Label{Urgent, ActionRequired, Meeting, FYI, Newsletter, Suspicious, Review}

// Category is the Outlook category name and colour preset for each label.
var Category = map[Label]struct{ Name, Color string }{
	Urgent:         {"Sift: Urgent", "preset0"},          // red
	ActionRequired: {"Sift: Action Required", "preset1"}, // orange
	Meeting:        {"Sift: Meeting", "preset7"},         // blue
	FYI:            {"Sift: FYI", "preset4"},             // green
	Newsletter:     {"Sift: Newsletter", "preset12"},     // grey
	Suspicious:     {"Sift: Suspicious", "preset9"},      // cranberry
	Review:         {"Sift: Review", "preset3"},          // yellow
}

// CategoryPrefix marks messages Sift has already processed.
const CategoryPrefix = "Sift: "

// NeedsAttention reports whether a label should also flag the message.
func (l Label) NeedsAttention() bool { return l == Urgent || l == ActionRequired }

// Email is the (already redacted) view of a message a backend is allowed to see.
type Email struct {
	FromDomain     string
	SenderInternal bool
	Subject        string
	Body           string
	Importance     string
	Received       time.Time
}

type Result struct {
	Label      Label
	Confidence float64 // 0–1; Ollama backend reports 1 (no calibrated confidence)
	Reason     string  // short, non-sensitive explanation for audit logs
}

type Classifier interface {
	Classify(ctx context.Context, e Email) (Result, error)
	Name() string
}

// sanitize drops control characters that could confuse downstream parsing.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, s)
}
