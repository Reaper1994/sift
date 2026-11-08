package classifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Reaper1994/sift/internal/httpx"
)

// Jev calls TypeSafe's System One API (POST /v1/systemone).
//
// Instead of one big "classify this" prompt, it asks four small, independent
// questions in a single request — the pattern TypeSafe recommends — and
// combines the typed answers with plain Go logic in Decide.
type Jev struct {
	BaseURL string
	APIKey  string
	Model   string
	HTTP    *http.Client

	// MinConfidence below which the category answer is sent to Review.
	MinConfidence float64
	// PhishingThreshold: probability above which a message is Suspicious.
	PhishingThreshold float64
	MaxRetries        int
}

func NewJev(baseURL, apiKey, model string) *Jev {
	return &Jev{
		BaseURL: strings.TrimRight(baseURL, "/"), APIKey: apiKey, Model: model,
		HTTP:          httpx.NewClient(20 * time.Second),
		MinConfidence: 0.5, PhishingThreshold: 0.7, MaxRetries: 4,
	}
}

func (j *Jev) Name() string { return "jev" }

// Answers from the API. Only the fields Sift uses are decoded.
type jevChoice struct {
	Choice     string  `json:"choice"`
	Confidence float64 `json:"confidence"`
}
type jevScore struct {
	Score      float64 `json:"score"`
	Confidence float64 `json:"confidence"`
}
type jevNoul struct {
	Noul float64 `json:"noul"`
}

// JevAnswers is the typed result of one evaluation.
type JevAnswers struct {
	Category   jevChoice
	Urgency    jevScore // 0 = none, 1 = this week, 2 = today
	NeedsReply jevNoul
	Phishing   jevNoul
}

// Question set. Keys are never sent to the model; instructions and criteria are.
var jevQuestions = map[string]any{
	"category": map[string]any{
		"type":         "choice",
		"instructions": "What kind of email is this, from the recipient's point of view?",
		"criteria": map[string]string{
			"request":    "Asks the recipient to do, decide, approve, review, or provide something",
			"meeting":    "A meeting invitation, reschedule, cancellation, or agenda",
			"update":     "Information or a status update for the recipient; no action asked of them",
			"newsletter": "Bulk mail, marketing, subscriptions, or automated system notifications",
			"social":     "Personal, social, or thank-you message with nothing to do",
		},
	},
	"urgency": map[string]any{
		"type":         "score",
		"instructions": "How time-sensitive is this for the recipient?",
		"criteria": []string{
			"No time pressure",
			"Should be handled within the next few days",
			"Needs attention today: same-day deadline, outage, escalation, regulator, or senior leadership request",
		},
	},
	"needs_reply": map[string]any{
		"type":         "noul",
		"instructions": "Is the sender waiting for a reply or decision from the recipient?",
	},
	"phishing": map[string]any{
		"type":         "noul",
		"instructions": "Is this likely phishing or fraud: credential or MFA requests, unexpected payment or bank-detail changes, impersonation of an executive or supplier, gift-card or wire-transfer pressure, or a mismatched sender?",
	},
}

func (j *Jev) Classify(ctx context.Context, e Email) (Result, error) {
	a, err := j.Evaluate(ctx, e)
	if err != nil {
		return Result{}, err
	}
	return j.Decide(a), nil
}

// jevQuestionsJSON is jevQuestions encoded once: it is identical in every request.
var jevQuestionsJSON = func() json.RawMessage {
	b, err := json.Marshal(jevQuestions)
	if err != nil {
		panic(err) // static data
	}
	return b
}()

// jevRequest is the request body. Fields are declared in alphabetical order so
// the encoding matches what a map[string]any would produce byte for byte.
type jevRequest struct {
	Model     string          `json:"model"`
	Questions json.RawMessage `json:"questions"`
	State     jevState        `json:"state"`
}

// jevState is structured program state: Jev is built for it, not for chat
// transcripts. Alphabetical field order, as above.
type jevState struct {
	Body           string `json:"body"`
	Importance     string `json:"importance"`
	Received       string `json:"received"`
	SenderDomain   string `json:"sender_domain"`
	SenderInternal bool   `json:"sender_internal"`
	Subject        string `json:"subject"`
}

// payload builds the request body for one email.
func (j *Jev) payload(e Email) ([]byte, error) {
	return json.Marshal(jevRequest{
		Model:     j.Model,
		Questions: jevQuestionsJSON,
		State: jevState{
			Body:           sanitize(e.Body),
			Importance:     e.Importance,
			Received:       e.Received.UTC().Format(time.RFC3339),
			SenderDomain:   e.FromDomain,
			SenderInternal: e.SenderInternal,
			Subject:        sanitize(e.Subject),
		},
	})
}

// Evaluate sends one request and returns the typed answers.
func (j *Jev) Evaluate(ctx context.Context, e Email) (JevAnswers, error) {
	payload, err := j.payload(e)
	if err != nil {
		return JevAnswers{}, err
	}

	var raw struct {
		Answers map[string]json.RawMessage `json:"answers"`
	}
	if err := j.post(ctx, payload, &raw); err != nil {
		return JevAnswers{}, err
	}
	var a JevAnswers
	for key, dst := range map[string]any{
		"category": &a.Category, "urgency": &a.Urgency,
		"needs_reply": &a.NeedsReply, "phishing": &a.Phishing,
	} {
		msg, ok := raw.Answers[key]
		if !ok {
			return JevAnswers{}, fmt.Errorf("jev: missing answer %q", key)
		}
		if err := json.Unmarshal(msg, dst); err != nil {
			return JevAnswers{}, fmt.Errorf("jev: bad answer %q", key)
		}
	}
	return a, nil
}

// Decide is the triage policy, kept in code so it's testable and tunable
// without touching any prompt.
func (j *Jev) Decide(a JevAnswers) Result {
	switch {
	case a.Phishing.Noul >= j.PhishingThreshold:
		return Result{Suspicious, a.Phishing.Noul, "likely phishing/fraud"}
	case a.Category.Confidence < j.MinConfidence:
		return Result{Review, a.Category.Confidence, "low confidence: " + a.Category.Choice}
	}
	wantsAction := a.Category.Choice == "request" || a.NeedsReply.Noul >= 0.6
	switch {
	case wantsAction && a.Urgency.Score >= 1.5:
		return Result{Urgent, a.Category.Confidence, fmt.Sprintf("action needed, urgency %.1f/2", a.Urgency.Score)}
	case wantsAction:
		return Result{ActionRequired, a.Category.Confidence, "action or reply needed"}
	case a.Category.Choice == "meeting":
		return Result{Meeting, a.Category.Confidence, "meeting"}
	case a.Category.Choice == "newsletter":
		return Result{Newsletter, a.Category.Confidence, "bulk/automated"}
	default:
		return Result{FYI, a.Category.Confidence, a.Category.Choice}
	}
}

func (j *Jev) post(ctx context.Context, payload []byte, out any) error {
	backoff := 500 * time.Millisecond
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, j.BaseURL+"/v1/systemone", bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+j.APIKey)
		req.Header.Set("Content-Type", "application/json")
		resp, err := j.HTTP.Do(req)
		if err != nil {
			var ue *url.Error
			if errors.As(err, &ue) {
				err = fmt.Errorf("jev request failed: %v", ue.Err) // don't echo URL/payload
			}
			return err
		}
		retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == 529 || resp.StatusCode >= 500
		if resp.StatusCode == http.StatusOK {
			defer httpx.Close(resp.Body)
			return json.NewDecoder(resp.Body).Decode(out)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10)) // error bodies may echo input; never log them
		httpx.Close(resp.Body)
		if !retryable || attempt >= j.MaxRetries {
			return fmt.Errorf("jev: %s", resp.Status)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
}
