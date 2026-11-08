package classifier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func fakeJev(t *testing.T, status []int, answers string) (*httptest.Server, *int32, *map[string]any) {
	t.Helper()
	var calls int32
	var lastBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if r.URL.Path != "/v1/systemone" || r.Header.Get("Authorization") != "Bearer k" {
			t.Errorf("bad request: %s auth=%q", r.URL.Path, r.Header.Get("Authorization"))
		}
		_ = json.NewDecoder(r.Body).Decode(&lastBody)
		if int(n) <= len(status) {
			w.WriteHeader(status[n-1])
			return
		}
		_, _ = w.Write([]byte(`{"model":"jev-1.13.0","answers":` + answers + `}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls, &lastBody
}

const urgentAnswers = `{
 "category":{"type":"choice","choice":"request","confidence":0.92},
 "urgency":{"type":"score","score":1.8,"confidence":0.8},
 "needs_reply":{"type":"noul","noul":0.9},
 "phishing":{"type":"noul","noul":0.02}}`

func TestJevClassifyAndRequestShape(t *testing.T) {
	srv, _, body := fakeJev(t, nil, urgentAnswers)
	j := NewJev(srv.URL, "k", "jev-latest")
	res, err := j.Classify(context.Background(), Email{FromDomain: "broker.com", Subject: "Bind by 5pm", Body: "x", Received: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Label != Urgent {
		t.Fatalf("got %s", res.Label)
	}
	b := *body
	if b["model"] != "jev-latest" {
		t.Errorf("model not sent")
	}
	qs := b["questions"].(map[string]any)
	for _, k := range []string{"category", "urgency", "needs_reply", "phishing"} {
		if _, ok := qs[k]; !ok {
			t.Errorf("question %s missing", k)
		}
	}
	state := b["state"].(map[string]any)
	if state["sender_domain"] != "broker.com" {
		t.Errorf("state not structured: %v", state)
	}
}

func TestJevRetriesOn429And529(t *testing.T) {
	srv, calls, _ := fakeJev(t, []int{429, 529}, urgentAnswers)
	j := NewJev(srv.URL, "k", "jev-latest")
	if _, err := j.Classify(context.Background(), Email{}); err != nil {
		t.Fatal(err)
	}
	if *calls != 3 {
		t.Fatalf("expected 3 calls, got %d", *calls)
	}
}

func TestJevNoRetryOn422(t *testing.T) {
	srv, calls, _ := fakeJev(t, []int{422}, urgentAnswers)
	if _, err := NewJev(srv.URL, "k", "m").Classify(context.Background(), Email{}); err == nil || *calls != 1 {
		t.Fatalf("err=%v calls=%d", err, *calls)
	}
}

func TestJevMissingAnswerIsError(t *testing.T) {
	srv, _, _ := fakeJev(t, nil, `{"category":{"choice":"update","confidence":0.9}}`)
	if _, err := NewJev(srv.URL, "k", "m").Classify(context.Background(), Email{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestDecide(t *testing.T) {
	j := NewJev("", "", "")
	mk := func(cat string, conf, urg, reply, phish float64) JevAnswers {
		return JevAnswers{jevChoice{cat, conf}, jevScore{urg, 0.9}, jevNoul{reply}, jevNoul{phish}}
	}
	cases := []struct {
		name string
		a    JevAnswers
		want Label
	}{
		{"phishing wins over everything", mk("request", 0.99, 2, 1, 0.85), Suspicious},
		{"low confidence goes to review", mk("update", 0.3, 0, 0, 0), Review},
		{"urgent request", mk("request", 0.9, 1.7, 0.5, 0), Urgent},
		{"non-urgent request", mk("request", 0.9, 0.6, 0.5, 0), ActionRequired},
		{"update that awaits reply", mk("update", 0.9, 0.2, 0.8, 0), ActionRequired},
		{"meeting", mk("meeting", 0.9, 0.5, 0.1, 0), Meeting},
		{"newsletter", mk("newsletter", 0.9, 0, 0, 0.1), Newsletter},
		{"social is fyi", mk("social", 0.9, 0, 0.1, 0), FYI},
	}
	for _, c := range cases {
		if got := j.Decide(c.a).Label; got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

func TestParseLLM(t *testing.T) {
	if r, err := ParseLLM("sure! {\"label\":\"Meeting\",\"reason\":\"invite\"}"); err != nil || r.Label != Meeting {
		t.Fatalf("%v %v", r, err)
	}
	for _, bad := range []string{`{"label":"delete_all"}`, `{"label":"review"}`, "nonsense"} {
		if _, err := ParseLLM(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestEveryLabelHasCategory(t *testing.T) {
	for _, l := range AllLabels {
		if c, ok := Category[l]; !ok || c.Name[:len(CategoryPrefix)] != CategoryPrefix {
			t.Errorf("label %s missing/unprefixed category", l)
		}
	}
}
